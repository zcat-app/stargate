// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package audit holds private volatile traffic totals and exports only completed
// immutable UTC-hour buckets (Constitution III; control-grpc.md T158 transition).
// Only authenticated requests count. Bytes are booked once, after both forwarding
// pumps finish, in the completion hour. No destination, client identity or payload
// enters this store. It performs no I/O or logging; restart loses every row.
package audit

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/zcat-app/stargate/data-plane/internal/forward"
	"github.com/zcat-app/stargate/data-plane/internal/listener"
	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

const RouteTOR = "TOR"
const retentionHours = 7 * 24

var (
	_ listener.Audit      = (*Counters)(nil)
	_ forward.ByteCounter = (*Counters)(nil)
)

type bucketKey struct {
	route string
	hour  uint64
}
type bucketTotals struct{ requests, bytes uint64 }

// Counters serializes clock observation, increments and publication. hour never
// decreases: clock rollback must not reopen a bucket already disclosed to a peer.
type Counters struct {
	mu       sync.Mutex
	now      func() time.Time
	hour     uint64
	disabled bool
	buckets  map[bucketKey]*bucketTotals
}

func New() *Counters { return NewWithClock(time.Now) }

// NewWithClock is an internal construction seam for deterministic clock tests.
// Production has no RPC, environment option or runtime setter for this clock.
func NewWithClock(now func() time.Time) *Counters {
	return &Counters{now: now, hour: hourBucket(now()), buckets: make(map[bucketKey]*bucketTotals)}
}

func hourBucket(now time.Time) uint64 {
	if now.Unix() < 0 {
		return 0
	}
	return uint64(now.Unix() / 3600) // #nosec G115 -- negative Unix times return above; quotient is nonnegative
}

// advance closes all earlier hours and expires entire rows. Callers hold mu.
// Using a high-water mark also prevents expired rows reappearing after rollback.
func (c *Counters) advance(now time.Time) {
	h := hourBucket(now)
	if h <= c.hour {
		return
	}
	c.hour = h
	for k := range c.buckets {
		if c.hour-k.hour >= retentionHours {
			delete(c.buckets, k)
		}
	}
}

func (c *Counters) AuthPassedRequest()         { c.add(1, 0) }
func (c *Counters) AddForwardedBytes(n uint64) { c.add(0, n) }
func (c *Counters) add(requests, bytes uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disabled {
		return
	}
	c.advance(c.now())
	if requests == 0 && bytes == 0 {
		return
	}
	k := bucketKey{RouteTOR, c.hour}
	t := c.buckets[k]
	if t == nil {
		t = &bucketTotals{}
		c.buckets[k] = t
	}
	t.requests += requests
	t.bytes += bytes
}

// Disable discards all traffic state and stops further collection for this boot.
func (c *Counters) Disable() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.disabled = true
	c.buckets = nil
}

// Run owns idle expiry until the process context ends. Reads independently prune
// at the same cutoff, so delayed scheduling never exports an expired row.
func (c *Counters) Run(ctx context.Context) { c.run(ctx, time.After) }
func (c *Counters) run(ctx context.Context, after func(time.Duration) <-chan time.Time) {
	for {
		c.mu.Lock()
		if c.disabled {
			c.mu.Unlock()
			return
		}
		now := c.now()
		c.advance(now)
		delay := now.Truncate(time.Hour).Add(time.Hour).Sub(now)
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-after(delay):
		}
	}
}

// Snapshot may finalize/expire buckets but never increments traffic. It copies
// only completed rows; polling during activity cannot observe changing totals.
func (c *Counters) Snapshot() *grpcpb.StatusResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advance(c.now())
	keys := make([]bucketKey, 0, len(c.buckets))
	for k := range c.buckets {
		if k.hour < c.hour {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].hour < keys[j].hour })
	rows := make([]*grpcpb.RouteCounter, 0, len(keys))
	for _, k := range keys {
		t := c.buckets[k]
		rows = append(rows, &grpcpb.RouteCounter{Route: k.route, HourBucket: k.hour, RequestCount: t.requests, ByteCount: t.bytes})
	}
	return &grpcpb.StatusResponse{Counters: rows}
}
