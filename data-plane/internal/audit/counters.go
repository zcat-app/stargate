// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package audit implements the FR-008 aggregate counters (T049): the
// in-memory (route, hour_bucket) → (request_count, byte_count) store of
// data-model.md §3. Only requests that pass authentication count (counting
// auth failures would side-channel token guessing — Principle III); route
// failures after auth still count because the listeners fire the count
// before the request phase. byte_count is fed only by bytes forwarded
// between client and upstream — the data plane's synthesised reply bytes
// never cross the counting conn (forward dials and wraps the upstream).
//
// Privacy posture (arch §6.4): the aggregate carries no destination, no
// token, and no sub-hour data — structurally, by having no field for any.
// In v1 the store is process-memory only (lost on DP restart); the DP
// never touches the aggregate_counters SQLite table, and the production
// CP-side flush caller is deferred to the admin-UI feature. The package
// performs no I/O and emits no log lines (FR-008).
package audit

import (
	"sort"
	"sync"
	"time"

	"github.com/zcat-app/stargate/data-plane/internal/forward"
	"github.com/zcat-app/stargate/data-plane/internal/listener"
	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

// RouteTOR is the only route label rows carry in this feature
// (data-model.md §3; later sidecars add their own labels in their features).
const RouteTOR = "TOR"

// Compile-time seam conformance: Counters is what the listeners count
// through and what GetStatus reads through — both pins fail the build if
// either seam drifts.
var (
	_ listener.Audit      = (*Counters)(nil)
	_ forward.ByteCounter = (*Counters)(nil)
)

type bucketKey struct {
	route string
	hour  uint64
}

type bucketTotals struct {
	requests uint64
	bytes    uint64
}

// Counters is the aggregate store. The mutex is uncontended in practice:
// one AuthPassedRequest per request and one close-flush per tunnel, against
// a GetStatus surface that in v1 only the contract-test harness calls
// (research.md §11).
type Counters struct {
	mu      sync.Mutex
	buckets map[bucketKey]*bucketTotals
}

// New builds the empty store. T050 constructs one per boot and wires the
// same value into the listeners (Audit seams) and the DP gRPC server
// (StatusFunc seam).
func New() *Counters {
	return &Counters{buckets: make(map[bucketKey]*bucketTotals)}
}

// hourBucket is the unix-hour of now — the bucket key of data-model.md §3,
// computed at increment time.
func hourBucket(now time.Time) uint64 { return uint64(now.Unix() / 3600) }

// AuthPassedRequest implements listener.Audit: exactly one request_count
// increment in the current hour bucket. Route outcome is irrelevant here —
// the count fires at the auth boundary, before the request phase, which is
// what makes route failures count and auth failures not (FR-008 asymmetry).
func (c *Counters) AuthPassedRequest() { c.authPassedAt(time.Now()) }

// authPassedAt is the clock-injectable form (tests only).
func (c *Counters) authPassedAt(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bucketAt(now).requests++
}

// AddForwardedBytes implements forward.ByteCounter: the bytes a tunnel
// moved in both directions, handed over once at request close by the
// counting conn.
func (c *Counters) AddForwardedBytes(n uint64) { c.addBytesAt(time.Now(), n) }

// addBytesAt is the clock-injectable form (tests only).
func (c *Counters) addBytesAt(now time.Time, n uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bucketAt(now).bytes += n
}

// bucketAt returns the row for now's bucket, creating it on first touch.
// Callers hold c.mu.
func (c *Counters) bucketAt(now time.Time) *bucketTotals {
	k := bucketKey{route: RouteTOR, hour: hourBucket(now)}
	t, ok := c.buckets[k]
	if !ok {
		t = &bucketTotals{}
		c.buckets[k] = t
	}
	return t
}

// Snapshot returns a point-in-time copy of the store as the GetStatus
// payload — it conforms to controlclient.StatusFunc. It increments nothing
// (§"GetStatus (minimum subset)": a side-effecting probe would defeat
// T025c's no-traffic sandwich), never aliases the internal map, and orders
// rows by (route, hour) so the RPC surface is stable for callers.
func (c *Counters) Snapshot() *grpcpb.StatusResponse {
	c.mu.Lock()
	defer c.mu.Unlock()

	keys := make([]bucketKey, 0, len(c.buckets))
	for k := range c.buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].route != keys[j].route {
			return keys[i].route < keys[j].route
		}
		return keys[i].hour < keys[j].hour
	})

	counters := make([]*grpcpb.RouteCounter, 0, len(keys))
	for _, k := range keys {
		t := c.buckets[k]
		counters = append(counters, &grpcpb.RouteCounter{
			Route:        k.route,
			HourBucket:   k.hour,
			RequestCount: t.requests,
			ByteCount:    t.bytes,
		})
	}
	return &grpcpb.StatusResponse{Counters: counters}
}
