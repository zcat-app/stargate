// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

// midHour is a wall-clock instant safely inside an hour so tests can shift
// by whole hours and land in unambiguous buckets.
var midHour = time.Date(2026, 9, 4, 10, 30, 0, 0, time.UTC)

func TestAuthPassedIncrementsCurrentHour(t *testing.T) {
	c := New()
	c.authPassedAt(midHour)
	c.authPassedAt(midHour)
	c.authPassedAt(midHour)

	got := c.Snapshot()
	if len(got.GetCounters()) != 1 {
		t.Fatalf("Snapshot rows = %d, want 1", len(got.GetCounters()))
	}
	row := got.GetCounters()[0]
	if row.GetRoute() != RouteTOR {
		t.Errorf("route = %q, want %q", row.GetRoute(), RouteTOR)
	}
	if row.GetHourBucket() != uint64(midHour.Unix()/3600) {
		t.Errorf("hour_bucket = %d, want %d (unix-hour of the increment)",
			row.GetHourBucket(), uint64(midHour.Unix()/3600))
	}
	if row.GetRequestCount() != 3 {
		t.Errorf("request_count = %d, want 3", row.GetRequestCount())
	}
	if row.GetByteCount() != 0 {
		t.Errorf("byte_count = %d, want 0 (auth pass alone forwards nothing)", row.GetByteCount())
	}
}

func TestAddForwardedBytesAccumulatesInCurrentBucket(t *testing.T) {
	c := New()
	c.addBytesAt(midHour, 100)
	c.addBytesAt(midHour, 23)

	row := c.Snapshot().GetCounters()[0]
	if row.GetByteCount() != 123 {
		t.Errorf("byte_count = %d, want 123 (accumulates across calls)", row.GetByteCount())
	}
	if row.GetRequestCount() != 0 {
		t.Errorf("request_count = %d, want 0 (byte accounting never counts a request)", row.GetRequestCount())
	}
}

func TestHourRolloverCreatesAdjacentRow(t *testing.T) {
	c := New()
	c.authPassedAt(midHour)                       // hour H
	c.addBytesAt(midHour.Add(25*time.Minute), 7)  // 10:55, still hour H
	c.authPassedAt(midHour.Add(29 * time.Minute)) // 10:59, hour H, request 2
	c.addBytesAt(midHour.Add(95*time.Minute), 5)  // 12:05, hour H+2, new row
	c.authPassedAt(midHour.Add(99 * time.Minute)) // 12:09, hour H+2, request 1

	rows := c.Snapshot().GetCounters()
	if len(rows) != 2 {
		t.Fatalf("Snapshot rows = %d, want 2 (H and H+2)", len(rows))
	}
	first, second := rows[0], rows[1]
	h := uint64(midHour.Unix() / 3600)
	if first.GetHourBucket() != h || second.GetHourBucket() != h+2 {
		t.Fatalf("hour buckets = [%d, %d], want [%d, %d]", first.GetHourBucket(), second.GetHourBucket(), h, h+2)
	}
	if first.GetRequestCount() != 2 || first.GetByteCount() != 7 {
		t.Errorf("hour H row = (requests %d, bytes %d), want (2, 7)", first.GetRequestCount(), first.GetByteCount())
	}
	if second.GetRequestCount() != 1 || second.GetByteCount() != 5 {
		t.Errorf("hour H+2 row = (requests %d, bytes %d), want (1, 5)", second.GetRequestCount(), second.GetByteCount())
	}
}

func TestSnapshotIsPureRead(t *testing.T) {
	c := New()
	c.authPassedAt(midHour)

	// The GetStatus sandwich (contracts/control-grpc.md §"GetStatus
	// (minimum subset)"): reads with no traffic between them return the
	// same counters — the read surface, not the write surface.
	first := c.Snapshot()
	second := c.Snapshot()
	if !proto.Equal(first, second) {
		t.Fatalf("two reads with no traffic differ:\n %v\n %v", first, second)
	}

	// The snapshot is a copy: mutating the returned proto must not leak
	// into the store, and later increments must not retro-alter a
	// previously returned snapshot.
	first.GetCounters()[0].RequestCount = 99
	c.authPassedAt(midHour.Add(2 * time.Hour))
	third := c.Snapshot()
	if got := third.GetCounters()[0].GetRequestCount(); got != 1 {
		t.Errorf("request_count after mutated snapshot = %d, want 1 (copy semantics)", got)
	}
	if len(first.GetCounters()) != 1 {
		t.Errorf("earlier snapshot now has %d rows, want 1 (point-in-time)", len(first.GetCounters()))
	}
}

func TestSnapshotDeterministicOrder(t *testing.T) {
	c := New()
	c.addBytesAt(midHour.Add(3*time.Hour), 1) // inserted first, highest hour
	c.authPassedAt(midHour)                   // hour H
	c.addBytesAt(midHour.Add(1*time.Hour), 2) // hour H+1

	rows := c.Snapshot().GetCounters()
	if len(rows) != 3 {
		t.Fatalf("Snapshot rows = %d, want 3", len(rows))
	}
	h := uint64(midHour.Unix() / 3600)
	for i, want := range []uint64{h, h + 1, h + 3} {
		if got := rows[i].GetHourBucket(); got != want {
			t.Errorf("row %d hour_bucket = %d, want %d (ascending, insertion-order independent)", i, got, want)
		}
	}
}
