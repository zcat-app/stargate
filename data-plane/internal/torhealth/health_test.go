// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package torhealth

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func healthDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/dev/shm", "stargate-health-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func TestContractRecordVector(t *testing.T) {
	// foundation-boundaries.md pins every wire field independently of the encoder.
	vector, err := hex.DecodeString("53474831020000002a0000000000000000e40b5402000000")
	if err != nil {
		t.Fatal(err)
	}
	stamp := Stamp{Boot: 10000000000, Domain: 42}
	t.Run("encoder", func(t *testing.T) {
		d := healthDir(t)
		if err := Write(d, Ready, stamp); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(d, "latest"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, vector) {
			t.Fatalf("record = %x, want contract vector %x", got, vector)
		}
	})
	t.Run("decoder", func(t *testing.T) {
		d := healthDir(t)
		if err := os.WriteFile(filepath.Join(d, "latest"), vector, 0600); err != nil {
			t.Fatal(err)
		}
		clock := func() (Stamp, error) { return Stamp{Boot: 11000000000, Domain: 42}, nil }
		if got := readAt(d, clock); got != Ready {
			t.Fatalf("contract vector state = %v, want READY", got)
		}
	})
}

func TestFreshnessBoundariesAndNoRenewal(t *testing.T) {
	d := healthDir(t)
	start := Stamp{Boot: 10 * int64(time.Second), Domain: 42}
	if err := Write(d, Ready, start); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		age    int64
		domain uint64
		want   State
	}{
		{0, 42, Ready}, {int64(4*time.Second) - 1, 42, Ready}, {int64(4 * time.Second), 42, Unavailable},
		{-1, 42, Unavailable}, {0, 43, Unavailable}, {1<<63 - 1, 42, Unavailable},
	} {
		got := readAt(d, func() (Stamp, error) { return Stamp{Boot: start.Boot + tc.age, Domain: tc.domain}, nil })
		if got != tc.want {
			t.Fatalf("age=%d domain=%d: %v want %v", tc.age, tc.domain, got, tc.want)
		}
	}
	// A fresh reader, touched mtime and arbitrary wall time cannot renew the lease.
	_ = os.Chtimes(filepath.Join(d, "latest"), time.Unix(0, 0), time.Now().Add(24*time.Hour))
	if got := readAt(d, func() (Stamp, error) { return Stamp{Boot: start.Boot + int64(5*time.Second), Domain: 42}, nil }); got != Unavailable {
		t.Fatal("mtime/restart renewed old READY")
	}
}

func TestRecordAndFileEdgesFailUnavailable(t *testing.T) {
	d := healthDir(t)
	stamp, err := Now()
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(d, Ready, stamp); err != nil {
		t.Fatal(err)
	}
	valid, err := os.ReadFile(filepath.Join(d, "latest"))
	if err != nil {
		t.Fatal(err)
	}
	if Read(d) != Ready {
		t.Fatal("regular tmpfs positive control failed")
	}
	for _, b := range [][]byte{nil, valid[:len(valid)-1], append(append([]byte{}, valid...), 0), make([]byte, 8192), append([]byte("BAD1"), valid[4:]...)} {
		if err := os.WriteFile(filepath.Join(d, "latest"), b, 0600); err != nil {
			t.Fatal(err)
		}
		if Read(d) != Unavailable {
			t.Fatal("invalid record accepted")
		}
	}
	bad := append([]byte{}, valid...)
	bad[4] = 255
	_ = os.WriteFile(filepath.Join(d, "latest"), bad, 0600)
	if Read(d) != Unavailable {
		t.Fatal("unknown state accepted")
	}
	for _, negative := range []uint64{1 << 63, ^uint64(0)} {
		bad = append([]byte{}, valid...)
		binary.LittleEndian.PutUint64(bad[16:], negative)
		_ = os.WriteFile(filepath.Join(d, "latest"), bad, 0600)
		if Read(d) != Unavailable {
			t.Fatal("negative signed timestamp accepted")
		}
	}
	bad = append([]byte{}, valid...)
	binary.LittleEndian.PutUint64(bad[16:], uint64(stamp.Boot+int64(time.Hour)))
	_ = os.WriteFile(filepath.Join(d, "latest"), bad, 0600)
	if Read(d) != Unavailable {
		t.Fatal("future sample accepted")
	}
	_ = os.Remove(filepath.Join(d, "latest"))
	_ = os.Symlink("/dev/zero", filepath.Join(d, "latest"))
	if Read(d) != Unavailable {
		t.Fatal("symlink accepted")
	}
	_ = os.Remove(filepath.Join(d, "latest"))
	if err := unix.Mkfifo(filepath.Join(d, "latest"), 0600); err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	if Read(d) != Unavailable || time.Since(begin) > time.Second {
		t.Fatal("FIFO did not fail promptly")
	}
	if Read(t.TempDir()) != Unavailable {
		t.Fatal("unproven persistent backing accepted")
	}
}

func TestAtomicPublicationBoundedAndClockFailure(t *testing.T) {
	d := healthDir(t)
	stamp, err := Now()
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []State{Unavailable, NotReady, Ready} {
		if err := Write(d, state, stamp); err != nil {
			t.Fatal(err)
		}
		if got := Read(d); got != state {
			t.Fatalf("state=%v got=%v", state, got)
		}
	}
	entries, err := os.ReadDir(d)
	if err != nil || len(entries) != 1 || entries[0].Name() != "latest" {
		t.Fatal("publication accumulated history")
	}
	if got := readAt(d, func() (Stamp, error) { return Stamp{}, os.ErrPermission }); got != Unavailable {
		t.Fatal("clock failure accepted")
	}
	// Existing hostile temp links cannot redirect output.
	target := filepath.Join(t.TempDir(), "sentinel")
	_ = os.WriteFile(target, []byte("sentinel"), 0600)
	_ = os.Symlink(target, filepath.Join(d, "pending"))
	if err := Write(d, Ready, stamp); err == nil {
		t.Fatal("followed temporary symlink")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "sentinel" {
		t.Fatal("modified symlink target")
	}
}
