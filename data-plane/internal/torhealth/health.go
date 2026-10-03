// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package torhealth carries only finite current health across the Tor/observer
// boundary (Constitution II/III; foundation-boundaries.md). No control client or
// raw Tor data belongs in this package or the observer.
package torhealth

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type State byte

const (
	Unavailable State = iota
	NotReady
	Ready
	Window     = 4 * time.Second
	Directory  = "/run/tor-health"
	recordSize = 24
)

// Stamp is private volatile freshness metadata; it never enters CP responses.
// Linux time-namespace identity proves that both endpoints use the same
// CLOCK_BOOTTIME offset. tmpfs backing prevents cross-boot sample reuse.
type Stamp struct {
	Boot   int64
	Domain uint64
}

func Now() (Stamp, error) {
	var ts unix.Timespec
	var ns unix.Stat_t
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return Stamp{}, err
	}
	if err := unix.Stat("/proc/self/ns/time", &ns); err != nil {
		return Stamp{}, err
	}
	if ts.Sec < 0 || ts.Sec > int64(^uint64(0)>>1)/int64(time.Second) || ns.Ino == 0 {
		return Stamp{}, errors.New("invalid clock domain")
	}
	return Stamp{Boot: ts.Nano(), Domain: ns.Ino}, nil
}

func directory(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.TMPFS_MAGIC {
		_ = unix.Close(fd)
		return -1, errors.New("unproven volatile backing")
	}
	return fd, nil
}

// Read freshly validates a bounded regular file for every decision; reader
// restart and repeated RPCs cannot renew the producer's original lease.
func Read(path string) State { return readAt(path, Now) }
func readAt(path string, clock func() (Stamp, error)) State {
	dir, err := directory(path)
	if err != nil {
		return Unavailable
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, "latest", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return Unavailable
	}
	file := os.NewFile(uintptr(fd), "latest")
	defer file.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size != recordSize {
		return Unavailable
	}
	var data [recordSize + 1]byte
	n, err := io.ReadFull(file, data[:])
	if n != recordSize || err != io.ErrUnexpectedEOF || string(data[:4]) != "SGH1" || data[4] > byte(Ready) || data[5] != 0 || data[6] != 0 || data[7] != 0 {
		return Unavailable
	}
	stamp := Stamp{Domain: binary.LittleEndian.Uint64(data[8:16]), Boot: int64(binary.LittleEndian.Uint64(data[16:24]))} // #nosec G115 -- Signed wire encoding; stamp.Boot < 0 below rejects high-bit values.
	now, err := clock()                                                                                                  // Check after I/O; a delayed read cannot extend the lease.
	if err != nil || stamp.Domain == 0 || now.Domain != stamp.Domain || stamp.Boot < 0 || now.Boot < stamp.Boot || now.Boot-stamp.Boot >= int64(Window) {
		return Unavailable
	}
	return State(data[4])
}

// Write replaces one fixed record through one fixed temp file. The publisher
// is the sole writer; no observer-owned paths are opened here.
func Write(path string, state State, stamp Stamp) error {
	dir, err := directory(path)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, "pending", unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "pending")
	defer file.Close()
	defer unix.Unlinkat(dir, "pending", 0)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("invalid publication file")
	}
	var data [recordSize]byte
	copy(data[:4], "SGH1")
	data[4] = byte(state)
	binary.LittleEndian.PutUint64(data[8:16], stamp.Domain)
	binary.LittleEndian.PutUint64(data[16:24], uint64(stamp.Boot)) // #nosec G115 -- Preserve signed wire bits; readers reject negative stamps.
	if _, err = file.Write(data[:]); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return unix.Renameat(dir, "pending", dir, "latest")
}
