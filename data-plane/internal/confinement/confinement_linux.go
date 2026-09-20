// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

// Package confinement establishes the DP's irreversible IP boundary before
// any untrusted serving. T168 / Constitution III: owner rules are additional
// protection, not the running process's only barrier against independent egress.
package confinement

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var errBoundary = errors.New("network confinement unavailable")

// Apply must run in the trusted boot phase, before any serving goroutine or
// adapter dial. The sole socket may be an ordinary TCP loopback listener.
// Callers must close it and exit on error: installation can be partially applied.
func Apply(listener *net.TCPListener) error {
	raw, err := listener.SyscallConn()
	if err != nil {
		return errBoundary
	}
	var checked error
	if err = raw.Control(func(fd uintptr) { checked = checkDescriptors(int(fd)) }); err != nil {
		return errBoundary
	}
	if checked != nil {
		return errBoundary
	}
	return restrictProcess()
}

func checkDescriptors(listener int) error {
	proto, err := unix.GetsockoptInt(listener, unix.SOL_SOCKET, unix.SO_PROTOCOL)
	if err != nil || proto != unix.IPPROTO_TCP {
		return errBoundary
	}
	listening, err := unix.GetsockoptInt(listener, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err != nil || listening != 1 {
		return errBoundary
	}
	address, err := unix.Getsockname(listener)
	if err != nil {
		return errBoundary
	}
	switch a := address.(type) {
	case *unix.SockaddrInet4:
		if !net.IP(a.Addr[:]).IsLoopback() {
			return errBoundary
		}
	case *unix.SockaddrInet6:
		if !net.IP(a.Addr[:]).IsLoopback() {
			return errBoundary
		}
	default:
		return errBoundary
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return errBoundary
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			return errBoundary
		}
		if fd == listener {
			continue
		}
		var stat unix.Stat_t
		if err = unix.Fstat(fd, &stat); err == unix.EBADF {
			continue
		} else if err != nil {
			return errBoundary
		}
		// Include stdin/out/err: an inherited socket or tun device is already an
		// egress capability even if creation and connect are subsequently forbidden.
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFSOCK:
			return errBoundary
		case unix.S_IFCHR:
			if uint64(stat.Rdev) != unix.Mkdev(1, 3) {
				return errBoundary
			}
		}
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return errBoundary
		}
		// Go owns its poll/event handles. Reject other anonymous capabilities,
		// including inherited SQPOLL rings that can submit without another syscall.
		if strings.HasPrefix(target, "anon_inode:") && target != "anon_inode:[eventpoll]" && target != "anon_inode:[eventfd]" {
			return errBoundary
		}
	}
	return nil
}

func restrictProcess() error {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi < 4 {
		return errBoundary
	}
	// ABI4 has exactly these first two fields. Do not accidentally request newer
	// struct fields merely because the build machine has newer UAPI headers.
	attr := struct{ FS, Net uint64 }{Net: unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return errBoundary
	}
	defer unix.Close(int(fd))
	if _, _, err := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); err != 0 {
		return fmt.Errorf("%w: %w", errBoundary, err)
	}
	if _, _, err := syscall.AllThreadsSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, quietLandlockFlags(abi), 0); err != 0 {
		return fmt.Errorf("%w: %w", errBoundary, err)
	}
	filter := socketFilter()
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	// TSYNC may return an unsynchronized TID rather than setting errno.
	if errno != 0 || result != 0 {
		return errBoundary
	}
	return nil
}

func quietLandlockFlags(abi uintptr) uintptr {
	if abi >= 7 {
		return unix.LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF | unix.LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF
	}
	return 0
}

func socketFilter() []unix.SockFilter {
	arch := uint32(unix.AUDIT_ARCH_X86_64)
	if runtime.GOARCH == "arm64" {
		arch = unix.AUDIT_ARCH_AARCH64
	}
	const ld = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	const eq = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	const ret = unix.BPF_RET | unix.BPF_K
	const deny = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	f := []unix.SockFilter{
		{Code: ld, K: 4}, // seccomp_data.arch
		{Code: eq, K: arch, Jt: 1},
		{Code: ret, K: deny},
	}
	if runtime.GOARCH == "amd64" {
		f = append(f, unix.SockFilter{Code: ld, K: 0},
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: 0x40000000, Jf: 1},
			unix.SockFilter{Code: ret, K: deny}) // x32 has the same audit architecture
	}
	for _, nr := range []uint32{unix.SYS_SOCKET, unix.SYS_SOCKETPAIR} {
		f = append(f, unix.SockFilter{Code: ld, K: 0}, unix.SockFilter{Code: eq, K: nr, Jf: 4},
			unix.SockFilter{Code: ld, K: 16}, // low word of socket family; supported architectures are little-endian
			unix.SockFilter{Code: eq, K: unix.AF_UNIX, Jt: 1}, unix.SockFilter{Code: ret, K: deny}, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW})
	}
	// Fast Open can originate TCP through message sends without connect(2).
	// Message receives and pidfd_getfd can import sockets; io_uring offers both
	// creation and I/O outside the ordinary syscall entries. None is used by the
	// DP's read/write stream transport. Landlock closes reuse via connect(2).
	for _, nr := range []uint32{unix.SYS_SENDTO, unix.SYS_SENDMSG, unix.SYS_SENDMMSG,
		unix.SYS_RECVMSG, unix.SYS_RECVMMSG, unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER,
		unix.SYS_IO_URING_REGISTER, unix.SYS_PIDFD_GETFD} {
		f = append(f, unix.SockFilter{Code: ld, K: 0}, unix.SockFilter{Code: eq, K: nr, Jf: 1}, unix.SockFilter{Code: ret, K: deny})
	}
	return append(f, unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW})
}
