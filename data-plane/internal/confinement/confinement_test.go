// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package confinement

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func echo(l net.Listener) {
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		go func() { defer c.Close(); io.Copy(c, c) }()
	}
}
func roundtrip(network, addr, text string) error {
	c, e := net.DialTimeout(network, addr, time.Second)
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, e = c.Write([]byte(text)); e != nil {
		return e
	}
	b := make([]byte, len(text))
	_, e = io.ReadFull(c, b)
	if e != nil {
		return e
	}
	if string(b) != text {
		return fmt.Errorf("echo mismatch")
	}
	return nil
}
func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}

func TestSandbox(t *testing.T) {
	if os.Getenv("T168_CHILD") == "1" {
		child(t)
		return
	}
	tcp4, e := net.Listen("tcp4", "127.0.0.1:0")
	must(t, e)
	defer tcp4.Close()
	go echo(tcp4)
	tcp6, e := net.Listen("tcp6", "[::1]:0")
	must(t, e)
	defer tcp6.Close()
	go echo(tcp6)
	dir, e := os.MkdirTemp("", "t168uds")
	must(t, e)
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "tor.sock")
	ul, e := net.Listen("unix", path)
	must(t, e)
	defer func() { ul.Close() }()
	rotated := make(chan struct{})
	go func() {
		for {
			c, e := ul.Accept()
			if e != nil {
				return
			}
			b := make([]byte, 32)
			n, e := c.Read(b)
			if e == nil {
				c.Write(b[:n])
			}
			c.Close()
			if string(b[:n]) == "ROTATE" {
				ul.Close()
				ul, e = net.Listen("unix", path)
				if e != nil {
					return
				}
				close(rotated)
			}
		}
	}()
	for _, p := range []struct{ n, a string }{{"tcp4", tcp4.Addr().String()}, {"tcp6", tcp6.Addr().String()}, {"unix", path}} {
		must(t, roundtrip(p.n, p.a, "CONTROL"))
	}
	lc := net.ListenConfig{}
	lc.SetMultipathTCP(false)
	inbound, e := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	must(t, e)
	defer inbound.Close()
	file, e := inbound.(*net.TCPListener).File()
	must(t, e)
	defer file.Close()
	exe := helperBinary(t, "0")
	cmd := exec.Command(exe, "-test.run=^TestSandbox$", "-test.v", "-test.timeout=20s")
	cmd.Env = append(os.Environ(), "T168_CHILD=1", "T168_V4="+tcp4.Addr().String(), "T168_V6="+tcp6.Addr().String(), "T168_UNIX="+path)
	cmd.ExtraFiles = []*os.File{file}
	out, e := cmd.StdoutPipe()
	must(t, e)
	cmd.Stderr = os.Stderr
	must(t, cmd.Start())
	scanner := bufio.NewScanner(out)
	ready := false
	for scanner.Scan() {
		line := scanner.Text()
		t.Log(line)
		if line == "READY" {
			ready = true
			must(t, roundtrip("tcp4", inbound.Addr().String(), "INBOUND"))
		}
	}
	must(t, cmd.Wait())
	if !ready {
		t.Fatal("no readiness")
	}
	select {
	case <-rotated:
	default:
		t.Fatal("Unix listener was not recreated")
	}
}

func child(t *testing.T) {
	l, e := net.FileListener(os.NewFile(3, "listener"))
	must(t, e)
	defer l.Close()
	fdAddresses := make([]struct {
		fd int
		sa syscall.Sockaddr
	}, 24)
	for i := range fdAddresses {
		family, env := syscall.AF_INET, "T168_V4"
		if i%2 == 1 {
			family, env = syscall.AF_INET6, "T168_V6"
		}
		host, ps, e := net.SplitHostPort(os.Getenv(env))
		must(t, e)
		port, e := strconv.Atoi(ps)
		must(t, e)
		fd, e := syscall.Socket(family, syscall.SOCK_STREAM, 0)
		must(t, e)
		var sa syscall.Sockaddr
		if family == syscall.AF_INET {
			a := &syscall.SockaddrInet4{Port: port}
			copy(a.Addr[:], net.ParseIP(host).To4())
			sa = a
		} else {
			a := &syscall.SockaddrInet6{Port: port}
			copy(a.Addr[:], net.ParseIP(host).To16())
			sa = a
		}
		fdAddresses[i] = struct {
			fd int
			sa syscall.Sockaddr
		}{fd, sa}
	}
	start := make(chan struct{})
	ready := make(chan int, 24)
	results := make(chan error, 24)
	hold := make(chan struct{})
	worker := func(i int) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ready <- syscall.Gettid()
		<-start
		p := fdAddresses[i]
		e := syscall.Connect(p.fd, p.sa)
		syscall.Close(p.fd)
		if e != syscall.EACCES {
			results <- fmt.Errorf("thread %d TCP connect: %v", syscall.Gettid(), e)
		} else {
			results <- nil
		}
		<-hold
	}
	tids := map[int]bool{}
	for i := 0; i < 8; i++ {
		go worker(i)
	}
	for i := 0; i < 8; i++ {
		tids[<-ready] = true
	}
	must(t, restrictProcess())
	for i := 8; i < 24; i++ {
		go worker(i)
	}
	for i := 8; i < 24; i++ {
		tids[<-ready] = true
	}
	close(start)
	for i := 0; i < 24; i++ {
		must(t, <-results)
	}
	close(hold)
	if len(tids) != 24 {
		t.Fatalf("wanted 24 distinct OS threads, got %d", len(tids))
	}
	t.Log("PASS: pre-existing and newly created OS threads deny IPv4/IPv6 connects")
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		for _, kind := range []int{syscall.SOCK_STREAM, syscall.SOCK_DGRAM} {
			fd, e := syscall.Socket(family, kind, 0)
			if fd >= 0 {
				syscall.Close(fd)
			}
			if e != syscall.EPERM {
				t.Fatalf("new socket %d/%d: %v", family, kind, e)
			}
		}
	}
	fmt.Println("READY")
	c, e := l.Accept()
	must(t, e)
	b := make([]byte, 7)
	_, e = io.ReadFull(c, b)
	must(t, e)
	_, e = c.Write(b)
	must(t, e)
	// Test the accepted descriptor and listener separately, without creating a socket.
	for _, v := range []syscall.Conn{c.(syscall.Conn), l.(syscall.Conn)} {
		raw, e := v.SyscallConn()
		must(t, e)
		var result error
		must(t, raw.Control(func(fd uintptr) {
			proto, _ := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, 38)
			typ, _ := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
			t.Logf("reuse tid=%d proto=%d type=%d", syscall.Gettid(), proto, typ)
			a := syscall.RawSockaddr{Family: syscall.AF_UNSPEC}
			_, _, e := syscall.Syscall(syscall.SYS_CONNECT, fd, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a))
			if e != 0 {
				result = e
				return
			}
			result = syscall.Connect(int(fd), fdAddresses[0].sa)
		}))
		if result != syscall.EACCES {
			t.Fatalf("reused socket connect: %v", result)
		}
	}
	c.Close()
	t.Log("PASS: incoming TCP still works; accepted socket and listener reuse denied")
	must(t, roundtrip("unix", os.Getenv("T168_UNIX"), "ROTATE"))
	deadline := time.Now().Add(2 * time.Second)
	for {
		e = roundtrip("unix", os.Getenv("T168_UNIX"), "RECONNECTED")
		if e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(e)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Log("PASS: Unix socket reconnect after listener recreation")

}

var helperOnce sync.Once
var helperPath string
var helperErr error

func helperBinary(t *testing.T, cgo string) string {
	t.Helper()
	if cgo != "0" {
		t.Fatal("unexpected helper mode")
	}
	helperOnce.Do(func() {
		dir, err := os.MkdirTemp("", "stargate-confinement-bin")
		if err != nil {
			helperErr = err
			return
		}
		helperPath = filepath.Join(dir, "confinement.test")
		cmd := exec.Command("go", "test", "-c", "-o", helperPath, ".")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			helperErr = fmt.Errorf("build static helper: %w: %s", err, out)
		}
	})
	if helperErr != nil {
		t.Fatal(helperErr)
	}
	return helperPath
}

func TestStartupRejectsInheritedSockets(t *testing.T) {
	for _, domain := range []int{unix.AF_INET, unix.AF_INET6, unix.AF_UNIX} {
		for _, stdio := range []bool{false, true} {
			t.Run(fmt.Sprintf("domain=%d/stdio=%v", domain, stdio), func(t *testing.T) {
				fd, err := unix.Socket(domain, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
				must(t, err)
				f := os.NewFile(uintptr(fd), "inherited socket")
				defer f.Close()
				cmd := exec.Command(helperBinary(t, "0"), "-test.run=^TestPublicHelper$", "-test.v")
				cmd.Env = append(os.Environ(), "T168_PUBLIC=reject")
				if stdio {
					cmd.Stdin = f
				} else {
					cmd.ExtraFiles = []*os.File{f}
				}
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("inherited socket not refused: %v\n%s", err, out)
				}
			})
		}
	}
}

func TestPublicBoundary(t *testing.T) {
	sink, err := net.Listen("tcp4", "127.0.0.1:0")
	must(t, err)
	defer sink.Close()
	go echo(sink)
	must(t, roundtrip("tcp4", sink.Addr().String(), "CONTROL"))
	dir, err := os.MkdirTemp("", "t168-public")
	must(t, err)
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "tor.sock")
	ul, err := net.Listen("unix", sock)
	must(t, err)
	defer ul.Close()
	go echo(ul)
	cmd := exec.Command(helperBinary(t, "0"), "-test.run=^TestPublicHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "T168_PUBLIC=restrict", "T168_V4="+sink.Addr().String(), "T168_UNIX="+sock, "GODEBUG=multipathtcp=1")
	out, err := cmd.StdoutPipe()
	must(t, err)
	cmd.Stderr = os.Stderr
	must(t, cmd.Start())
	scanner := bufio.NewScanner(out)
	ready := false
	for scanner.Scan() {
		line := scanner.Text()
		t.Log(line)
		if strings.HasPrefix(line, "READY ") {
			ready = true
			must(t, roundtrip("tcp4", strings.TrimPrefix(line, "READY "), "INBOUND"))
		}
	}
	must(t, cmd.Wait())
	if !ready {
		t.Fatal("confinement never reached admission")
	}
}

func TestPublicHelper(t *testing.T) {
	mode := os.Getenv("T168_PUBLIC")
	if mode == "" {
		return
	}
	if mode == "descendant" {
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			fd, err := unix.Socket(family, unix.SOCK_STREAM, 0)
			if fd >= 0 {
				unix.Close(fd)
			}
			if err != unix.EPERM {
				t.Fatalf("descendant IP socket: %v", err)
			}
		}
		host, ps, err := net.SplitHostPort(os.Getenv("T168_V4"))
		must(t, err)
		port, err := strconv.Atoi(ps)
		must(t, err)
		dest := &unix.SockaddrInet4{Port: port}
		copy(dest.Addr[:], net.ParseIP(host).To4())
		if err := unix.Connect(3, dest); err != unix.EACCES {
			t.Fatalf("descendant inherited socket reconnect: %v", err)
		}
		must(t, roundtrip("unix", os.Getenv("T168_UNIX"), "CHILD"))
		return
	}
	lc := net.ListenConfig{}
	lc.SetMultipathTCP(false)
	l, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	must(t, err)
	defer l.Close()
	err = Apply(l.(*net.TCPListener))
	if mode == "reject" {
		if err == nil {
			t.Fatal("admitted with inherited network capability")
		}
		return
	}
	must(t, err)
	fmt.Println("READY " + l.Addr().String())
	c, err := l.Accept()
	must(t, err)
	defer c.Close()
	b := make([]byte, 7)
	_, err = io.ReadFull(c, b)
	must(t, err)
	_, err = c.Write(b)
	must(t, err)
	host, ps, err := net.SplitHostPort(os.Getenv("T168_V4"))
	must(t, err)
	port, err := strconv.Atoi(ps)
	must(t, err)
	dest := &unix.SockaddrInet4{Port: port}
	copy(dest.Addr[:], net.ParseIP(host).To4())
	for _, v := range []syscall.Conn{c.(syscall.Conn), l.(syscall.Conn)} {
		raw, err := v.SyscallConn()
		must(t, err)
		must(t, raw.Control(func(fd uintptr) {
			proto, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
			must(t, err)
			if proto != unix.IPPROTO_TCP {
				t.Fatalf("listener protocol=%d, not ordinary TCP", proto)
			}
			a := unix.RawSockaddr{Family: unix.AF_UNSPEC}
			_, _, e := unix.Syscall(unix.SYS_CONNECT, fd, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a))
			if e != 0 {
				t.Fatal(e)
			}
			if err := unix.Connect(int(fd), dest); err != unix.EACCES {
				t.Fatalf("socket reuse: %v", err)
			}
			if err := unix.Sendto(int(fd), []byte("BYPASS"), unix.MSG_FASTOPEN, dest); err != unix.EPERM {
				t.Fatalf("Fast Open sendto: %v", err)
			}
			if _, err := unix.SendmsgN(int(fd), []byte("BYPASS"), nil, dest, unix.MSG_FASTOPEN); err != unix.EPERM {
				t.Fatalf("Fast Open sendmsg: %v", err)
			}
		}))
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	must(t, err)
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	if _, _, _, _, err := unix.Recvmsg(pair[0], make([]byte, 1), make([]byte, 64), unix.MSG_DONTWAIT); err != unix.EPERM {
		t.Fatalf("descriptor import: %v", err)
	}
	for _, nr := range []uintptr{unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER, unix.SYS_PIDFD_GETFD} {
		_, _, err := unix.Syscall(nr, 0, 0, 0)
		if err != unix.EPERM {
			t.Fatalf("alternate entry %d: %v", nr, err)
		}
	}
	must(t, roundtrip("unix", os.Getenv("T168_UNIX"), "UNIX"))
	exe, err := os.Executable()
	must(t, err)
	child := exec.Command(exe, "-test.run=^TestPublicHelper$")
	child.Env = append(os.Environ(), "T168_PUBLIC=descendant")
	inherited, err := l.(*net.TCPListener).File()
	must(t, err)
	defer inherited.Close()
	child.ExtraFiles = []*os.File{inherited}
	if out, err := child.CombinedOutput(); err != nil {
		t.Fatalf("descendant confinement: %v\n%s", err, out)
	}
}

func TestCgoRefuses(t *testing.T) {
	if _, _, err := syscall.AllThreadsSyscall(unix.SYS_GETPID, 0, 0, 0); err != syscall.ENOTSUP {
		t.Skip("this test binary is pure Go; cgo refusal requires a cgo-linked binary")
	}
	if os.Getenv("T168_CGO") == "1" {
		lc := net.ListenConfig{}
		lc.SetMultipathTCP(false)
		l, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
		must(t, err)
		defer l.Close()
		if err := Apply(l.(*net.TCPListener)); !errors.Is(err, syscall.ENOTSUP) {
			t.Fatalf("cgo confinement must refuse: %v", err)
		}
		return
	}
	exe, err := os.Executable()
	must(t, err)
	cmd := exec.Command(exe, "-test.run=^TestCgoRefuses$")
	cmd.Env = append(os.Environ(), "T168_CGO=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cgo refusal: %v\n%s", err, out)
	}
}

// TestPacketProbe is the live suite's compiled attack process. A missing or
// broken sandbox exits 78, distinct from proven syscall denial (77), so a
// crashed helper cannot be mistaken for zero-packet enforcement.
func TestPacketProbe(t *testing.T) {
	kind := os.Getenv("STARGATE_PACKET_PROBE")
	if kind == "" {
		return
	}
	lc := net.ListenConfig{}
	lc.SetMultipathTCP(false)
	network, address := "tcp4", "127.0.0.1:0"
	if os.Getenv("STARGATE_PACKET_FAMILY") == "6" {
		network, address = "tcp6", "[::1]:0"
	}
	l, err := lc.Listen(context.Background(), network, address)
	if err != nil {
		os.Exit(78)
	}
	if err := Apply(l.(*net.TCPListener)); err != nil {
		os.Exit(78)
	}
	family := unix.AF_INET
	if os.Getenv("STARGATE_PACKET_FAMILY") == "6" {
		family = unix.AF_INET6
	}
	port, err := strconv.Atoi(os.Getenv("STARGATE_PACKET_PORT"))
	if err != nil {
		os.Exit(78)
	}
	ip := net.ParseIP(os.Getenv("STARGATE_PACKET_ADDRESS"))
	if ip == nil {
		os.Exit(78)
	}
	var dest unix.Sockaddr
	if family == unix.AF_INET {
		a := &unix.SockaddrInet4{Port: port}
		copy(a.Addr[:], ip.To4())
		dest = a
	} else {
		a := &unix.SockaddrInet6{Port: port}
		copy(a.Addr[:], ip.To16())
		dest = a
	}
	var attempt error
	if kind == "reuse" || kind == "fastopen" || kind == "forwarder" {
		raw, err := l.(*net.TCPListener).SyscallConn()
		if err != nil {
			os.Exit(78)
		}
		err = raw.Control(func(fd uintptr) {
			a := unix.RawSockaddr{Family: unix.AF_UNSPEC}
			_, _, e := unix.Syscall(unix.SYS_CONNECT, fd, uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a))
			if e != 0 {
				os.Exit(78)
			}
			if kind == "fastopen" {
				attempt = unix.Sendto(int(fd), []byte("t163-"), unix.MSG_FASTOPEN, dest)
			} else {
				attempt = unix.Connect(int(fd), dest)
			}
		})
		if err != nil {
			os.Exit(78)
		}
	} else {
		typ := unix.SOCK_STREAM
		if kind == "udp" || kind == "dns" || kind == "dns-reply" {
			typ = unix.SOCK_DGRAM
		}
		fd, e := unix.Socket(family, typ, 0)
		attempt = e
		if fd >= 0 {
			unix.Close(fd)
		}
	}
	if attempt == unix.EPERM || attempt == unix.EACCES {
		os.Exit(77)
	}
	if attempt == nil {
		os.Exit(0)
	}
	os.Exit(79)
}
