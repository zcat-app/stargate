// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Command profileprobe is the unprivileged, static test client for T162's
// AppArmor AF_UNIX caller matrix, T170 signal-peer checks and T191 procfs reads. It never sends destinations or credentials.
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: profileprobe socks|dial|listen|serve|abstract-dial|abstract-serve|signal-exists|read <address-pid-or-path>")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "signal-exists":
		pid, parseErr := strconv.Atoi(os.Args[2])
		if parseErr != nil || pid <= 0 {
			fmt.Fprintln(os.Stderr, "signal-exists requires a positive PID")
			os.Exit(2)
		}
		err = syscall.Kill(pid, 0)
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			fmt.Println("DENIED")
			os.Exit(77)
		}
	case "socks", "dial", "abstract-dial":
		var conn net.Conn
		address := os.Args[2]
		if os.Args[1] == "abstract-dial" {
			address = "\x00" + address
		}
		conn, err = net.DialTimeout("unix", address, 2*time.Second)
		if err == nil {
			defer conn.Close()
			if os.Args[1] == "abstract-dial" {
				_, err = conn.Write([]byte{'x'})
				if err == nil {
					var reply [1]byte
					_, err = io.ReadFull(conn, reply[:])
					if err == nil && reply != [1]byte{'y'} {
						err = fmt.Errorf("unexpected abstract reply")
					}
				}
			} else if os.Args[1] == "socks" {
				_, err = conn.Write([]byte{5, 1, 2})
				if err == nil {
					var reply [2]byte
					_, err = io.ReadFull(conn, reply[:])
					if err == nil && reply != [2]byte{5, 2} {
						err = fmt.Errorf("unexpected SOCKS method reply")
					}
				}
			}
		}
	case "read":
		// T191: whole-file read of a procfs path. Only the byte count is
		// printed, never the content (host socket tables stay out of logs).
		var data []byte
		data, err = os.ReadFile(os.Args[2])
		if err == nil && len(data) == 0 {
			err = fmt.Errorf("empty read")
		}
		if err == nil {
			fmt.Printf("READ %d bytes\n", len(data))
		}
	case "listen":
		var ln net.Listener
		ln, err = net.Listen("unix", os.Args[2])
		if err == nil {
			ln.Close()
		}
	case "serve", "abstract-serve":
		var ln net.Listener
		address := os.Args[2]
		if os.Args[1] == "abstract-serve" {
			address = "\x00" + address
		}
		ln, err = net.Listen("unix", address)
		if err == nil {
			defer ln.Close()
			if os.Args[1] == "serve" {
				err = os.Chmod(address, 0660)
				if err != nil {
					break
				}
			}
			ln.(*net.UnixListener).SetDeadline(time.Now().Add(30 * time.Second))
			var conn net.Conn
			conn, err = ln.Accept()
			if err == nil {
				if os.Args[1] == "abstract-serve" {
					var request [1]byte
					_, err = io.ReadFull(conn, request[:])
					if err == nil && request == [1]byte{'x'} {
						_, err = conn.Write([]byte{'y'})
					}
				}
				conn.Close()
			}
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown probe mode")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("OK")
}
