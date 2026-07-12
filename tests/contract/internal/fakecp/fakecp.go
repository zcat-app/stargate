// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package fakecp hosts a programmable control-plane Events server on
// a Unix domain socket. It is the contract-test surrogate for the
// production control plane that hosts WatchEvents on
// /run/stargate/control.sock (T038). Tests host the fake BEFORE the
// data-plane process boots (via dpharness.WithBeforeBoot) so the DP's
// first WatchEvents dial (T045 client.go) succeeds immediately and
// the test can drive the event stream from the server side.
//
// The pattern is extracted from
// tests/contract/control-grpc/watch_events_test.go's fakeEventsServer.
// That file is deliberately NOT refactored to import from here — out
// of scope per ticket §Out-of-scope; the duplication is the
// established repo pattern (mirrors tests/contract/tor/findRepoRoot).
//
// Scope: T024 (this package's author) needs only the programmable-
// stream + Send capability (to push advisory HEALTHY/STARTED events;
// admission is not CP-gated per T090/data-model.md §2). The full
// surface (closeFromServer, dialCount, latestStream) is included
// because the package is designed for reuse by T025a–d, T026, T028,
// T070b — all of which need some subset.
package fakecp

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

// Server is a programmable Events server hosted on a Unix domain
// socket. Each WatchEvents call creates a controlledStream that test
// code drives via Send / CloseFromServer and observes via DialCount /
// LatestStream. The zero value is NOT usable; construct via Start.
type Server struct {
	grpcpb.UnimplementedEventsServer

	mu      sync.Mutex
	dials   int
	streams []*ControlledStream
}

// ControlledStream is one WatchEvents RPC invocation. Push feeds
// events to the DP; Done is closed when the handler returns (DP
// disconnect, test-initiated close, or stream-context cancel);
// closeSig lets the test end the stream from the server side.
type ControlledStream struct {
	push     chan *grpcpb.SidecarEvent
	done     chan struct{}
	closeSig chan struct{}
}

// WatchEvents is the gRPC server handler. It creates a fresh
// ControlledStream, registers it, and blocks feeding events to the
// DP until either the test pushes them, the test closes the stream,
// or the DP disconnects (stream context cancelled).
func (s *Server) WatchEvents(_ *grpcpb.WatchEventsRequest, stream grpcpb.Events_WatchEventsServer) error {
	s.mu.Lock()
	s.dials++
	cs := &ControlledStream{
		push:     make(chan *grpcpb.SidecarEvent, 16),
		done:     make(chan struct{}),
		closeSig: make(chan struct{}),
	}
	s.streams = append(s.streams, cs)
	s.mu.Unlock()

	defer close(cs.done)
	for {
		select {
		case ev := <-cs.push:
			if err := stream.Send(ev); err != nil {
				return err
			}
		case <-cs.closeSig:
			return nil
		case <-stream.Context().Done():
			return nil
		}
	}
}

// DialCount returns the number of WatchEvents calls the DP has made
// to this Server. Used to assert reconnect behaviour (T021 row 3).
func (s *Server) DialCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dials
}

// LatestStream returns the most recently created ControlledStream, or
// nil if none exists. Used by tests that push events to the active
// stream without tracking the stream pointer themselves.
func (s *Server) LatestStream() *ControlledStream {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.streams) == 0 {
		return nil
	}
	return s.streams[len(s.streams)-1]
}

// Send pushes an event to the most-recent stream's handler, which
// forwards it to the DP via stream.Send. Returns an error if no
// stream exists or it has already ended. The common path is
// Healthy("tor"), an advisory status event (data-model.md §2;
// admission is not CP-gated per T090/Principle II — events do NOT
// gate admission, they update advisory status only).
func (s *Server) Send(ev *grpcpb.SidecarEvent) error {
	cs := s.LatestStream()
	if cs == nil {
		return errors.New("no active WatchEvents stream")
	}
	select {
	case cs.push <- ev:
		return nil
	case <-cs.done:
		return errors.New("stream already ended")
	}
}

// CloseFromServer ends the latest stream from the server side (the
// disconnect scenario in T021 row 3). Safe to call multiple times; a
// no-op on streams already closed.
func (s *Server) CloseFromServer() {
	cs := s.LatestStream()
	if cs == nil {
		return
	}
	select {
	case <-cs.closeSig:
	default:
		close(cs.closeSig)
	}
}

// Start hosts a fake control plane on ${ipcDir}/control.sock BEFORE
// the DP boots, so the DP's first WatchEvents dial succeeds
// immediately. Cleanup (GracefulStop + listener close + socket file
// removal) is registered with t.
//
// ipcDir is the same dir the data plane reads via STARGATE_IPC_DIR
// (typically the harness's IPCDir field). The socket file name
// "control.sock" matches the production contract
// (contracts/control-grpc.md §"Socket topology").
func Start(t *testing.T, ipcDir string) *Server {
	t.Helper()
	sockPath := filepath.Join(ipcDir, "control.sock")
	// Remove any stale socket file from a prior run. MkdirTemp gives
	// a fresh dir, but belt-and-braces: a stale file at this exact
	// path would make Listen(unix) fail with EADDRINUSE.
	_ = os.Remove(sockPath)
	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("fakecp: listen on %s: %v", sockPath, err)
	}
	srv := grpc.NewServer()
	s := &Server{}
	grpcpb.RegisterEventsServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.GracefulStop()
		_ = os.Remove(sockPath)
	})
	return s
}

// Healthy is a convenience constructor for the canonical HEALTHY
// SidecarEvent for the named sidecar. This is an advisory status
// event (data-model.md §2; admission is not CP-gated per
// T090/Principle II — events do NOT gate admission). Some tests push
// exactly one Healthy("tor") event after the DP's WatchEvents dial
// lands for advisory status visibility; the forward path is reached
// with or without it.
func Healthy(sidecar string) *grpcpb.SidecarEvent {
	return &grpcpb.SidecarEvent{
		Ts:      timestamppb.Now(),
		Sidecar: sidecar,
		Kind:    grpcpb.EventKind_EVENT_KIND_HEALTHY,
		Detail:  "healthcheck_pass",
	}
}

// Started is a convenience constructor for the STARTED SidecarEvent
// (paired with detail "container_start"). Tests that need to walk a
// sidecar through the full STARTED → HEALTHY advisory sequence use
// this before Healthy; tests that only need advisory status skip
// straight to Healthy.
func Started(sidecar string) *grpcpb.SidecarEvent {
	return &grpcpb.SidecarEvent{
		Ts:      timestamppb.Now(),
		Sidecar: sidecar,
		Kind:    grpcpb.EventKind_EVENT_KIND_STARTED,
		Detail:  "container_start",
	}
}
