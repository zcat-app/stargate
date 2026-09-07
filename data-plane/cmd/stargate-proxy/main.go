// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// main.go — the data-plane boot sequence (T050). The order below is
// load-bearing (ticket §Analysis; Principle II; data-model.md §2;
// sol-review B3):
//
//  1. FR-010 bind-safety check (bind/check.go) — fatal before ANY listener
//  2. token store + cold-start snapshot restore (T046) — never fatal
//  3. inter-plane TLS material (T045 tls.go; wire-auth.md §2) — degraded
//     mode on failure: the DP keeps routing port 8881 without the
//     inter-plane surface (never an unauthenticated inter-plane socket)
//  4. DP gRPC server on dp.sock (T045 server.go; bind(2) role separation)
//  5. WatchEvents client dialed at control.sock (T045 client.go) — the
//     backoff loop runs concurrently; its events are advisory
//  6. port-8881 listener + listener.Deps wiring (T042/T043)
//  7. accept loop — forwarding begins immediately, gated on nothing
//
// Configuration surface: the test-defined env contract pinned in
// tests/contract/control-grpc/dpharness_test.go §header (STARGATE_IPC_DIR,
// STARGATE_STATE_DIR, STARGATE_KEYS_DIR, STARGATE_LISTEN_ADDR,
// STARGATE_TOR_SOCKS_ADDR, STARGATE_IN_CONTAINER); production compose
// sets STARGATE_LISTEN_ADDR and STARGATE_IN_CONTAINER (T125).
package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/zcat-app/stargate/data-plane/internal/audit"
	"github.com/zcat-app/stargate/data-plane/internal/auth"
	"github.com/zcat-app/stargate/data-plane/internal/bind"
	"github.com/zcat-app/stargate/data-plane/internal/controlclient"
	"github.com/zcat-app/stargate/data-plane/internal/errortpl"
	"github.com/zcat-app/stargate/data-plane/internal/forward"
	"github.com/zcat-app/stargate/data-plane/internal/listener"
	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

// Deployment defaults (compose mounts own these paths; the env contract
// exists for the contract-test harness and alternative deployments).
const (
	defaultIPCDir     = "/run/stargate"
	defaultStateDir   = "/var/lib/stargate"
	defaultListenAddr = "127.0.0.1:8881" // FR-005; FR-010's bind check still applies
	defaultTorSOCKS   = "tor:9050"       // FR-007; overridden via STARGATE_TOR_SOCKS_ADDR in tests
)

// gracefulStopGrace bounds the dp.sock GracefulStop wait on shutdown; the
// process harness allows 3 s between SIGINT and SIGKILL.
const gracefulStopGrace = 2 * time.Second

func main() { os.Exit(run()) }

func run() int {
	// The DP journal (loginvariants): slog TextHandler on stderr with the
	// time= attribute stripped — every line must stay inside the fixed
	// line-class allowlist at ≥1h timestamp resolution (FR-008; arch §6.4).
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- (1) bind safety FIRST (FR-010, T125-amended): no listener exists
	// yet ----------- The env contract's listen address is host:port; the
	// bind check operates on the HOST literal (bind/check.go is a pure
	// IP-literal parser — a host:port string would parse-fail). A
	// malformed address is a fatal config error, same class as a
	// refused host. Inside compose (STARGATE_IN_CONTAINER=1, set by
	// docker-compose.local.yml) the listener binds the container-wide
	// address: the loopback-only HOST guarantee is carried by the
	// host-published 127.0.0.1 binding + the container netns (a
	// container-loopback listener is unreachable through Docker's port
	// publishing — SECURITY-DECISIONS.md, user-approved amend-spec).
	listenAddr := envOr("STARGATE_LISTEN_ADDR", defaultListenAddr)
	bindHost, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		log.Error("shutdown", "reason", "listen address "+listenAddr+": "+err.Error())
		return 1
	}
	inContainer := envOr("STARGATE_IN_CONTAINER", "0") == "1"
	if err := bind.CheckListener(bindHost, inContainer); err != nil {
		// The startup class vocabulary has no fatal-boot line; the shutdown
		// class (reason field) is the journal-visible exit record.
		log.Error("shutdown", "reason", err.Error())
		return 1
	}

	counters := audit.New()
	store := auth.NewTokenStore()

	// --- (2) cold-start snapshot (arch §5.5): a missing or broken cache
	// must not take routing down — RestoreSnapshot never fails the boot.
	stateDir := envOr("STARGATE_STATE_DIR", defaultStateDir)
	controlclient.RestoreSnapshot(stateDir, store, log)

	// Pepper: a wrong-length file is a corrupt install and fails loudly
	// here (data-model.md §1.5/§1.7) — a silent boot would authenticate
	// nothing forever.
	keysDir := envOr("STARGATE_KEYS_DIR", auth.DefaultKeysDir)
	pepper, err := auth.LoadPepper(keysDir)
	if err != nil {
		log.Error("shutdown", "reason", err.Error())
		return 1
	}

	// --- (3) inter-plane TLS material (wire-auth.md §2; degraded mode per
	// §2.2/§3.3 and ticket acceptance #3): without it the WatchEvents
	// client never starts (NewClient rejects nil TLS — never an
	// unauthenticated inter-plane dial) while routing continues.
	clientTLS, _, tlsErr := controlclient.DeriveDPTLS(keysDir)
	if tlsErr != nil {
		// The control_channel class's degraded line — the same vocabulary
		// client.go journals on runtime channel loss. The error text is
		// path/fs detail, never key material (Principle III).
		log.Warn("control channel degraded", "err", tlsErr.Error())
	}

	ipcDir := envOr("STARGATE_IPC_DIR", defaultIPCDir)

	// --- (4) DP gRPC server on dp.sock (bind(2) role separation; mode
	// 0660 past umask; §5.3 interceptor chain via NewGRPCServer — the only
	// server shape T050 may boot).
	// A SIGKILL leaves the socket file in the persistent ipc volume; the
	// next boot would fail bind(2) forever (restart crash-loop). The DP is
	// the only process wired to bind dp.sock (control-grpc.md §"Socket
	// topology"), so clearing its own stale socket is safe.
	_ = os.Remove(filepath.Join(ipcDir, "dp.sock"))
	sockLis, err := controlclient.Listen(ipcDir)
	if err != nil {
		log.Error("shutdown", "reason", err.Error())
		return 1
	}
	ctl := controlclient.NewServer(store,
		controlclient.SnapshotWriter(stateDir, log), counters.Snapshot, log)
	grpcSrv := controlclient.NewGRPCServer(ctl)
	go func() { _ = grpcSrv.Serve(sockLis) }() // returns on GracefulStop/Stop

	// --- (5) control-plane client (T045): concurrent, advisory, never
	// fatal (Principle II). With no TLS material the boot already
	// degraded above and the client never starts.
	if clientTLS != nil {
		sink := advisorySink{} // T073 wires the audit/status application
		client, err := controlclient.NewClient(controlclient.ClientConfig{
			ControlSocket: filepath.Join(ipcDir, "control.sock"),
			TLS:           clientTLS,
			Sink:          sink,
			Log:           log,
		}, nil)
		if err != nil {
			log.Warn("control channel degraded", "err", err.Error())
		} else {
			go client.Run(ctx)
		}
	}

	// --- (6) the port-8881 proxy listener (FR-005). The bind check (step
	// 1) already proved the address is an IP literal — loopback, or the
	// wildcard behind the container boundary (T125) — so net.Listen
	// performs no name resolution (Principle I/FR-007).
	proxyLis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Error("shutdown", "reason", err.Error())
		return 1
	}

	verifier := auth.NewTokenVerifier(pepper, store)
	forwarder := forward.New(envOr("STARGATE_TOR_SOCKS_ADDR", defaultTorSOCKS), counters)
	renderer := &errortpl.Renderer{}
	deps := &listener.Deps{
		Auth:    verifier,
		Forward: forwarder,
		Audit:   counters,
		Connect: func(conn net.Conn) {
			listener.HandleConnect(conn, &listener.ConnectDeps{
				Auth:     verifier,
				Tunnel:   forwarder,
				Audit:    counters,
				Renderer: renderer,
			})
		},
	}

	log.Info("startup", "listener", proxyLis.Addr().String())

	// --- (7) accept loop: forwarding begins with the first connection and
	// is gated on nothing — no SidecarEvent, no CP dial, no channel state
	// (data-model.md §2; T090; sol-review B3). No per-connection log line
	// (FR-008).
	acceptErr := make(chan error, 1)
	go func() {
		for {
			conn, err := proxyLis.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			go listener.HandleConn(conn, deps)
		}
	}()

	select {
	case <-ctx.Done():
		// Shutdown (SIGINT/SIGTERM): stop the signal notifications, tear
		// the inter-plane server down gracefully (bounded — a wedged
		// RPC must not hang the exit past the supervisor's grace), close
		// the proxy listener so the accept loop unblocks, and journal the
		// shutdown line.
		stop()
	case err := <-acceptErr:
		// The proxy listener died on its own — routing is down; journal
		// and exit non-zero rather than spin.
		log.Error("shutdown", "reason", err.Error())
		grpcGracefulStop(grpcSrv)
		return 1
	}

	grpcGracefulStop(grpcSrv)
	_ = proxyLis.Close()
	log.Info("shutdown", "reason", "signal")
	return 0
}

// grpcGracefulStop stops the dp.sock server, forcing after the grace
// window (an in-flight RPC that never finishes must not wedge the
// process past its supervisor's SIGKILL).
func grpcGracefulStop(srv *grpc.Server) {
	stopped := make(chan struct{})
	go func() { srv.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(gracefulStopGrace):
		srv.Stop()
	}
}

// advisorySink is the T050 placeholder for T073's advisory-event
// application: the client journals every validated event's receipt
// (sidecar_event class) and nothing in the forwarding path consults the
// sink, so a no-op cannot gate admission (Principle II).
type advisorySink struct{}

func (advisorySink) HandleSidecarEvent(*grpcpb.SidecarEvent) {}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
