// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// main.go — the data-plane boot sequence (T050). The order below is
// load-bearing (ticket §Analysis; Principle II; data-model.md §2;
// sol-review B3):
//
//  1. FR-010 bind-safety check (bind/check.go) — fatal before ANY listener
//  2. ordinary TCP listener + all-thread kernel confinement (T168) — fail closed
//  3. token store + cold-start snapshot restore (T046) — never fatal
//  4. inter-plane TLS material (T045 tls.go; wire-auth.md §2) — degraded
//     mode on failure: the DP keeps routing port 8881 without the
//     inter-plane surface (never an unauthenticated inter-plane socket)
//  5. DP gRPC server on dp.sock (T045 server.go; bind(2) role separation)
//  6. WatchEvents client dialed at control.sock (T045 client.go) — the
//     backoff loop runs concurrently; its events are advisory
//  7. listener.Deps wiring (T042/T043)
//  8. accept loop — authentication gates admission; CP health remains advisory
//
// Configuration surface: the test-defined env contract pinned in
// tests/contract/control-grpc/dpharness_test.go §header (STARGATE_IPC_DIR,
// STARGATE_STATE_DIR, STARGATE_KEYS_DIR, STARGATE_LISTEN_ADDR,
// STARGATE_TOR_SOCKS_ADDR); production compose sets the Unix fabric path.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/zcat-app/stargate/data-plane/internal/audit"
	"github.com/zcat-app/stargate/data-plane/internal/auth"
	"github.com/zcat-app/stargate/data-plane/internal/bind"
	"github.com/zcat-app/stargate/data-plane/internal/confinement"
	"github.com/zcat-app/stargate/data-plane/internal/controlclient"
	"github.com/zcat-app/stargate/data-plane/internal/forward"
	"github.com/zcat-app/stargate/data-plane/internal/listener"
	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

// Deployment defaults (compose mounts own these paths; the env contract
// exists for the contract-test harness and alternative deployments).
const (
	defaultIPCDir     = "/run/stargate"
	defaultStateDir   = "/var/lib/stargate"
	defaultListenAddr = "127.0.0.1:8881"                          // FR-005; FR-010's bind check still applies
	defaultTorSOCKS   = "unix:///run/stargate-tor/tor-socks.sock" // FR-007
)

// gracefulStopGrace bounds the dp.sock GracefulStop wait on shutdown; the
// process harness allows 3 s between SIGINT and SIGKILL.
const gracefulStopGrace = 2 * time.Second

func main() { os.Exit(run()) }

func run() int { return runWithCounters(audit.New) }

func trafficCountersEnabled(raw string) (bool, error) {
	switch raw {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, errors.New("invalid traffic counter configuration")
}

func runWithCounters(newCounters func() *audit.Counters) int {
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

	counterOption, configured := os.LookupEnv("STARGATE_TRAFFIC_COUNTERS")
	if !configured {
		counterOption = "true"
	}
	countersEnabled, err := trafficCountersEnabled(counterOption)
	if err != nil {
		log.Error("shutdown", "reason", err.Error())
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- (1) bind safety FIRST (FR-010): no listener exists
	// yet ----------- The env contract's listen address is host:port; the
	// bind check operates on the HOST literal (bind/check.go is a pure
	// IP-literal parser — a host:port string would parse-fail). A
	// malformed address is a fatal config error, same class as a
	// refused host. The host-network container binds this same strict
	// loopback address directly, with no Docker port publication.
	listenAddr := envOr("STARGATE_LISTEN_ADDR", defaultListenAddr)
	bindHost, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		log.Error("shutdown", "reason", "listen address "+listenAddr+": "+err.Error())
		return 1
	}
	if err := bind.CheckListener(bindHost); err != nil {
		// The startup class vocabulary has no fatal-boot line; the shutdown
		// class (reason field) is the journal-visible exit record.
		log.Error("shutdown", "reason", err.Error())
		return 1
	}

	// T168 / Constitution III: no serving or adapter dial occurs before the
	// process boundary is installed. Ordinary TCP is required: MPTCP listeners
	// can expose connection paths outside older Landlock TCP mediation.
	upstream := envOr("STARGATE_TOR_SOCKS_ADDR", defaultTorSOCKS)
	if !strings.HasPrefix(upstream, "unix://") || !filepath.IsAbs(strings.TrimPrefix(upstream, "unix://")) || strings.ContainsRune(upstream, 0) {
		log.Error("shutdown", "reason", "invalid Unix adapter configuration")
		return 1
	}
	lc := net.ListenConfig{}
	lc.SetMultipathTCP(false)
	proxyLis, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		log.Error("shutdown", "reason", "listener unavailable")
		return 1
	}
	defer proxyLis.Close()
	if err := confinement.Apply(proxyLis.(*net.TCPListener)); err != nil {
		log.Error("shutdown", "reason", "network confinement unavailable")
		return 1
	}

	counters := newCounters()
	if !countersEnabled {
		counters.Disable()
	}
	go counters.Run(ctx) // Idle expiry ends with the process context (Constitution III).

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
	// T130: BOTH halves are consumed — the client config for the
	// control.sock dialer below, the SERVER config for dp.sock. The
	// pre-T130 wiring discarded the server half, so dp.sock served
	// PLAINTEXT and the CP's mutual-TLS dial failed every push.
	clientTLS, serverTLS, tlsErr := controlclient.DeriveDPTLS(keysDir)
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
	// T130: dp.sock is a mutual-TLS surface — served ONLY when the TLS
	// material derived (wire-auth.md §4: "never degraded into an
	// unauthenticated socket"). Degraded mode (no keys) serves NO dp.sock
	// at all: routing on 8881 continues (Principle II), the CP's pushes
	// fail to connect and re-sync on its next boot (§1.8 containment),
	// and a plaintext listener is never substituted.
	// A SIGKILL leaves the socket file in the persistent ipc volume; the
	// next boot would fail bind(2) forever (restart crash-loop). The DP is
	// the only process wired to bind dp.sock (control-grpc.md §"Socket
	// topology"), so clearing its own stale socket is safe.
	_ = os.Remove(filepath.Join(ipcDir, "dp.sock"))
	var grpcSrv *grpc.Server
	if serverTLS != nil {
		sockLis, err := controlclient.Listen(ipcDir)
		if err != nil {
			log.Error("shutdown", "reason", err.Error())
			return 1
		}
		ctl := controlclient.NewServer(store,
			controlclient.SnapshotWriter(stateDir, log), counters.Snapshot, log)
		grpcSrv, err = controlclient.NewGRPCServer(ctl, serverTLS)
		if err != nil {
			log.Error("shutdown", "reason", err.Error())
			return 1
		}
		go func() { _ = grpcSrv.Serve(sockLis) }() // returns on GracefulStop/Stop
	} else {
		// FR-008 journal vocabulary: folds into the existing
		// control_channel class (six-class allowlist — a new class is a
		// Constitution-level change; T045's allowlist-amendment
		// precedent, T130 round-1 review).
		log.Warn("control channel degraded", "err", "dp.sock not served: no inter-plane TLS material (wire-auth.md §2.2 degraded mode; T130)")
	}

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

	verifier := auth.NewTokenVerifier(pepper, store)
	forwarder := forward.New(upstream, counters)
	deps := &listener.Deps{
		Auth:    verifier,
		Forward: forwarder,
		Audit:   counters,
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
	if srv == nil { // T130 degraded mode never served dp.sock
		return
	}
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
