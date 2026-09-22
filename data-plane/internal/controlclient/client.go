// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// client.go — the DP's WatchEvents consumer (T045): a long-lived gRPC
// client on /run/stargate/control.sock (contracts/control-grpc.md
// §"Socket topology" — the DP dials only control.sock; role separation via
// bind(2)) that applies SidecarEvents as ADVISORY status/audit hints.
// Events MUST NOT gate admission, listening, authenticating, dialing, or
// forwarding — the upstream dial is the sole ground truth (data-model.md
// §2; Constitution Principle II; sol-review B3; T090; T073 wires the
// advisory application).
//
// Reconnect policy per §"WatchEvents": exponential backoff, initial 1s,
// cap 30s, jitter ±20%; a CP that is unreachable or fails the TLS
// handshake (wire-auth.md §4) is a degraded-mode warning and the DP keeps
// routing (arch §5.4; Principle II) — the loop is never fatal.
package controlclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/zcat-app/stargate/data-plane/internal/protoversion"
	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

// detailVocabulary is the closed detail set (contracts/control-grpc.md
// §"WatchEvents"): a value outside it is a contract violation — the CP
// must never pipe sidecar free text in (arch §5.2). `config_render` is in
// the set now (reserved for the bridges feature) so a future emitter does
// not flip this gate into a vocabulary bump.
var detailVocabulary = map[string]bool{
	"healthcheck_pass": true,
	"healthcheck_fail": true,
	"container_exit":   true,
	"container_start":  true,
	"config_render":    true,
}

// torSidecar is the only sidecar this feature consumes; other values are
// later features' and are ignored (§"WatchEvents" contract).
const torSidecar = "tor"

// errDetailViolation marks a stream torn down for an out-of-vocabulary
// detail: the violation is already journaled at detection, so the Run loop
// must not double-log it as a degradation.
var errDetailViolation = errors.New("sidecar event rejected: detail outside closed vocabulary")

// EventSink is the advisory-application seam (T073 wires the audit-journal
// and status reporting application). The client guarantees the sink only
// ever sees in-vocabulary tor events; nothing the sink does can gate
// admission, because nothing in the forwarding path consults it.
type EventSink interface {
	HandleSidecarEvent(*grpcpb.SidecarEvent)
}

// ClientConfig wires the WatchEvents consumer. TLS is REQUIRED — an
// inter-plane dial without the §4 mutual-TLS configuration cannot be
// constructed (wire-auth.md §4: the pin hook is the sole trust decision).
type ClientConfig struct {
	// ControlSocket is the unix socket path of the CP's WatchEvents
	// listener (/run/stargate/control.sock in deployment).
	ControlSocket string
	// TLS is the DP's client half from DeriveDPTLS.
	TLS *tls.Config
	// Sink receives validated events (advisory only).
	Sink EventSink
	// Log is the DP journal logger (slog, no time= field — loginvariants).
	Log *slog.Logger

	// fastBackoff shrinks the backoff constants for in-process tests.
	// Unexported: production callers cannot construct a non-contract
	// backoff; same-package tests set it directly.
	fastBackoff bool
}

// Client consumes the CP's event stream. Construct via NewClient; run via
// Run (blocking; T050 owns the goroutine).
type Client struct {
	conn   *grpc.ClientConn
	events grpcpb.EventsClient
	sink   EventSink
	log    *slog.Logger
	bo     *backoff
	// degraded tracks the journal-visible channel state: the degraded-mode
	// warning fires on the transition in, the recovery line on the first
	// event after it. Owned by the single Run goroutine — no lock.
	degraded bool
}

// NewClient dials control.sock over the §4 TLS configuration with the §5.3
// client interceptors installed (the three version metadata keys ride every
// call). NewClient performs no I/O (gRPC connects lazily); the Run loop
// owns reconnection behavior.
func NewClient(cfg ClientConfig, jitter func() float64) (*Client, error) {
	if cfg.ControlSocket == "" {
		return nil, errors.New("controlclient: empty control socket path")
	}
	if cfg.TLS == nil {
		return nil, errors.New("controlclient: nil TLS config — wire-auth.md §4 forbids unauthenticated inter-plane dials")
	}
	if cfg.Sink == nil {
		return nil, errors.New("controlclient: nil event sink")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	bo := newBackoff(backoffConfig{initial: time.Second, max: 30 * time.Second, jitterPct: 0.2}, jitter)
	if cfg.fastBackoff {
		bo.cfg.initial, bo.cfg.max = 20*time.Millisecond, 100*time.Millisecond
	}
	conn, err := grpc.NewClient(
		"unix://"+cfg.ControlSocket,
		grpc.WithTransportCredentials(NewTransportCredentials(cfg.TLS)),
		// §5.3: the client interceptor sets the three metadata keys on
		// EVERY call — installed here, on the only client conn the DP
		// dials, so no call can bypass it.
		grpc.WithChainUnaryInterceptor(UnaryClientVersionInterceptor),
		grpc.WithChainStreamInterceptor(StreamClientVersionInterceptor),
	)
	if err != nil {
		return nil, fmt.Errorf("controlclient: dialing %s: %w", cfg.ControlSocket, err)
	}
	return &Client{
		conn:   conn,
		events: grpcpb.NewEventsClient(conn),
		sink:   cfg.Sink,
		log:    log,
		bo:     bo,
	}, nil
}

// Run consumes event streams until ctx is cancelled. Every stream failure
// — dial, TLS handshake (wire-auth §4), or mid-stream drop — logs the
// degraded-mode transition once and retries on the §"WatchEvents" backoff;
// the DP keeps routing throughout (Principle II): this loop gates nothing.
func (c *Client) Run(ctx context.Context) {
	for {
		err := c.streamOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if !errors.Is(err, errDetailViolation) && !c.degraded {
			// Transition into degraded mode, journaled once (not per
			// retry). The error text is transport/TLS detail — never
			// event or token content.
			c.log.Warn("control channel degraded", "err", err.Error())
			c.degraded = true
		}
		if !c.wait(ctx) {
			return
		}
	}
}

// streamOnce runs one WatchEvents stream to completion. A nil error means
// the stream ended cleanly server-side (io.EOF-shaped); the Run loop
// treats every error path identically (warn-once, backoff, retry).
func (c *Client) streamOnce(ctx context.Context) error {
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := c.events.WatchEvents(streamCtx, &grpcpb.WatchEventsRequest{})
	if err != nil {
		return err
	}
	for {
		ev, err := stream.Recv()
		if err != nil {
			return err
		}
		if !c.deliver(ev, cancel) {
			return errDetailViolation
		}
		// The stream proved alive: the next drop waits the initial band,
		// not the accumulated cap (control-grpc.md §"WatchEvents").
		c.bo.reset()
	}
}

// deliver validates and forwards one event. It reports false when the
// event violates the closed-vocabulary contract: the violation is
// journaled (without the offending value — Principle III) and the stream
// is cancelled, which the CP observes as a client-side close.
func (c *Client) deliver(ev *grpcpb.SidecarEvent, cancel context.CancelFunc) bool {
	if ev.GetSidecar() != torSidecar {
		// §"WatchEvents": other sidecars belong to later features — ignored.
		return true
	}
	if !detailVocabulary[ev.GetDetail()] {
		// Contract violation: journal it WITHOUT the detail value (any
		// encoding — the vocabulary exists to keep sidecar free text out
		// of this journal), then tear the stream down.
		c.log.Error("sidecar event rejected", "kind", ev.GetKind().String(),
			"err", "detail outside closed vocabulary")
		cancel()
		return false
	}
	if c.degraded {
		c.log.Info("control channel recovered")
		c.degraded = false
	}
	// Receipt line under the loginvariants sidecar_event class; the detail
	// field is safe here because the value just passed the closed set.
	c.log.Info("sidecar event", "sidecar", ev.GetSidecar(),
		"kind", ev.GetKind().String(), "detail", ev.GetDetail())
	c.sink.HandleSidecarEvent(ev)
	return true
}

// wait sleeps one backoff step, returning false when ctx ends first.
func (c *Client) wait(ctx context.Context) bool {
	d := c.bo.next()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// UnaryClientVersionInterceptor is the §5.3 client interceptor (unary).
func UnaryClientVersionInterceptor(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	return invoker(versionContext(ctx), method, req, reply, cc, opts...)
}

// StreamClientVersionInterceptor is the §5.3 client interceptor (streaming).
func StreamClientVersionInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return streamer(versionContext(ctx), desc, cc, method, opts...)
}

// versionContext carries the §5.1 metadata: compiled-in major/minor plus
// the closed capability set, on every outgoing call.
func versionContext(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx,
		protoversion.MetaMajor, strconv.Itoa(protoversion.Major),
		protoversion.MetaMinor, strconv.Itoa(protoversion.Minor),
		protoversion.MetaCapabilities, protoversion.Capabilities,
	)
}

// --- backoff -----------------------------------------------------------------

// backoffConfig is the §"WatchEvents" schedule: exponential growth from
// initial, jittered ±jitterPct, capped at max (the cap applies after
// jitter, so a wait never exceeds the contract's 30s).
type backoffConfig struct {
	initial   time.Duration
	max       time.Duration
	jitterPct float64
}

// backoff tracks the consecutive-failure chain. reset() on a proven-alive
// stream; next() on every failure path.
type backoff struct {
	cfg     backoffConfig
	rng     func() float64 // uniform [0,1); injectable for deterministic tests
	attempt int
}

func newBackoff(cfg backoffConfig, rng func() float64) *backoff {
	if rng == nil {
		rng = rand.Float64
	}
	return &backoff{cfg: cfg, rng: rng}
}

// next returns the wait for the current failure and advances the chain:
// initial·2^attempt (capped at max) scaled by (1 ± jitterPct), then clamped
// to max so jitter can never overshoot the contract cap.
func (b *backoff) next() time.Duration {
	base := b.cfg.initial
	for i := 0; i < b.attempt && base < b.cfg.max; i++ {
		base *= 2
	}
	if base > b.cfg.max {
		base = b.cfg.max
	}
	factor := 1 + (2*b.rng()-1)*b.cfg.jitterPct
	wait := time.Duration(float64(base) * factor)
	if wait > b.cfg.max {
		wait = b.cfg.max
	}
	b.attempt++
	return wait
}

// reset restarts the chain at the initial step (a stream delivered an
// event — the next drop is a first failure again).
func (b *backoff) reset() { b.attempt = 0 }
