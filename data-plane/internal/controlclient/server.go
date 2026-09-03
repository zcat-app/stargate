// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// server.go — the DP half of the inter-plane gRPC surface (T045): the
// Control service (ReloadTokens + GetStatus) hosted on the DP-owned
// /run/stargate/dp.sock (mode 0660, owner stargate-dp:stargate-ipc per
// contracts/control-grpc.md §"Socket topology" — the socket is what the
// process binds; the stargate-ipc ownership is deployment, gated by R1 in
// tests/contract/compose/inter_plane_wire_test.sh), plus the §5.3 server
// interceptor chain rejecting unknown proto majors before any handler.
//
// The package name `controlclient` predates the DP-hosted server; the
// carry-over is deliberate (ticket task body — renaming is deferred until
// a second gRPC service forces the issue).
package controlclient

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zcat-app/stargate/data-plane/internal/auth"
	"github.com/zcat-app/stargate/data-plane/internal/protoversion"
	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

// verifierLen is the TokenVerifier wire contract: exactly 32 bytes
// (contracts/control-grpc.md §"ReloadTokens"; HMAC-SHA-256 tag, T092).
const verifierLen = 32

// SnapshotFunc is the dp-snapshot.json persist seam (T046's snapshot.go):
// contract row 4 — called after the in-memory swap, before the OK response;
// a failure is journaled and the response stays OK (in-memory truth wins;
// the snapshot is only a cold-start cache).
type SnapshotFunc func(*auth.Generation) error

// StatusFunc is the counter-snapshot seam (T049's audit/counters.go):
// GetStatus returns whatever this returns, verbatim and side-effect-free
// (§"GetStatus (minimum subset)": a side-effecting probe would defeat
// T025c's no-traffic sandwich).
type StatusFunc func() *grpcpb.StatusResponse

// Server hosts the DP-side Control service. All three seams arrive wired —
// T050 constructs it; there are no nil checks inside the trust boundary
// (CONTRIBUTING doctrine).
type Server struct {
	grpcpb.UnimplementedControlServer

	tokens  *auth.TokenStore
	persist SnapshotFunc
	status  StatusFunc
	log     *slog.Logger

	// reloadMu serialises the stale-check→swap→persist triple per RPC.
	// Without it, two concurrent ReloadTokens could interleave swap(A)
	// swap(B) persist(A) persist(B) — leaving the snapshot older than the
	// in-memory generation (contract row 5's convergence property).
	reloadMu sync.Mutex
}

// NewServer wires the DP-side Control service. T050 supplies the boot's
// TokenStore, T046's snapshot writer, and T049's counter snapshot source.
func NewServer(tokens *auth.TokenStore, persist SnapshotFunc, status StatusFunc, log *slog.Logger) *Server {
	return &Server{tokens: tokens, persist: persist, status: status, log: log}
}

// ReloadTokens atomically swaps the bearer-token generation
// (contracts/control-grpc.md §"ReloadTokens"):
//
//   - any verifier not exactly 32 bytes → APPLY_STATUS_INVALID, no change;
//   - request generation ≤ current → APPLY_STATUS_STALE_GENERATION with
//     current_generation echoed (T092 reconciliation) and no change;
//   - otherwise the store pointer swaps and the snapshot persists BEFORE
//     the OK response; a persist failure is journaled and stays OK (row 4).
//
// Verifier bytes are never logged (Principle III; the contract's
// no-logging bullet — labels, pepper, and bytes all stay out of the
// journal; the swap line carries only the generation and count).
func (s *Server) ReloadTokens(_ context.Context, req *grpcpb.ReloadTokensRequest) (*grpcpb.ReloadTokensResponse, error) {
	current := s.tokens.Current()

	// Validate before touching any state: a malformed push consumes no
	// generation number and swaps nothing (contract row 3).
	verifiers := make([][]byte, 0, len(req.GetTokens()))
	for _, tok := range req.GetTokens() {
		if len(tok.GetVerifier()) != verifierLen {
			return &grpcpb.ReloadTokensResponse{
				AppliedGeneration: current.Generation,
				Status:            grpcpb.ApplyStatus_APPLY_STATUS_INVALID,
			}, nil
		}
		// Copy out of the request-owned buffer: the generation must not
		// alias protobuf memory the framework may reuse, and requests are
		// never retained beyond the handler.
		verifiers = append(verifiers, append([]byte(nil), tok.GetVerifier()...))
	}

	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	current = s.tokens.Current() // re-read under the lock: a concurrent valid push may have landed

	if req.GetGeneration() <= current.Generation {
		return &grpcpb.ReloadTokensResponse{
			AppliedGeneration: current.Generation,
			Status:            grpcpb.ApplyStatus_APPLY_STATUS_STALE_GENERATION,
			CurrentGeneration: current.Generation,
		}, nil
	}

	gen := &auth.Generation{
		Generation: req.GetGeneration(),
		Verifiers:  verifiers,
		LoadedAt:   time.Now(),
	}
	s.tokens.Swap(gen)

	resp := &grpcpb.ReloadTokensResponse{
		AppliedGeneration: gen.Generation,
		Status:            grpcpb.ApplyStatus_APPLY_STATUS_OK,
	}
	if err := s.persist(gen); err != nil {
		// Contract row 4: in-memory truth wins; the failure is journaled
		// under the snapshot_write line class (loginvariants). The error
		// text is an fs/path error — never token bytes.
		s.log.Error("snapshot write failed", "err", err.Error())
	}
	s.log.Info("tokens applied", "generation", gen.Generation, "count", len(gen.Verifiers))
	return resp, nil
}

// GetStatus returns the audit counters' point-in-time snapshot through the
// StatusFunc seam. It increments nothing (§"GetStatus (minimum subset)":
// the read surface, not the write surface) and keeps no state. The CP has
// no production caller for this RPC in v1 (T022 row 10 pins that); the v1
// callers are the contract-test harness probes.
func (s *Server) GetStatus(_ context.Context, _ *grpcpb.StatusRequest) (*grpcpb.StatusResponse, error) {
	return s.status(), nil
}

// Listen binds the DP's IPC socket (bind(2) is the role separation: the DP
// never opens a listening FD on control.sock — §"Socket topology") and
// forces mode 0660 past any umask, so the shared stargate-ipc group can
// dial while non-group processes cannot (the kernel-enforced dial gate).
func Listen(ipcDir string) (net.Listener, error) {
	path := filepath.Join(ipcDir, "dp.sock")
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		lis.Close()
		return nil, err
	}
	return lis, nil
}

// NewGRPCServer builds the DP gRPC server with the §5.3 interceptor chain
// installed and the Control service registered on it — the only shape T050
// may boot, so no handler can ever run un-gated (§5.3: an RPC that
// bypasses the interceptor chain is a contract violation).
func NewGRPCServer(control *Server) *grpc.Server {
	gs := grpc.NewServer(
		grpc.ChainUnaryInterceptor(UnaryProtoVersionInterceptor),
		grpc.ChainStreamInterceptor(StreamProtoVersionInterceptor),
	)
	grpcpb.RegisterControlServer(gs, control)
	return gs
}

// Serve boots NewGRPCServer on lis. Blocking; T050 owns the goroutine and
// the GracefulStop path.
func (s *Server) Serve(lis net.Listener) error {
	return NewGRPCServer(s).Serve(lis)
}

// UnaryProtoVersionInterceptor is the §5.3 server interceptor (unary):
// it runs the §5.2 rejection rule BEFORE the application handler. The
// receiver's own major is the compiled-in protoversion constant, so an RPC
// is accepted iff the caller compiled against the same major (§5.2 —
// stricter than arch §5.3's newer-peer-only rule, on purpose: it blocks
// silent downgrade during an asymmetric plane upgrade; see the §5.2 note).
func UnaryProtoVersionInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	if err := checkProtoVersion(md); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

// StreamProtoVersionInterceptor is the §5.3 server interceptor (streaming).
func StreamProtoVersionInterceptor(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	md, _ := metadata.FromIncomingContext(ss.Context())
	if err := checkProtoVersion(md); err != nil {
		return err
	}
	return handler(srv, ss)
}

// checkProtoVersion is the §5.2 rejection rule shared by both interceptor
// shapes. Equal major accepts any minor (additive minors are compatible,
// arch §5.3); the minor is debug-logged for diagnostics, never gated.
func checkProtoVersion(md metadata.MD) error {
	values := md.Get(protoversion.MetaMajor)
	if len(values) == 0 {
		return status.Error(codes.FailedPrecondition,
			"stargate: missing x-stargate-proto-major metadata")
	}
	peerMajor, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil {
		return status.Error(codes.FailedPrecondition,
			"stargate: x-stargate-proto-major is not parseable as uint")
	}
	switch {
	case peerMajor < protoversion.Major:
		return status.Errorf(codes.FailedPrecondition,
			"stargate: peer major %d < server major %d", peerMajor, protoversion.Major)
	case peerMajor > protoversion.Major:
		// arch §5.5 row 4: a newer peer is rejected, logged, and — on the
		// DP — never degrades proxy forwarding (Principle II).
		return status.Errorf(codes.FailedPrecondition,
			"stargate: peer major %d > server major %d", peerMajor, protoversion.Major)
	}
	if minor := md.Get(protoversion.MetaMinor); len(minor) > 0 {
		slog.Debug("stargate: peer minor", "minor", minor[0])
	}
	return nil
}
