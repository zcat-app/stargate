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
	"bytes"
	"context"
	"crypto/tls"
	"errors"
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

// SnapshotFunc is the dp-snapshot.json persist seam (T046's snapshot.go).
// T159 requires it to succeed before an in-memory swap or durable OK.
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

	// reloadMu serialises the stale-check→persist→swap triple per RPC.
	// Without it, two concurrent ReloadTokens could interleave persist(A)
	// persist(B) swap(A) swap(B) — briefly publishing an authority that does
	// not match the durable snapshot and making exact acknowledgments ambiguous.
	reloadMu sync.Mutex
}

// NewServer wires the DP-side Control service. T050 supplies the boot's
// TokenStore, T046's snapshot writer, and T049's counter snapshot source.
func NewServer(tokens *auth.TokenStore, persist SnapshotFunc, status StatusFunc, _ *slog.Logger) *Server {
	return &Server{tokens: tokens, persist: persist, status: status}
}

// ReloadTokens validates the mandatory auth-set-v1 envelope, persists before
// visibility, and returns an exact durable acknowledgment. Same-generation
// exact content is idempotent; stale/conflicting content never mutates state.
func (s *Server) ReloadTokens(_ context.Context, req *grpcpb.ReloadTokensRequest) (*grpcpb.ReloadTokensResponse, error) {
	current := s.tokens.Current()
	durable := req.GetDurable()
	if durable == nil || durable.GetSemanticsVersion() != authSetVersion {
		return nil, status.Error(codes.FailedPrecondition,
			"stargate: compatible durable token authority envelope required")
	}

	// The empty legacy list is the mixed-version fail-closed bridge: an old
	// DP can see revoke-all only, never the candidate credential material.
	if len(req.GetTokens()) != 0 || req.GetGeneration() == 0 ||
		durable.GetGeneration() != req.GetGeneration() ||
		len(durable.GetCommitment()) != sha256CommitmentLen {
		return invalidReloadResponse(current.Generation), nil
	}

	verifiers := make([][]byte, 0, len(durable.GetTokens()))
	for _, tok := range durable.GetTokens() {
		if len(tok.GetVerifier()) != verifierLen {
			return invalidReloadResponse(current.Generation), nil
		}
		// Copy out of the request-owned buffer: the generation must not
		// alias protobuf memory the framework may reuse, and requests are
		// never retained beyond the handler.
		verifiers = append(verifiers, append([]byte(nil), tok.GetVerifier()...))
	}
	commitment := authSetCommitment(verifiers)
	if !bytes.Equal(commitment, durable.GetCommitment()) {
		return invalidReloadResponse(current.Generation), nil
	}

	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	current = s.tokens.Current() // re-read under the lock: a concurrent valid push may have landed

	currentCommitment := authSetCommitment(current.Verifiers)
	if req.GetGeneration() < current.Generation ||
		(req.GetGeneration() == current.Generation && !bytes.Equal(commitment, currentCommitment)) {
		return &grpcpb.ReloadTokensResponse{
			AppliedGeneration: current.Generation,
			Status:            grpcpb.ApplyStatus_APPLY_STATUS_STALE_GENERATION,
			CurrentGeneration: current.Generation,
		}, nil
	}
	if req.GetGeneration() == current.Generation {
		// Reassert the active authority before every exact replay ACK. A prior
		// failed write may have renamed a newer candidate before directory
		// fsync failed; rewriting current closes that ambiguity on restart.
		if err := s.persist(current); err != nil {
			return nil, status.Error(codes.Unavailable,
				"stargate: durable token authority persistence unavailable")
		}
		return acknowledgedReloadResponse(current.Generation, commitment), nil
	}

	gen := &auth.Generation{
		Generation: req.GetGeneration(),
		Verifiers:  verifiers,
		LoadedAt:   time.Now(),
	}
	if err := s.persist(gen); err != nil {
		return nil, status.Error(codes.Unavailable,
			"stargate: durable token authority persistence unavailable")
	}
	s.tokens.Swap(gen)
	return acknowledgedReloadResponse(gen.Generation, commitment), nil
}

func invalidReloadResponse(current uint64) *grpcpb.ReloadTokensResponse {
	return &grpcpb.ReloadTokensResponse{
		AppliedGeneration: current,
		Status:            grpcpb.ApplyStatus_APPLY_STATUS_INVALID,
	}
}

func acknowledgedReloadResponse(generation uint64, commitment []byte) *grpcpb.ReloadTokensResponse {
	return &grpcpb.ReloadTokensResponse{
		AppliedGeneration:     generation,
		CurrentGeneration:     generation,
		Status:                grpcpb.ApplyStatus_APPLY_STATUS_OK,
		AcknowledgmentVersion: authSetVersion,
		Commitment:            append([]byte(nil), commitment...),
	}
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
	if err := os.Chmod(path, 0o660); err != nil { // #nosec G302 -- DP/CP group access is required for the authenticated IPC socket
		_ = lis.Close() // chmod failed; preserve its error and abandon listener
		return nil, err
	}
	return lis, nil
}

// NewGRPCServer builds the DP gRPC server with the §5.3 interceptor chain
// installed and the Control service registered on it — the only shape T050
// may boot, so no handler can ever run un-gated (§5.3: an RPC that
// bypasses the interceptor chain is a contract violation).
//
// T130: serverTLS is REQUIRED — dp.sock is a mutual-TLS surface
// (wire-auth.md §4: mTLS, peer-pinned, "never degraded into an
// unauthenticated socket"). The pre-T130 constructor had no TLS pathway,
// so main.go's wiring served dp.sock PLAINTEXT: the Java CP's ClientHello
// was read as an HTTP/2 preface ("bogus greeting") and ReloadTokens never
// delivered (live-caught, first-ever Java↔Go execution). A nil config is
// an error, not a plaintext fallback; the caller's degraded mode is to
// not serve dp.sock at all.
func NewGRPCServer(control *Server, serverTLS *tls.Config) (*grpc.Server, error) {
	if serverTLS == nil {
		return nil, errors.New("dp.sock requires server TLS material (wire-auth.md §4; T130) — refusing to serve unauthenticated")
	}
	gs := grpc.NewServer(
		grpc.Creds(NewTransportCredentials(serverTLS)),
		grpc.ChainUnaryInterceptor(UnaryProtoVersionInterceptor),
		grpc.ChainStreamInterceptor(StreamProtoVersionInterceptor),
	)
	grpcpb.RegisterControlServer(gs, control)
	return gs, nil
}

// Serve boots NewGRPCServer on lis with the given server TLS config.
// Blocking; T050 owns the goroutine and the GracefulStop path.
func (s *Server) Serve(lis net.Listener, serverTLS *tls.Config) error {
	gs, err := NewGRPCServer(s, serverTLS)
	if err != nil {
		return err
	}
	return gs.Serve(lis)
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
// arch §5.3); the minor is never gated.
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
		// A newer peer is rejected without degrading forwarding (Principle II).
		return status.Errorf(codes.FailedPrecondition,
			"stargate: peer major %d > server major %d", peerMajor, protoversion.Major)
	}
	return nil
}
