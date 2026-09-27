// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the dp-snapshot.json persistence layer (T046 snapshot.go):
// data-model.md §1.4 (schemaVersion 3, verifier commitment, atomic os.Rename
// + directory fsync, stale schemas ignored rather than misparsed) and contracts/control-grpc.md
// §"ReloadTokens" row 4 (persist before visibility or acknowledgment; a
// failed persist leaves the active in-memory authority unchanged). The process-level tiers are T020
// (tests/contract/control-grpc/reload_tokens_test.go, whose harness reads
// this exact file shape) and T020a (cold-start restore end-to-end, gated on
// T050's boot sequence). The silence of the process journal
// lines is pinned where the allowlist lives:
// tests/internal/loginvariants (separate module — the dependency arrow
// must not invert).
package controlclient

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/zcat-app/stargate/data-plane/internal/auth"
)

// --- fixtures -----------------------------------------------------------------

// The Docker policy gate supplies the actual deployment path under AppArmor;
// ordinary Go runs exercise the same durable-write/restore contract in TempDir.
func TestDeploymentSnapshotCommitAndRestore(t *testing.T) {
	dir := t.TempDir()
	if os.Getenv("STARGATE_TEST_DEPLOYMENT_STATE") == "1" {
		dir = "/var/lib/stargate"
	}
	plaintext := strings.Repeat("a", 32)
	generation := &auth.Generation{
		Generation: 1,
		Verifiers:  [][]byte{mintVerifier(plaintext)},
		LoadedAt:   fixedTime,
	}
	if err := WriteSnapshot(dir, generation); err != nil {
		t.Fatalf("durable snapshot commit: %v", err)
	}
	store := auth.NewTokenStore()
	log, journal := journalLogger()
	RestoreSnapshot(dir, store, log)
	if store.Current().Generation != 1 || !auth.NewTokenVerifier(testPepper, store).VerifyPassword([]byte(plaintext)) {
		t.Fatal("durably committed deployment snapshot did not restore authentication")
	}
	if journal.Len() != 0 {
		t.Fatal("snapshot persistence emitted operational diagnostics")
	}
}

// testPepper is the fixture pepper both the minted verifiers and the
// round-trip auth.TokenVerifier use (data-model.md §1.5: same pepper on
// both sides; length pinned by auth.PepperLen).
var testPepper = [auth.PepperLen]byte{0x5A}

// mintVerifier derives the HMAC-SHA-256 tag for a plaintext the way the
// control plane does (§1.5) — an independent reference copy, not a call
// into the code under test.
func mintVerifier(plaintext string) []byte {
	mac := hmac.New(sha256.New, testPepper[:])
	mac.Write([]byte(plaintext))
	return mac.Sum(nil)
}

// fixedTime is a stable wall clock for loadedAt round-tripping.
var fixedTime = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

// testGeneration builds generation n with count verifiers derived from
// distinct plaintexts.
func testGeneration(n uint64, count int) *auth.Generation {
	g := &auth.Generation{Generation: n, LoadedAt: fixedTime}
	for i := 0; i < count; i++ {
		g.Verifiers = append(g.Verifiers, mintVerifier(strings.Repeat("a", 32)[:28]+string(rune('a'+i))+strings.Repeat("b", 3)))
	}
	return g
}

// journalLogger supplies a writable capture to prove operations stay silent
// independently of production descriptor suppression.
func journalLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{ReplaceAttr: dropTime})), buf
}

func dropTime(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}

// snapshotMirror is the test's independent copy of the §1.4 shape — the
// tests pin the spec's on-disk contract, not the implementation's struct.
type snapshotMirror struct {
	SchemaVersion  int          `json:"schemaVersion"`
	AuthSetVersion int          `json:"authSetVersion"`
	Generation     uint64       `json:"generation"`
	Commitment     string       `json:"commitment"`
	LoadedAt       string       `json:"loadedAt"`
	Verifiers      []mirrorItem `json:"verifiers"`
}

// mirrorItem is the §1.4 verifier entry: an object with one base64 field.
type mirrorItem struct {
	Verifier string `json:"verifier"`
}

// readMirror unmarshals dir/dp-snapshot.json, failing the test with a
// redacted diagnostic (the file holds verifier material — same hygiene as
// the contract harness's readSnapshot).
func readMirror(t *testing.T, dir string) snapshotMirror {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "dp-snapshot.json"))
	if err != nil {
		t.Fatalf("reading snapshot: %v", err)
	}
	var m snapshotMirror
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal snapshot (%d bytes, content redacted): %v", len(raw), err)
	}
	return m
}

// listDirNames returns the sorted directory entry names.
func listDirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func mirrorCommitment(verifiers [][]byte) []byte {
	members := make([][]byte, len(verifiers))
	for i, verifier := range verifiers {
		members[i] = append([]byte(nil), verifier...)
	}
	sort.Slice(members, func(i, j int) bool { return bytes.Compare(members[i], members[j]) < 0 })
	h := sha256.New()
	h.Write(append([]byte("stargate-auth-set-v1"), 0))
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(members)))
	h.Write(count[:])
	for _, member := range members {
		h.Write(member)
	}
	return h.Sum(nil)
}

func TestAuthSetCommitmentReferenceVectors(t *testing.T) {
	ascending := make([]byte, 32)
	descending := make([]byte, 32)
	for i := range ascending {
		ascending[i] = byte(i)
		descending[i] = byte(255 - i)
	}
	cases := []struct {
		name      string
		verifiers [][]byte
		wantHex   string
	}{
		{"empty", nil, "d1a4d9356a1106626240b962a184f79428f0a4bc69fae59633b599df95411675"},
		{"one fixed member", [][]byte{ascending}, "0c649950e636116a68b5a738b8f2772a8a8e86147c2e9a552329c600f16793d1"},
		{"unsorted duplicate members", [][]byte{descending, ascending, descending}, "090dc7c7c4c28962f5ebe37fb34db11a67afffa98c8b5a1784587e1aa2f2c4c0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.wantHex)
			if err != nil {
				t.Fatal(err)
			}
			if got := authSetCommitment(tc.verifiers); !bytes.Equal(got, want) {
				t.Errorf("auth-set-v1 commitment does not match the pinned contract vector")
			}
		})
	}
}

// --- write path ----------------------------------------------------------------

func TestWriteSnapshotShapeAndFidelity(t *testing.T) {
	dir := t.TempDir()
	g := testGeneration(7, 2)

	if err := WriteSnapshot(dir, g); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	// No temp files left behind: the atomic rename consumed its temp.
	if names := listDirNames(t, dir); len(names) != 1 || names[0] != "dp-snapshot.json" {
		t.Errorf("dir = %v, want exactly [dp-snapshot.json] (temp leftover breaks the atomic-write contract)", names)
	}

	m := readMirror(t, dir)
	if m.SchemaVersion != 3 || m.AuthSetVersion != 1 {
		t.Errorf("snapshot versions = %d/%d, want schema 3 / auth-set 1", m.SchemaVersion, m.AuthSetVersion)
	}
	if m.Generation != 7 {
		t.Errorf("generation = %d, want 7", m.Generation)
	}
	if m.LoadedAt != fixedTime.Format(time.RFC3339) {
		t.Errorf("loadedAt = %q, want %q (RFC 3339 round trip)", m.LoadedAt, fixedTime.Format(time.RFC3339))
	}
	if len(m.Verifiers) != 2 {
		t.Fatalf("verifiers count = %d, want 2", len(m.Verifiers))
	}
	commitment, err := base64.StdEncoding.DecodeString(m.Commitment)
	if err != nil || !bytes.Equal(commitment, mirrorCommitment(g.Verifiers)) {
		t.Error("snapshot commitment does not bind the exact auth-set-v1 verifier multiset")
	}
	for i, want := range g.Verifiers {
		got, err := base64.StdEncoding.DecodeString(m.Verifiers[i].Verifier)
		if err != nil {
			t.Fatalf("verifiers[%d] not base64: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("verifiers[%d] does not match the pushed verifier (value redacted)", i)
		}
	}

	// Verifier material on a private volume: 0600, not the ambient umask.
	info, err := os.Stat(filepath.Join(dir, "dp-snapshot.json"))
	if err != nil {
		t.Fatalf("stat snapshot: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("snapshot mode = %o, want 600", info.Mode().Perm())
	}
}

func TestWriteSnapshotReplacesPrevious(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSnapshot(dir, testGeneration(7, 1)); err != nil {
		t.Fatalf("first WriteSnapshot: %v", err)
	}
	if err := WriteSnapshot(dir, testGeneration(8, 3)); err != nil {
		t.Fatalf("second WriteSnapshot: %v", err)
	}
	if m := readMirror(t, dir); m.Generation != 8 || len(m.Verifiers) != 3 {
		t.Errorf("snapshot after rewrite: generation %d / %d verifiers, want 8 / 3", m.Generation, len(m.Verifiers))
	}
}

// TestWriteSnapshotEmptyVerifiersIsArray pins the revoke-all persist
// shape: §1.4's verifiers is an array, so a pushed zero-verifier
// generation must land as "verifiers":[] — json.Marshal renders a nil
// slice as null, which is a different on-disk contract even though
// today's restore path happens to fail closed on both.
func TestWriteSnapshotEmptyVerifiersIsArray(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSnapshot(dir, &auth.Generation{Generation: 12, LoadedAt: fixedTime}); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "dp-snapshot.json"))
	if err != nil {
		t.Fatalf("reading snapshot: %v", err)
	}
	if !strings.Contains(string(raw), `"verifiers":[]`) {
		t.Errorf("revoke-all snapshot lacks a verifiers array (%d bytes, content redacted)", len(raw))
	}
	if strings.Contains(string(raw), "null") {
		t.Error("revoke-all snapshot rendered verifiers as null — not the §1.4 array shape")
	}
}

func TestWriteSnapshotFailureKeepsPreviousIntact(t *testing.T) {
	if os.Geteuid() == 0 {
		// The failure injection is permission-based (chmod 0500); uid 0
		// writes through it, so the negative case is meaningless in a
		// root container (T050's container-validation gate runs as root).
		t.Skip("read-only-dir injection does not bind uid 0 — run this suite unprivileged")
	}
	dir := t.TempDir()
	if err := WriteSnapshot(dir, testGeneration(7, 1)); err != nil {
		t.Fatalf("first WriteSnapshot: %v", err)
	}

	// Read-only parent: CreateTemp fails, rename never happens.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := WriteSnapshot(dir, testGeneration(8, 1))
	if err == nil {
		t.Fatal("WriteSnapshot into a read-only dir = nil error, want failure")
	}
	if m := readMirror(t, dir); m.Generation != 7 {
		t.Errorf("previous snapshot clobbered: generation %d, want 7 (row 4: failed persist leaves on-disk state intact)", m.Generation)
	}
	if names := listDirNames(t, dir); len(names) != 1 {
		t.Errorf("dir = %v, want exactly [dp-snapshot.json] (failed write must not leave temp debris)", names)
	}

	// The error names the failure, never the material (§1.6/Principle III).
	secret := testGeneration(8, 1).Verifiers[0]
	renderings := [][]byte{secret, []byte(base64.StdEncoding.EncodeToString(secret)),
		[]byte(hex.EncodeToString(secret)), []byte(strings.ToUpper(hex.EncodeToString(secret)))}
	for _, r := range renderings {
		if bytes.Contains([]byte(err.Error()), r) {
			t.Error("WriteSnapshot error text carries verifier material (value redacted)")
		}
	}
}

// --- restore path ----------------------------------------------------------------

func TestRestoreSnapshotInstallsGeneration(t *testing.T) {
	dir := t.TempDir()
	plaintext := "0123456789abcdef0123456789abcdef"
	g := &auth.Generation{
		Generation: 7,
		Verifiers:  [][]byte{mintVerifier(plaintext)},
		LoadedAt:   fixedTime,
	}
	if err := WriteSnapshot(dir, g); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}

	tokens := auth.NewTokenStore()
	log, buf := journalLogger()
	RestoreSnapshot(dir, tokens, log)

	if got := tokens.Current().Generation; got != 7 {
		t.Errorf("restored generation = %d, want 7", got)
	}
	// Round trip: the restored verifier authenticates under the same
	// pepper (§1.5) — this is the cold-start property FR-013 buys.
	verifier := auth.NewTokenVerifier(testPepper, tokens)
	if !verifier.VerifyPassword([]byte(plaintext)) {
		t.Error("snapshot-restored token did not authenticate (FR-013 cold-start invariant)")
	}
	if verifier.VerifyPassword([]byte("ffffffffffffffffffffffffffffffff")) {
		t.Error("unrelated token authenticated after restore")
	}
	if buf.Len() != 0 {
		t.Error("operational action emitted a journal record")
	}
}

func TestRestoreSnapshotMissingFileLeavesEmptyGeneration(t *testing.T) {
	dir := t.TempDir()
	tokens := auth.NewTokenStore()
	log, buf := journalLogger()

	RestoreSnapshot(dir, tokens, log) // must not panic or warn

	if got := tokens.Current(); got.Generation != 0 || len(got.Verifiers) != 0 {
		t.Errorf("generation after missing-file restore = %d / %d verifiers, want empty (revoke-all until the CP pushes)", got.Generation, len(got.Verifiers))
	}
	if strings.Contains(buf.String(), "snapshot restore ignored") {
		t.Errorf("missing snapshot on first boot is normal, not a warning; journal:\n%s", buf.String())
	}
}

// writeRawSnapshot plants a hand-built file bypassing WriteSnapshot — the
// restore path must judge bytes it did not necessarily write.
func writeRawSnapshot(t *testing.T, dir string, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "dp-snapshot.json"), []byte(content), 0o600); err != nil {
		t.Fatalf("planting snapshot: %v", err)
	}
}

func TestRestoreSnapshotIgnoresStaleV1(t *testing.T) {
	// The pre-T092 shape: {hash, salt} pairs under schemaVersion 1.
	// Parsing it as v2 would authenticate nothing and silently break
	// routing (§1.4 T092 note) — it must be ignored wholesale.
	dir := t.TempDir()
	writeRawSnapshot(t, dir, `{"schemaVersion":1,"generation":4,"loadedAt":"2026-05-01T00:00:00Z","hashes":[{"hash":"AAAA","salt":"BBBB"}]}`)

	tokens := auth.NewTokenStore()
	log, buf := journalLogger()
	RestoreSnapshot(dir, tokens, log)

	if got := tokens.Current(); got.Generation != 0 || len(got.Verifiers) != 0 {
		t.Errorf("stale v1 snapshot was restored (%d / %d verifiers) — must be ignored, serving no tokens until the CP pushes",
			got.Generation, len(got.Verifiers))
	}
	if buf.Len() != 0 {
		t.Error("operational action emitted a journal record")
	}
}

func TestRestoreSnapshotIgnoresIncompatibleOrUnusableState(t *testing.T) {
	emptyCommitment := base64.StdEncoding.EncodeToString(mirrorCommitment(nil))
	cases := []struct {
		name    string
		content string
	}{
		{"corrupt json", `{"schemaVersion":3,"generation":9,`},
		{"legacy schema v2", `{"schemaVersion":2,"generation":9,"loadedAt":"2026-09-03T12:00:00Z","verifiers":[]}`},
		{"unknown schema version", `{"schemaVersion":4,"generation":9,"loadedAt":"2026-09-03T12:00:00Z","verifiers":[]}`},
		{"zero generation", `{"schemaVersion":3,"authSetVersion":1,"generation":0,"commitment":"` + emptyCommitment + `","loadedAt":"2026-09-03T12:00:00Z","verifiers":[]}`},
		{"wrong auth-set version", `{"schemaVersion":3,"authSetVersion":2,"generation":9,"commitment":"` + emptyCommitment + `","loadedAt":"2026-09-03T12:00:00Z","verifiers":[]}`},
		{"wrong commitment", `{"schemaVersion":3,"authSetVersion":1,"generation":9,"commitment":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + `","loadedAt":"2026-09-03T12:00:00Z","verifiers":[]}`},
		{"wrong-length verifier", `{"schemaVersion":3,"authSetVersion":1,"generation":9,"commitment":"` + emptyCommitment + `","loadedAt":"2026-09-03T12:00:00Z","verifiers":[{"verifier":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 17)) + `"}]}`},
		{"non-base64 verifier", `{"schemaVersion":3,"authSetVersion":1,"generation":9,"commitment":"` + emptyCommitment + `","loadedAt":"2026-09-03T12:00:00Z","verifiers":[{"verifier":"!!!!not-base64!!!!"}]}`},
		{"unparsable loadedAt", `{"schemaVersion":3,"authSetVersion":1,"generation":9,"commitment":"` + emptyCommitment + `","loadedAt":"yesterday","verifiers":[]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRawSnapshot(t, dir, tc.content)
			tokens := auth.NewTokenStore()
			log, buf := journalLogger()

			RestoreSnapshot(dir, tokens, log)

			if got := tokens.Current(); got.Generation != 0 || len(got.Verifiers) != 0 {
				t.Errorf("unusable snapshot was restored (%d / %d verifiers) — serve no tokens instead of a partial trust state",
					got.Generation, len(got.Verifiers))
			}
			if buf.Len() != 0 {
				t.Error("operational action emitted a journal record")
			}
		})
	}
}

func TestRestoreSnapshotAcceptsEmptyVerifierSet(t *testing.T) {
	// A pushed revoke-all (zero verifiers) is legitimate persisted state:
	// restoring it must yield generation N with nothing authenticating,
	// not an ignored file (which would resurrect generation 0).
	dir := t.TempDir()
	// Literal base64 of the contract's independently derived empty-set vector.
	writeRawSnapshot(t, dir, `{"schemaVersion":3,"authSetVersion":1,"generation":12,"commitment":"0aTZNWoRBmJiQLlioYT3lCjwpLxp+uWWM7WZ35VBFnU=","loadedAt":"2026-09-03T12:00:00Z","verifiers":[]}`)

	tokens := auth.NewTokenStore()
	log, _ := journalLogger()
	RestoreSnapshot(dir, tokens, log)

	if got := tokens.Current(); got.Generation != 12 || len(got.Verifiers) != 0 {
		t.Errorf("revoke-all restore = generation %d / %d verifiers, want 12 / 0", got.Generation, len(got.Verifiers))
	}
}

// TestSnapshotWriterSeamConformsToServerContract pins the SnapshotFunc
// wiring: the closure persists to the fixed dir, so server.go's persist
// seam and T050's constructor get the same behavior for one dir.
func TestSnapshotWriterSeamConformsToServerContract(t *testing.T) {
	dir := t.TempDir()
	log, buf := journalLogger()

	var seam SnapshotFunc = SnapshotWriter(dir, log)
	if err := seam(testGeneration(7, 1)); err != nil {
		t.Fatalf("SnapshotWriter seam: %v", err)
	}
	if m := readMirror(t, dir); m.Generation != 7 {
		t.Errorf("seam-written generation = %d, want 7", m.Generation)
	}
	if buf.Len() != 0 {
		t.Error("operational action emitted a journal record")
	}
}

// Constitution III: even credential-state maintenance is not an event journal.
func TestOperationalSnapshotWritesAreSilent(t *testing.T) {
	dir := t.TempDir()
	logger, out := journalLogger()
	if err := SnapshotWriter(dir, logger)(testGeneration(8675309, 1)); err != nil {
		t.Fatal(err)
	}
	if readMirror(t, dir).Generation != 8675309 {
		t.Fatal("snapshot positive control failed")
	}
	if out.Len() != 0 {
		t.Fatal("snapshot operation emitted a persistent diagnostic event")
	}
}
