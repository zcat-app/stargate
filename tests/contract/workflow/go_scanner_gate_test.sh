#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# T114: exercise the real discovered gate with findings that vet and ordinary
# tests do not report, plus a race that only -race detects.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
GATE="${STARGATE_T114_GATE:-$REPO_ROOT/scripts/go-workspace-gate.py}"
command -v go >/dev/null || { echo "SKIP: go not installed"; exit 0; }
command -v python3 >/dev/null || { echo "SKIP: python3 not installed"; exit 0; }

SANDBOX="$(mktemp -d -t stargate-t114-XXXXXX)"
trap 'rm -rf "$SANDBOX"' EXIT
mkdir -p "$SANDBOX/work/data-plane" "$SANDBOX/tool-less"
cat > "$SANDBOX/work/go.work" <<'EOF'
go 1.26
use ./data-plane
EOF
cat > "$SANDBOX/work/data-plane/go.mod" <<'EOF'
module example.com/scanner-fixture
go 1.26
EOF
cat > "$SANDBOX/work/data-plane/ready.go" <<'EOF'
package fixture
func Ready() bool { return true }
EOF
cat > "$SANDBOX/work/data-plane/ready_test.go" <<'EOF'
package fixture
import "testing"
func TestReady(t *testing.T) { if !Ready() { t.Fatal("not ready") } }
EOF

CASE_OUT=""
CASE_RC=0
run_case() {
  local gate="$1"
  gofmt -w "$SANDBOX/work/data-plane/ready.go" "$SANDBOX/work/data-plane/ready_test.go"
  if CASE_OUT="$(python3 "$gate" "$SANDBOX/work" 2>&1)"; then
    CASE_RC=0
  else
    CASE_RC=$?
  fi
}
expect() {
  local label="$1" pattern="$2"
  if ! printf '%s\n' "$CASE_OUT" | grep -qE "$pattern"; then
    echo "FAIL: $label — missing /$pattern/" >&2
    printf '%s\n' "$CASE_OUT" >&2
    exit 1
  fi
}
expect_rc() {
  local label="$1" wanted="$2"
  if [ "$CASE_RC" -ne "$wanted" ]; then
    echo "FAIL: $label — rc=$CASE_RC, want $wanted" >&2
    printf '%s\n' "$CASE_OUT" >&2
    exit 1
  fi
}

run_case "$GATE"
expect_rc clean 0
expect clean-staticcheck 'PASS[[:space:]]+staticcheck:data-plane'
expect clean-gosec 'PASS[[:space:]]+gosec:data-plane'
expect clean-workspace 'go-workspace: GREEN'

cat >> "$SANDBOX/work/data-plane/ready.go" <<'EOF'
func unusedFunction() {}
EOF
run_case "$GATE"
expect_rc staticcheck-finding 1
expect staticcheck-finding 'FAIL[[:space:]]+staticcheck:data-plane'
expect staticcheck-rule 'U1000'

cat > "$SANDBOX/work/data-plane/ready.go" <<'EOF'
package fixture
import "crypto/tls"
func Ready() bool { return true }
func Insecure() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
EOF
run_case "$GATE"
expect_rc gosec-finding 1
expect gosec-finding 'FAIL[[:space:]]+gosec:data-plane'
expect gosec-rule 'G402'

cat > "$SANDBOX/work/data-plane/ready.go" <<'EOF'
package fixture
func Ready() bool { return true }
EOF
cp "$GATE" "$SANDBOX/tool-less/go-workspace-gate.py"
run_case "$SANDBOX/tool-less/go-workspace-gate.py"
expect_rc missing-pinned-tools 1
expect missing-pinned-tools 'FAIL[[:space:]]+staticcheck:data-plane'

cat > "$SANDBOX/work/data-plane/ready_test.go" <<'EOF'
package fixture
import "testing"
func TestRace(t *testing.T) {
    var shared int
    done := make(chan struct{})
    go func() { shared = 1; close(done) }()
    shared = 2
    <-done
    _ = shared
}
EOF
run_case "$GATE"
expect_rc race-finding 1
expect race-diagnostic 'WARNING: DATA RACE'
expect race-package 'FAIL[[:space:]]+go:data-plane:example.com/scanner-fixture'

echo "PASS: T114 scanner findings, unavailable pinned tools and race detector fail the real Go gate"
