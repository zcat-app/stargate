#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/contract/compose/inter_plane_wire_test.sh — T095 regression test for
# the inter-plane wire-auth contract (specs/001-tor-route/contracts/wire-auth.md).
#
# Why this test exists (review sol-review.md M5): T022 marked done while
# transport_test.go:7-16 deferred socket ownership, peer-UID access, mutual
# Ed25519, schema-version rejection, and plane-down behavior to "impl detail".
# T095 completes the wire contract BEFORE T038/T045/T050 so implementation
# cannot invent the wire shape; this test is the regression gate.
#
# Two tiers, mirroring T022's local-process vs compose-level split:
#
# STRUCTURAL tier (runs NOW, hermetic, no stack bring-up):
#   - contracts/wire-auth.md exists and pins the binding shape (cert fields,
#     pin check, validity window, metadata keys, interceptor placement).
#   - arch §5.3/§5.4 reference wire-auth.md (single-source-of-truth guard).
#   - contracts/control-grpc.md §"Transport invariants" references wire-auth.md.
#   - init script references wire-auth.md and installs keys (+ pepper from
#     T092), NOT certs (certs derived at plane startup).
#   - compose file mounts stargate-keys at /etc/stargate/keys with the right
#     UID/GID numerics matching the Dockerfiles.
#   - proto package is stargate.v1 (the runtime major-version source).
#   - SECURITY-DECISIONS.md carries the T095 cert-validity acceptance entry.
#   - THREAT-MODEL.md §5.13 carries the inter-plane residue.
#
# RUNTIME tier (content-gated; SELF-SKIPS until T038/T045/T050 land, then
# self-lifts — the same content-gate discipline T022 used):
#   - socket ownership/mode 0660, owner stargate-{cp,dp}, group stargate-ipc.
#   - peer-plane UID connect(2) succeeds; non-group UID gets EACCES.
#   - wrong-key peer rejected at TLS handshake.
#   - unknown x-stargate-proto-major rejected before app handler.
#   - additive minor accepted (minor compatibility).
#   - no TCP listener beyond the proxy port (no TCP gRPC transport).
#   - DP keeps routing port 8881 across a CP restart (Principle II).
#
# The runtime rows require a built+running compose stack with distinct UIDs
# and key material — they cannot be exercised before the impl tickets land.
# The structural rows gate the contract those runtime rows will pin, so a
# silent doc/spec drift fails the PR gate today rather than at first impl.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

errs=()
bail() { errs+=("$*"); }

# Content gate for the RUNTIME tier: T038 (CP gRPC server), T045 (DP gRPC
# server + client), T050 (DP main). Two detection mechanisms so a path
# rename or package refactor cannot silently keep the gate dark:
#   (a) file-existence probe at the expected paths (primary)
#   (b) content-based probe: grep the impl tree for gRPC construction
#       call-sites — the generated stubs' registration/client entry points,
#       `Register...Server(` / `New...Client(` (secondary; catches a
#       refactor that moves the impl to a different path). T115: the probe
#       matches CONSTRUCTION SYMBOLS AT CALL-SITES, never bare RPC names —
#       the original bare-word alternation matched COMMENT text (T044's doc
#       comments name the RPCs) and flipped verify.sh RED on an impl-absent
#       tree. Substrate: inter_plane_wire_gate_test.sh.
# When ALL are present the runtime tier MUST be lifted (see T095 §Notes
# R1-R9); until then it SKIPs. The structural tier (S1-S9 below) runs
# unconditionally — it needs only grep, not docker.
RUNTIME_GATE_FILES=(
  "control-plane/api/src/main/java/io/quarkus/stargate/control/grpc/ControlGrpcService.java"
  "data-plane/internal/controlclient/server.go"
  "data-plane/internal/controlclient/client.go"
  "data-plane/cmd/stargate-proxy/main.go"
)
runtime_gate_files_present=1
for f in "${RUNTIME_GATE_FILES[@]}"; do
  if [ ! -f "$f" ]; then
    runtime_gate_files_present=0
    break
  fi
done
# Secondary content-based gate: if the impl moved to a different path but a
# gRPC server registration or client CONSTRUCTION call-site exists anywhere
# under the DP source tree, the gate fires too. This catches a package
# refactor that would leave runtime_gate_files_present=0 forever (redteam
# Minor: path-rename bypass). The DP-side check is the cross-tree proxy — a
# DP gRPC server necessarily calls the generated stubs' registration/client
# entry points (control.proto `service Control` → RegisterControlServer;
# events.proto `service Events` → NewEventsClient), so detecting either is
# sufficient to know impl landed.
#
# Why call-site symbols and not RPC names (T115): a bare-word probe matches
# comment text — T044's doc comments name ReloadTokens/WatchEvents while
# describing the token store, which flipped verify.sh RED with the impl
# absent. Requiring the symbol shape plus the call's open paren restricts
# matches to code-shaped text. Accepted residues (fail-closed direction): a
# comment quoting a construction call verbatim still trips the gate, and the
# pattern is not gRPC-specific — a non-gRPC constructor named `New...Client(`
# or `Register...Server(` in data-plane/internal/ would force the lift on an
# impl-absent tree; if one ever lands, tighten the pattern via a gate-accuracy
# follow-up ticket (T114 is the structural precedent). --include narrows the
# sweep to Go sources.
runtime_content_detected=0
if grep -qrE 'Register[A-Za-z0-9_]+Server\(|New[A-Za-z0-9_]+Client\(' \
   --include='*.go' data-plane/internal/ 2>/dev/null; then
  runtime_content_detected=1
fi
runtime_gate_present=0
if [ "$runtime_gate_files_present" = "1" ] || [ "$runtime_content_detected" = "1" ]; then
  runtime_gate_present=1
fi
if [ "$runtime_gate_present" = "0" ]; then
  echo "RUNTIME tier SKIP: T038/T045/T050 impl absent — self-lifts when all land (FAIL-forcing; see T095 §Notes)." >&2
else
  echo "RUNTIME tier GATE-LIFT REQUIRED: impl present; R1-R9 assertions must be authored in this file (see T095 §Notes)." >&2
fi

# has_literal <file> <pattern> <label>
has_literal() {
  local file="$1" pat="$2" label="$3"
  if grep -Eq -- "$pat" "$file" 2>/dev/null; then
    :
  else
    bail "$label: pattern '$pat' not found in $file"
  fi
}
lacks_literal() {
  local file="$1" pat="$2" label="$3"
  if grep -Eq -- "$pat" "$file" 2>/dev/null; then
    bail "$label: forbidden pattern '$pat' found in $file"
  fi
}

WIRE_AUTH="specs/001-tor-route/contracts/wire-auth.md"
CONTROL_GRPC="specs/001-tor-route/contracts/control-grpc.md"
ARCH_SPEC="specs/000-architecture/spec.md"
INIT="scripts/subcommands/init"
COMPOSE="compose/docker-compose.local.yml"
DP_DOCKERFILE="data-plane/Dockerfile"
CP_DOCKERFILE="control-plane/Dockerfile"
SEC_DEC="SECURITY-DECISIONS.md"
THREAT_MODEL="THREAT-MODEL.md"
CONTROL_PROTO="proto/stargate/v1/control.proto"
EVENTS_PROTO="proto/stargate/v1/events.proto"

# --- file existence --------------------------------------------------------
for f in "$WIRE_AUTH" "$CONTROL_GRPC" "$ARCH_SPEC" "$INIT" "$COMPOSE" \
         "$DP_DOCKERFILE" "$CP_DOCKERFILE" "$SEC_DEC" "$THREAT_MODEL" \
         "$CONTROL_PROTO" "$EVENTS_PROTO"; do
  [ -f "$f" ] || bail "STRUCTURAL: required file $f missing"
done

# --- S1: wire-auth.md pins the binding wire shape ---------------------------
# Certificate derivation section + the load-bearing fields.
has_literal "$WIRE_AUTH" "## 2\. X\.509 certificate derivation" \
  "S1: wire-auth.md must have §2 cert derivation"
has_literal "$WIRE_AUTH" "Ed25519" \
  "S1: wire-auth.md must pin Ed25519 signature algorithm"
has_literal "$WIRE_AUTH" "self-signed" \
  "S1: wire-auth.md must specify self-signed cert (no CA chain)"
has_literal "$WIRE_AUTH" "NotAfter.*now \+ 30 days" \
  "S1: wire-auth.md must pin 30-day cert validity"
has_literal "$WIRE_AUTH" "NotBefore.*now . 5 min" \
  "S1: wire-auth.md must pin 5-min negative-skew window"
has_literal "$WIRE_AUTH" "spiffe://stargate.local/" \
  "S1: wire-auth.md must pin URI SAN identity"
has_literal "$WIRE_AUTH" "ExtKeyUsage.*ServerAuth, ClientAuth" \
  "S1: wire-auth.md must pin both ExtKeyUsage roles (each plane is client AND server)"

# Peer-pin section: byte-equal public-key comparison, NOT CA-chain.
has_literal "$WIRE_AUTH" "## 3\. Peer public-key pinning" \
  "S1: wire-auth.md must have §3 peer pinning"
has_literal "$WIRE_AUTH" "byte-equal" \
  "S1: wire-auth.md must specify byte-equal pin check"
has_literal "$WIRE_AUTH" "VerifyPeerCertificate" \
  "S1: wire-auth.md must name the custom TLS verifier hook"
# The pin check must explicitly reject CA-chain validation. (We do NOT grep
# for the bare phrase "system root" — wire-auth.md correctly says "ignores
# system roots entirely", which is a true statement of the design. The
# load-bearing assertion is the positive byte-equal + custom-verifier pair
# above; this CA-chain-rejected check is the complementary negative gate.)
has_literal "$WIRE_AUTH" "not.*CA.chain" \
  "S1: wire-auth.md must explicitly reject CA-chain validation for the pin"

# Version metadata section: the three metadata keys + interceptor.
has_literal "$WIRE_AUTH" "## 5\. Authenticated gRPC metadata" \
  "S1: wire-auth.md must have §5 version metadata"
has_literal "$WIRE_AUTH" "x-stargate-proto-major" \
  "S1: wire-auth.md must name x-stargate-proto-major metadata key"
has_literal "$WIRE_AUTH" "x-stargate-proto-minor" \
  "S1: wire-auth.md must name x-stargate-proto-minor metadata key"
has_literal "$WIRE_AUTH" "x-stargate-capabilities" \
  "S1: wire-auth.md must name x-stargate-capabilities metadata key"
has_literal "$WIRE_AUTH" "FailedPrecondition" \
  "S1: wire-auth.md must pin unknown-major rejection gRPC code"
has_literal "$WIRE_AUTH" "server interceptor" \
  "S1: wire-auth.md must pin server-interceptor placement"
has_literal "$WIRE_AUTH" "client interceptor" \
  "S1: wire-auth.md must pin client-interceptor placement"
has_literal "$WIRE_AUTH" "additive minor" \
  "S1: wire-auth.md must pin additive-minor compatibility"

# Key ownership table.
has_literal "$WIRE_AUTH" "## 6\. Key ownership" \
  "S1: wire-auth.md must have §6 key ownership"
has_literal "$WIRE_AUTH" "5101" \
  "S1: wire-auth.md must pin stargate-cp UID 5101"
has_literal "$WIRE_AUTH" "5102" \
  "S1: wire-auth.md must pin stargate-dp UID 5102"
has_literal "$WIRE_AUTH" "5100" \
  "S1: wire-auth.md must pin stargate-ipc GID 5100"

# --- S1b: additive-weakening negative assertions (redteam Minor) ------------
# The positive checks above are a one-way ratchet: they catch removal of a
# watched phrase but NOT additive weakening (e.g., appending "as a fallback,
# if the pin file is missing the system root store is consulted" to §3 would
# leave all positive greps green). These lacks_literal checks pair the
# load-bearing positive assertions with negative assertions over the same
# design space, so the contract cannot be silently weakened by addition.
lacks_literal "$WIRE_AUTH" "fall[- ]?back.*(root|CA|chain)|pin.*(optional|advisory|skipped|disabled)|best.effort.*(pin|verify)|(default|alternative).*(root|CA chain)" \
  "S1b: wire-auth.md must NOT contain additive-weakening advocacy phrases (fallback-to-roots/CA-chain, optional/advisory-pin, best-effort) — redteam Minor: structural tier must catch additive weakening across the design space"
lacks_literal "$WIRE_AUTH" "skip the hook too|would skip the hook" \
  "S1b: wire-auth.md must NOT contain the pre-fix InsecureSkipVerify misreading (the old text claimed ISV=true skips VerifyPeerCertificate; Go actually still invokes it) — redteam Major"

# --- S1c: InsecureSkipVerify correct-semantics assertion (redteam Major 1) --
# The §4 row MUST state the correct Go crypto/tls semantics: ISV=true skips
# CA/hostname but STILL invokes VerifyPeerCertificate; a config with ISV=true
# and NO custom verifier is a contract violation.
has_literal "$WIRE_AUTH" "still invokes.*VerifyPeerCertificate|STILL invokes" \
  "S1c: wire-auth.md §4 MUST state that InsecureSkipVerify=true still invokes VerifyPeerCertificate (Go crypto/tls) — redteam Major 1 factual fix"
has_literal "$WIRE_AUTH" "no.*VerifyPeerCertificate.*contract violation" \
  "S1c: wire-auth.md §4 MUST state that ISV=true without a custom verifier is a contract violation"

# --- S1d: per-handshake pin re-read + encoding pin (redteam Major 3 + Minor 3)
has_literal "$WIRE_AUTH" "fresh from disk on every TLS handshake" \
  "S1d: wire-auth.md §3.1 MUST pin per-handshake re-read of *.pub (rotation-incident-response lever) — redteam Major 3"
has_literal "$WIRE_AUTH" "MUST NOT cache the pinned public key" \
  "S1d: wire-auth.md §3.1 MUST forbid caching the pinned key across handshakes"
has_literal "$WIRE_AUTH" "raw 32-byte Ed25519 public key" \
  "S1d: wire-auth.md §3.1 MUST pin the comparison encoding (raw 32-byte key, not DER/PEM wrapper) — redteam Minor 3"

# --- S2: arch §5.3/§5.4 single-source-of-truth pointer to wire-auth --------
has_literal "$ARCH_SPEC" "contracts/wire-auth\.md" \
  "S2: arch spec must reference contracts/wire-auth.md (§5.3/§5.4 pointer)"
has_literal "$ARCH_SPEC" "x-stargate-proto-major" \
  "S2: arch spec must name the version metadata key"

# --- S3: control-grpc.md transport invariants reference wire-auth ---------
has_literal "$CONTROL_GRPC" "contracts/wire-auth\.md" \
  "S3: control-grpc.md must reference contracts/wire-auth.md"
has_literal "$CONTROL_GRPC" "inter_plane_wire_test\.sh" \
  "S3: control-grpc.md must name the T095 compose-level test as the deferred-rows owner"

# --- S4: init installs keys (+ pepper from T092), NO certs on disk ---------
has_literal "$INIT" "contracts/wire-auth\.md" \
  "S4: init script must reference contracts/wire-auth.md (installer key contract)"
# T088/T092: init now installs the bearer-token pepper alongside the keys, so
# the pre-T092 "KEYS ONLY" marker no longer holds. The load-bearing invariant
# is "no certs installed — certs derived at plane startup" (the privacy
# property the certs-absence check below gates); assert init DOCUMENTS it.
has_literal "$INIT" "self-signed cert" \
  "S4: init must document certs are derived at plane startup (not installed by init)"
# The four key filenames must appear (already gated by init_test.sh M4; re-pin
# here so the wire-contract test is self-contained).
for kf in cp\.priv dp\.priv cp\.pub dp\.pub; do
  has_literal "$INIT" "${kf}" "S4: key filename ${kf} missing from init"
done
# Cert files must NOT be installed by init (certs are in-memory only).
lacks_literal "$INIT" "/etc/stargate/.*\.crt|/etc/stargate/.*\.pem.*cert" \
  "S4: init must NOT install cert files (certs derived in-memory per wire-auth.md §2.1)"

# --- S5: compose UID/GID numerics match wire-auth.md §6.1 ------------------
has_literal "$COMPOSE" '"5101:5100"' "S5: compose must set stargate-control user: \"5101:5100\""
has_literal "$COMPOSE" '"5102:5100"' "S5: compose must set stargate-dp user: \"5102:5100\""
# stargate-keys volume mounted into both planes at /etc/stargate/keys (arch §4.3).
# The render-based mount-target check needs docker + jq; skip ONLY this sub-check
# (not the whole test) when either is absent. The grep-based UID/GID checks above
# and below run unconditionally so the contract-drift gate is not bypassed in a
# dockerless environment.
if command -v docker >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
  RENDER="$(mktemp)"
  trap 'rm -f "$RENDER"' EXIT
  ENV_FILE="compose/env/local.env.example"
  if [ -f "$ENV_FILE" ] && docker compose -f "$COMPOSE" --env-file "$ENV_FILE" config --format json >"$RENDER" 2>/dev/null; then
    keys_cp_target="$(jq -r '[.services["stargate-control"].volumes[] | select(.source == "stargate-keys") | .target] | join(",")' "$RENDER")"
    [ "$keys_cp_target" = "/etc/stargate/keys" ] \
      || bail "S5: stargate-keys must mount into stargate-control at /etc/stargate/keys (got: '$keys_cp_target')"
    keys_dp_target="$(jq -r '[.services["stargate-dp"].volumes[] | select(.source == "stargate-keys") | .target] | join(",")' "$RENDER")"
    [ "$keys_dp_target" = "/etc/stargate/keys" ] \
      || bail "S5: stargate-keys must mount into stargate-dp at /etc/stargate/keys (got: '$keys_dp_target')"
  else
    echo "S5: could not render compose config (env file missing or render failed); skipping mount-target check" >&2
  fi
else
  echo "S5: docker or jq absent; skipping compose mount-target render check (UID/GID grep checks above still ran)." >&2
fi

# Dockerfile UID/GID cross-check (mirrors local_compose_test.sh M6 + init_test.sh M4).
has_literal "$CP_DOCKERFILE" "5101" "S5: control-plane/Dockerfile must define UID 5101"
has_literal "$CP_DOCKERFILE" "5100" "S5: control-plane/Dockerfile must define GID 5100"
has_literal "$DP_DOCKERFILE" "5102" "S5: data-plane/Dockerfile must define UID 5102"
has_literal "$DP_DOCKERFILE" "5100" "S5: data-plane/Dockerfile must define GID 5100"

# --- S6: proto package is stargate.v1 (runtime major source) ---------------
has_literal "$CONTROL_PROTO" "^package stargate\.v1;" \
  "S6: control.proto must declare package stargate.v1 (runtime major-version source per wire-auth.md §5)"
has_literal "$EVENTS_PROTO" "^package stargate\.v1;" \
  "S6: events.proto must declare package stargate.v1"
# The proto package is the runtime major source; a bare v2 would need a
# migration test (arch §5.3). Pin that v1 is current.
lacks_literal "$CONTROL_PROTO" "package stargate\.v2" \
  "S6: control.proto must not declare a v2 package (v1 is current; v2 needs a migration test)"
lacks_literal "$EVENTS_PROTO" "package stargate\.v2" \
  "S6: events.proto must not declare a v2 package"

# --- S7: SECURITY-DECISIONS.md carries the T095 entry ----------------------
has_literal "$SEC_DEC" "2026-07-12 — Inter-plane X\.509 certificate validity policy" \
  "S7: SECURITY-DECISIONS.md must carry the T095 cert-validity entry (reverse-chronological, top of dated region)"
has_literal "$SEC_DEC" "operator-manual" \
  "S7: SECURITY-DECISIONS.md must record that key rotation is operator-manual in v1"

# --- S8: THREAT-MODEL.md §5.13 residue -------------------------------------
has_literal "$THREAT_MODEL" "### 5\.13 Inter-plane channel authentication" \
  "S8: THREAT-MODEL.md must have §5.13 inter-plane channel residue"
has_literal "$THREAT_MODEL" "30 days" \
  "S8: THREAT-MODEL.md must name the 30-day cert-validity window"
has_literal "$THREAT_MODEL" "No automated key rotation" \
  "S8: THREAT-MODEL.md must record the no-automated-rotation residue"

# --- S9: T038/T045/T050 tickets consume wire-auth.md verbatim --------------
# §Acceptance #5 of T095: the downstream tickets reference the contract; they
# do NOT re-define the wire shape. This is the pre-impl gate that the
# contract is consumed.
T038="specs/001-tor-route/tickets/T038-in-control-planeapisrcmainjava-a-control.md"
T045="specs/001-tor-route/tickets/T045-implement-data-planeinternalcontrolclien.md"
T050="specs/001-tor-route/tickets/T050-implement-data-planecmdstargate-proxymai.md"
for t in "$T038" "$T045" "$T050"; do
  [ -f "$t" ] || bail "S9: $t missing (T095 §Acceptance #5 depends on it)"
  has_literal "$t" "contracts/wire-auth\.md" \
    "S9: $t must reference contracts/wire-auth.md (T095 §Acceptance #5 consume-verbatim)"
done

# --- RUNTIME tier (content-gated; FAIL-forcing on lift) -------------------
# The runtime rows require the T038/T045/T050 impl + a live compose stack.
# Two states:
#
# (A) Impl files ABSENT (today): SKIP the runtime tier. The structural tier
#     above (S1-S9) is the PR-cadence gate and runs unconditionally.
#
# (B) Impl files PRESENT: FAIL until R1-R9 are authored in this file. This
#     is the FAIL-forcing gate — it prevents T038/T045/T050 from completing
#     with the 9 auth properties dark. The lift authors the assertions
#     below against a `stargate init`-brought-up stack:
#       R1 socket mode 0660, owner stargate-{cp,dp}:stargate-ipc
#       R2 peer-plane UID connect(2) succeeds on its dial-direction socket
#       R3 non-group UID connect(2) fails with EACCES on both sockets
#       R4 wrong-key peer (replaced *.pub) rejected at TLS handshake
#       R5 unknown x-stargate-proto-major rejected before app handler
#       R6 additive minor version accepted (minor compatibility)
#       R7 no TCP LISTEN beyond the proxy port (no TCP gRPC transport)
#       R8 DP keeps routing port 8881 across a CP restart (Principle II)
#     See T095 §Notes for the row-by-row source citations.
if [ "$runtime_gate_present" = "0" ]; then
  : # state (A) — SKIP; already logged above
else
  # State (B) — impl files present; the runtime lift MUST be authored. The
  # gate counts `# LIFT-MARKER: R<n>` lines in THIS file (one per authored
  # runtime assertion row). An implementer cannot bypass the gate by
  # flipping a constant — they must add the 9 marker lines, one per row
  # they actually implement, EACH PAIRED with assertion code on the next
  # non-comment line. This is the defence against the redteam Minor:
  # "sentinel-flip bypass" and "empty-marker bypass."
  #
  # NOTE: the gate uses paired_markers (below), not a raw count. Each
  # marker must be paired with assertion code to count.
  # Each marker MUST be paired with a non-comment, non-empty line within
  # the next 3 lines — bare comment markers without assertion code do not
  # count (redteam Minor: empty-marker bypass).
  paired_markers=0
  while IFS= read -r line_num; do
    [ -z "$line_num" ] && continue
    end_line=$((line_num + 3))
    cur="$line_num"
    while [ "$cur" -le "$end_line" ]; do
      cur=$((cur + 1))
      content=$(sed -n "${cur}p" "$0" 2>/dev/null)
      # Skip blank lines and comment-only lines.
      case "$content" in
        ''|'#'*|' '*'#'*) continue ;;
      esac
      # Found a non-comment line within 3 lines of the marker → paired.
      paired_markers=$((paired_markers + 1))
      break
    done
  done < <(grep -nE '^# LIFT-MARKER: R[0-9]+$' "$0" 2>/dev/null | cut -d: -f1)
  if [ "$paired_markers" -lt 9 ]; then
    bail "RUNTIME tier GATE-LIFT REQUIRED: T038/T045/T050 impl present but only $paired_markers/9 LIFT-MARKER rows WITH PAIRED ASSERTION CODE authored in this file — author R1-R9 assertions per T095 §Notes (each assertion needs a '# LIFT-MARKER: R<n>' comment followed within 3 lines by a non-comment assertion line; the paired count is the forcing function)"
  fi
fi

# --- report ----------------------------------------------------------------
if [ "${#errs[@]}" -gt 0 ]; then
  echo "FAIL: T095 inter-plane wire contract test (${#errs[@]} finding(s)):" >&2
  for e in "${errs[@]}"; do echo "  - $e" >&2; done
  exit 1
fi
echo "OK: T095 inter-plane wire-auth contract (structural tier green; runtime tier content-gated)"
exit 0
