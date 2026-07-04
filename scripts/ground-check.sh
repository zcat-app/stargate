#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# scripts/ground-check.sh — verify external-world PINS: the one class of defect
# that cross-artifact consistency analysis (/speckit-analyze) structurally
# cannot catch.
#
# Why this exists (evidence, not theory): the Tor-route spec passed five clean
# /speckit-analyze runs yet still pinned Go 1.23 — which was already
# end-of-life. Consistency analysis proves the artifacts agree with EACH OTHER;
# it cannot prove they agree with REALITY (is this toolchain still supported?
# does this image digest still resolve?). The pin sat invisible in go.mod and
# nobody looked. This script makes every external pin visible every run and
# validates what it can, so that miss cannot recur silently.
#
# Two depths:
#   OFFLINE (default): structural validation + surfacing. No network. FAILs
#     only on a structurally broken pin (malformed digest, un-pinned non-scratch
#     base image). Surfaces every version pin with an endoflife.date pointer for
#     human confirmation.
#   ONLINE (STARGATE_GROUND_ONLINE=1): additionally resolves each image digest
#     against its registry (needs docker) and checks the Go toolchain cycle
#     against endoflife.date (needs curl). This is the depth that actually
#     CATCHES an EOL toolchain or a pruned digest. Opt-in because it makes
#     network calls — consistent with the project's no-surprise-egress stance.
#
# Exit 0 if all pins are structurally valid (warnings allowed); 1 on a hard pin
# defect. Phase-aware: skips checks whose inputs do not exist yet.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

ONLINE="${STARGATE_GROUND_ONLINE:-0}"
fail=0; warn=0
err()  { printf 'FAIL: %s\n' "$*"; fail=1; }
note() { printf 'WARN: %s\n' "$*"; warn=$((warn+1)); }
ok()   { printf 'ok:   %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "Stargate ground-check — mode: $([ "$ONLINE" = 1 ] && echo ONLINE || echo offline)"
echo "----------------------------------------------------------------"

# === 1. Container base-image digest pins (Principle IV) ===================
mapfile -t dfs < <(git ls-files -- '*Dockerfile' '*Dockerfile.*' 2>/dev/null)
if [ "${#dfs[@]}" -eq 0 ]; then
  echo "(no Dockerfiles tracked yet — skipping digest checks)"
else
  for df in "${dfs[@]}"; do
    [ -f "$df" ] || continue
    while IFS= read -r line; do
      img=$(printf '%s' "$line" | awk '{print $2}')
      [ "$img" = scratch ] && { ok "$df: FROM scratch (no digest needed)"; continue; }
      base=${img%%@*}
      if [[ "$img" != *@sha256:* ]]; then
        err "$df: un-pinned base image '$img' (no @sha256 digest — Principle IV)"
        continue
      fi
      digest=${img#*@sha256:}
      if [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
        err "$df: malformed sha256 on '$base' (got '${digest:0:12}…', need 64 lowercase hex)"
        continue
      fi
      ok "$df: $base @sha256:${digest:0:12}…"
      if [ "$ONLINE" = 1 ]; then
        if have docker; then
          # Use `docker buildx imagetools inspect`, NOT `docker manifest inspect`:
          # the latter fails on multi-arch OCI index digests (official library
          # images like maven/eclipse-temurin/golang/debian) with "manifest
          # verification failed for digest" — it fetches the index but the
          # content-vs-digest check is confused by the index-vs-manifest
          # distinction. `buildx imagetools inspect` handles both single-manifest
          # and multi-arch index digests correctly. Requires docker buildx
          # (bundled with Docker CE 20.10+ and Docker Desktop).
          if docker buildx imagetools inspect "$img" >/dev/null 2>&1; then
            ok "  └ digest resolves in registry"
          else
            err "  └ digest does NOT resolve in registry: $img"
          fi
        else
          note "$df: docker absent — cannot resolve digest online"
        fi
      fi
    done < <(grep -E '^FROM ' "$df")
  done
fi

# === 1b. Compose image digest pins (Principle IV) =========================
# Compose `image:` directives and `compose/env/*.env*` files can carry
# external image references that Dockerfile-FROM scanning (section 1) does
# not catch. This block enforces the same pin discipline on those refs.
#
# Two patterns:
#   (a) Literal refs in yml:  `image: <repo>/<name>:<tag>@sha256:<64hex>`
#   (b) Variable substitution:`image: ${VAR}`  — the literal pin lives in a
#       `compose/env/*.env*` file as `VAR=<repo>/<name>:<tag>@sha256:<64hex>`.
#
# Validation is structural (offline) + registry-resolve (online). A bare-tag
# ref (no `@sha256:`) is FAIL unless it's a Stargate-built image keyed on a
# `build:` directive in the same service block (those are pinned via the
# Dockerfile FROM, scanned in section 1).
echo
echo "Compose image pins —"
# Build the set of service keys that use `build:` (their `image:` is a local
# tag, not a registry pull, so no @sha256: is expected).
build_service_keys=""
if ls compose/*.yml compose/*.yaml >/dev/null 2>&1; then
  # Extract <service>: for any service block that has a `build:` directive.
  # Service keys are top-level under `services:` and are typically non-indented
  # by 2 spaces; service blocks are siblings. We approximate by finding lines
  # like `  <key>:` followed within a few lines by `    build:`.
  build_service_keys="$(
    awk '
      /^services:[[:space:]]*$/ { in_services=1; next }
      in_services && /^[^[:space:]]/ { in_services=0 }
      in_services && /^  [a-zA-Z0-9_-]+:[[:space:]]*$/ { svc=$1; sub(/:/, "", svc); have_build[svc]=0; next }
      in_services && /^    build:[[:space:]]*$/ { if (svc!="") have_build[svc]=1; next }
      END { for (k in have_build) if (have_build[k]) print k }
    ' compose/*.yml compose/*.yaml 2>/dev/null | sort -u | paste -sd'|' -
  )"
fi

# Scan compose yml `image:` directives + env files for image refs.
shopt -s nullglob
compose_files=( compose/*.yml compose/*.yaml )
env_files=( compose/env/*.env compose/env/*.env.* )
shopt -u nullglob

# Collect candidate image refs across both surfaces.
declare -A refs_seen

# (a) Literal `image:` lines in compose yml.
for f in "${compose_files[@]:-}"; do
  [ -f "$f" ] || continue
  while IFS= read -r line; do
    # Match `    image: <something>` (4-space indent under a service block).
    case "$line" in
      *image[:*]*)
        # Skip comments.
        case "$(printf '%s' "$line" | tr -d '[:space:]')" in \#*) continue;; esac
        val="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*image:[[:space:]]*//; s/[[:space:]]*$//; s/^["\x27]//; s/["\x27]$//')"
        [ -n "$val" ] || continue
        refs_seen["$f|$val"]=1
        ;;
    esac
  done < "$f"
done

# (b) `<KEY>=<value>` lines in env files where value contains `:` (heuristic
# for "looks like an image ref"). Cheap and catches the
# DOCKER_SOCKET_PROXY_IMAGE=tecnativa/...:0.3.0@sha256:... case.
for f in "${env_files[@]:-}"; do
  [ -f "$f" ] || continue
  while IFS= read -r line; do
    case "$line" in
      [A-Za-z_]*=*)
        # Strip leading `KEY=`.
        val="${line#*=}"
        # Strip surrounding quotes / whitespace.
        val="${val#\"}"; val="${val%\"}"; val="${val#\'}"; val="${val%\'}"
        val="$(printf '%s' "$val" | tr -d '[:space:]')"
        # Heuristic: contains `/` AND `:` → plausibly an image ref.
        case "$val" in
          */*:*) refs_seen["$f|$val"]=1 ;;
        esac
        ;;
    esac
  done < "$f"
done

# Validate each unique ref.
seen_any_compose_ref=0
for key in "${!refs_seen[@]}"; do
  seen_any_compose_ref=1
  src="${key%%|*}"; img="${key#*|}"
  # Skip variable substitutions; they are validated via the env file path.
  case "$img" in
    '${'*'}')  # ${VAR} form
      varname="${img#\$\{}"; varname="${varname%\}}"
      resolved=""
      for ef in "${env_files[@]:-}"; do
        [ -f "$ef" ] || continue
        v="$(grep -E "^${varname}=" "$ef" 2>/dev/null | head -1)"
        [ -n "$v" ] && { resolved="${v#*=}"; break; }
      done
      if [ -z "$resolved" ]; then
        note "$src: image ref is '\$${varname}' but no env file sets ${varname}= — cannot validate pin"
        continue
      fi
      img="$resolved"
      ;;
    '$'*)  # $VAR form (rare in compose)
      varname="${img#\$}"
      resolved=""
      for ef in "${env_files[@]:-}"; do
        [ -f "$ef" ] || continue
        v="$(grep -E "^${varname}=" "$ef" 2>/dev/null | head -1)"
        [ -n "$v" ] && { resolved="${v#*=}"; break; }
      done
      if [ -z "$resolved" ]; then
        note "$src: image ref is '\$${varname}' but no env file sets ${varname}= — cannot validate pin"
        continue
      fi
      img="$resolved"
      ;;
  esac
  # Skip refs that are bare local tags for build-directive services.
  case "$img" in
    stargate/*|localhost/*|ghcr.io/zcat-app/stargate-*)
      # Stargate-built image keyed on a build: directive — base-digest pin
      # lives in the Dockerfile (section 1). Final-image digest pin is
      # deferred to release-tag (see T015 §Analysis R1).
      ok "$src: $img (Stargate-built, base-digest pinned in Dockerfile — section 1)"
      continue
      ;;
  esac
  if [[ "$img" != *@sha256:* ]]; then
    err "$src: un-pinned external image '$img' (no @sha256 digest — Principle IV)"
    continue
  fi
  digest="${img#*@sha256:}"
  base="${img%@*}"
  if [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
    err "$src: malformed sha256 on '$base' (got '${digest:0:12}…', need 64 lowercase hex)"
    continue
  fi
  ok "$src: $base @sha256:${digest:0:12}…"
  if [ "$ONLINE" = 1 ]; then
    if have docker; then
      # docker buildx imagetools inspect handles multi-arch OCI index digests
      # correctly (see section 1 note). Pass the tag@digest form.
      if docker buildx imagetools inspect "$img" >/dev/null 2>&1; then
        ok "  └ digest resolves in registry"
      else
        err "  └ digest does NOT resolve in registry: $img"
      fi
    else
      note "$src: docker absent — cannot resolve compose image digest online"
    fi
  fi
done
if [ "$seen_any_compose_ref" = 0 ]; then
  echo "(no compose image refs found — skipping)"
fi

# === 2. Toolchain / framework version pins ===============================
echo
echo "Version pins — confirm each is a SUPPORTED (non-EOL) release:"

# --- Go (the pin class with the proven miss) ---
if [ -f data-plane/go.mod ]; then
  goline=$(grep -E '^go '        data-plane/go.mod | awk '{print $2}')
  gotool=$(grep -E '^toolchain ' data-plane/go.mod | awk '{print $2}')
  printf '  Go:      directive=%s toolchain=%s   https://endoflife.date/go\n' "${goline:-?}" "${gotool:-?}"
  if have go; then
    inst=$(go env GOVERSION 2>/dev/null | sed 's/^go//')
    [ -n "$inst" ] && [ -n "${gotool:-}" ] && [ "go$inst" != "$gotool" ] \
      && note "installed Go ($inst) != pinned toolchain (${gotool#go})"
  fi
  if [ "$ONLINE" = 1 ] && have curl; then
    cyc=$(printf '%s' "${goline:-${gotool#go}}" | grep -oE '^[0-9]+\.[0-9]+')
    if [ -n "$cyc" ]; then
      json=$(curl -fsS --max-time 10 "https://endoflife.date/api/go/${cyc}.json" 2>/dev/null || true)
      eol=$(printf '%s' "$json" | grep -oE '"eol":[^,}]*' | head -1 | cut -d: -f2- | tr -d ' "')
      today=$(date -u +%Y-%m-%d)
      if [ -z "$eol" ]; then note "could not fetch endoflife.date for Go $cyc"
      elif [ "$eol" = false ]; then ok "  └ Go $cyc is supported (eol: false)"
      elif [[ "$eol" < "$today" ]]; then err "  └ Go $cyc is END-OF-LIFE since $eol — bump the pin"
      else ok "  └ Go $cyc supported until $eol"
      fi
    fi
  fi
fi

# --- JDK / Quarkus / Maven (surfaced; auto-EOL check scoped to Go for now) ---
if [ -f control-plane/pom.xml ]; then
  jdk=$(grep -oE 'maven.compiler.release>[0-9]+' control-plane/pom.xml | grep -oE '[0-9]+' | head -1)
  qk=$(grep -oE 'quarkus.platform.version>[0-9.]+' control-plane/pom.xml | grep -oE '[0-9][0-9.]*' | head -1)
  [ -n "${jdk:-}" ] && printf '  JDK:     %s                          https://endoflife.date/eclipse-temurin\n' "$jdk"
  [ -n "${qk:-}" ]  && printf '  Quarkus: %s                       https://endoflife.date/quarkus\n' "$qk"
fi
mvn=$(grep -oE 'apache-maven-[0-9.]+-bin' control-plane/.mvn/wrapper/maven-wrapper.properties 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
[ -n "${mvn:-}" ] && printf '  Maven:   %s                       https://endoflife.date/maven\n' "$mvn"

# === Summary =============================================================
echo
echo "----------------------------------------------------------------"
if [ "$fail" -ne 0 ]; then
  echo "ground-check: FAIL — broken pin(s) above ($warn warning(s))."
  exit 1
fi
if [ "$ONLINE" != 1 ]; then
  echo "ground-check: OK (offline; $warn warning(s)). Pins surfaced above are"
  echo "  NOT auto-verified against EOL/registry — run with STARGATE_GROUND_ONLINE=1"
  echo "  (needs curl/docker) before a release to verify them for real."
else
  echo "ground-check: OK — pins resolved/verified online ($warn warning(s))."
fi
exit 0
