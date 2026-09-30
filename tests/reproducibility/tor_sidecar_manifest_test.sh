#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/reproducibility/tor_sidecar_manifest_test.sh — T099 acceptance #3,
# T184 acceptance #2/#3.
#
# Rebuilds the Tor sidecar image twice from a cold cache and asserts each
# build's installed package set (image arch, name, version, package arch) equals
# the COMMITTED golden rows in sidecars/tor/package-closure.lock, and that the
# two builds agree. Comparing build A with build B alone cannot catch an
# on-path attacker who serves both builds the same older signed index (T184),
# so the committed lock is the reference. The build itself additionally checks
# each row's archive sha256; the image no longer carries apt lists, so this
# test compares identities only.
#
# Negative controls (T184 acceptance #3) — each must FAIL the build at the
# named T184 check, or this test fails:
#   - tampered lock: this arch's libssl3 row is changed in a copy of the build
#     context; the build must stop at the closure check.
#   - rolled-back index: a loopback HTTP proxy (the on-path attacker) relays
#     the genuine 12.15 snapshot for the first InRelease fetch (stage 1) and
#     then serves the genuinely signed Debian 12.12 snapshot (20251201) under
#     the pinned 20260714 URL. Without T184 apt accepts it and installs libssl3
#     3.0.17; the build must stop at the InRelease pin.
#
# What is NOT gated: a byte-stable final image DIGEST (apt postinst scripts,
# dpkg status mtimes and layer timestamps vary; see BUILD-DIFFS.md).
#
# Release cadence: opt-in via STARGATE_VERIFY_REPRO=1 (scripts/verify.sh
# Gate 5). Four cold builds are network- and time-heavy; they do not run in the
# default PR gate. The hermetic structural gate lives in
# tests/contract/security-decisions/tor_build_inputs_test.sh.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

CONTEXT="sidecars/tor"
LOCK="$CONTEXT/package-closure.lock"
PINNED_RUN="20260714T082229Z"
ROLLBACK_RUN="20251201T030959Z"   # bookworm 12.12, genuinely signed, libssl3 3.0.17
WORK="$(mktemp -d)"
PROXY_PID=""
IMAGES="stargate/tor:repro-a stargate/tor:repro-b stargate/tor:repro-tampered stargate/tor:repro-rollback"
cleanup() {
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
  # shellcheck disable=SC2086 # intentional word splitting of the image list
  docker rmi -f $IMAGES >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || { echo "SKIP: docker not available"; exit 0; }
docker info >/dev/null 2>&1 || { echo "SKIP: docker daemon unreachable"; exit 0; }
[ -f "$LOCK" ] || { echo "FAIL: $LOCK missing (T184 acceptance #1)" >&2; exit 1; }

case "$(docker info -f '{{.Architecture}}')" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "FAIL: unsupported docker architecture" >&2; exit 1 ;;
esac

failures=()
fail() { failures+=("$*"); echo "FAIL: $*" >&2; }

installed() {
  docker run --rm --entrypoint dpkg-query "$1" -W \
    -f="$ARCH \${Package} \${Version} \${Architecture}\n" | LC_ALL=C sort
}
awk -v a="$ARCH" '$1 == a { print $1, $2, $3, $4 }' "$LOCK" | LC_ALL=C sort > "$WORK/expected.txt"
[ -s "$WORK/expected.txt" ] || fail "no $ARCH rows in $LOCK"

build() { # build <tag> <context> <log> [extra docker build args...]
  local tag=$1 ctx=$2 log=$3
  shift 3
  docker build --no-cache --progress=plain "$@" -t "$tag" "$ctx" > "$log" 2>&1
}

# --- honest cold builds vs the committed lock ------------------------------
for b in a b; do
  echo ">>> cold build $b (stargate/tor:repro-$b)"
  if build "stargate/tor:repro-$b" "$CONTEXT" "$WORK/build-$b.log"; then
    installed "stargate/tor:repro-$b" > "$WORK/manifest-$b.txt"
    diff -u "$WORK/expected.txt" "$WORK/manifest-$b.txt" > "$WORK/diff-$b.txt" \
      || { fail "build $b differs from $LOCK:"; cat "$WORK/diff-$b.txt" >&2; }
  else
    fail "cold build $b failed:"; tail -20 "$WORK/build-$b.log" >&2
  fi
done
if [ -f "$WORK/manifest-a.txt" ] && [ -f "$WORK/manifest-b.txt" ]; then
  cmp -s "$WORK/manifest-a.txt" "$WORK/manifest-b.txt" || fail "package set drifted between cold rebuilds"
fi

# --- control 1: a tampered lock must fail the build ------------------------
echo ">>> control: tampered lock"
mkdir "$WORK/tampered"
cp -a "$CONTEXT/." "$WORK/tampered/"
awk -v a="$ARCH" '$1 == a && $2 == "libssl3" { $3 = "3.0.17-1~deb12u2" } { print }' \
  "$LOCK" > "$WORK/tampered/package-closure.lock"
if cmp -s "$LOCK" "$WORK/tampered/package-closure.lock"; then
  fail "tamper control did not change the lock"
elif build stargate/tor:repro-tampered "$WORK/tampered" "$WORK/build-tampered.log"; then
  fail "build accepted a lock that does not match the installed closure"
elif ! grep -q 'T184: installed package closure differs' "$WORK/build-tampered.log"; then
  fail "tampered-lock build failed, but not at the T184 closure check:"; tail -20 "$WORK/build-tampered.log" >&2
fi

# --- control 2: a replayed older signed index must fail the build ----------
echo ">>> control: rolled-back signed index ($ROLLBACK_RUN served as $PINNED_RUN)"
python3 - "$WORK" "$PINNED_RUN" "$ROLLBACK_RUN" <<'PY' &
import http.server, pathlib, shutil, sys, threading, urllib.error, urllib.request
work, pinned, old = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
lock, state = threading.Lock(), {"inrelease": 0}
log = open(work / "proxy.log", "a", buffering=1)

class Attacker(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        url = self.path
        with lock:
            if url.endswith("/InRelease"):
                state["inrelease"] += 1
            rollback = state["inrelease"] > 1   # stage 1 honest, stage 2 replayed
        if rollback:
            url = url.replace(f"/{pinned}/", f"/{old}/")
        log.write(("rollback " if rollback else "honest ") + url + "\n")
        try:
            upstream = urllib.request.urlopen(url, timeout=120)
        except urllib.error.HTTPError as exc:
            self.send_error(exc.code)
            return
        with upstream:
            self.send_response(200)
            length = upstream.headers.get("Content-Length")
            if length:
                self.send_header("Content-Length", length)
            self.end_headers()
            shutil.copyfileobj(upstream, self.wfile)

    def log_message(self, *args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Attacker)
(work / "proxy.port").write_text(str(server.server_address[1]))
server.serve_forever()
PY
PROXY_PID=$!
for _ in $(seq 50); do [ -s "$WORK/proxy.port" ] && break; sleep 0.1; done
if [ ! -s "$WORK/proxy.port" ]; then
  fail "rollback proxy did not start"
else
  PROXY="http://127.0.0.1:$(cat "$WORK/proxy.port")"
  # Predefined proxy build args route apt's http:// snapshot fetches through
  # the attacker; apt would also send HTTPS there, so no_proxy keeps
  # deb.torproject.org direct. Host networking lets the build reach the
  # loopback-only attacker.
  if build stargate/tor:repro-rollback "$CONTEXT" "$WORK/build-rollback.log" \
       --network=host --build-arg "http_proxy=$PROXY" \
       --build-arg no_proxy=deb.torproject.org; then
    ssl=$(installed stargate/tor:repro-rollback | awk '$2 == "libssl3" { print $3 }')
    fail "build accepted the replayed 12.12 index (installed libssl3 ${ssl:-unknown})"
  elif ! grep -q 'T184: snapshot InRelease does not match the pinned hash' "$WORK/build-rollback.log"; then
    fail "rolled-back build failed, but not at the T184 InRelease pin:"; tail -20 "$WORK/build-rollback.log" >&2
  fi
  grep -q "^rollback .*/$ROLLBACK_RUN/dists/bookworm/InRelease$" "$WORK/proxy.log" \
    || fail "the proxy never served the older InRelease; the control did not exercise the attack"
fi

if [ "${#failures[@]}" -gt 0 ]; then
  echo "FAIL: Tor package-closure reproducibility (${#failures[@]} finding(s))" >&2
  exit 1
fi
n=$(wc -l < "$WORK/expected.txt" | tr -d ' ')
echo "OK: $ARCH package closure equals $LOCK across two cold rebuilds ($n packages);"
echo "    tampered lock and replayed older signed index both refused at the T184 checks"
exit 0
