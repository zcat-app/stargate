#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# Constitution III: production container output cannot become an event archive.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
render="$(mktemp)"
trap 'rm -f "$render"' EXIT
docker compose -f compose/docker-compose.local.yml --env-file compose/env/local.env.example config --format json >"$render"
python3 - "$render" <<'PY'
import json, sys
services = json.load(open(sys.argv[1]))['services']
assert len(services) == 4, 'positive control: all production services rendered'
for name, service in services.items():
    assert service.get('logging', {}).get('driver') == 'none', name + ': raw container output is retained'
    assert service.get('healthcheck', {}).get('disable') is True, name + ': Docker health probes retain timestamped history'
print('PASS: all production containers disable diagnostic and health-history retention')
PY

# JVM and Tor launchers must discard output even when the outer capture is enabled.
probe="$(mktemp -d)"
containers=()
cleanup() {
    for cid in "${containers[@]}"; do docker rm -f "$cid" >/dev/null 2>&1 || true; done
    rm -rf "$probe"
    rm -f "$render"
}
trap cleanup EXIT
chmod 755 "$probe"
cat > "$probe/java" <<'PROBE'
#!/bin/sh
[ -z "${JAVA_TOOL_OPTIONS+x}${JDK_JAVA_OPTIONS+x}${_JAVA_OPTIONS+x}" ] || exit 12
printf 'T152-private-runtime-marker\n'
printf 'T152-private-runtime-marker\n' >&2
exit 0
PROBE
cat > "$probe/tor" <<'PROBE'
#!/bin/sh
printf 'T152-private-sidecar-marker\n'
printf 'T152-private-sidecar-marker\n' >&2
exit 0
PROBE
chmod 755 "$probe/java" "$probe/tor"
# Local process capture verifies the Java wrapper before a container driver can mask a leak.
JAVA_TOOL_OPTIONS=forbidden JDK_JAVA_OPTIONS=forbidden _JAVA_OPTIONS=forbidden \
    PATH="$probe:$PATH" sh control-plane/entrypoint.sh >"$probe/captured" 2>&1
[ ! -s "$probe/captured" ] || { echo 'FAIL: JVM entrypoint exported diagnostics' >&2; exit 1; }
PATH="$probe:$PATH" sh sidecars/tor/entrypoint.sh >"$probe/captured" 2>&1
[ ! -s "$probe/captured" ] || { echo 'FAIL: Tor entrypoint exported diagnostics' >&2; exit 1; }
"$probe/java" >"$probe/positive" 2>&1
[ -s "$probe/positive" ] || { echo 'FAIL: diagnostic capture positive control' >&2; exit 1; }
echo 'PASS: actual launchers suppress stdout/stderr; positive control captures the same writers'

case ",${STARGATE_TEST_TAGS:-}," in
    *,docker,*) ;;
    *) echo 'SKIP: Docker operational capture; set STARGATE_TEST_TAGS=docker'; exit 0 ;;
esac
# Pinned fixture input, no deployed credentials or network access in the test containers.
fixture='debian:12-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df'
if ! docker image inspect "$fixture" >/dev/null 2>&1; then docker pull "$fixture" >/dev/null; fi
start() {
    local driver="$1" entry="$2"
    cid="$(docker run -d --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
        --ulimit core=0 --no-healthcheck --log-driver "$driver" \
        -v "$probe:/probe:ro" -v "$(pwd):/source:ro" \
        -e PATH=/probe:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        "$fixture" sh "$entry")"
    containers+=("$cid")
    [ "$(docker wait "$cid")" = 0 ] || { echo 'FAIL: capture fixture did not execute' >&2; exit 1; }
}
start json-file /probe/java
[ -n "$(docker logs "$cid" 2>&1)" ] || { echo 'FAIL: Docker capture positive control' >&2; exit 1; }
for entry in /source/control-plane/entrypoint.sh /source/sidecars/tor/entrypoint.sh; do
    start json-file "$entry"
    [ -z "$(docker logs "$cid" 2>&1)" ] || { echo 'FAIL: launcher leaked to Docker capture' >&2; exit 1; }
done
for service in stargate-control stargate-dp tor tor-observer; do
    driver="$(jq -r --arg service "$service" '.services[$service].logging.driver' "$render")"
    start "$driver" /probe/java
    # The none driver may return a static "reading unsupported" error. Its
    # stdout must be empty, and the daemon must have no retained log path.
    docker logs "$cid" >"$probe/logs" 2>"$probe/log-error" || true
    [ ! -s "$probe/logs" ] || { echo "FAIL: $service diagnostic retention" >&2; exit 1; }
    if grep -q T152-private "$probe/log-error"; then echo 'FAIL: raw output echoed as error' >&2; exit 1; fi
    docker inspect "$cid" | jq -e '.[0] | .LogPath == "" and .HostConfig.LogConfig.Type == "none" and .State.Health == null' >/dev/null

done
echo 'PASS: Docker positive control, launcher capture, all four service retention boundaries'
