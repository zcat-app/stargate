#!/usr/bin/env bash
# The container command below is intentionally a literal shell program passed to `sh -c`.
# shellcheck disable=SC2016
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# T109 compares a host JVM build with the same source and Maven inputs under a
# different JDK vendor, glibc release, and non-root identity (arch §12.2,
# Constitution Principle VI). The pinned Debian image is glibc-based because
# the locked protoc-gen-grpc-java executable requires glibc; this checks two
# glibc releases, not independence from a libc family.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
cd "$REPO_ROOT"

IMAGE='azul-zulu:25.36-25.0.4.1-jdk-debian13@sha256:69c15f697dcf6e42d11e581cf929ee340584e74f905cd77f3e300e6b1c9a9568'
TICKET=T109

skip() {
  printf 'SKIP: %s (%s)\n' "$1" "$TICKET"
  exit 0
}

fail() {
  printf 'FAIL: %s (%s)\n' "$1" "$TICKET" >&2
  exit 1
}

for tool in java javac javap sha256sum python3 readlink getconf; do
  command -v "$tool" >/dev/null 2>&1 || skip "$tool is unavailable"
done
[ -x control-plane/mvnw ] || skip 'control-plane/mvnw is absent'
[ -f control-plane/.mvn/wrapper/maven-wrapper.properties ] || skip 'Maven wrapper properties are absent'
[ -d proto/stargate/v1 ] || skip 'proto/stargate/v1 is absent'
for module in api core persistence ui runtime; do
  [ -d "control-plane/$module" ] || fail "expected control-plane module is absent: $module"
done

DOCKER="$(command -v docker 2>/dev/null || true)"
[ -n "$DOCKER" ] || skip 'Docker CLI is unavailable'
if ! "$DOCKER" info >/dev/null 2>&1; then
  skip 'Docker daemon is unavailable'
fi

JAVA_BIN="$(readlink -f "$(command -v java)")"
HOST_JAVA_HOME="$(dirname "$(dirname "$JAVA_BIN")")"
[ -x "$HOST_JAVA_HOME/bin/javac" ] || fail "resolved host JAVA_HOME has no javac: $HOST_JAVA_HOME"
HOST_IDENTITY="$(JAVA_HOME="$HOST_JAVA_HOME" "$HOST_JAVA_HOME/bin/java" -XshowSettings:properties -version 2>&1)"
HOST_VENDOR="$(sed -n 's/^[[:space:]]*java.vendor = //p' <<< "$HOST_IDENTITY" | head -1)"
HOST_SPEC="$(sed -n 's/^[[:space:]]*java.specification.version = //p' <<< "$HOST_IDENTITY" | head -1)"
[ -n "$HOST_VENDOR" ] || fail 'could not determine host Java vendor'
[ "$HOST_SPEC" = 25 ] || fail "host Java specification is $HOST_SPEC, expected 25"
HOST_LIBC="$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"
[ -n "$HOST_LIBC" ] || fail 'host GNU libc version is unavailable'
HOST_PLATFORM="$("$DOCKER" info --format '{{.OSType}}/{{.Architecture}}' 2>/dev/null)" \
  || fail 'could not determine Docker platform'
case "$HOST_PLATFORM" in
  linux/x86_64) HOST_PLATFORM=linux/amd64 ;;
  linux/aarch64) HOST_PLATFORM=linux/arm64 ;;
  linux/amd64|linux/arm64) : ;;
  *) fail "pinned image does not declare a supported comparison platform: $HOST_PLATFORM" ;;
esac

WORK="$(mktemp -d "${TMPDIR:-/tmp}/stargate-t109.XXXXXXXX")" || fail 'could not create work directory'
CONTAINER="stargate-t109-$(basename "$WORK")"
cleanup() {
  rc=$?
  trap - EXIT INT TERM
  if [ -n "${STARGATE_T109_DIAGNOSTICS_DIR:-}" ]; then
    diagnostics_dir="$STARGATE_T109_DIAGNOSTICS_DIR"
    mkdir -p "$diagnostics_dir/host" "$diagnostics_dir/container"
    for relative in runtime/target/quarkus-app/quarkus/generated-bytecode.jar \
      runtime/target/quarkus-app/quarkus/quarkus-application.dat \
      runtime/target/quarkus-app/quarkus/transformed-bytecode.jar \
      runtime/target/quarkus-artifact.properties; do
      if [ -f "$WORK/host/control-plane/$relative" ] && [ -f "$WORK/container/control-plane/$relative" ]; then
        mkdir -p "$diagnostics_dir/host/$(dirname "$relative")" \
          "$diagnostics_dir/container/$(dirname "$relative")"
        cp -a "$WORK/host/control-plane/$relative" "$diagnostics_dir/host/$relative"
        cp -a "$WORK/container/control-plane/$relative" "$diagnostics_dir/container/$relative"
      fi
    done
    cp -a "$WORK"/*.log "$WORK"/*.sha256 "$WORK"/*.diff \
      "$WORK"/*.jar-metadata "$diagnostics_dir/" 2>/dev/null || true
    cp -a "$WORK/container/container.identity" "$diagnostics_dir/" 2>/dev/null || true
    cp -a "$WORK/source.sha256" "$diagnostics_dir/" 2>/dev/null || true
  fi
  if [ "$rc" -ne 0 ]; then
    for diagnostic in pull.log maven-bootstrap.log host-build.log container-build.log \
      host.sha256 container.sha256 host.jar-metadata container.jar-metadata \
      artifacts.diff metadata.diff; do
      if [ -f "$WORK/$diagnostic" ]; then
        printf '\nT109 diagnostic %s (last 80 lines):\n' "$diagnostic" >&2
        tail -80 "$WORK/$diagnostic" >&2
      fi
    done
  fi
  label="$("$DOCKER" inspect --format '{{ index .Config.Labels "com.stargate.t109.run" }}' \
    "$CONTAINER" 2>/dev/null || true)"
  if [ "$label" = "$CONTAINER" ]; then
    "$DOCKER" rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$WORK"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$WORK/snapshot" "$WORK/host/.m2" "$WORK/container/.m2" \
  "$WORK/maven-user-home" "$WORK/home" "$WORK/tmp"
# Snapshot once, then derive both build copies from exactly those source bytes.
cp -a control-plane proto "$WORK/snapshot/"
find "$WORK/snapshot" -type d -name target -prune -exec rm -rf -- {} +
source_manifest() {
  (cd "$1" && find control-plane proto -type f -print0 | LC_ALL=C sort -z \
    | xargs -0 sha256sum)
}
source_manifest "$WORK/snapshot" > "$WORK/source.sha256"
SOURCE_HASH="$(sha256sum "$WORK/source.sha256" | awk '{print $1}')"
cp -a "$WORK/snapshot/control-plane" "$WORK/snapshot/proto" "$WORK/host/"
cp -a "$WORK/snapshot/control-plane" "$WORK/snapshot/proto" "$WORK/container/"
for copy in host container; do
  source_manifest "$WORK/$copy" > "$WORK/$copy.source.sha256"
  cmp -s "$WORK/source.sha256" "$WORK/$copy.source.sha256" \
    || fail "$copy source copy differs from the input snapshot"
done

printf 'T109 host: vendor=%s spec=%s libc=%s platform=%s\n' \
  "$HOST_VENDOR" "$HOST_SPEC" "$HOST_LIBC" "$HOST_PLATFORM"
printf 'T109 source snapshot sha256=%s\n' "$SOURCE_HASH"
if ! "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1; then
  printf 'T109: pulling pinned runtime image %s\n' "$IMAGE"
  "$DOCKER" pull "$IMAGE" >"$WORK/pull.log" 2>&1 \
    || { tail -40 "$WORK/pull.log" >&2; fail 'pinned runtime image pull failed'; }
fi

# The wrapper bootstraps only into this per-run home. Its checked-in SHA-256
# verifies the archive; the resulting Maven distribution is mounted read-only.
if ! (cd "$WORK/host/control-plane" && \
    env -u MAVEN_ARGS -u MAVEN_OPTS -u MAVEN_CONFIG \
    JAVA_HOME="$HOST_JAVA_HOME" MAVEN_USER_HOME="$WORK/maven-user-home" \
    ./mvnw -B -ntp -Dmaven.repo.local="$WORK/host/.m2" -v) \
    >"$WORK/maven-bootstrap.log" 2>&1; then
  tail -40 "$WORK/maven-bootstrap.log" >&2
  fail 'Maven wrapper bootstrap failed'
fi
MAVEN_BIN="$(find "$WORK/maven-user-home/wrapper/dists" -type f -path '*/bin/mvn' -print -quit 2>/dev/null)"
if [ -z "$MAVEN_BIN" ] || [ ! -x "$MAVEN_BIN" ]; then
  fail 'bootstrapped Maven distribution was not found'
fi
MAVEN_DIST="$(dirname "$(dirname "$MAVEN_BIN")")"
MAVEN_VERSION="$(env -u MAVEN_ARGS -u MAVEN_OPTS -u MAVEN_CONFIG "$MAVEN_BIN" -v | sed -n '1p')"
MAVEN_HASH="$(find "$MAVEN_DIST" -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
printf 'T109 Maven distribution: %s; tree sha256=%s\n' "$MAVEN_VERSION" "$MAVEN_HASH"

if ! (cd "$WORK/host/control-plane" && \
    env -u MAVEN_ARGS -u MAVEN_OPTS -u MAVEN_CONFIG \
    JAVA_HOME="$HOST_JAVA_HOME" MAVEN_USER_HOME="$WORK/maven-user-home" \
    "$MAVEN_BIN" -B -ntp -Dmaven.repo.local="$WORK/host/.m2" clean package -DskipTests) \
    >"$WORK/host-build.log" 2>&1; then
  tail -60 "$WORK/host-build.log" >&2
  fail 'host clean package failed'
fi

# Keep source and artifact modes intact. The VPS runner already owns these
# paths; only a root-host fallback changes ownership inside this private tree.
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"
[ "$HOST_UID" -ne 0 ] || { HOST_UID=65532; HOST_GID=65532; }
if [ "$(id -u)" -eq 0 ]; then
  chown -R "$HOST_UID:$HOST_GID" "$WORK/container" "$WORK/home" "$WORK/tmp"
fi

# Probe and build in one bounded --rm container so explicit JAVA_HOME is shared
# by the identity check and Maven invocation.
if ! "$DOCKER" run --rm --name "$CONTAINER" --platform "$HOST_PLATFORM" \
    --label "com.stargate.t109.run=$CONTAINER" \
    --user "$HOST_UID:$HOST_GID" --workdir /workspace/container/control-plane \
    --env HOME=/home/build --env TMPDIR=/tmp/build \
    --volume "$WORK/container:/workspace/container:rw" \
    --volume "$MAVEN_DIST:/opt/maven:ro" \
    --volume "$WORK/home:/home/build:rw" --volume "$WORK/tmp:/tmp/build:rw" \
    --entrypoint /bin/sh "$IMAGE" -ec '
      java_bin=$(readlink -f "$(command -v java)")
      java_home=$(dirname "$(dirname "$java_bin")")
      JAVA_HOME=$java_home
      PATH=$JAVA_HOME/bin:$PATH
      export JAVA_HOME PATH
      vendor=$(java -XshowSettings:properties -version 2>&1 | sed -n "s/^[[:space:]]*java.vendor = //p" | sed -n "1p")
      spec=$(java -XshowSettings:properties -version 2>&1 | sed -n "s/^[[:space:]]*java.specification.version = //p" | sed -n "1p")
      os=$(. /etc/os-release && printf "%s %s" "$ID" "$VERSION_ID")
      libc=$(getconf GNU_LIBC_VERSION)
      uid=$(id -u)
      printf "vendor=%s\nspec=%s\nos=%s\nlibc=%s\nuid=%s\njava_home=%s\n" "$vendor" "$spec" "$os" "$libc" "$uid" "$JAVA_HOME" > /workspace/container/container.identity
      test "$spec" = 25
      test "$uid" -ne 0
      case "$os" in "debian 13"|"debian 13."*) : ;; *) echo "unexpected container OS: $os" >&2; exit 1 ;; esac
      case "$vendor" in *Azul*|*Zulu*) ;; *) echo "unexpected container Java vendor: $vendor" >&2; exit 1 ;; esac
      test "$libc" != "'"$HOST_LIBC"'"
      test "$vendor" != "'"$HOST_VENDOR"'"
      unset MAVEN_ARGS MAVEN_OPTS MAVEN_CONFIG
      /opt/maven/bin/mvn -B -ntp -Dmaven.repo.local=/workspace/container/.m2 clean package -DskipTests
    ' >"$WORK/container-build.log" 2>&1; then
  tail -80 "$WORK/container-build.log" >&2
  [ ! -f "$WORK/container/container.identity" ] || cat "$WORK/container/container.identity" >&2
  fail 'container identity check or clean package failed'
fi
cat "$WORK/container/container.identity"

manifest() {
  local root="$1"
  (cd "$root" && find . -path '*/target/*' -type f \
    ! -path '*/target/maven-status/*' \
    ! -path './api/target/quarkus-grpc*.sh' -print0 \
    | LC_ALL=C sort -z | xargs -0 -r sha256sum)
}
compare_files() {
  diff -u "$1" "$2" > "$3"
}
jar_metadata() {
  python3 - "$1" <<'PY'
import pathlib, sys, zipfile
root = pathlib.Path(sys.argv[1])
for jar in sorted(root.glob("*/target/**/*.jar")):
    rel = jar.relative_to(root).as_posix()
    with zipfile.ZipFile(jar) as archive:
        try:
            raw = archive.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
        except KeyError:
            raw = ""
    unfolded = []
    for line in raw.splitlines():
        if line.startswith(" ") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    attrs = dict(line.split(": ", 1) for line in unfolded if ": " in line)
    print(f"{rel}\tCreated-By={attrs.get('Created-By', '<absent>')}\tBuild-Jdk-Spec={attrs.get('Build-Jdk-Spec', '<absent>')}")
PY
}
validate_outputs() {
  local root="$1" label="$2" module jar count stubs
  for module in api core persistence ui runtime; do
    jar="$(find "$root/$module/target" -maxdepth 1 -type f -name '*.jar' -print -quit)"
    [ -n "$jar" ] || fail "$label is missing the expected $module module jar"
  done
  [ -s "$root/runtime/target/quarkus-app/quarkus-run.jar" ] \
    || fail "$label is missing runtime fast-jar launcher"
  [ -d "$root/runtime/target/quarkus-app/app" ] \
    || fail "$label is missing runtime fast-jar app layout"
  [ -d "$root/runtime/target/quarkus-app/lib" ] \
    || fail "$label is missing runtime fast-jar lib layout"
  count="$(find "$root" -path '*/target/*' -type f -name '*.class' | wc -l | tr -d ' ')"
  [ "$count" -gt 0 ] || fail "$label produced no class files"
  jar="$(find "$root/api/target" -maxdepth 1 -type f -name 'api-*.jar' -print -quit)"
  [ -n "$jar" ] || fail "$label is missing the API jar"
  stubs="$(python3 - "$jar" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    print(sum(1 for name in archive.namelist()
              if name.startswith("stargate/v1/") and name.endswith(".class")))
PY
  )"
  [ "$stubs" -ge 10 ] || fail "$label API jar has only $stubs gRPC stub classes"
}

assert_generated_order() {
  local root="$1" label="$2"
  python3 - "$root/runtime/target/quarkus-app/quarkus/generated-bytecode.jar" "$label" <<'PY'
import pathlib, subprocess, sys, tempfile, zipfile

jar = pathlib.Path(sys.argv[1])
label = sys.argv[2]
with zipfile.ZipFile(jar) as archive:
    names = archive.namelist()
    grpc = [name for name in names if name.startswith(
        "io/quarkus/runner/recorded/GrpcServerProcessor$gatherGrpcInterceptors")
        and name.endswith(".class")]
    arc = [name for name in names if name.endswith("_Synthetic_Bean.class")
           and b"parameter 'em' of app.zcat.stargate.persistence.AuditLogService constructor" in archive.read(name)
           and b"parameter 'em' of app.zcat.stargate.persistence.SqliteTokenState constructor" in archive.read(name)]
    if len(grpc) != 1:
        raise SystemExit(f"{label}: expected one generated gRPC interceptor recorder, found {grpc}")
    if len(arc) != 1:
        raise SystemExit(f"{label}: expected one Arc inactive-bean class with both injection fragments, found {arc}")
    with tempfile.TemporaryDirectory(prefix="stargate-t217-bytecode-") as tmp:
        paths = []
        for name in (grpc[0], arc[0]):
            out = pathlib.Path(tmp) / pathlib.Path(name).name
            out.write_bytes(archive.read(name))
            paths.append(out)
        grpc_text = subprocess.check_output(["javap", "-c", "-p", str(paths[0])], text=True)
        arc_text = subprocess.check_output(["javap", "-c", "-p", str(paths[1])], text=True).replace("\\'", "'")

def ordered_positions(text, expected, description):
    positions = []
    for fragment in expected:
        matches = [i for i, line in enumerate(text.splitlines()) if fragment in line]
        if len(matches) != 1:
            raise SystemExit(f"{label}: {description} fragment {fragment!r} occurs {len(matches)} times")
        positions.append(matches[0])
    if positions != sorted(positions):
        raise SystemExit(f"{label}: {description} fragments are out of order: {positions}")

ordered_positions(grpc_text, [
    "io.quarkus.grpc.runtime.supports.context.GrpcDuplicatedContextGrpcInterceptor",
    "io.quarkus.grpc.runtime.supports.context.GrpcRequestContextGrpcInterceptor",
    "io.quarkus.grpc.runtime.supports.exc.ExceptionInterceptor",
], "gRPC global interceptor")
ordered_positions(arc_text, [
    "parameter 'em' of app.zcat.stargate.persistence.AuditLogService constructor",
    "parameter 'em' of app.zcat.stargate.persistence.SqliteTokenState constructor",
], "Arc inactive-bean message")
print(f"OK: T217 {label} generated gRPC and Arc message order")
PY
}

assert_transformed_input_order() {
  python3 - "$WORK/host" "$WORK/container" <<'PY'
import hashlib, pathlib, sys, zipfile

def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()

def inputs(checkout):
    cp = checkout / 'control-plane'
    transformed = cp / 'runtime/target/quarkus-app/quarkus/transformed-bytecode.jar'
    app_lib = cp / 'runtime/target/quarkus-app/lib/main'
    repository = checkout / '.m2'
    module_classes = [cp / module / 'target/classes' for module in
                      ('api', 'core', 'persistence', 'ui', 'runtime')]
    repo_by_hash = {}
    for path in repository.rglob('*.jar'):
        repo_by_hash.setdefault(digest(path), []).append(path)
    module_by_hash = {}
    for classes in module_classes:
        for path in classes.parent.glob('*.jar'):
            module_by_hash.setdefault(digest(path), []).append(classes.relative_to(checkout))
    packaged = []
    for path in app_lib.glob('*.jar'):
        matches = repo_by_hash.get(digest(path), [])
        if len(matches) == 1:
            packaged.append((path, matches[0].relative_to(checkout)))
            continue
        module_matches = module_by_hash.get(digest(path), [])
        if not matches and len(module_matches) == 1:
            # Reactor artifacts are transformed from their classes directory;
            # the corresponding module JAR is only the packaged lib/main copy.
            packaged.append((path, module_matches[0]))
            continue
        raise SystemExit(f'{checkout.name}: cannot map packaged dependency {path.name} to one Maven artifact or reactor module: {matches}, {module_matches}')
    origins = set()
    with zipfile.ZipFile(transformed) as archive:
        for name in archive.namelist():
            if not name.endswith('.class'):
                continue
            candidates = []
            for classes in module_classes:
                if (classes / name).is_file():
                    candidates.append(classes.relative_to(checkout))
            for jar, repo_path in packaged:
                if repo_path.as_posix().endswith('/target/classes'):
                    continue
                with zipfile.ZipFile(jar) as dependency:
                    if name in dependency.namelist():
                        candidates.append(repo_path)
            if len(candidates) != 1:
                raise SystemExit(f'{checkout.name}: transformed class {name} has {len(candidates)} resolved input origins: {candidates}')
            origins.add(candidates[0].as_posix())
    return sorted(origins)

host_root, container_root = (pathlib.Path(path).resolve() for path in sys.argv[1:])
host = inputs(host_root)
container = inputs(container_root)
if host_root.resolve() == container_root.resolve():
    raise SystemExit('cross-host source roots unexpectedly share an absolute path')
host_order = sorted(host, key=lambda path: str(host_root / path))
container_order = sorted(container, key=lambda path: str(container_root / path))
if host_order != container_order:
    raise SystemExit(f'absolute-path producer order differs:\nhost={host_order}\ncontainer={container_order}')
if set(host) != set(container):
    raise SystemExit(f'transformed input relative paths differ:\nhost={host}\ncontainer={container}')
repo_paths = [path for path in host if path.startswith('.m2/')]
class_paths = [path for path in host if path.startswith('control-plane/') and path.endswith('/target/classes')]
if not repo_paths or not class_paths or len(repo_paths) + len(class_paths) != len(host):
    raise SystemExit(f'transformed inputs are not fully classified as .m2 artifacts or module classes: {host}')
if host_order != sorted(repo_paths + class_paths):
    raise SystemExit(f'transformed inputs are not ordered as .m2 then module classes: {host_order}')
release_path = lambda path: path.removeprefix('control-plane/')
release_order = sorted(host, key=lambda path: str(pathlib.Path('/src') / release_path(path)))
if release_order != host_order:
    raise SystemExit(f'release Docker /src order differs from comparison order: {release_order} != {host_order}')
print('T217 transformed-input paths (absolute source/cache paths in sorted producer order):')
for path in host_order:
    print(f'  host:      {host_root / path}')
    print(f'  container: /workspace/container/{path}')
    print(f'  release:   /src/{release_path(path)}')
print(f'T217 path-order model: {len(repo_paths)} Maven artifacts precede {len(class_paths)} module class directories; /src projection matches')
PY
}

exclude_unshipped_metadata() {
  # Release Dockerfile copies only runtime/target/quarkus-app; repository-wide
  # inspection found no consumer of this target-root bookkeeping file.
  python3 - "$1" <<'PY'
import pathlib, sys

manifest = pathlib.Path(sys.argv[1])
relative = './runtime/target/quarkus-artifact.properties'
lines = manifest.read_text().splitlines()
matches = [line for line in lines if line.rsplit('  ', 1)[-1] == relative]
if len(matches) != 1:
    raise SystemExit(f'expected exactly one unshipped metadata entry in {manifest}, found {len(matches)}')
manifest.write_text('\n'.join(line for line in lines if line.rsplit('  ', 1)[-1] != relative) + '\n')
PY
}

validate_outputs "$WORK/host/control-plane" host
validate_outputs "$WORK/container/control-plane" container
assert_generated_order "$WORK/host/control-plane" host
assert_generated_order "$WORK/container/control-plane" container
assert_transformed_input_order
manifest "$WORK/host/control-plane" > "$WORK/host.sha256"
manifest "$WORK/container/control-plane" > "$WORK/container.sha256"
exclude_unshipped_metadata "$WORK/host.sha256"
exclude_unshipped_metadata "$WORK/container.sha256"
if [ ! -s "$WORK/host.sha256" ] || [ ! -s "$WORK/container.sha256" ]; then
  fail 'one build produced an empty artifact manifest'
fi
jar_metadata "$WORK/host/control-plane" > "$WORK/host.jar-metadata"
jar_metadata "$WORK/container/control-plane" > "$WORK/container.jar-metadata"
if ! compare_files "$WORK/host.jar-metadata" "$WORK/container.jar-metadata" "$WORK/metadata.diff"; then
  cat "$WORK/metadata.diff" >&2
  fail 'Created-By or Build-Jdk-Spec differs between builds'
fi
if ! compare_files "$WORK/host.sha256" "$WORK/container.sha256" "$WORK/artifacts.diff"; then
  printf 'T109 differing artifact paths and hashes:\n' >&2
  cat "$WORK/artifacts.diff" >&2
  fail 'host and container build artifacts differ'
fi

# Negative controls exercise the same comparison function without rebuilding
# or changing either source snapshot or produced artifact.
cp "$WORK/host.sha256" "$WORK/negative-artifact.sha256"
python3 - "$WORK/negative-artifact.sha256" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
lines = path.read_text().splitlines()
if not lines:
    raise SystemExit("empty artifact manifest in negative control")
first = lines[0]
lines[0] = ("0" if first[0] != "0" else "1") + first[1:]
path.write_text("\n".join(lines) + "\n")
PY
if compare_files "$WORK/host.sha256" "$WORK/negative-artifact.sha256" "$WORK/negative-artifact.diff"; then
  fail 'artifact-hash negative control did not detect a changed hash'
fi
for attribute in Created-By Build-Jdk-Spec; do
  cp "$WORK/host.jar-metadata" "$WORK/negative-metadata"
  python3 - "$WORK/negative-metadata" "$attribute" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
attribute = sys.argv[2]
text = path.read_text()
needle = attribute + "="
if needle not in text:
    raise SystemExit("metadata attribute absent from comparison output")
before, after = text.split(needle, 1)
value, separator, tail = after.partition("\t")
if not separator:
    value, separator, tail = after.partition("\n")
if not separator:
    raise SystemExit("metadata value boundary missing")
path.write_text(before + needle + "T109-negative-control" + separator + tail)
PY
  if compare_files "$WORK/host.jar-metadata" "$WORK/negative-metadata" "$WORK/negative-metadata.diff"; then
    fail "$attribute negative control did not detect a changed value"
  fi
done
printf 'OK: T109 negative controls reject changed artifact hashes and JAR metadata\n'

for output in \
  runtime/target/quarkus-app/quarkus/generated-bytecode.jar \
  runtime/target/quarkus-app/quarkus/transformed-bytecode.jar \
  runtime/target/quarkus-app/quarkus/quarkus-application.dat; do
  host_hash="$(sha256sum "$WORK/host/control-plane/$output" | awk '{print $1}')"
  container_hash="$(sha256sum "$WORK/container/control-plane/$output" | awk '{print $1}')"
  [ "$host_hash" = "$container_hash" ] || fail "repaired shipped output differs: $output"
  printf 'T217 shipped-output sha256 %s host=%s container=%s\n' \
    "$output" "$host_hash" "$container_hash"
done
printf 'T217 complete-manifest sha256 host=%s container=%s\n' \
  "$(sha256sum "$WORK/host.sha256" | awk '{print $1}')" \
  "$(sha256sum "$WORK/container.sha256" | awk '{print $1}')"

printf 'OK: T109 host/container JVM artifacts match (%s files; source=%s; %s)\n' \
  "$(wc -l < "$WORK/host.sha256" | tr -d ' ')" "$SOURCE_HASH" "$MAVEN_VERSION"
