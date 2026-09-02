#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/reproducibility/extension_test.sh — T075b.
#
# Gates the byte-reproducibility claim for the browser extension zip
# (arch §12.3, Constitution Principle VI): two builds of the same source
# bytes must produce byte-identical extension/dist/stargate-extension.zip
# even when the source copies carry different mtimes and different file
# permissions — nothing about the build host may leak into the archive.
#
# Falsification case: source trees with identical bytes but deliberately
# different mtimes (tree A: 2024, tree B: 2031) and non-canonical modes
# (tree A: 0644, tree B: 0664). Comparing two copies that preserve the
# same mtimes would reconfirm package.sh instead of testing
# reproducibility, so the perturbation is the point of the test.
#
# T097 closed the known-fail gap: extension/package.sh stages sources at
# touch -d @0 + chmod 0644 before archiving, so upstream Info-ZIP 3.0's
# ignoring of SOURCE_DATE_EPOCH no longer leaks host mtimes/modes.
#
# Canonical archive properties asserted per build (arch §12.3):
#   - member set == the extension sources (package.sh's filter: everything
#     under extension/ except package.sh, dist/, and .keep placeholders)
#   - stored member order == LC_ALL=C lexicographic
#   - every member mtime == the SOURCE_DATE_EPOCH=0 canonical encoding
#     under zip -X: DOS (1980-01-01 00:00:00), no UT extra field — the
#     unique lossless-in-dos representation of the pinned epoch
#   - every member mode == 100644 (regular file; no host umask leakage)
#   - create_system == Unix; extra fields empty (zip -X: no
#     host-specific extended attributes)
#
# Release cadence: opt-in via STARGATE_VERIFY_REPRO=1 (scripts/verify.sh
# Gate 5). CI wiring for PRs touching extension/ is T076.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

SRC="extension"
ZIP_NAME="stargate-extension.zip"

command -v zip >/dev/null 2>&1 || { echo "SKIP: zip not available"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not available"; exit 0; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() {
  echo "FAIL: $1 (T075b)" >&2
  shift
  local line
  for line in "$@"; do echo "  $line" >&2; done
  exit 1
}

# --- two clean copies, perturbed differently -------------------------------
# If packaging is reproducible, none of this metadata reaches the archive.
# The trees stay byte-identical; only mtime + mode differ, and they differ
# per-file (offset by position) so no single unperturbed file could sneak
# through as a false confirmation.
cp -a "$SRC" "$WORK/a"
cp -a "$SRC" "$WORK/b"

perturb() {
  local dir="$1" base_epoch="$2" mode="$3" i=0 f
  base_epoch="$(date -d "$base_epoch" +%s)"
  while IFS= read -r f; do
    i=$((i + 1))
    touch -d "@$((base_epoch + i))" "$dir/$f"
    chmod "$mode" "$dir/$f"
  done < <(cd "$dir" && find . -type f | LC_ALL=C sort)
}
perturb "$WORK/a" "2024-03-01 00:00:00 UTC" 644
perturb "$WORK/b" "2031-11-05 00:00:00 UTC" 664

# --- package both trees -----------------------------------------------------
for tree in a b; do
  (cd "$WORK/$tree" && bash package.sh) > "$WORK/$tree.log" 2>&1 \
    || fail "package.sh failed in copy $tree" "$(tail -5 "$WORK/$tree.log")"
  [ -f "$WORK/$tree/dist/$ZIP_NAME" ] \
    || fail "copy $tree produced no dist/$ZIP_NAME" "$(tail -5 "$WORK/$tree.log")"
done

# --- expected member list (package.sh's own filter) -------------------------
expected_members() {
  (cd "$1" && find . \
    -type f \
    -not -path "./dist/*" \
    -not -name "package.sh" \
    -not -name ".keep" \
    | LC_ALL=C sort | sed 's|^\./||')
}
expected_members "$WORK/a" > "$WORK/expected-a.txt"
expected_members "$WORK/b" > "$WORK/expected-b.txt"
diff -u "$WORK/expected-a.txt" "$WORK/expected-b.txt" > /dev/null 2>&1 \
  || fail "the two source copies diverged in file content list — test harness bug"

# --- structural canonical-form checks per build ------------------------------
# Canonical form: SOURCE_DATE_EPOCH=0 + zip -X has exactly one valid
# encoding (see header). Anything else is host leakage even if bytes
# happen to match.
for tree in a b; do
  python3 - "$WORK/$tree/dist/$ZIP_NAME" "$WORK/expected-$tree.txt" <<'PYEOF' \
    || fail "copy $tree zip violates the canonical archive form"
import struct, sys, zipfile

zip_path, expected_path = sys.argv[1], sys.argv[2]
with open(expected_path, "rb") as fh:
    expected = fh.read().decode().splitlines()
problems = []
with zipfile.ZipFile(zip_path) as zf:
    infos = zf.infolist()
    names = [i.filename for i in infos]
    if names != expected:
        problems.append(f"member list/order: {names} != expected {expected}")
    for i in infos:
        if i.create_system != 3:
            problems.append(f"{i.filename}: create_system={i.create_system}, want Unix(3)")
        if i.extra != b"":
            problems.append(f"{i.filename}: extra fields present: {i.extra!r}")
        mode = i.external_attr >> 16
        if mode != 0o100644:
            problems.append(f"{i.filename}: mode={oct(mode)}, want 0o100644")
        if i.date_time != (1980, 1, 1, 0, 0, 0):
            problems.append(
                f"{i.filename}: mtime={i.date_time}, want the "
                "SOURCE_DATE_EPOCH=0 encoding (1980-01-01 00:00:00)"
            )
if problems:
    for p in problems:
        print(f"  {zip_path}: {p}", file=sys.stderr)
    sys.exit(1)
PYEOF
done

# --- the byte-identity gate --------------------------------------------------
if ! cmp -s "$WORK/a/dist/$ZIP_NAME" "$WORK/b/dist/$ZIP_NAME"; then
  size_a="$(stat --format=%s "$WORK/a/dist/$ZIP_NAME")"
  size_b="$(stat --format=%s "$WORK/b/dist/$ZIP_NAME")"
  ndiff="$(cmp -l "$WORK/a/dist/$ZIP_NAME" "$WORK/b/dist/$ZIP_NAME" 2>/dev/null | wc -l | tr -d ' ')"
  fail "two builds from identical source bytes produced different zips" \
    "copy a: $size_a bytes, copy b: $size_b bytes, $ndiff differing bytes" \
    "(source mtimes/modes differed on purpose; the archive must not care)"
fi

echo "OK: extension zip byte-reproducible across mtime/mode perturbation" \
  "($(wc -l < "$WORK/expected-a.txt" | tr -d ' ') members, canonical SOURCE_DATE_EPOCH=0 form)"
