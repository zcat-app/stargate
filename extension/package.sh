#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# extension/package.sh — produce a deterministic, byte-reproducible zip
# of the Mullvad Browser MV2 extension per arch §12.3 / Principle VI.
#
# Two invocations of this script over the same source tree MUST yield
# the same zip bytes regardless of build host, build directory, build
# time, file system inode order, locale, or umask. The mechanisms:
#
#   SOURCE_DATE_EPOCH=0   fixed timestamp (1970-01-01 UTC) for every
#                         archive member. Info-ZIP zip >= 3.0 honors
#                         this env var (reproducible-builds.org).
#   LC_ALL=C sort         locale-independent lexicographic ordering of
#                         the file list so inode order / locale never
#                         affects archive-member order.
#   zip -X                strip extra file attributes (uid/gid, atime,
#                         ctime, file-system-specific metadata).
#   zip -9                fixed maximum compression level; same input
#                         + same level = same compressed bytes.
#
# Output: extension/dist/stargate-extension.zip
#
# Inputs included in the zip: everything under extension/ except this
# script, the dist/ output directory, and `.keep` placeholders (which
# are git-tracking artefacts, not extension content).
#
# Exit non-zero on any error; verified by the extension-side
# reproducibility test that lands with the rest of US3.

set -euo pipefail

# Run from the extension/ directory so archive members are stored with
# clean relative paths (no "./extension/..." prefix).
cd "$(dirname "$0")"

OUT_DIR="dist"
OUT_FILE="$OUT_DIR/stargate-extension.zip"

mkdir -p "$OUT_DIR"
rm -f "$OUT_FILE"

# Reproducibility env vars (exported so any child zip invocations also
# honor them).
export SOURCE_DATE_EPOCH=0
export TZ=UTC

# Collect every file under extension/ except the dist/ tree, this
# script itself, and `.keep` placeholders, in locale-independent
# lexicographic order. `mapfile` + null-terminated would be safer
# against pathological filenames, but extension/ paths are controlled
# (ASCII-only, no whitespace) so plain newline-separation is fine.
mapfile -t FILES < <(
  find . \
    -type f \
    -not -path "./$OUT_DIR/*" \
    -not -name "package.sh" \
    -not -name ".keep" \
    | LC_ALL=C sort
)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "package.sh: no files to package under extension/" >&2
  exit 1
fi

# Strip extra file attributes (-X), max + deterministic compression
# (-9), quiet (-q). Archive members are added in the order given,
# which is our pre-sorted list — so on-disk order in the zip matches
# lexicographic order.
zip -X -q -9 "$OUT_FILE" "${FILES[@]}"

echo "package.sh: wrote $OUT_FILE ($(stat --format='%s bytes, %y' "$OUT_FILE"))"
