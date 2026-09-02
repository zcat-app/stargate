#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# extension/package.sh — produce a deterministic, byte-reproducible zip
# of the Mullvad Browser MV2 extension per arch §12.3 / Principle VI.
#
# Two invocations of this script over the same source tree MUST yield
# the same zip bytes regardless of build host, build directory, build
# time, source mtimes/modes, file system inode order, locale, or umask.
#
# Why staging: upstream Info-ZIP 3.0 ignores SOURCE_DATE_EPOCH for
# stored member timestamps and stores each file's on-disk mode verbatim
# (T075b) — both leak the build host into the archive. So instead of
# trusting the archiver, sources are copied into a throwaway staging
# tree and normalized there:
#
#   touch -d @0               every staged member gets the canonical
#                             timestamp; zip encodes epoch 0 as DOS
#                             1980-01-01 00:00:00 (the unique
#                             lossless-in-DOS epoch-0 encoding)
#   chmod 0644                every member mode is normalized; no host
#                             umask or working-tree mode bit reaches
#                             external_attr
#   LC_ALL=C sort             locale-independent lexicographic ordering
#                             of the member list so inode order / locale
#                             never affects archive-member order
#   zip -X                    strip extra fields (uid/gid, UT atime/
#                             ctime, host-specific extended attributes)
#   zip -9                    fixed maximum compression level
#
# SOURCE_DATE_EPOCH stays exported for zip builds that do honor it; it
# converges on the same canonical encoding, so the output is identical
# either way.
#
# Output: extension/dist/stargate-extension.zip
#
# Inputs included in the zip: everything under extension/ except this
# script, the dist/ output directory, and `.keep` placeholders (which
# are git-tracking artefacts, not extension content).
#
# Exit non-zero on any error; gated byte-for-byte by
# tests/reproducibility/extension_test.sh (Principle VI).

set -euo pipefail

# Run from the extension/ directory so archive members are stored with
# clean relative paths (no "./extension/..." prefix).
cd "$(dirname "$0")"

OUT_DIR="dist"
OUT_FILE="$PWD/$OUT_DIR/stargate-extension.zip"

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

# Normalize timestamp + mode in a staging copy rather than in the
# working tree: packaging must not mutate the sources it archives.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

for f in "${FILES[@]}"; do
  rel="${f#./}"
  mkdir -p "$STAGE/$(dirname "$rel")"
  cp "$f" "$STAGE/$rel"
  touch -d @0 "$STAGE/$rel"
  chmod 0644 "$STAGE/$rel"
done

# Archive members are added in the order given, which is our pre-sorted
# list — so on-disk order in the zip matches lexicographic order.
( cd "$STAGE" && zip -X -q -9 "$OUT_FILE" "${FILES[@]#./}" )

echo "package.sh: wrote $OUT_FILE ($(stat --format='%s bytes' "$OUT_FILE"))"
