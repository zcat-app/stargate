#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# scripts/check-license-headers.sh — verify the Apache 2.0 SPDX header on
# every tracked source file whose extension is in scope for this feature.
#
# Why SPDX rather than the full Apache boilerplate (Principle VI / Open and
# Auditable): the SPDX identifier is a single language-agnostic marker that
# is REUSE-spec compliant and recognised by every license scanner. The
# canonical license text lives at the repo root (LICENSE); per-file SPDX
# is the licensing claim. See licenses/APACHE-2.0-HEADER.txt for the
# template contributors copy into new files.
#
# Why pattern-match the SPDX line rather than parse each comment syntax:
# the literal "SPDX-License-Identifier: Apache-2.0" is identical across
# //, #, --, and <!-- --> comment styles, so one check covers .go, .sh,
# .sql, Dockerfile, .proto, etc. without per-language branches.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

SPDX_MARKER='SPDX-License-Identifier: Apache-2.0'
HEAD_LINES=15

# Tracked files matching the extensions T006 enumerates. Dockerfile is
# matched in three forms to cover bare, suffixed, and prefixed naming.
mapfile -t candidates < <(
  git ls-files -- \
    '*.go' '*.java' '*.js' '*.proto' '*.sh' '*.sql' \
    'Dockerfile' 'Dockerfile.*' '*.Dockerfile' \
  | grep -Ev '^(\.specify/|licenses/)' \
  || true
)

missing=()
for f in "${candidates[@]}"; do
  [[ -f "$f" ]] || continue
  if ! head -n "$HEAD_LINES" -- "$f" | grep -qF "$SPDX_MARKER"; then
    missing+=("$f")
  fi
done

if ((${#missing[@]})); then
  printf 'Missing Apache 2.0 SPDX header in %d file(s):\n' "${#missing[@]}" >&2
  printf '  %s\n' "${missing[@]}" >&2
  printf '\nExpected marker in first %d lines: %s\n' "$HEAD_LINES" "$SPDX_MARKER" >&2
  printf 'Template: licenses/APACHE-2.0-HEADER.txt\n' >&2
  exit 1
fi

printf 'OK: %d in-scope file(s) carry the Apache 2.0 SPDX header.\n' "${#candidates[@]}"
