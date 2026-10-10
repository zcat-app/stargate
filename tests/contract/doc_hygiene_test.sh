#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# Lock the exact stale prose patterns removed by T083 out of living docs.

set -euo pipefail

failed=0

# This list is the contract. Add an exact phrase only after a separately
# grounded documentation sweep removes it; keep its source and reason beside it.
STALE_PHRASES=(
  # T083 removed false future-work wording from living docs; preserve that cleanup.
  'once that file is authored'
  # T083 removed this stale follow-up framing; historical tickets remain exempt.
  'outstanding follow-up'
  # T083 removed this inaccurate owed-work wording; historical tickets remain exempt.
  'owed for both'
)

for phrase in "${STALE_PHRASES[@]}"; do
  if output=$(grep -rInF \
    --exclude-dir=tickets \
    --exclude-dir=.handoffs \
    -- "$phrase" specs docs 2>&1); then
    printf 'doc_hygiene_test: stale phrase found: %s\n%s\n' "$phrase" "$output" >&2
    failed=1
  else
    grep_status=$?
    case "$grep_status" in
      1)
        # grep uses status 1 only when the phrase was absent.
        ;;
      *)
        printf 'doc_hygiene_test: grep failed (status %s) for phrase: %s\n%s\n' \
          "$grep_status" "$phrase" "$output" >&2
        failed=1
        ;;
    esac
  fi
done

if [ "$failed" -ne 0 ]; then
  exit 1
fi

printf 'doc_hygiene_test: PASS (no curated stale phrases in living docs)\n'
