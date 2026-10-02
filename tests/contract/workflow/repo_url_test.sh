#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# T191 item 12 (redteam A3-M6): every documented clone/source URL for this
# project names the real owner. quickstart.md cloned github.com/zcatapp/stargate,
# which returns 404 and could be registered by anyone; a reader following it
# would build attacker-supplied source. The canonical origin is
# github.com/zcat-app/stargate. Scope: every tracked *.md and *.html file
# except the append-only review records (reviews/, redteam/), which quote the
# defect as evidence and are never rewritten.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

OWNER=zcat-app

# check_tree <file>...: print each github.com/<owner>/stargate reference whose
# owner is not $OWNER, as path:line:url.
check_tree() {
  grep -HnoE 'github\.com/[A-Za-z0-9_.-]+/stargate([^A-Za-z0-9_-]|$)' "$@" 2>/dev/null \
    | grep -vE ":github\.com/${OWNER}/stargate([^A-Za-z0-9_-]|$)"
}

mapfile -t docs < <(git ls-files -- '*.md' '*.html' ':(exclude)reviews/**' ':(exclude)redteam/**')
[ "${#docs[@]}" -gt 0 ] || { echo "FAIL: no tracked *.md/*.html files found" >&2; exit 1; }

# Negative control: the lint must flag a wrong owner (the original defect) and
# accept the canonical one, so a pattern that matches nothing cannot pass.
fixture="$(mktemp)" || exit 1
trap 'rm -f "$fixture"' EXIT
printf '%s\n' 'git clone https://github.com/zcatapp/stargate.git' \
  'see https://github.com/zcat-app/stargate/issues' > "$fixture"
flagged="$(check_tree "$fixture")"
case "$flagged" in
  *zcatapp/stargate*) : ;;
  *) echo "FAIL: lint did not flag the wrong-owner fixture" >&2; exit 1 ;;
esac
if grep -q 'zcat-app' <<< "$flagged"; then
  echo "FAIL: lint flagged the canonical owner" >&2
  exit 1
fi

bad="$(check_tree "${docs[@]}")"
if [ -n "$bad" ]; then
  echo "FAIL: repository URLs must use owner $OWNER:" >&2
  printf '  %s\n' "$bad" >&2
  exit 1
fi
echo "OK: every github.com/<owner>/stargate URL in ${#docs[@]} tracked *.md/*.html files uses $OWNER"
