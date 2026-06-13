#!/usr/bin/env bash
# Copyright The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# Point this repo's git at the version-controlled hooks in .githooks/.
# Run once per clone (git's core.hooksPath is local config, not cloned).
# Idempotent.

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
git -C "$repo_root" config core.hooksPath .githooks
chmod +x "$repo_root/.githooks/"* 2>/dev/null || true

echo "✓ core.hooksPath set to .githooks (pre-commit secret scan active)."
if ! command -v gitleaks >/dev/null 2>&1; then
  echo "  note: gitleaks not found — the hook will use its built-in fallback scan."
  echo "        install gitleaks for stronger coverage (https://github.com/gitleaks/gitleaks)."
fi
