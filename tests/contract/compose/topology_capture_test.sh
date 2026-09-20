#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T163: keep the live recorder's decision rules in the deterministic gate.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 -B -m unittest discover -s tests/live-e2e/local-topology -p 'test_*.py' -v
python3 -B -c 'import ast, pathlib; ast.parse(pathlib.Path("tests/live-e2e/local-topology/run.py").read_text())'
