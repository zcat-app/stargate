#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T204: spec-derived boundary and calibrated namespace observation regressions.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 -B -m unittest discover -s tests/live-e2e/local-topology -p test_cp_listener.py
cd control-plane
sh mvnw -B -q -pl ui -am -Dtest=HttpListenerBoundaryTest -Dsurefire.failIfNoSpecifiedTests=false test
