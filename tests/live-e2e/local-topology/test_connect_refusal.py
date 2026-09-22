# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

import unittest
from connect_refusal import validate_trace

CONTROL = 'stargate-proxy-42 [000] 1.0: t173_connect: path="/run/stargate-tor/tor-socks.sock" task="stargate-proxy"'

class TraceVerdictTests(unittest.TestCase):
    def test_real_control_and_no_refused_dial(self):
        validate_trace('', CONTROL, [0, 0], 0)

    def test_disconnected_or_wrong_endpoint_cannot_prove_refusal(self):
        for control in ('', CONTROL.replace('tor-socks.sock', 'control.sock')):
            with self.assertRaises(AssertionError):
                validate_trace('', control, [0], 0)

    def test_any_refused_dial_invalidates_result(self):
        with self.assertRaises(AssertionError):
            validate_trace(CONTROL, CONTROL, [0], 0)

    def test_lost_or_missing_trace_accounting_invalidates_result(self):
        for overruns, missed in (([], 0), ([1], 0), ([0], 1)):
            with self.assertRaises(AssertionError):
                validate_trace('', CONTROL, overruns, missed)

    def test_failed_path_fetch_invalidates_result(self):
        with self.assertRaises(AssertionError):
            validate_trace(CONTROL.replace('/run/stargate-tor/tor-socks.sock', '(fault)'), CONTROL, [0], 0)
