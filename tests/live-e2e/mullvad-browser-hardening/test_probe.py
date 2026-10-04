# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
"""Reject false migration/restart evidence, independently of browser mocks."""
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('probe', pathlib.Path(__file__).with_name('probe.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class HardeningEvidenceTest(unittest.TestCase):
    def test_migration_requires_seed_and_preserved_unrelated_state(self):
        unrelated = {'device': {'bearerToken': 'synthetic'}, 'routes': {'default': 'DIRECT'},
                     'isolationProfileId': 'synthetic-profile', 'other': 'sentinel'}
        seeded = {**unrelated, 'hardening': {'lastAuditedAt': 497000, 'readError': 'marker'}}
        self.assertTrue(probe.t205_migration_closed(seeded, unrelated))
        for false_after in [{}, {'hardening': {}}, {**unrelated, 'hardening': None},
                            {**unrelated, 'device': {}}, {**unrelated, 'newHistory': 'marker'}]:
            self.assertFalse(probe.t205_migration_closed(seeded, false_after))
        self.assertFalse(probe.t205_migration_closed(unrelated, unrelated))
        self.assertFalse(probe.t205_migration_closed({'hardening': {}}, {}))

    def test_restart_requires_distinct_process_and_same_retained_profile(self):
        first = {'moz:processID': 101, 'moz:profile': '/disposable/profile'}
        second = {'moz:processID': 102, 'moz:profile': '/disposable/profile'}
        self.assertTrue(probe.t205_same_profile_restart(first, second, True))
        self.assertFalse(probe.t205_same_profile_restart(first, second, False))
        self.assertFalse(probe.t205_same_profile_restart(first, first, True))
        self.assertFalse(probe.t205_same_profile_restart(first, {**second, 'moz:profile': '/fresh'}, True))

    def test_status_requires_known_enum_and_matching_gate(self):
        for state in ['disabled', 'enabled', 'unknown']:
            self.assertTrue(probe.t205_status_matches({'status': state, 'hardeningOk': state == 'disabled'}, state))
        self.assertFalse(probe.t205_status_matches({'status': 'disabled', 'hardeningOk': False}, 'disabled'))
        self.assertFalse(probe.t205_status_matches({'status': 'raw error', 'hardeningOk': False}, 'unknown'))
        self.assertFalse(probe.t205_status_matches({}, 'unknown'))


if __name__ == '__main__':
    unittest.main()
