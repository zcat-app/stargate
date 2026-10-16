# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
"""Reject false migration/restart evidence, independently of browser mocks."""
import contextlib
import importlib.util
import json
import io
import pathlib
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

spec = importlib.util.spec_from_file_location('probe', pathlib.Path(__file__).with_name('probe.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class EffectBoundaryReached(Exception):
    """The first executable/version-check effect was reached without launch."""


class HardeningEvidenceTest(unittest.TestCase):
    def test_main_rejects_unhardened_template_before_first_effect(self):
        root = pathlib.Path(__file__).resolve().parents[3]
        browser = pathlib.Path(sys.executable)
        driver = pathlib.Path(sys.executable)
        self.assertTrue(browser.is_file())
        self.assertTrue(driver.is_file())
        base = {
            'network.trr.mode': 5,
            'network.http.http3.enable': False,
            'media.peerconnection.enabled': False,
        }
        invalid = (
            ({key: value for key, value in base.items()
              if key != 'network.trr.mode'}, 'network.trr.mode'),
            ({**base, 'network.trr.mode': 3}, 'network.trr.mode'),
            ({**base, 'network.trr.mode': 5.0}, 'network.trr.mode'),
            ({**base, 'network.trr.mode': '5'}, 'network.trr.mode'),
            ({**base, 'network.trr.mode': True}, 'network.trr.mode'),
            ({key: value for key, value in base.items()
              if key != 'network.http.http3.enable'}, 'network.http.http3.enable'),
            ({**base, 'network.http.http3.enable': True}, 'network.http.http3.enable'),
        )
        old_argv = sys.argv
        old_prefs = dict(probe.SHIPPED_TEMPLATE_PREFS)
        try:
            with tempfile.TemporaryDirectory() as temporary:
                temporary_path = pathlib.Path(temporary)
                extension = temporary_path / 'synthetic-extension.zip'
                manifest = {
                    'manifest_version': 2,
                    'name': 'T200 bounded preflight fixture',
                    'version': '1.0',
                }
                with zipfile.ZipFile(extension, 'w', compression=zipfile.ZIP_STORED) as package:
                    package.writestr('manifest.json', json.dumps(manifest))
                self.assertLess(extension.stat().st_size, 4096)
                template = temporary_path / 'user.js'
                for prefs, named_pref in invalid:
                    with self.subTest(pref=named_pref, prefs=prefs):
                        template.write_text(''.join(
                            f'user_pref({key!r}, {value!r});\n'
                            for key, value in prefs.items()
                        ).replace("'", '"').replace('True', 'true').replace('False', 'false'))
                        sys.argv = [
                            str(root / 'tests/live-e2e/mullvad-browser-hardening/probe.py'),
                            '--browser', str(browser), '--driver', str(driver),
                            '--extension', str(extension), '--profile-template', str(template),
                        ]
                        probe.SHIPPED_TEMPLATE_PREFS.clear()
                        reached = False

                        def stop_at_first_effect(*_args, **_kwargs):
                            nonlocal reached
                            reached = True
                            raise EffectBoundaryReached()

                        stderr = io.StringIO()
                        with mock.patch.object(probe.subprocess, 'check_output',
                                               side_effect=stop_at_first_effect):
                            with contextlib.redirect_stderr(stderr):
                                with self.assertRaises(SystemExit) as raised:
                                    probe.main()
                        self.assertEqual(raised.exception.code, 2)
                        self.assertFalse(reached, 'invalid template reached executable checks')
                        self.assertIn(named_pref, stderr.getvalue())

                with self.subTest(pref='complete-template-reaches-controlled-boundary'):
                    template.write_text(
                        'user_pref("network.trr.mode", 5);\n'
                        'user_pref("network.http.http3.enable", false);\n'
                        'user_pref("media.peerconnection.enabled", false);\n'
                    )
                    sys.argv = [
                        str(root / 'tests/live-e2e/mullvad-browser-hardening/probe.py'),
                        '--browser', str(browser), '--driver', str(driver),
                        '--extension', str(extension), '--profile-template', str(template),
                    ]
                    probe.SHIPPED_TEMPLATE_PREFS.clear()
                    reached = False

                    def stop_at_first_effect(*_args, **_kwargs):
                        nonlocal reached
                        reached = True
                        raise EffectBoundaryReached()

                    with mock.patch.object(probe.subprocess, 'check_output',
                                           side_effect=stop_at_first_effect):
                        with self.assertRaises(EffectBoundaryReached):
                            probe.main()
                    self.assertTrue(reached, 'complete template did not reach the controlled boundary')
        finally:
            sys.argv = old_argv
            probe.SHIPPED_TEMPLATE_PREFS.clear()
            probe.SHIPPED_TEMPLATE_PREFS.update(old_prefs)

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
