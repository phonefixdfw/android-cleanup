"""Synthetic job records only: no adb or phone access."""
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

SKILL = Path(__file__).resolve().parents[1] / 'plugins/android-cleanup/skills/adware-cleanup'
sys.path.insert(0, str(SKILL / 'scripts'))
import job


class JobTests(unittest.TestCase):
    def test_compare(self):
        before = dict(site_channels=[['2026-01-01', 'spam.example'], ['2026-01-02', 'keep.example']],
                      suspects=[dict(package='bad.app', score=4, source='SIDELOADED (no installer)'),
                                dict(package='keep.app', score=3, source='Play Store')],
                      access={key: ['bad.app', 'keep.app'] for key in job.ACCESS},
                      network_settings=dict(proxy='proxy.example:80', dns_mode='hostname', active_vpn_apps=['bad.app']),
                      website_shortcuts=['spam.example'])
        after = dict(site_channels=[['2026-01-02', 'keep.example']],
                     suspects=[dict(package='keep.app', score=2, source='Play Store')],
                     access={key: ['keep.app'] for key in job.ACCESS},
                     network_settings=dict(proxy='null', active_vpn_apps=[]), website_shortcuts=[])
        result = job.compare(before, after)
        for key in job.ACCESS:
            self.assertEqual(result['metrics'][key]['removed'], ['bad.app'])
            self.assertEqual(result['metrics'][key]['remaining'], ['keep.app'])
        self.assertEqual(result['metrics']['site_channels']['after'], 1)
        self.assertEqual(result['metrics']['sideloaded']['after'], 0)
        self.assertEqual(result['metrics']['suspects']['before'], 2)
        self.assertEqual(result['metrics']['suspects']['after'], 0)
        self.assertEqual(result['network_settings']['proxy'], dict(before='proxy.example:80', after='null'))
        self.assertNotIn('dns_mode', result['network_settings'])
        self.assertEqual(result['network_settings']['active_vpn_apps']['removed'], ['bad.app'])
        self.assertEqual(result['metrics']['website_shortcuts']['removed'], ['spam.example'])

    def test_missing_and_skipped_are_not_zero_counts(self):
        self.assertEqual(job.compare({}, {}), dict(metrics={}, network_settings={}))
        data = dict(access={'device admin': []}, user_certificates=[],
                    skipped_checks=['device admin: unsupported', 'user CA certificates (user 0): permission denied'])
        self.assertEqual(job.compare(data, data)['metrics'], {})

    def test_cli_records_and_comparison_in_current_job_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            previous = Path.cwd()
            try:
                os.chdir(folder)
                with contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(job.main(['start', '--ticket', '123', '--tech', 'AB']), 0)
                    self.assertEqual(job.main(['start', '--ticket', '456']), 1)
                    self.assertEqual(json.loads(Path('job.json').read_text())['ticket'], '123')
                    for name, channels in [('before', [['2026-01-01', 'spam.example']]), ('after', [])]:
                        Path(name + '.json').write_text(json.dumps(dict(site_channels=channels)))
                    self.assertEqual(job.main(['compare', 'before.json', 'after.json']), 0)
                self.assertEqual(json.loads(Path('compare.json').read_text())['metrics']['site_channels']['removed'],
                                 [['2026-01-01', 'spam.example']])
                self.assertIn('1 -> 0', output.getvalue())
                self.assertIn('remaining:', output.getvalue())
            finally:
                os.chdir(previous)

    def test_optional_findings_order_and_missing_values(self):
        data = dict(user_certificates=['abc.0'], website_shortcuts=['site.example'],
                    calendar_subscriptions=[dict(account_type='subscription', display_name='Calendar', account_domain='example')],
                    notification_sources=[dict(package='com.example.app', count=2)],
                    site_channels=[['2026-01-01', 'site.example'], ['2026-01-01', 'site.example']],
                    access=None, network_settings=None)
        result = job.compare(data, data)
        for key in job.OPTIONAL:
            self.assertEqual(result['metrics'][key]['before'], 1)
            self.assertEqual(result['metrics'][key]['removed'], [])
            self.assertEqual(len(result['metrics'][key]['remaining']), 1)
        self.assertEqual(result['metrics']['site_channels']['before'], 2)
        self.assertEqual(len(result['metrics']['site_channels']['remaining']), 2)
