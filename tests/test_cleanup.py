"""Device-free tests: never construct a real Phone or execute adb."""
import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / 'plugins/android-cleanup/skills/adware-cleanup'
sys.path.insert(0, str(SKILL / 'scripts'))
sys.path.insert(0, str(SKILL / 'report'))
import adbtools
import triage
import usage_events
import ui
import make_report

FIXTURES = Path(__file__).parent / 'fixtures'
TODAY = dt.date(2026, 11, 13)


class FakePhone:
    def __init__(self, case):
        self.case = FIXTURES / case
        self.calls = []

    def require_connected(self):
        pass

    def shell(self, command, timeout=60):
        name = next(k for k, v in triage.COMMANDS.items() if v == command)
        self.calls.append((name, timeout))
        return (self.case / (name + '.txt')).read_text(encoding='utf-8')


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.raw = triage.collect(FakePhone('galaxy'))

    def test_install_sources(self):
        for source, label in (('com.android.vending', 'Play Store'),
                              ('com.sec.android.app.samsungapps', 'Galaxy Store'),
                              ('com.sec.android.easyMover', 'Smart Switch transfer'),
                              ('com.att.preload', 'carrier preload')):
            self.assertEqual(triage.install_source(source), (label, False))
        for source in (None, '', 'null', 'com.example.files'):
            self.assertTrue(triage.install_source(source)[1])

    def test_channels_and_extreme_timestamps(self):
        self.assertEqual(triage.site_channels(self.raw['notif']), [('2026-11-13', 'offers.example')])
        self.assertEqual(triage.site_channels("mId='web:https://a.example;garbage'"), [])

    def test_usage_merges_latest_and_maximum(self):
        used = triage.app_usage(self.raw['usage'])
        self.assertEqual(used['com.example.boost'], ('2026-11-13 11:00:00', 5))
        self.assertEqual(triage.app_usage('package=com.example.app totalTimeUsed="0" lastTimeUsed="1970-01-01" appLaunchCount=?')['com.example.app'], ('', 0))

    def test_events_deduplicate_filter_and_close_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'usage.txt'
            path.write_text(self.raw['usage'], encoding='utf-8')
            events = usage_events.events(path, [str(TODAY)])
            self.assertEqual(len(events), 4)
            selected = usage_events.interesting(events)
            self.assertEqual(len(selected), 3)
            self.assertEqual(selected[-1][2], 'com.android.chrome')
            self.assertEqual(usage_events.events(path, ['2000-01-01']), [])
            path.unlink()  # also verifies the reader releases the file on Windows

    def test_suspect_score(self):
        result = triage.analyze(self.raw, TODAY)
        suspect = result['suspects'][0]
        # sideload 4, overlay 1, admin 3, accessibility 3, hidden 2,
        # recent install 1, utility name 1, install appop 1, install permission 1
        self.assertEqual((suspect['package'], suspect['score']), ('com.example.boost', 17))
        self.assertEqual(result['device']['android_version'], '14')
        self.assertEqual(result['browsers'], [{'name': 'Chrome', 'package': 'com.android.chrome'}])
        self.assertEqual(result['skipped_checks'], [])
        json.dumps(result)

    def test_unknown_install_date_sorts_last_and_still_flags_sideload(self):
        listing = self.raw['third-party'] + 'package:com.example.unknown installer=null\n'
        rows = triage.packages_newest_first(self.raw['packages'], listing)
        self.assertEqual(rows[-1][3], 'com.example.unknown')
        scores = triage.suspect_apps(self.raw['packages'], listing, '', TODAY, {}, set())
        self.assertTrue(next(r for r in scores if r[1] == 'com.example.unknown')[2].startswith('SIDELOADED'))

    def test_empty_and_malformed_core_dumps_fail(self):
        with self.assertRaisesRegex(ValueError, 'phone disconnected or adb failed, re-run'):
            triage.analyze(triage.collect(FakePhone('disconnected')), TODAY)
        for name in ('packages', 'third-party', 'usage', 'notif'):
            for value in ('', 'Error: service unavailable', 'unrecognized garbage'):
                raw = dict(self.raw, **{name: value})
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    triage.analyze(raw, TODAY)

    def test_unsupported_checks_are_skipped_and_not_scored(self):
        result = triage.analyze(triage.collect(FakePhone('older')), TODAY)
        self.assertEqual(len(result['skipped_checks']), 6)
        self.assertEqual(result['access']['draws over other apps'], [])
        self.assertNotIn('no app icon', ' '.join(result['suspects'][0]['reasons']))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            triage.print_summary(result, Path('triage'))
        self.assertNotIn('Unknown command', output.getvalue())
        self.assertNotIn("Can't find service", output.getvalue())
        self.assertIn('== CHECKS SKIPPED', output.getvalue())
        for skipped in result['skipped_checks']:
            self.assertIn(skipped, output.getvalue())

    def test_usage_help_is_skipped_even_with_success_exit(self):
        for name, help_text in (("overlays", "AppOps service (appops) commands:"),
                                ("home_role", "Role manager (role) commands:"),
                                ("browsing", "Package manager (package) commands:")):
            raw = dict(self.raw, **{name: help_text})
            result = triage.analyze(raw, TODAY)
            self.assertTrue(any(s.startswith(triage.CHECKS[name] + ':') for s in result['skipped_checks']))

    def test_collect_timeouts_and_notification_redaction(self):
        phone = FakePhone('galaxy')
        triage.collect(phone)
        self.assertEqual(dict(phone.calls)['usage'], 180)
        self.assertEqual(dict(phone.calls)['packages'], 180)
        self.assertEqual(triage.COMMANDS['notif'], 'dumpsys notification')

    def test_report_html_escapes_customer_text(self):
        html = make_report.build_html({'title': '<script>bad</script>',
            'info': [['Customer', '']], 'findings': [['Browser', '**spam**', '`blocked`']],
            'checked': [['Overlay', 'clear & verified']]}, {'name': 'Synthetic Shop & Co'})
        self.assertIn('&lt;script&gt;bad&lt;/script&gt;', html)
        self.assertIn('Synthetic Shop &amp; Co', html)
        self.assertIn('<strong>spam</strong>', html)
        self.assertIn('clear &amp; verified', html)
        self.assertIn('class=blank', html)


class CommandTests(unittest.TestCase):
    def phone(self):
        # Bypass discovery entirely: subprocess.run is mocked in every test.
        phone = object.__new__(adbtools.Phone)
        phone.adb, phone.serial = 'fake-adb', 'synthetic'
        return phone

    def test_timeout_exits_plainly(self):
        with patch('adbtools.subprocess.run', side_effect=subprocess.TimeoutExpired('fake-adb', 60)) as run:
            with self.assertRaisesRegex(SystemExit, 'timed out after 60s'):
                self.phone().raw('get-state')
            self.assertEqual(run.call_args.kwargs['timeout'], 60)

    def test_nonzero_without_stderr_warns(self):
        result = subprocess.CompletedProcess([], 1, b'', b'')
        output = io.StringIO()
        with patch('adbtools.subprocess.run', return_value=result), contextlib.redirect_stderr(output):
            text = self.phone().shell('fake-command', timeout=180)
        self.assertIn('exit 1', output.getvalue())
        self.assertIn('adb command failed', text)

    def test_stderr_only_unsupported_is_available_to_analysis(self):
        result = subprocess.CompletedProcess([], 1, b'', b'Unknown command: query-op')
        with patch('adbtools.subprocess.run', return_value=result), contextlib.redirect_stderr(io.StringIO()):
            text = self.phone().shell('fake-command')
        self.assertTrue(triage.ERROR.search(text))

    def test_around_requires_date_before_reading_file(self):
        with patch.object(sys, 'argv', ['usage_events.py', 'missing', '--around', '12:00']), contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(SystemExit):
                usage_events.main()
        self.assertIn('--around requires --date', err.getvalue())

    def test_invalid_regex_before_connecting(self):
        with patch.object(sys, 'argv', ['ui.py', 'find', '[']), patch('ui.Phone') as phone, contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(SystemExit):
                ui.main()
        phone.assert_not_called()
        self.assertIn('invalid search pattern', err.getvalue())

    def test_disconnected_cli_does_not_print_clean_summary_or_write_files(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'triage'
            summary = Path(folder) / 'summary.json'
            with patch.object(sys, 'argv', ['triage.py', str(out), '--json', str(summary)]), patch('triage.Phone', return_value=FakePhone('disconnected')), contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaisesRegex(SystemExit, 'phone disconnected or adb failed, re-run'):
                    triage.main()
            self.assertEqual(output.getvalue(), '')
            self.assertFalse(summary.exists())
            self.assertFalse(out.exists())

    def test_json_cli_summary(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'triage'
            summary = Path(folder) / 'summary.json'
            with patch.object(sys, 'argv', ['triage.py', str(out), '--json', str(summary)]), patch('triage.Phone', return_value=FakePhone('galaxy')), contextlib.redirect_stdout(io.StringIO()):
                triage.main()
            result = json.loads(summary.read_text(encoding='utf-8'))
            self.assertEqual(result['device']['model'], 'Galaxy Synthetic')
            self.assertEqual(result['site_channels'], [['2026-11-13', 'offers.example']])
            self.assertEqual(len(list(out.glob('*.txt'))), 4)


if __name__ == '__main__':
    unittest.main()
