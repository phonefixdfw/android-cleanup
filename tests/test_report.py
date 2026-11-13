"""Build HTML from synthetic job files; no browser or device required."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

SKILL = Path(__file__).resolve().parents[1] / 'plugins/android-cleanup/skills/adware-cleanup'
sys.path.insert(0, str(SKILL / 'report'))
import make_report


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.write('triage-before.json', dict(device=dict(model='Synthetic Phone', android_version='14', serial='SECRET')))
        self.write('job.json', dict(ticket='123'))
        self.write('compare.json', dict(metrics=dict(sites=dict(label='Site-notification channels', before=7, after=0))))
        rows = [dict(package='com.example.' + action, action=action, result=result)
                for action, result in [('uninstall', 'success: Success'), ('disable', 'success: disabled-user'),
                                       ('backup', 'success'), ('restore', 'success'), ('dryrun', 'dry-run'),
                                       ('failed', 'failed: denied')]]
        rows += [dict(package='com.example.label', action='uninstall', result='success', label='Verified App', label_verified=True),
                 dict(package='com.example.unknown', action='uninstall', result='success', label='Unverified'),
                 dict(package='com.example.verify', action='uninstall', result='success'),
                 dict(package='com.example.verify', action='verify', result='failed')]
        (self.folder / 'actions.log').write_text('\n'.join(json.dumps(r) for r in rows) + '\nnot json\n', encoding='utf-8')

    def write(self, name, data):
        (self.folder / name).write_text(json.dumps(data), encoding='utf-8')

    def test_prefill_and_optional_shop_fields(self):
        html = make_report.build_html({}, dict(name='Shop', warranty='30 days & terms', reviewUrl='https://shop.example/review'), job=self.folder)
        for text in ('Synthetic Phone', '>14<', 'Ticket', '>123<', 'com.example.uninstall', 'Disabled for user 0',
                     'Verified App', 'class="mono">com.example.unknown', 'Before / after', '7 -&gt; 0',
                     '30 days &amp; terms', 'https://shop.example/review'):
            self.assertIn(text, html)
        for text in ('SECRET', 'Unverified', 'com.example.verify', 'com.example.backup', 'com.example.failed', 'com.example.restore'):
            self.assertNotIn(text, html)

    def test_explicit_fields_override_individually(self):
        data = dict(info=[['Device', 'Manual phone'], ['Ticket', '456']], removed=[], beforeAfter=[])
        html = make_report.build_html(data, {}, job=self.folder)
        self.assertIn('Manual phone', html)
        self.assertIn('>456<', html)
        self.assertIn('>14<', html)
        for text in ('Synthetic Phone', 'Apps removed', 'Before / after'):
            self.assertNotIn(text, html)
        self.assertEqual(data['info'], [['Device', 'Manual phone'], ['Ticket', '456']])
        self.assertNotIn('class="info"', make_report.build_html(dict(info=[]), {}, job=self.folder))

    def test_missing_files_and_legacy_no_job(self):
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(make_report.build_html({}, {}, job=empty), make_report.build_html({}, {}))
        (self.folder / 'job.json').unlink()
        self.assertNotIn('>Ticket<', make_report.build_html({}, {}, job=self.folder))

    def test_later_enable_undoes_disabled_row(self):
        with (self.folder / 'actions.log').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(dict(package='com.example.disable', action='enable', result='success')) + '\n')
        self.assertNotIn('Disabled for user 0', make_report.build_html({}, {}, job=self.folder))

    def test_partial_or_invalid_optional_records_degrade_gracefully(self):
        self.write('triage-before.json', dict(device=None))
        self.write('compare.json', dict(metrics=None, network_settings=None))
        (self.folder / 'job.json').write_text('incomplete json', encoding='utf-8')
        html = make_report.build_html(dict(removed=[['Explicit app', 'Tech verified']]), {}, job=self.folder)
        self.assertIn('Explicit app', html)
        self.assertNotIn('com.example.uninstall', html)
        self.assertNotIn('Before / after', html)
