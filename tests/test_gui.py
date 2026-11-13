"""HTTP integration tests with synthetic records and fully mocked adb."""
import http.client
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

SKILL = Path(__file__).resolve().parents[1] / 'plugins/android-cleanup/skills/adware-cleanup'
sys.path.insert(0, str(SKILL / 'scripts'))
import gui


class GuiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / 'job'
        shutil.copytree(Path(__file__).parent / 'fixtures/gui', self.folder)
        self.phone_patch = patch.object(gui, 'Phone')
        self.Phone = self.phone_patch.start()
        self.addCleanup(self.phone_patch.stop)
        self.phone = self.Phone.return_value
        self.phone.last_returncode = 0
        self.phone.raw.return_value = b'List of devices attached\nSYNTHETIC device model:Test_Phone\nLOCKED unauthorized\nDOWN offline\n'
        self.server = gui.Viewer(self.folder)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, path='/', method='GET', auth=True, headers=None, body=None):
        h = {'Host': self.server.origin[7:]}
        if auth:
            h['X-Access-Token'] = self.server.token
        h.update(headers or {})
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        conn.request(method, path, body=body, headers=h)
        response = conn.getresponse()
        data, result = response.read(), (response.status, dict(response.getheaders()))
        conn.close()
        return result[0], result[1], data

    def test_token_cookie_host_and_no_cors(self):
        for path in ('/', '/api/state', '/style.css', '/api/session', '/files/report.pdf'):
            self.assertEqual(self.request(path, auth=False)[0], 401)
        self.assertEqual(self.request(headers={'Host': 'evil.example'})[0], 403)
        self.assertEqual(self.request(headers={'Host': 'localhost:'+str(self.server.server_port)})[0], 403)
        status, headers, _ = self.request('/?token='+self.server.token, auth=False)
        self.assertEqual(status, 200)
        self.assertIn('HttpOnly; SameSite=Strict', headers['Set-Cookie'])
        self.assertNotIn('Access-Control-Allow-Origin', headers)
        self.assertEqual(self.request('/api/state', auth=False, headers={'Cookie': headers['Set-Cookie'].split(';')[0]})[0], 200)
        self.assertEqual(self.server.server_address[0], '127.0.0.1')

    def test_allowlist_traversal_and_symlinks(self):
        (self.folder/'packages.txt').write_text('PRIVATE')
        (self.folder/'report.pdf').write_bytes(b'%PDF synthetic')
        (self.folder/'screens').mkdir()
        (self.folder/'screens'/'one.png').write_bytes(b'\x89PNG synthetic')
        for path in ('/files/packages.txt','/files/triage-before/packages.txt','/files/device.json','/files/actions.log','/files/job.json','/files/screens/no.txt','/files/../device.json','/files/%2e%2e/device.json','/files/screens%5c..%5cdevice.json','/unknown'):
            self.assertIn(self.request(path)[0], (403,404), path)
        self.assertEqual(self.request('/files/report.pdf')[0],200)
        self.assertEqual(self.request('/files/screens/one.png')[0],200)
        outside = Path(self.temp.name)/'outside.pdf'
        outside.write_bytes(b'PRIVATE')
        try:
            (self.folder/'link.pdf').symlink_to(outside)
        except (OSError, NotImplementedError):
            return  # Windows may lack symlink privileges.
        self.assertEqual(self.request('/files/link.pdf')[0],404)

    def test_state_formats_privacy_and_changes(self):
        status, _, body = self.request('/api/state')
        self.assertEqual(status,200)
        state = json.loads(body)
        self.assertIn('triage-before.json', state['mtimes'])
        self.assertEqual(state['phones'][0]['model'],'Test Phone')
        self.assertIn('tap Allow', state['phones'][1]['advice'])
        self.assertIn('cable carries data', state['phones'][2]['advice'])
        content = state['html']
        for expected in ('TEST-123','CHECKS SKIPPED','Install source', 'overstate', 'Calendar subscriptions','Notification sources','Removal log','Before / after'):
            self.assertIn(expected,content)
        self.assertLess(content.index('com.example.bad'),content.index('com.example.lower'))
        self.assertNotIn('<script>',content)
        self.assertNotIn('DO-NOT-EXPOSE',body.decode())
        self.assertNotIn('SYNTHETIC-SERIAL',content)
        (self.folder/'triage-after.json').write_text('{"website_shortcuts":["after.example"]}')
        after = json.loads(self.request('/api/state')[2])
        self.assertNotEqual(state['mtimes'],after['mtimes'])
        self.assertIn('after.example',after['html'])
        self.phone.raw.assert_called_with('devices','-l',timeout=5)

    def test_missing_malformed_and_wrong_types(self):
        for path in self.folder.glob('*'):
            path.unlink()
        (self.folder/'triage-before.json').write_text('{"suspects":[null,{}, {"score":"bad"}],"access":null,"site_channels":[null],"network_settings":[],"device":null}')
        (self.folder/'compare.json').write_text('{"metrics":{"bad":null}}')
        (self.folder/'job.json').write_text('partial')
        status, _, body = self.request('/api/state')
        self.assertEqual(status,200)
        self.assertNotIn('Calendar subscriptions',json.loads(body)['html'])
        self.assertEqual(gui.findings({},'Missing'),'')

    def test_screenshot_origin_selection_rate_and_readonly_adb(self):
        def post(data, headers=None, auth=True):
            return self.request('/api/screenshot', 'POST', auth=auth, body=json.dumps(data), headers=headers)[0]
        origin = {'Origin':self.server.origin}
        self.assertEqual(post({'serial':'SYNTHETIC'}),403)
        self.assertEqual(post({'serial':'SYNTHETIC'}, {'Origin':'http://evil.example'}),403)
        self.assertEqual(post({'serial':'SYNTHETIC'},origin,False),401)
        self.assertEqual(post({},origin),400)
        self.assertEqual(post({'serial':'LOCKED'},origin),400)
        self.assertEqual(post({'serial':'UNKNOWN'},origin),400)
        # The imported ui.screenshot calls only exec-out screencap; no shell or phone writes.
        self.phone.raw.side_effect = lambda *args, **kw: b'\x89PNG synthetic' if args[0]=='exec-out' else b'List of devices attached\nSYNTHETIC device model:Test_Phone\n'
        self.assertEqual(post({'serial':'SYNTHETIC'},origin),200)
        self.Phone.assert_called_with('SYNTHETIC')
        self.phone.raw.assert_called_with('exec-out','screencap','-p')
        self.assertEqual(len(list((self.folder/'screens').glob('*.png'))),1)
        self.assertEqual(post({'serial':'SYNTHETIC'},origin),429)
        self.phone.shell.assert_not_called()

    def test_adb_missing_degrades_without_device(self):
        self.Phone.side_effect = SystemExit('adb not found')
        state = json.loads(self.request('/api/state')[2])
        self.assertEqual(state['phones'],[])
        self.assertEqual(state['phone_error'],'adb not found')

    def test_post_requires_header_token_even_with_cookie(self):
        headers = {'Cookie': 'viewer_token='+self.server.token, 'Origin':self.server.origin}
        self.assertEqual(self.request('/api/screenshot', 'POST', False, headers, '{}')[0],403)
        self.assertEqual(self.request('/api/screenshot', 'POST', True, {'Origin':'null'}, '{}')[0],403)
        for method in ('OPTIONS', 'HEAD', 'PUT', 'DELETE', 'PATCH'):
            self.assertEqual(self.request(method=method,auth=False)[0],401)
            self.assertEqual(self.request(method=method)[0],405)

    def test_partial_writes_and_ignored_raw_fields(self):
        record = self.folder/'triage-before.json'
        record.write_text('{"device":{"summary":"PRIVATE"},"access_display":{"admins":"PRIVATE"},"packages":"PRIVATE","usage_events":"PRIVATE"}')
        self.assertNotIn('PRIVATE',self.request('/api/state')[2].decode())
        record.write_text('{"device":')
        self.assertEqual(self.request('/api/state')[0],200)
        record.write_text('{"skipped_checks":["Restored after write"]}')
        self.assertIn('Restored after write',self.request('/api/state')[2].decode())

    def test_capture_failure_and_bad_request_do_not_save(self):
        headers = {'Origin':self.server.origin}
        self.assertEqual(self.request('/api/screenshot','POST',headers=headers,body='invalid')[0],400)
        with patch.object(gui, 'screenshot', side_effect=SystemExit('screenshot failed')):
            self.assertEqual(self.request('/api/screenshot','POST',headers=headers,body='{"serial":"SYNTHETIC"}')[0],400)
        self.assertFalse(list((self.folder/'screens').glob('*.png')))
