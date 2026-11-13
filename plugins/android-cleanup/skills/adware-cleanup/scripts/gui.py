"""Loopback-only job viewer: python gui.py --job JOB_FOLDER [--port N]."""
import argparse
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
from pathlib import Path
import secrets
import sys
import threading
import time
from urllib.parse import parse_qs, unquote, urlsplit, quote
import webbrowser

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adbtools import Phone
from ui import screenshot

RECORDS = ('triage-before.json', 'triage-after.json', 'compare.json',
           'actions.log', 'job.json', 'device.json')
ASSETS = Path(__file__).resolve().parent.parent / 'gui'


def mapping(value):
    return value if isinstance(value, dict) else {}


def read_json(path):
    try:
        return mapping(json.loads(path.read_text(encoding='utf-8')))
    except (OSError, ValueError):
        return {}


def esc(value):
    return html.escape(str(value), quote=True)


def text(value):
    if isinstance(value, list):
        return '; '.join(text(x) for x in value) or 'None listed'
    if isinstance(value, dict):
        return '; '.join(str(k).replace('_', ' ') + ': ' + text(v) for k, v in value.items())
    return str(value)


def table(headings, rows):
    rows = list(rows)
    if not rows:
        return ''
    return '<div class="scroll"><table><thead><tr>' + ''.join('<th>'+esc(x)+'</th>' for x in headings) + '</tr></thead><tbody>' + ''.join(
        '<tr>'+''.join('<td>'+esc(text(x))+'</td>' for x in row)+'</tr>' for row in rows) + '</tbody></table></div>'


def section(title, content, warning=False):
    return '<section'+(' class="warning"' if warning else '')+'><h2>'+esc(title)+'</h2>'+content+'</section>' if content else ''


def findings(data, label):
    parts = []
    skipped = data.get('skipped_checks')
    if isinstance(skipped, list) and skipped:
        parts.append(section('CHECKS SKIPPED', '<ul>'+''.join('<li>'+esc(text(x))+'</li>' for x in skipped)+'</ul>', True))
    suspects = data.get('suspects')
    if isinstance(suspects, list):
        suspects = [r for r in suspects if isinstance(r, dict)]
        suspects.sort(key=lambda r: r.get('score') if isinstance(r.get('score'), (float, int)) else -1, reverse=True)
        parts.append(section('Suspect apps', table(['Score', 'Package', 'Install source', 'Red flags'],
            ((r.get('score', ''), r.get('package', ''), r.get('source', ''), r.get('reasons', [])) for r in suspects))))
    channels = data.get('site_channels')
    if isinstance(channels, list) and channels:
        parts.append(section('Site-notification channels', '<p>Channels may overstate what\'s live: Android can retain blocked sites. Verify browser settings.</p>'+table(['Date', 'Site'], (r for r in channels if isinstance(r, list)))))
    access = mapping(data.get('access'))
    parts.append(section('Special access holders', table(['Access', 'Packages'], access.items())))
    parts.append(section('Proxy / DNS / VPN', table(['Setting', 'Value'], mapping(data.get('network_settings')).items())))
    for key, title in [('website_shortcuts', 'Website shortcuts'), ('calendar_subscriptions', 'Calendar subscriptions'),
                       ('notification_sources', 'Notification sources (bounded recent snapshot)'), ('user_certificates', 'User CA certificates (user 0)')]:
        values = data.get(key)
        if isinstance(values, list):
            parts.append(section(title, table(['Finding'], ([x] for x in values))))
    return section(label, ''.join(parts))


def phones():
    phone = Phone()
    output = phone.raw('devices', '-l', timeout=5).decode('utf-8', errors='replace')
    if phone.last_returncode:
        raise RuntimeError(phone.last_error or 'Could not list phones')
    rows = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2 or line.startswith(('List of devices', '*')):
            continue
        serial, state = fields[:2]
        model = next((x[6:].replace('_', ' ') for x in fields[2:] if x.startswith('model:')), '')
        advice = ''
        if state == 'unauthorized':
            advice = "Unlock it and tap Allow on the 'Allow USB debugging?' prompt."
        elif state != 'device':
            advice = 'Check USB debugging is on and the cable carries data.'
        if state == 'no' and 'permissions' in line:
            state = 'no permissions'
            advice = "Install your distro's adb udev rules, unplug and replug the phone, and try again."
        rows.append(dict(serial=serial, model=model, state=state, advice=advice))
    return rows


class Viewer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, job, port=0):
        self.job = Path(job).resolve()
        self.token = secrets.token_urlsafe(32)
        self.capture_lock = threading.Lock()
        self.last_capture = float('-inf')
        super().__init__(('127.0.0.1', port), Handler)
        self.origin = 'http://127.0.0.1:{}'.format(self.server_port)

    def files(self):
        # No symlinks (including symlink directories), nested reports, or raw dumps.
        allowed = {}
        candidates = [self.job / n for n in RECORDS] + list(self.job.glob('*.pdf'))
        screens = self.job / 'screens'
        if not screens.is_symlink():
            candidates += list(screens.glob('*.png'))
        for path in candidates:
            if not path.is_symlink() and path.is_file() and path.resolve().parent in (self.job, self.job / 'screens'):
                allowed[path.relative_to(self.job).as_posix()] = path
        return allowed

    def state(self):
        files = self.files()
        records = {n: read_json(p) for n, p in files.items() if n.endswith('.json')}
        job = records.get('job.json', {})
        device = records.get('device.json', {})
        before = records.get('triage-before.json', {})
        info = [(k, v) for k, v in [('Ticket', job.get('ticket')), ('Technician', job.get('tech')),
                ('Started', job.get('started')), ('Model', device.get('model') or mapping(before.get('device')).get('model')),
                ('Android', mapping(before.get('device')).get('android_version'))] if v]
        content = section('Job', table(['Field', 'Value'], info))
        content += findings(before, 'Before findings') + findings(records.get('triage-after.json', {}), 'After findings')
        compare = records.get('compare.json', {})
        for key, title in [('metrics', 'Before / after'), ('network_settings', 'Network before / after')]:
            content += section(title, table(['Check', 'Before', 'After', 'Details'],
                ((r.get('label', k), r.get('before', ''), r.get('after', ''),
                  {n: r[n] for n in ('removed', 'remaining', 'added') if n in r})
                 for k, r in mapping(compare.get(key)).items() if isinstance(r, dict))))
        actions = []
        if 'actions.log' in files:
            try:
                for line in files['actions.log'].read_text(encoding='utf-8', errors='replace').splitlines():
                    try:
                        row = mapping(json.loads(line))
                        if row:
                            actions.append([row.get(k, '') for k in ('timestamp', 'package', 'action', 'result')])
                    except ValueError:
                        pass  # Concurrent writer may have an incomplete last line.
            except OSError:
                pass
        content += section('Removal log', table(['Time', 'Package', 'Action', 'Result'], actions))
        try:
            connected, error = phones(), ''
        except (SystemExit, OSError, RuntimeError) as exc:
            connected, error = [], str(exc)
        mtimes = {}
        for name, path in files.items():
            try:
                stat = path.stat()
                mtimes[name] = [stat.st_mtime_ns, stat.st_size]
            except OSError:
                pass  # Files can be replaced while the agent works.
        return dict(mtimes=mtimes,
                    html=content, phones=connected, phone_error=error,
                    serial=device.get('serial', ''), reports=[n for n in files if n.endswith('.pdf')])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Never log the access token or customer filenames.

    def send(self, status, data=b'', mime='text/plain; charset=utf-8', cookie=False):
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        if cookie:
            self.send_header('Set-Cookie', 'viewer_token={}; HttpOnly; SameSite=Strict; Path=/'.format(self.server.token))
        self.end_headers()
        self.wfile.write(data)

    def json(self, value, status=200):
        self.send(status, json.dumps(value).encode('utf-8'), 'application/json')

    def authorized(self, post=False):
        if self.headers.get_all('Host') != [self.server.origin[7:]]:
            self.send(403)
            return False
        parsed = urlsplit(self.path)
        query_token = parse_qs(parsed.query).get('token', [''])[0]
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get('Cookie', ''))
        except CookieError:
            pass
        value = cookie.get('viewer_token')
        candidates = [query_token, value.value if value else '', self.headers.get('X-Access-Token', '')]
        if not any(secrets.compare_digest(x.encode('utf-8'), self.server.token.encode('utf-8')) for x in candidates):
            self.send(401)
            return False
        if post and (self.headers.get('Origin') != self.server.origin or
                     not secrets.compare_digest(self.headers.get('X-Access-Token', '').encode('utf-8'), self.server.token.encode('utf-8'))):
            self.send(403)
            return False
        return True

    def unsupported(self):
        if self.authorized():
            self.send(405)

    do_HEAD = unsupported
    do_OPTIONS = unsupported
    do_PUT = unsupported
    do_DELETE = unsupported
    do_PATCH = unsupported


    def do_GET(self):
        if not self.authorized():
            return
        path = unquote(urlsplit(self.path).path)
        if '\\' in path or any(x in ('.', '..') for x in path.split('/')):
            self.send(403)
        elif path == '/':
            self.send(200, (ASSETS / 'index.html').read_bytes(), 'text/html; charset=utf-8', cookie=True)
        elif path in ('/app.js', '/style.css'):
            self.send(200, (ASSETS / path[1:]).read_bytes(), 'text/javascript' if path.endswith('.js') else 'text/css')
        elif path == '/favicon.ico':
            self.send(204)
        elif path == '/api/session':
            self.json(dict(token=self.server.token))
        elif path == '/api/state':
            self.json(self.server.state())
        elif path.startswith('/files/'):
            name = path[7:]
            file = self.server.files().get(name)
            if file and (name.endswith('.pdf') or name.startswith('screens/')):
                try:
                    self.send(200, file.read_bytes(), 'application/pdf' if name.endswith('.pdf') else 'image/png')
                except OSError:
                    self.send(404)
            else:
                self.send(404)
        else:
            self.send(404)

    def do_POST(self):
        if not self.authorized(post=True):
            return
        if self.path != '/api/screenshot':
            self.send(404)
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 4096:
                raise ValueError('Invalid request size')
            serial = mapping(json.loads(self.rfile.read(length))).get('serial')
            if not isinstance(serial, str) or not serial:
                raise ValueError('Select a phone explicitly first')
            with self.server.capture_lock:
                if time.monotonic() - self.server.last_capture < 10:
                    self.json(dict(error='Wait at least 10 seconds between screenshots'), 429)
                    return
                if serial not in [p['serial'] for p in phones() if p['state'] == 'device']:
                    raise ValueError('Select a connected, authorized phone')
                self.server.last_capture = time.monotonic()
                folder = self.server.job / 'screens'
                if folder.is_symlink():
                    raise ValueError('Screens folder must not be a symlink')
                folder.mkdir(exist_ok=True)
                destination = folder / ('screen-' + secrets.token_hex(12) + '.png')
                phone = Phone(serial)
                phone.require_connected()
                screenshot(phone, destination)
            self.json(dict(url='/files/screens/' + destination.name))
        except (ValueError, OSError, RuntimeError, SystemExit) as exc:
            self.json(dict(error=str(exc)), 400)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job', required=True, type=Path)
    parser.add_argument('--port', type=int, default=0)
    args = parser.parse_args()
    if not args.job.is_dir():
        parser.error('--job must be an existing job folder')
    with Viewer(args.job, args.port) as server:
        url = server.origin + '/?token=' + quote(server.token)
        print(url, flush=True)
        webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
