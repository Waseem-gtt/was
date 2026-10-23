"""Desktop integration uses temporary directories and an ephemeral HTTP server."""
import http.client
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from cyber_platform import desktop
from cyber_platform.server import App
from cyber_platform.store import Store, Problem


class DesktopTests(unittest.TestCase):
    def test_fixed_browser_choices_and_no_shell_argument(self):
        for choice in ('/tmp/browser', 'chromium --no-sandbox', 'firefox'):
            with self.assertRaises(Problem):
                desktop.browser_executable(choice)
        with patch.object(desktop.shutil, 'which', return_value=None):
            with self.assertRaises(Problem):
                desktop.browser_executable()

    def test_app_arguments_preserve_sandbox_and_local_origin(self):
        args = desktop.browser_arguments('/usr/bin/chromium', 8123, '/tmp/profile with spaces')
        self.assertIn('--app=http://127.0.0.1:8123', args)
        self.assertIn('--user-data-dir=/tmp/profile with spaces', args)
        self.assertFalse(any('no-sandbox' in arg or 'remote-debugging' in arg for arg in args))
        for port in (0, True, 65536, '8080'):
            with self.assertRaises(Problem):
                desktop.browser_arguments('/usr/bin/chromium', port, '/tmp/p')

    def test_no_graphical_session_fails_before_process(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(desktop, 'browser_executable', return_value='/usr/bin/chromium'), patch.object(desktop.subprocess, 'Popen') as process:
            with self.assertRaisesRegex(Problem, 'graphical session'):
                desktop.run(None, '/tmp')
            process.assert_not_called()

    def test_real_http_lifecycle_ends_with_window_and_cleans_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp)
            app = App(('127.0.0.1', 0), store)
            profiles = []
            class Window:
                def __init__(self, args):
                    profile = Path(next(arg.split('=', 1)[1] for arg in args if arg.startswith('--user-data-dir=')))
                    profiles.append(profile)
                    self_test.assertEqual(profile.stat().st_mode & 0o777, 0o700)
                    conn = http.client.HTTPConnection('127.0.0.1', app.server_port, timeout=5)
                    conn.request('GET', '/healthz')
                    self_test.assertEqual(conn.getresponse().status, 200)
                    conn.close()
                def wait(self): return 0
                def poll(self): return 0
            self_test = self
            try:
                with patch.dict(os.environ, {'DISPLAY': ':synthetic'}), patch.object(desktop, 'browser_executable', return_value='/usr/bin/chromium'), patch.object(desktop.subprocess, 'Popen', side_effect=Window):
                    desktop.run(app, store.root)
                self.assertEqual(len(profiles), 1)
                self.assertFalse(profiles[0].exists())
            finally:
                app.server_close()
                store.close()

    def test_browser_start_failure_stops_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(tmp); app = App(('127.0.0.1', 0), store)
            try:
                with patch.dict(os.environ, {'DISPLAY': ':synthetic'}), patch.object(desktop, 'browser_executable', return_value='/usr/bin/chromium'), patch.object(desktop.subprocess, 'Popen', side_effect=OSError('test start failed')):
                    with self.assertRaises(OSError): desktop.run(app, store.root)
                self.assertFalse(list(store.root.glob('.desktop-*')))
            finally:
                app.server_close(); store.close()

    def test_menu_install_no_overwrite_and_explicit_replace(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = desktop.install_entry(Path(tmp)/'private data', Path(tmp)/'apps', port=0)
            self.assertIn('Terminal=false', target.read_text())
            self.assertIn('"desktop"', target.read_text())
            self.assertNotIn('/ABSOLUTE/PATH', target.read_text())
            with self.assertRaises(FileExistsError): desktop.install_entry(tmp, target.parent)
            desktop.install_entry(tmp, target.parent, replace=True)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            if desktop.shutil.which('desktop-file-validate'):
                result = subprocess.run(['desktop-file-validate', str(target)], capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_menu_refuses_symlinks_and_newline_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp); original = folder/'owner-file'; original.write_text('private')
            (folder/'was-platform.desktop').symlink_to(original)
            with self.assertRaises(Problem): desktop.install_entry(tmp, folder, replace=True)
            self.assertEqual(original.read_text(), 'private')
            with self.assertRaises(Problem): desktop.desktop_entry('/tmp/a\nExec=bad')

    def test_menu_exec_escapes_field_codes_and_shell_metacharacters(self):
        entry = desktop.desktop_entry('/tmp/percent%name $value `quote` "double"')
        command = next(line for line in entry.splitlines() if line.startswith('Exec='))
        self.assertIn('percent%%name', command)
        self.assertNotIn('sh -c', command)
        self.assertIn('\\$', command)
        self.assertIn('\\`', command)
