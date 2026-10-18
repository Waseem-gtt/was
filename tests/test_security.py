import json
import socket
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
import tests.test_platform as core
from cyber_platform import sandbox
from cyber_platform.server import App
from cyber_platform.store import Problem, Store, PASSWORD_COST, password_hash, encode


class SandboxAvailabilityTests(unittest.TestCase):
    def test_missing_bubblewrap_refuses_execution_with_clear_isolation_message(self):
        with patch('cyber_platform.sandbox.Path.is_file', return_value=False), patch('cyber_platform.sandbox.subprocess.Popen') as process:
            with self.assertRaises(Problem) as result:
                sandbox.run('print("test")')
            self.assertEqual(result.exception.status, 503)
            self.assertIn('عزل', str(result.exception))
            process.assert_not_called()

    def test_workshop_command_has_fixed_executable_and_isolation_flags(self):
        args = sandbox.command(Path('/synthetic/input'))
        self.assertEqual(args[0], '/usr/bin/prlimit')
        self.assertIn('/usr/bin/bwrap', args)
        self.assertIn('--cpu=3:3', args)
        self.assertIn('--as=201326592:201326592', args)
        self.assertIn('--unshare-all', args)
        self.assertIn('--clearenv', args)
        self.assertIn('--cap-drop', args)
        self.assertNotIn('/workspace', args)
        self.assertEqual(args[-1], '/work/main.py')


class StorageBoundaryTests(core.StoreCase):
    def test_legacy_password_hash_upgraded_after_successful_auth_only(self):
        salt=b'0123456789abcdef'
        legacy={'salt':salt.hex(),'hash':password_hash('legacy-password-123',salt)}
        with self.store.lock,self.store.db:
            self.store.db.execute("INSERT INTO settings VALUES('owner',?)",(encode(legacy),))
        self.assertFalse(self.store.check_password('incorrect-password'))
        self.assertNotIn('n',self.store.setting('owner'))
        self.assertTrue(self.store.check_password('legacy-password-123'))
        self.assertEqual(self.store.setting('owner')['n'],PASSWORD_COST)
        self.assertNotEqual(self.store.setting('owner')['salt'],salt.hex())
        self.assertTrue(self.store.check_password('legacy-password-123'))

    def test_private_data_directory_required(self):
        path = Path(self.temp.name) / 'shared'
        path.mkdir(mode=0o755)
        path.chmod(0o755)
        with self.assertRaises(Problem):
            Store(path)

    def test_database_and_blob_directory_symlinks_rejected(self):
        for entry in ('evidence','platform.db'):
            path = Path(self.temp.name) / entry.replace('.', '-')
            path.mkdir(mode=0o700)
            (path / entry).symlink_to(self.store.blobs if entry=='evidence' else self.store.root/'platform.db')
            with self.assertRaises(Problem):
                Store(path)

    def test_control_characters_in_filenames_rejected(self):
        for name in ('bad\nname','bad\rname','bad\tname','bad\x7fname'):
            with self.assertRaises(Problem):
                self.store.add_evidence(self.pid,name,b'example')


class HTTPBoundaryTests(core.StoreCase):
    request = core.HTTPTests.request
    login = core.HTTPTests.login

    def setUp(self):
        super().setUp()
        self.app = App(('127.0.0.1',0), self.store)
        self.thread = threading.Thread(target=self.app.serve_forever,daemon=True)
        self.thread.start()
        self.cookie, self.csrf = '', ''

    def tearDown(self):
        self.app.shutdown();self.app.server_close();self.thread.join()
        super().tearDown()

    def raw(self, body=b'{}', path='/api/projects', headers=(), omit_body=False):
        base = [('Host',f'127.0.0.1:{self.app.server_port}'),('Content-Type','application/json'),
                ('Cookie',self.cookie),('X-CSRF-Token',self.csrf),('Content-Length',str(len(body)))]
        data=('POST '+path+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in [*base,*headers])+'\r\n').encode()
        with socket.create_connection(('127.0.0.1',self.app.server_port),timeout=2) as conn:
            conn.sendall(data+(b'' if omit_body else body))
            response=conn.recv(4096)
        return int(response.split(b' ',2)[1])

    def test_unauthenticated_large_body_rejected_before_read(self):
        self.assertEqual(self.raw(b'x'*1000000,omit_body=True),401)

    def test_public_auth_body_has_small_limit(self):
        self.assertEqual(self.raw(b'x'*4097,path='/api/login',omit_body=True),413)

    def test_duplicate_host_length_and_transfer_encoding_rejected(self):
        self.login()
        self.assertEqual(self.raw(headers=[('Host','evil.test')]),400)
        self.assertEqual(self.raw(headers=[('Content-Length','999')]),400)
        self.assertEqual(self.raw(headers=[('Transfer-Encoding','chunked')]),400)

    def test_duplicate_json_keys_and_nonfinite_numbers_rejected(self):
        self.login()
        for body in (b'{"name":"one","name":"two"}',b'{"name":"demo","extra":NaN}',b'{"name":"demo","extra":Infinity}'):
            self.assertEqual(self.raw(body),400)
        self.assertEqual(len(self.store.rows('SELECT * FROM projects')),1)

    def test_worker_limit_bounds_connections(self):
        for _ in range(16):
            self.assertTrue(self.app.worker_slots.acquire(blocking=False))
        try:
            self.assertEqual(self.request('/healthz')[0],503)
        finally:
            for _ in range(16):self.app.worker_slots.release()
        self.assertEqual(self.request('/healthz')[0],200)

    def test_login_failures_are_audited_without_passwords(self):
        self.login()
        self.assertEqual(self.request('/api/login',{'password':'incorrect-password-sample'})[0],401)
        events=self.store.rows('SELECT action,details FROM audit')
        self.assertIn('owner.login_failed',[e['action'] for e in events])
        self.assertNotIn('incorrect-password-sample',json.dumps(events))

    def test_owner_enrollment_needs_private_token_and_does_not_expose_it(self):
        token=self.store.setup_token()
        path=self.store.root/'setup-token'
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        self.assertNotIn(token.encode(),self.request('/api/status')[2])
        self.assertEqual(self.request('/setup-token')[0],401)
        self.assertEqual(self.request('/api/setup',{'password':'strong-password-123'})[0],403)
        self.assertEqual(self.request('/api/setup',{'password':'strong-password-123','setup_token':'incorrect'})[0],403)
        self.assertFalse(self.store.setting('owner'))
        self.login()
        self.assertFalse(path.exists())
        self.assertEqual(self.request('/api/setup',{'password':'another-password-123','setup_token':token})[0],409)
        self.assertNotIn(token,json.dumps(self.store.rows('SELECT * FROM audit')))

    def test_new_workflow_endpoints_require_auth_csrf_and_scoped_fields(self):
        for endpoint,data in [('/api/workflows/resume',{'project_id':self.pid,'source_job_id':None,'steps':[]}),
                              ('/api/results/compare',{'project_id':self.pid,'left_id':'missing','right_id':'missing'})]:
            self.assertEqual(self.request(endpoint,data)[0],401)
        self.login()
        self.assertEqual(self.request('/api/workflows/resume',{'project_id':self.pid,'source_job_id':None,'steps':[]})[0],400)
        self.assertEqual(self.request('/api/results/compare',{'project_id':self.pid,'left_id':'a','right_id':'b'},{'X-CSRF-Token':'bad'})[0],403)
        self.assertEqual(self.request('/api/results/compare',{'project_id':self.pid,'left_id':'a','right_id':'b','target':'outside'})[0],400)
