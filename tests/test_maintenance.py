import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from cyber_platform import backup, maintenance
from cyber_platform import __main__ as cli
from cyber_platform.store import Problem, Store
from tests.test_platform import StoreCase
import tests.test_platform as core
from cyber_platform.server import App


class MaintenanceTests(StoreCase):
    def test_all_sections_execute_linked_tools_and_persist_report(self):
        self.evidence()
        result = maintenance.check(self.store)
        self.assertTrue(result['passed'], result)
        self.assertEqual(len(result['sections']), 22)
        ids = {c['id'] for c in result['checks'] if c['id'].startswith('tool:')}
        expected = {'tool:' + tool for s in maintenance.CATALOG for p in s['platforms'] for tool in p['tool_ids']}
        self.assertEqual(ids, expected)
        self.assertEqual(maintenance.history(self.store)['runs'][0]['report'], result)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_repair_permission_only_and_corrupt_evidence_preserved(self):
        e = self.evidence()
        path = self.store.blobs / e['id']
        path.chmod(0o644)
        check = maintenance.check(self.store, section_id='01')
        self.assertFalse(check['passed'])
        fixed = maintenance.check(self.store, 'repair', '01')
        self.assertTrue(fixed['passed'], fixed)
        self.assertEqual(path.stat().st_mode & 0o777, 0o400)
        self.assertEqual(len(fixed['repairs']), 1)
        path.chmod(0o600)
        path.write_bytes(b'evil')
        failed = maintenance.check(self.store, 'repair', '01')
        self.assertFalse(failed['passed'])
        self.assertEqual(path.read_bytes(), b'evil')
        self.assertEqual(failed['repairs'], [])

    def test_symlink_evidence_not_followed_or_repaired(self):
        e = self.evidence()
        other = self.store.root / 'unrelated'
        other.write_bytes(b'test')
        other.chmod(0o644)
        path = self.store.blobs / e['id']
        path.unlink()
        path.symlink_to(other)
        result = maintenance.check(self.store, 'repair', '01')
        self.assertFalse(result['passed'])
        self.assertTrue(path.is_symlink())
        self.assertEqual(other.stat().st_mode & 0o777, 0o644)

    def test_fifo_evidence_and_setup_token_refused_without_blocking(self):
        e = self.evidence()
        evidence_path = self.store.blobs / e['id']
        evidence_path.unlink()
        os.mkfifo(evidence_path,0o600)
        os.mkfifo(self.store.root/'setup-token',0o600)
        program = '''import sys
from cyber_platform.store import Store, Problem
s = Store(sys.argv[1])
try:
    if sys.argv[2] == 'setup':
        s.setup_token()
    else:
        s.read_evidence(sys.argv[2],sys.argv[3])
except Problem:
    sys.exit(0)
finally:
    s.close()
sys.exit(1)
'''
        for args in [('setup',),(self.pid,e['id'])]:
            result = subprocess.run([sys.executable,'-c',program,str(self.store.root),*args],capture_output=True,timeout=3)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_worker_failure_is_failed_check(self):
        with patch('cyber_platform.maintenance.worker.analyze', side_effect=ValueError('limit')):
            result = maintenance.check(self.store, section_id='01')
        self.assertFalse(result['passed'])
        self.assertEqual(next(c for c in result['checks'] if c['id']=='tool:ioc')['status'], 'failed')

    def test_bounded_evidence_check_does_not_report_success_when_incomplete(self):
        self.evidence()
        with self.store.db:
            self.store.db.execute('UPDATE evidence SET size=?',(65*1024*1024,))
        result = maintenance.check(self.store, section_id='01')
        self.assertFalse(result['passed'])
        detail = next(c['detail'] for c in result['checks'] if c['id']=='evidence')
        self.assertFalse(detail['complete'])
        self.assertEqual(detail['verified'], 0)

    def test_invalid_scope_and_arbitrary_operation_rejected(self):
        for operation, section in [('shell',None),('check','bad'),('check',[]),('repair','99')]:
            with self.assertRaises(Problem):
                maintenance.check(self.store, operation, section)

    def test_development_lifecycle_and_backup_restore(self):
        created = maintenance.task(self.store, {'section_id':'01','title':'مراجعة تحليل المؤشرات'})
        for status in ['in_progress','done','open']:
            changed = maintenance.task(self.store, {'id':created['id'],'status':status})
            self.assertEqual(changed['tasks'][0]['status'],status)
        maintenance.check(self.store, section_id='01')
        dest = Path(self.temp.name) / 'restored'
        backup.restore(backup.export(self.store,'maintenance-backup-test'), 'maintenance-backup-test', dest)
        restored = Store(dest)
        try:
            self.assertEqual(len(maintenance.history(restored)['runs']),1)
            self.assertEqual(maintenance.history(restored)['tasks'][0]['id'],created['id'])
        finally:
            restored.close()
        for body in [{'section_id':None,'title':'abc'}, {'section_id':'01','title':'x'}, {'id':'missing','status':'done'}, {'id':created['id'],'status':'executed'}, {'command':'rm'}]:
            with self.assertRaises(Problem):
                maintenance.task(self.store, body)

    def test_legacy_store_additive_migration_preserves_evidence_and_audit(self):
        e = self.evidence()
        before = self.store.verify_audit()
        with self.store.db:
            self.store.db.execute('DROP TABLE maintenance_runs')
            self.store.db.execute('DROP TABLE development_tasks')
        reopened = Store(self.store.root)
        try:
            self.assertEqual(reopened.read_evidence(self.pid,e['id']), b'test')
            self.assertEqual(reopened.verify_audit(), before)
            self.assertEqual(maintenance.history(reopened)['tasks'], [])
        finally:
            reopened.close()

    def test_desktop_dispatch_uses_local_browser_and_keeps_server_lifecycle(self):
        with patch.object(sys,'argv',['was-platform','desktop','--data',str(self.store.root),'--port','0']), patch.object(cli,'App') as app_class, patch.object(cli.threading,'Thread') as thread:
            app = app_class.return_value
            app.server_port = 8123
            cli.main()
            thread.assert_called_once_with(target=cli.webbrowser.open,args=('http://127.0.0.1:8123',),daemon=True)
            thread.return_value.start.assert_called_once()
            app.serve_forever.assert_called_once()
            app.server_close.assert_called_once()


class MaintenanceHTTPTests(StoreCase):
    request = core.HTTPTests.request
    login = core.HTTPTests.login

    def setUp(self):
        super().setUp()
        self.app = App(('127.0.0.1',0), self.store)
        self.thread = threading.Thread(target=self.app.serve_forever,daemon=True)
        self.thread.start()
        self.cookie, self.csrf = '', ''

    def tearDown(self):
        self.app.shutdown()
        self.app.server_close()
        self.thread.join()
        super().tearDown()

    def test_private_endpoints_csrf_and_execution_lock(self):
        self.assertEqual(self.request('/api/maintenance')[0],401)
        self.assertEqual(self.request('/api/maintenance',{'operation':'check','section_id':'01'})[0],401)
        self.login()
        self.assertEqual(self.request('/api/maintenance')[0],200)
        self.assertEqual(self.request('/api/maintenance',{'operation':'check','section_id':'01'},{'X-CSRF-Token':'wrong'})[0],403)
        self.app.execution_lock.acquire()
        try:
            self.assertEqual(self.request('/api/maintenance',{'operation':'check','section_id':'01'})[0],409)
        finally:
            self.app.execution_lock.release()
        self.assertEqual(self.request('/api/maintenance',{'operation':'shell','section_id':'01'})[0],400)
        self.assertEqual(self.request('/api/maintenance',{'operation':'check','section_id':'01'})[0],200)
        self.assertEqual(self.request('/api/development',{'section_id':'01','title':'متابعة الخطأ'})[0],200)


class LinuxReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.prefix = Path(self.temp.name) / 'private'
        self.prefix.mkdir(mode=0o700)
        (self.prefix/'releases').mkdir(mode=0o700)
        self.script = str(Path('scripts/release.sh').resolve())

    def tearDown(self):
        self.temp.cleanup()

    def ready(self, sha):
        root = self.prefix/'releases'/sha
        root.mkdir()
        (root/'payload').write_bytes(b'synthetic-release')
        (root/'.release-sha256').write_text(hashlib.sha256(b'synthetic-release').hexdigest()+'  payload\n')
        (root/'.ready').write_text(sha+'\n')
        return root

    def run_script(self, *args):
        return subprocess.run(['bash',self.script,*args,str(self.prefix)], capture_output=True, text=True, timeout=10)

    def test_activation_idempotence_rollback_and_modification_refusal(self):
        first, second = 'a'*40,'b'*40
        self.ready(first)
        second_dir = self.ready(second)
        self.assertEqual(self.run_script('activate',first).returncode,0)
        self.assertEqual(self.run_script('activate',second).returncode,0)
        self.assertEqual(self.run_script('activate',second).returncode,0)
        self.assertEqual(os.readlink(self.prefix/'previous'),'releases/'+first)
        self.assertEqual(self.run_script('rollback').returncode,0)
        self.assertEqual(os.readlink(self.prefix/'current'),'releases/'+first)
        (second_dir/'payload').write_bytes(b'tampered')
        self.assertNotEqual(self.run_script('activate',second).returncode,0)
        self.assertEqual(os.readlink(self.prefix/'current'),'releases/'+first)

    def test_untested_release_path_injection_and_user_files_refused(self):
        self.assertNotEqual(self.run_script('activate','../bad').returncode,0)
        self.assertNotEqual(self.run_script('activate','c'*40).returncode,0)
        self.ready('a'*40)
        (self.prefix/'previous').write_text('preserve')
        self.assertNotEqual(self.run_script('activate','a'*40).returncode,0)
        self.assertEqual((self.prefix/'previous').read_text(),'preserve')

    def test_damaged_current_release_can_roll_back_to_verified_previous(self):
        first, second = 'a'*40,'b'*40
        self.ready(first)
        bad = self.ready(second)
        self.assertEqual(self.run_script('activate',first).returncode,0)
        self.assertEqual(self.run_script('activate',second).returncode,0)
        (bad/'payload').write_bytes(b'broken-current')
        self.assertEqual(self.run_script('rollback').returncode,0)
        self.assertEqual(os.readlink(self.prefix/'current'),'releases/'+first)
        self.assertEqual(os.readlink(self.prefix/'previous'),'releases/'+first)
