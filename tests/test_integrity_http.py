import json
import threading
import tests.test_platform as core
from cyber_platform.server import App


class IntegrityHTTPTests(core.StoreCase):
    request = core.HTTPTests.request
    login = core.HTTPTests.login

    def setUp(self):
        super().setUp()
        self.app=App(('127.0.0.1',0),self.store)
        self.thread=threading.Thread(target=self.app.serve_forever,daemon=True)
        self.thread.start()
        self.cookie,self.csrf='',''

    def tearDown(self):
        self.app.shutdown()
        self.app.server_close()
        self.thread.join()
        super().tearDown()

    def test_owner_csrf_strict_fields_and_busy_gate(self):
        self.assertEqual(self.request('/api/integrity/history')[0],401)
        self.assertEqual(self.request('/api/integrity/start',{'project_id':self.pid})[0],401)
        self.login()
        self.assertEqual(self.request('/api/integrity/start',{'project_id':self.pid},{'X-CSRF-Token':'bad'})[0],403)
        self.assertEqual(self.request('/api/integrity/start',{'project_id':self.pid,'command':'anything'})[0],400)
        self.assertEqual(self.request('/api/integrity/start',{'project_id':[]})[0],400)
        self.assertEqual(self.request('/api/integrity/advance',{'scan_id':'bad','max_bytes':1})[0],400)
        self.assertEqual(self.request('/api/integrity/advance',{'scan_id':'bad'})[0],404)
        self.app.execution_lock.acquire()
        try:
            self.assertEqual(self.request('/api/integrity/start',{'project_id':None})[0],409)
        finally:
            self.app.execution_lock.release()

    def test_scan_persists_progress_and_public_history_excludes_manifest(self):
        self.login()
        self.evidence()
        status,_,body=self.request('/api/integrity/start',{'project_id':self.pid})
        self.assertEqual(status,200)
        scan=json.loads(body)
        self.assertFalse(scan['passed'])
        self.assertNotIn('manifest',scan)
        status,_,body=self.request('/api/integrity/advance',{'scan_id':scan['id']})
        self.assertEqual(status,200)
        finished=json.loads(body)
        self.assertTrue(finished['passed'])
        self.assertEqual(finished['verified'],1)
        self.assertEqual(json.loads(self.request('/api/integrity?scan='+scan['id'])[2]),finished)
        history=json.loads(self.request('/api/integrity/history')[2])
        self.assertEqual(history['scans'][0],finished)
        self.assertNotIn('manifest',history['scans'][0])
