import json
import threading
import time
import unittest
from unittest.mock import patch
import tests.test_platform as core
from cyber_platform.server import App
from cyber_platform.store import Problem, encode, uid


class AgentsHTTPTests(core.StoreCase):
    request = core.HTTPTests.request
    login = core.HTTPTests.login

    def setUp(self):
        super().setUp()
        self.app = App(('127.0.0.1',0),self.store)
        self.thread = threading.Thread(target=self.app.serve_forever,daemon=True)
        self.thread.start()
        self.cookie,self.csrf = '', ''

    def tearDown(self):
        self.app.shutdown()
        self.app.server_close()
        self.thread.join()
        super().tearDown()

    def body(self,**changes):
        return {'project_id':self.pid,'question':'راجع الدليل المقدم','evidence_ids':[],'role_ids':['researcher'],**changes}

    def wait_job(self,identifier):
        until=time.monotonic()+5
        while time.monotonic()<until:
            status,_,data=self.request('/api/agents?project='+self.pid+'&job='+identifier)
            self.assertEqual(status,200)
            result=json.loads(data)
            if result['status'] not in ('queued','running'):
                return result
            time.sleep(.01)
        self.fail('Agent job did not finish in fixture time')

    def test_auth_csrf_catalog_and_strict_fields(self):
        self.assertEqual(self.request('/api/agents/roles')[0],401)
        self.assertEqual(self.request('/api/agents/start',self.body())[0],401)
        self.login()
        status,_,data=self.request('/api/agents/roles')
        self.assertEqual(status,200)
        roles=json.loads(data)
        self.assertEqual(len(roles['roles']),40)
        self.assertEqual(roles['max_parallel'],2)
        self.assertEqual(self.request('/api/agents/start',self.body(),{'X-CSRF-Token':'bad'})[0],403)
        self.assertEqual(self.request('/api/agents/start',self.body(command='anything'))[0],400)
        self.assertEqual(self.request('/api/agents/start',self.body(role_ids=['not-registered']))[0],400)
        self.assertEqual(self.request('/api/agents/start',self.body(project_id={}))[0],400)
        self.assertEqual(self.request('/api/agents/start',self.body(question=' '*4000+'x'))[0],400)

    def test_startup_marks_queued_and_running_jobs_interrupted(self):
        identifiers=[]
        with self.store.lock,self.store.db:
            for status in ('queued','running'):
                identifier=uid()
                identifiers.append(identifier)
                self.store.db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)',(identifier,self.pid,'synthetic recovery',status,
                    encode({'schema':'was.agents/1','roles':['researcher']}),encode([{'role_id':'researcher','status':'queued'}]),time.time()))
        recovered=App(('127.0.0.1',0),self.store)
        try:
            for identifier in identifiers:
                self.assertEqual(recovered.agents.status(self.pid,identifier)['status'],'interrupted')
        finally:
            recovered.server_close()

    def test_persisted_result_project_isolation_and_history(self):
        self.login()
        with patch('cyber_platform.agents.local_ai.chat',return_value={'answer':'Synthetic reviewed answer','evidence':[]}):
            status,_,data=self.request('/api/agents/start',self.body())
            self.assertEqual(status,200,data)
            job=json.loads(data)
            completed=self.wait_job(job['id'])
        self.assertEqual(completed['status'],'succeeded',completed)
        self.assertEqual(completed['results'][0]['answer'],'Synthetic reviewed answer')
        status,_,data=self.request('/api/agents?project='+self.pid)
        self.assertEqual(status,200)
        self.assertEqual(json.loads(data)['jobs'][0]['id'],job['id'])
        other=self.store.create_project('other project')
        self.assertEqual(self.request('/api/agents?project='+other['id']+'&job='+job['id'])[0],404)
        evidence=self.store.add_evidence(other['id'],'foreign.txt',b'synthetic')
        self.assertEqual(self.request('/api/agents/start',self.body(evidence_ids=[evidence['id']]))[0],404)

    def test_model_failure_visible_and_global_execution_lock(self):
        self.login()
        self.app.execution_lock.acquire()
        try:
            self.assertEqual(self.request('/api/agents/start',self.body())[0],409)
        finally:
            self.app.execution_lock.release()
        with patch('cyber_platform.agents.local_ai.chat',side_effect=Problem('Fixture model unavailable',503)):
            status,_,data=self.request('/api/agents/start',self.body())
            self.assertEqual(status,200)
            completed=self.wait_job(json.loads(data)['id'])
        self.assertEqual(completed['status'],'failed')
        self.assertEqual(completed['results'][0]['status'],'failed')
        self.assertTrue(self.app.execution_lock.acquire(blocking=False))
        self.app.execution_lock.release()
