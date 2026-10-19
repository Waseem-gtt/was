"""Private multi-feature research flow, with strict auth and scoped inputs."""
import json
import threading
from unittest.mock import patch
import tests.test_platform as core
from cyber_platform.server import App, Handler


class ResearchHTTPTests(core.StoreCase):
    request=core.HTTPTests.request
    login=core.HTTPTests.login

    def setUp(self):
        super().setUp(); self.app=App(('127.0.0.1',0),self.store)
        self.thread=threading.Thread(target=self.app.serve_forever,daemon=True);self.thread.start()
        self.cookie,self.csrf='',''

    def tearDown(self):
        self.app.shutdown();self.app.server_close();self.thread.join();super().tearDown()

    def post(self,path,body):
        code,_,raw=self.request('/api/'+path,body)
        self.assertEqual(code,200,(path,raw));return json.loads(raw)

    def operations(self):
        return [('events/normalize',{'project_id':self.pid,'evidence_id':'a'*32,'adapter':'windows-json'}),
                ('detection/save',{'project_id':self.pid,'rule':{}}),
                ('detection/test',{'project_id':self.pid,'evidence_id':'a'*32,'rule_ids':[]}),
                ('coverage/asset',{'project_id':self.pid,'name':'service','kind':'service'}),
                ('coverage/assessment',{'project_id':self.pid,'asset_id':'a'*32,'threat':'test','control':'test','evidence_id':'b'*32}),
                ('coverage/remove',{'project_id':self.pid,'assessment_id':'a'*32})]

    def test_auth_csrf_exact_fields_and_execution_contention(self):
        for path in ('events/adapters','detection/library?project='+self.pid,'coverage?project='+self.pid):
            self.assertEqual(self.request('/api/'+path)[0],401)
        for path,body in self.operations():self.assertEqual(self.request('/api/'+path,body)[0],401)
        self.login()
        for path,body in self.operations():
            self.assertEqual(self.request('/api/'+path,body,{'X-CSRF-Token':'bad'})[0],403)
            self.assertEqual(self.request('/api/'+path,{**body,'command':'outside'})[0],400)
        with self.app.execution_lock:
            for path,body in self.operations():self.assertEqual(self.request('/api/'+path,body)[0],409)
            self.assertEqual(self.request('/api/coverage?project='+self.pid)[0],409)
            self.assertEqual(self.request('/api/events/adapters')[0],200)

    def test_real_event_library_detection_and_coverage_flow(self):
        self.login()
        adapters=json.loads(self.request('/api/events/adapters')[2])['adapters'];self.assertEqual(len(adapters),3)
        sample=next(a for a in adapters if a['id']=='windows-json')
        source=self.evidence(sample['example_content'].encode())
        normalized=self.post('events/normalize',{'project_id':self.pid,'evidence_id':source['id'],'adapter':sample['id']})
        unknown=self.post('detection/test',{'project_id':self.pid,'evidence_id':normalized['evidence']['id'],'rule_ids':['was-login-failure']})
        self.assertFalse(unknown['report']['passed']);self.assertEqual(unknown['report']['evaluation_status'],'not_evaluated')
        library=json.loads(self.request('/api/detection/library?project='+self.pid)[2]);self.assertEqual(len(library['rules']),8)
        source=self.evidence(json.dumps(library['fixtures'][0]['input']).encode())
        tested=self.post('detection/test',{'project_id':self.pid,'evidence_id':source['id'],'rule_ids':[r['id'] for r in library['rules']]})
        self.assertTrue(tested['report']['passed'])
        asset=self.post('coverage/asset',{'project_id':self.pid,'name':'test service','kind':'service'})
        assessed=self.post('coverage/assessment',{'project_id':self.pid,'asset_id':asset['id'],'threat':'test threat','control':'test control','evidence_id':tested['evidence']['id']})
        self.assertEqual(assessed['status'],'supported')
        code,_,raw=self.request('/api/coverage?project='+self.pid);self.assertEqual(code,200)
        view=json.loads(raw);self.assertEqual(view['summary']['supported'],1)
        self.assertTrue(view['edges'])
        removed=self.post('coverage/remove',{'project_id':self.pid,'assessment_id':assessed['id']});self.assertTrue(removed['evidence_preserved'])
        self.assertTrue(self.store.read_evidence(self.pid,tested['evidence']['id']))
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_cross_project_and_uploaded_passed_flag_never_prove_coverage(self):
        self.login();other=self.store.create_project('Other')['id'];evidence=self.evidence(b'{"passed":true}')
        for path,body in [('events/normalize',{'project_id':other,'evidence_id':evidence['id'],'adapter':'windows-json'}),('detection/test',{'project_id':other,'evidence_id':evidence['id'],'rule_ids':['was-login-failure']})]:
            self.assertEqual(self.request('/api/'+path,body)[0],404)
        asset=self.post('coverage/asset',{'project_id':self.pid,'name':'unverified','kind':'host'})
        assessment=self.post('coverage/assessment',{'project_id':self.pid,'asset_id':asset['id'],'threat':'test','control':'test','evidence_id':evidence['id']})
        self.assertEqual(assessment['status'],'unverified')
        self.assertEqual(self.request('/api/coverage/assessment',{'project_id':other,'asset_id':asset['id'],'threat':'test','control':'test','evidence_id':evidence['id']})[0],404)

    def test_only_fixed_new_static_files_served(self):
        for path in ('/research.js','/coverage.js'):
            code,headers,raw=self.request(path);self.assertEqual(code,200)
            self.assertIn('javascript',headers['Content-Type']);self.assertTrue(raw)
        self.assertEqual(self.request('/../cyber_platform/store.py')[0],401)

    def test_completed_heavy_response_is_published_after_releasing_its_slot(self):
        self.login()
        observed=[]
        original=Handler.reply
        def checked_reply(handler,*args,**kwargs):
            if handler.path.startswith(('/api/quality/start','/api/coverage?')):
                observed.append(handler.server.execution_lock.locked())
            return original(handler,*args,**kwargs)
        with patch.object(Handler,'reply',checked_reply):
            self.post('quality/start',{})
            self.assertEqual(self.request('/api/coverage?project='+self.pid)[0],200)
        self.assertEqual(observed,[False,False])
