"""Authenticated durable plans, template proof and report integration."""
import json
import threading
import tests.test_platform as core
from cyber_platform.server import App


class PlansHTTPTests(core.StoreCase):
    request=core.HTTPTests.request
    login=core.HTTPTests.login
    def setUp(self):
        super().setUp();self.app=App(('127.0.0.1',0),self.store);self.thread=threading.Thread(target=self.app.serve_forever,daemon=True);self.thread.start();self.cookie,self.csrf='',''
    def tearDown(self):
        self.app.shutdown();self.app.server_close();self.thread.join();super().tearDown()
    def post(self,path,body):
        code,_,raw=self.request('/api/'+path,body);self.assertEqual(code,200,(path,raw));return json.loads(raw)
    def operations(self):
        pid=self.pid;rid='a'*32
        return [('plans/start',{'project_id':pid,'plan':{}}),('plans/advance',{'project_id':pid,'run_id':rid}),('plans/pause',{'project_id':pid,'run_id':rid}),('plans/resume',{'project_id':pid,'run_id':rid}),('plans/templates/save',{'project_id':pid,'template':{}}),('plans/templates/instantiate',{'project_id':pid,'template_id':'was-x','bindings':{}}),('coverage/scans/start',{'project_id':pid}),('coverage/scans/advance',{'project_id':pid,'scan_id':rid}),('case-reports/build',{'project_id':pid,'title':'Test','evidence_ids':[],'plan_run_ids':[],'coverage_scan_id':None}),('case-reports/verify',{'project_id':pid,'report_id':rid})]

    def test_new_reads_and_writes_require_owner(self):
        for path in ('plans/templates','plans/history','plans','coverage/scans/history','coverage/scans','case-reports/history','case-reports'):
            self.assertEqual(self.request('/api/'+path+'?project='+self.pid)[0],401)
        for path,body in self.operations():self.assertEqual(self.request('/api/'+path,body)[0],401)

    def test_csrf_strict_fields_and_shared_heavy_slot(self):
        self.login()
        for path,body in self.operations():
            self.assertEqual(self.request('/api/'+path,body,{'X-CSRF-Token':'bad'})[0],403)
            self.assertEqual(self.request('/api/'+path,{**body,'shell':'forbidden'})[0],400)
        with self.app.execution_lock:
            for path,body in self.operations():self.assertEqual(self.request('/api/'+path,body)[0],409)
            self.assertEqual(self.request('/api/plans/templates?project='+self.pid)[0],200)

    def generated(self):
        catalog=json.loads(self.request('/api/plans/templates?project='+self.pid)[2]);self.assertEqual(len(catalog['templates']),8)
        fixture=catalog['fixtures'][0];bindings={slot:self.evidence(data.encode())['id'] for slot,data in fixture['inputs'].items()}
        result=self.post('plans/templates/instantiate',{'project_id':self.pid,'template_id':fixture['template_id'],'bindings':bindings})
        return result,next(iter(bindings.values()))

    def test_real_template_branch_plan_scan_report_flow(self):
        self.login();bound,eid=self.generated()
        run=self.post('plans/start',{'project_id':self.pid,'plan':bound['plan'],'instantiation_id':bound['evidence']['id']})
        self.assertEqual(run['template_origin']['evidence_id'],bound['evidence']['id'])
        run=self.post('plans/advance',{'project_id':self.pid,'run_id':run['id']});self.assertLessEqual(run['counts']['completed'],2)
        run=self.post('plans/pause',{'project_id':self.pid,'run_id':run['id']});self.assertEqual(run['status'],'paused')
        run=self.post('plans/resume',{'project_id':self.pid,'run_id':run['id']})
        for _ in range(20):
            if run['status'] in ('completed','failed'):break
            run=self.post('plans/advance',{'project_id':self.pid,'run_id':run['id']})
        self.assertTrue(run['passed'])
        scan=self.post('coverage/scans/start',{'project_id':self.pid})
        for _ in range(10):
            if scan['status']=='completed':break
            scan=self.post('coverage/scans/advance',{'project_id':self.pid,'scan_id':scan['id']})
        self.assertEqual(scan['status'],'completed')
        report=self.post('case-reports/build',{'project_id':self.pid,'title':'<script>report fixture</script>','evidence_ids':[eid],'plan_run_ids':[run['id']],'coverage_scan_id':scan['id']})
        checked=self.post('case-reports/verify',{'project_id':self.pid,'report_id':report['evidence']['id']});self.assertTrue(checked['passed'])
        code,headers,raw=self.request('/api/case-reports?project='+self.pid+'&id='+report['evidence']['id']+'&format=html')
        self.assertEqual(code,200);self.assertIn('attachment',headers['Content-Disposition']);self.assertNotIn(b'<script>',raw);self.assertIn(b'&lt;script&gt;',raw)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_scoped_ids_and_arbitrary_code_never_start(self):
        self.login();bound,eid=self.generated();other=self.store.create_project('Other')['id']
        code,_,_=self.request('/api/plans/start',{'project_id':other,'plan':bound['plan']});self.assertEqual(code,404)
        invalid={'schema':'was.plan/1','name':'Bad','nodes':[{'id':'x','tool':'shell','input':{'evidence_id':eid}}]}
        self.assertEqual(self.request('/api/plans/start',{'project_id':self.pid,'plan':invalid})[0],400)
        run=self.post('plans/start',{'project_id':self.pid,'plan':bound['plan']})
        self.assertEqual(self.request('/api/plans?project='+other+'&run='+run['id'])[0],404)
        self.assertEqual(self.request('/api/plans/advance',{'project_id':other,'run_id':run['id']})[0],404)
        self.assertEqual(json.loads(self.request('/api/plans/history?project='+other)[2])['runs'],[])

    def test_export_formats_static_paths_and_empty_report_rejected(self):
        self.login();self.assertEqual(self.request('/api/case-reports?project='+self.pid+'&id='+'a'*32+'&format=script')[0],400)
        body={'project_id':self.pid,'title':'No refs','evidence_ids':[],'plan_run_ids':[],'coverage_scan_id':None}
        self.assertEqual(self.request('/api/case-reports/build',body)[0],400)
        for path in ('/plans.js','/coverage_scans.js','/reports.js'):
            code,headers,raw=self.request(path);self.assertEqual(code,200);self.assertIn('javascript',headers['Content-Type']);self.assertTrue(raw)

    def test_edited_template_plan_rejects_false_attribution(self):
        self.login();bound,eid=self.generated();bound['plan']['name']='Manual edited name'
        code,_,_=self.request('/api/plans/start',{'project_id':self.pid,'plan':bound['plan'],'instantiation_id':bound['evidence']['id']});self.assertEqual(code,409)
        run=self.post('plans/start',{'project_id':self.pid,'plan':bound['plan']});self.assertIsNone(run['template_origin'])

    def test_post_result_slot_released_for_new_operations(self):
        self.login()
        for _ in range(5):
            scan=self.post('coverage/scans/start',{'project_id':self.pid})
            self.assertEqual(scan['status'],'pending')
