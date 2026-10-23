"""F04 acceptance covers effective rule versions, source fixtures and real replay."""
import copy
import json
from pathlib import Path
import threading
from unittest.mock import patch
from cyber_platform import backup, detection, detection_acceptance, worker
from cyber_platform.server import App
from cyber_platform.store import Problem, Store, encode
from tests.test_platform import StoreCase
import tests.test_platform as core


def rule(**changes):
    return {'id':'owner-acceptance-login','title':'اختبار مالك اصطناعي','version':'1.0.0',
            'license':'CC0-1.0','source':'owner-authored synthetic fixture',
            'selection':{'action':'login','outcome':'failure'},**changes}


def dataset():
    return [{'action':'login','outcome':'failure'},
            {'action':'login','outcome':'success'},
            {'action':'logout','outcome':'failure'}]


class DetectionAcceptanceTests(StoreCase):
    def owner_rule(self, **changes):
        return detection.save(self.store,self.pid,rule(**changes))

    def fixture(self, value=None, indexes=None, rid='owner-acceptance-login'):
        source=self.evidence(encode(dataset() if value is None else value).encode(),'fixture.json')
        registered=detection_acceptance.register(self.store,self.pid,rid,source['id'],[0] if indexes is None else indexes)
        return source,registered

    def row(self,report,rid='owner-acceptance-login'):
        return next(row for row in report['rows'] if row['id']==rid)

    def test_builtin_rules_have_positive_negative_coverage_in_real_worker(self):
        result=detection_acceptance.run(self.store,self.pid)
        report=result['report']
        self.assertTrue(report['complete'])
        self.assertTrue(report['passed'])
        self.assertEqual(report['total_rules'],8)
        self.assertEqual(report['covered_rules'],8)
        self.assertEqual(len(report['rows']),8)
        self.assertTrue(all(row['status']=='passed' for row in report['rows']))
        for row in report['rows']:
            self.assertGreater(row['metrics']['true_positive'],0)
            self.assertGreater(row['metrics']['true_negative'],0)
            self.assertEqual(row['metrics']['false_positive'],0)
            self.assertEqual(row['metrics']['false_negative'],0)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_owner_rule_without_fixture_is_explicit_gap_not_pass(self):
        self.owner_rule()
        state=detection_acceptance.status(self.store,self.pid)
        owner=next(item for item in state['library'] if item['id']==rule()['id'])
        self.assertEqual(owner['fixture_status'],'missing')
        result=detection_acceptance.run(self.store,self.pid)['report']
        self.assertFalse(result['complete']);self.assertFalse(result['passed'])
        self.assertEqual(result['total_rules'],9);self.assertEqual(result['covered_rules'],8)
        self.assertEqual(self.row(result)['status'],'missing_fixture')

    def test_register_and_run_owner_fixture_preserves_original(self):
        self.owner_rule();source,registered=self.fixture()
        self.assertEqual(self.store.read_evidence(self.pid,source['id']),encode(dataset()).encode())
        self.assertEqual(registered['evidence']['parent_id'],source['id'])
        report=detection_acceptance.run(self.store,self.pid)['report']
        self.assertTrue(report['complete']);self.assertTrue(report['passed'])
        self.assertEqual(report['covered_rules'],9)
        self.assertEqual(self.row(report)['status'],'passed')
        metrics=self.row(report)['metrics']
        self.assertEqual(metrics['true_positive'],1);self.assertEqual(metrics['true_negative'],2)

    def test_wrong_reference_labels_show_false_positive_and_false_negative(self):
        self.owner_rule();self.fixture(indexes=[1])
        report=detection_acceptance.run(self.store,self.pid)['report']
        self.assertFalse(report['passed'])
        self.assertEqual(self.row(report)['status'],'failed')
        self.assertEqual(self.row(report)['metrics']['false_positive'],1)
        self.assertEqual(self.row(report)['metrics']['false_negative'],1)

    def test_new_rule_version_stales_fixture_until_registered_again(self):
        self.owner_rule();source,_=self.fixture()
        self.owner_rule(version='2.0.0',selection={'action':'logout','outcome':'failure'})
        report=detection_acceptance.run(self.store,self.pid)['report']
        self.assertFalse(report['complete']);self.assertFalse(report['passed'])
        self.assertEqual(self.row(report)['status'],'stale_fixture')
        detection_acceptance.register(self.store,self.pid,rule()['id'],source['id'],[2])
        self.assertTrue(detection_acceptance.run(self.store,self.pid)['report']['passed'])

    def test_cross_project_fixture_source_is_rejected(self):
        self.owner_rule();source=self.evidence(encode(dataset()).encode())
        other=self.store.create_project('other')['id'];detection.save(self.store,other,rule())
        with self.assertRaises(Problem):detection_acceptance.register(self.store,other,rule()['id'],source['id'],[0])

    def test_reference_indexes_require_positive_negative_and_valid_unique_integers(self):
        self.owner_rule();source=self.evidence(encode(dataset()).encode())
        for indexes in ([],[0,1,2],[0,0],[-1],[3],[True],['0'],None,{'0':1}):
            with self.subTest(indexes=indexes):
                with self.assertRaises(Problem):detection_acceptance.register(self.store,self.pid,rule()['id'],source['id'],indexes)

    def test_non_original_evidence_cannot_register_fixture(self):
        self.owner_rule();source=self.store.add_evidence(self.pid,'derived.json',encode(dataset()).encode(),'result')
        with self.assertRaises(Problem):detection_acceptance.register(self.store,self.pid,rule()['id'],source['id'],[0])

    def test_malformed_fixture_and_unknown_rule_cannot_register(self):
        self.owner_rule()
        for value in (b'not-json',b'{}',b'{"events":[],"events":[]}'):
            source=self.evidence(value)
            with self.assertRaises(Problem):detection_acceptance.register(self.store,self.pid,rule()['id'],source['id'],[0])
        source=self.evidence(encode(dataset()).encode())
        with self.assertRaises(Problem):detection_acceptance.register(self.store,self.pid,'missing-rule',source['id'],[0])

    def test_tampered_source_is_never_a_current_passing_fixture(self):
        self.owner_rule();source,_=self.fixture()
        path=self.store.blobs/source['id'];path.chmod(0o600);path.write_bytes(b'changed')
        try:
            report=detection_acceptance.run(self.store,self.pid)['report']
        except Problem:
            return
        self.assertFalse(report['passed'])
        self.assertNotEqual(self.row(report)['status'],'passed')

    def test_tampered_fixture_receipt_cannot_pass(self):
        self.owner_rule();_,registered=self.fixture()
        path=self.store.blobs/registered['evidence']['id'];path.chmod(0o600);path.write_bytes(b'{}')
        try:
            report=detection_acceptance.run(self.store,self.pid)['report']
        except Problem:
            return
        self.assertFalse(report['passed'])
        self.assertNotEqual(self.row(report)['status'],'passed')

    def test_register_audit_failure_rolls_back_artifact_and_enrollment(self):
        self.owner_rule();source=self.evidence(encode(dataset()).encode());before=set(self.store.blobs.iterdir())
        original=self.store.audit
        def fail(action,*args):
            if action.startswith('detection-fixture'):raise RuntimeError('synthetic audit failure')
            return original(action,*args)
        with patch.object(self.store,'audit',side_effect=fail):
            with self.assertRaises(RuntimeError):detection_acceptance.register(self.store,self.pid,rule()['id'],source['id'],[0])
        self.assertEqual(set(self.store.blobs.iterdir()),before)
        state=detection_acceptance.status(self.store,self.pid)
        self.assertEqual(next(item for item in state['library'] if item['id']==rule()['id'])['fixture_status'],'missing')

    def test_deleted_latest_receipt_and_rewound_index_cannot_reactivate_old_fixture(self):
        self.owner_rule();source,first=self.fixture()
        prior=copy.deepcopy(self.store.setting(detection_acceptance.PREFIX+self.pid))
        second=detection_acceptance.register(self.store,self.pid,rule()['id'],source['id'],[1])
        eid=second['evidence']['id']
        with self.store.db:
            self.store.db.execute('DELETE FROM relations WHERE target=?',(eid,))
            self.store.db.execute('DELETE FROM evidence WHERE id=?',(eid,))
            self.store.db.execute('UPDATE settings SET value=? WHERE key=?',(encode(prior),detection_acceptance.PREFIX+self.pid))
        self.assertTrue(self.store.verify_audit()['valid'])
        with self.assertRaises(Problem):detection_acceptance.status(self.store,self.pid)

    def test_register_rejects_engine_change_during_worker_without_publication(self):
        self.owner_rule();source=self.evidence(encode(dataset()).encode());before=set(self.store.blobs.iterdir())
        with patch.object(detection_acceptance,'fingerprint',side_effect=['a'*64,'b'*64]):
            with self.assertRaises(Problem):detection_acceptance.register(self.store,self.pid,rule()['id'],source['id'],[0])
        self.assertEqual(set(self.store.blobs.iterdir()),before)

    def test_register_rejects_source_tamper_during_worker(self):
        self.owner_rule();source=self.evidence(encode(dataset()).encode());before=set(self.store.blobs.iterdir());execute=worker.analyze
        def tamper(*args,**kwargs):
            result=execute(*args,**kwargs)
            path=self.store.blobs/source['id'];path.chmod(0o600);path.write_bytes(b'changed')
            return result
        with patch.object(worker,'analyze',side_effect=tamper):
            with self.assertRaises(Problem):detection_acceptance.register(self.store,self.pid,rule()['id'],source['id'],[0])
        self.assertEqual(set(self.store.blobs.iterdir()),before)

    def test_owner_rule_revision_index_cannot_rewind_while_newer_rule_exists(self):
        self.owner_rule();self.fixture()
        prior=copy.deepcopy(self.store.setting(detection.PREFIX+self.pid))
        self.owner_rule(version='2.0.0',selection={'action':'logout','outcome':'failure'})
        with self.store.db:
            self.store.db.execute('UPDATE settings SET value=? WHERE key=?',(encode(prior),detection.PREFIX+self.pid))
        with self.assertRaises(Problem):detection_acceptance.run(self.store,self.pid)

    def test_malformed_worker_response_does_not_publish_report(self):
        before=set(self.store.blobs.iterdir())
        for response in (None,[],[{'id':'unknown','events':2,'passed':True,'metrics':{'passed':True}}]*8):
            with self.subTest(response=response):
                with patch.object(worker,'analyze',return_value=response):
                    with self.assertRaises(Problem):detection_acceptance.run(self.store,self.pid)
        self.assertEqual(set(self.store.blobs.iterdir()),before)

    def test_inconsistent_worker_metrics_never_become_passing_report(self):
        rules=detection.library(self.store,self.pid)['rules'];before=set(self.store.blobs.iterdir())
        base={'true_positive':1,'false_positive':0,'false_negative':0,'true_negative':10,'precision':1.0,'recall':1.0,'passed':True}
        for changes in ({'false_positive':1,'true_negative':9,'precision':0.5},{'precision':0.25},{'true_positive':True},{'true_negative':11}):
            response=[{'id':item['id'],'events':11,'passed':True,'metrics':{**base,**changes}} for item in rules]
            with self.subTest(changes=changes):
                with patch.object(worker,'analyze',return_value=response):
                    with self.assertRaises(Problem):detection_acceptance.run(self.store,self.pid)
        self.assertEqual(set(self.store.blobs.iterdir()),before)

    def test_worker_failure_cannot_publish_successful_report(self):
        before=len(self.store.rows("SELECT * FROM evidence"))
        with patch.object(worker,'analyze',side_effect=ValueError('resource limit')):
            with self.assertRaises(Problem):detection_acceptance.run(self.store,self.pid)
        self.assertEqual(len(self.store.rows("SELECT * FROM evidence")),before)

    def test_repeated_runs_reexecute_and_save_distinct_reports(self):
        first=detection_acceptance.run(self.store,self.pid)
        second=detection_acceptance.run(self.store,self.pid)
        self.assertNotEqual(first['evidence']['id'],second['evidence']['id'])
        self.assertTrue(second['report']['passed'])
        state=detection_acceptance.status(self.store,self.pid)
        self.assertEqual(len(state['runs']),2)

    def test_saved_report_verifies_bytes_and_stays_historical(self):
        created=detection_acceptance.run(self.store,self.pid)
        saved=detection_acceptance.report(self.store,self.pid,created['evidence']['id'])
        self.assertEqual(saved['report'],created['report'])
        path=self.store.blobs/created['evidence']['id'];path.chmod(0o600);path.write_bytes(b'{}')
        with self.assertRaises(Problem):detection_acceptance.report(self.store,self.pid,created['evidence']['id'])

    def test_encrypted_restore_preserves_fixture_and_replay(self):
        self.owner_rule();self.fixture();run=detection_acceptance.run(self.store,self.pid)
        payload=backup.export(self.store,'test-acceptance-backup-123')
        destination=Path(self.temp.name)/'restored';backup.restore(payload,'test-acceptance-backup-123',destination);restored=Store(destination)
        try:
            self.assertEqual(detection_acceptance.report(restored,self.pid,run['evidence']['id'])['report'],run['report'])
            self.assertTrue(detection_acceptance.run(restored,self.pid)['report']['passed'])
        finally:restored.close()


class DetectionAcceptanceHTTPTests(StoreCase):
    request=core.HTTPTests.request
    login=core.HTTPTests.login

    def setUp(self):
        super().setUp();self.app=App(('127.0.0.1',0),self.store)
        self.thread=threading.Thread(target=self.app.serve_forever,daemon=True);self.thread.start();self.cookie,self.csrf='',''

    def tearDown(self):
        self.app.shutdown();self.app.server_close();self.thread.join();super().tearDown()

    def test_owner_auth_csrf_strict_fields_and_real_http_run(self):
        path='/api/detection/acceptance?project='+self.pid
        self.assertEqual(self.request(path)[0],401)
        self.assertEqual(self.request('/api/detection/acceptance/run',{'project_id':self.pid})[0],401)
        self.login()
        self.assertEqual(self.request('/api/detection/acceptance/run',{'project_id':self.pid},{'X-CSRF-Token':'bad'})[0],403)
        self.assertEqual(self.request('/api/detection/acceptance/run',{'project_id':self.pid,'command':'anything'})[0],400)
        status,_,body=self.request('/api/detection/acceptance/run',{'project_id':self.pid})
        self.assertEqual(status,200);created=json.loads(body);self.assertTrue(created['report']['passed'])
        status,_,body=self.request('/api/detection/acceptance/report?project='+self.pid+'&id='+created['evidence']['id'])
        self.assertEqual(status,200);self.assertEqual(json.loads(body)['report'],created['report'])

    def test_register_fixture_http_and_wrong_project_report_rejected(self):
        self.login();detection.save(self.store,self.pid,rule());source=self.evidence(encode(dataset()).encode())
        body={'project_id':self.pid,'rule_id':rule()['id'],'evidence_id':source['id'],'expected_indexes':[0]}
        self.assertEqual(self.request('/api/detection/fixtures/register',{**body,'url':'https://invalid.test'})[0],400)
        self.assertEqual(self.request('/api/detection/fixtures/register',body)[0],200)
        created=detection_acceptance.run(self.store,self.pid)
        other=self.store.create_project('other')['id']
        self.assertEqual(self.request('/api/detection/acceptance/report?project='+other+'&id='+created['evidence']['id'])[0],404)

    def test_heavy_execution_slot_and_consecutive_runs_release_before_response(self):
        self.login();self.app.execution_lock.acquire()
        try:
            self.assertEqual(self.request('/api/detection/acceptance/run',{'project_id':self.pid})[0],409)
        finally:self.app.execution_lock.release()
        for _ in range(3):self.assertEqual(self.request('/api/detection/acceptance/run',{'project_id':self.pid})[0],200)
