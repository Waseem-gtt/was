"""Rule libraries preserve evidence, explicit truth and revision provenance."""
import copy
import json
from unittest.mock import patch
from cyber_platform import detection
from cyber_platform.store import Problem, encode
from tests.test_platform import StoreCase


class DetectionTests(StoreCase):
    def rule(self, **changes):
        return {"id":"owner-login", "title":"Owner login", "version":"1.0.0",
                "license":"CC0-1.0", "source":"owner-authored synthetic", "selection":{"action":"login","outcome":"failure"}, **changes}

    def fixture(self):
        return detection.library(self.store, self.pid)["fixtures"][0]["input"]

    def uploaded(self, value):
        return self.evidence(encode(value).encode(), "events.json")

    def execute(self, value, ids):
        return detection.test(self.store, self.pid, self.uploaded(value)["id"], ids)

    def test_builtin_fixture_all_rules_real_workers(self):
        catalog = detection.library(self.store, self.pid)
        self.assertEqual(len(catalog['rules']), 8)
        self.assertEqual(len(catalog['bundle_sha256']), 64)
        result = self.execute(self.fixture(), [r['id'] for r in catalog['rules']])
        report = result['report']
        self.assertTrue(report['passed'])
        self.assertEqual(report['evaluated_rules'], 8)
        for rule in report['result']['rules']:
            self.assertEqual(rule['metrics'], {'true_positive':1,'false_positive':0,'false_negative':0,'true_negative':10,'precision':1.0,'recall':1.0,'passed':True})
        self.assertEqual(result['evidence']['parent_id'], report['input_evidence'])
        self.assertEqual(detection.verify_report(self.store,self.pid,result['evidence']['id'])['status'], 'supported')
        self.assertTrue(self.store.verify_audit()['valid'])
        self.assertTrue(any(r['target'] == result['evidence']['id'] for r in self.store.project_data(self.pid)['relations']))

    def test_no_truth_never_passes_and_partial_truth_not_full_pass(self):
        events = self.fixture()['events']
        result = self.execute(events, ['was-login-failure'])
        self.assertFalse(result['report']['passed'])
        self.assertEqual(result['report']['evaluation_status'],'not_evaluated')
        self.assertIsNone(result['report']['result']['rules'][0]['metrics'])
        self.assertEqual(detection.verify_report(self.store,self.pid,result['evidence']['id'])['status'],'unverified')
        result = self.execute({'schema':'was.event/1','events':events,'expected_matches':{'was-login-failure':[0]}}, ['was-login-failure','was-audit-disabled'])
        self.assertEqual(result['report']['evaluated_rules'],1)
        self.assertFalse(result['report']['passed'])

    def test_metrics_false_positive_negative_and_undefined(self):
        inp = self.fixture()
        inp['expected_matches'] = {'was-login-failure':[1]}
        result = self.execute(inp,['was-login-failure'])
        metrics = result['report']['result']['rules'][0]['metrics']
        self.assertEqual(metrics['false_positive'],1)
        self.assertEqual(metrics['false_negative'],1)
        self.assertEqual(metrics['precision'],0)
        self.assertEqual(detection.verify_report(self.store,self.pid,result['evidence']['id'])['status'],'gap')
        result = self.execute({'schema':'was.event/1','events':[],'expected_matches':{'was-login-failure':[]}},['was-login-failure'])
        metrics = result['report']['result']['rules'][0]['metrics']
        self.assertTrue(metrics['passed'])
        self.assertIsNone(metrics['precision'])
        self.assertIsNone(metrics['recall'])

    def test_owner_revisions_immutable_restart_and_latest_provenance(self):
        first = detection.save(self.store,self.pid,self.rule())
        data = self.store.read_evidence(self.pid,first['evidence']['id'])
        with self.assertRaises(Problem):
            detection.save(self.store,self.pid,self.rule(title='overwrite'))
        second = detection.save(self.store,self.pid,self.rule(version='1.0.1',selection={'outcome':'denied'}))
        self.assertEqual(second['revision'],2)
        self.assertEqual(second['evidence']['parent_id'],first['evidence']['id'])
        self.assertEqual(self.store.read_evidence(self.pid,first['evidence']['id']),data)
        rules = detection.library(self.store,self.pid)['rules']
        self.assertEqual(next(r for r in rules if r['id']=='owner-login'),second['rule'])
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_builtin_shadowing_permissions_and_invalid_selections_rejected(self):
        for rule in [self.rule(id='was-login-failure'), self.rule(permissions=['network']),
                     self.rule(selection={'a':{'regex':'.*'}}), self.rule(selection={}),
                     self.rule(selection={'a':float('nan')}), self.rule(version='bad'),
                     self.rule(selection={'a':'x'*1001}), self.rule(id='../escape')]:
            with self.subTest(rule=rule), self.assertRaises(Problem):
                detection.save(self.store,self.pid,rule)
        self.assertEqual(len(self.store.project_data(self.pid)['evidence']),0)

    def test_cross_project_rules_inputs_reports_rejected(self):
        owner = detection.save(self.store,self.pid,self.rule())
        result = self.execute(self.fixture(),['was-login-failure'])
        other = self.store.create_project('other')['id']
        self.assertFalse(any(r['id']=='owner-login' for r in detection.library(self.store,other)['rules']))
        with self.assertRaises(Problem):
            detection.test(self.store,other,result['report']['input_evidence'],['was-login-failure'])
        with self.assertRaises(Problem):
            detection.test(self.store,other,self.uploaded([])['id'],['owner-login'])
        self.assertEqual(detection.verify_report(self.store,other,result['evidence']['id'])['status'],'stale')
        self.assertEqual(owner['revision'],1)

    def test_bad_truth_and_duplicate_keys_before_writes(self):
        for truth in ({'was-login-failure':[True]}, {'was-login-failure':[0,0]}, {'was-login-failure':[-1]}, {'was-login-failure':[11]}, {'was-login-failure':'0'}):
            value = self.fixture()
            value['expected_matches']=truth
            inp = self.uploaded(value)
            before = len(self.store.project_data(self.pid)['evidence'])
            with self.assertRaises(Problem):
                detection.test(self.store,self.pid,inp['id'],['was-login-failure'])
            self.assertEqual(len(self.store.project_data(self.pid)['evidence']),before)
        inp = self.evidence(b'{"schema":"was.event/1","events":[],"events":[]}')
        with self.assertRaises(Problem):
            detection.test(self.store,self.pid,inp['id'],['was-login-failure'])

    def test_tampered_source_and_rule_revision_fail_closed(self):
        result = self.execute(self.fixture(),['was-login-failure'])
        path = self.store.blobs / result['report']['input_evidence']
        path.chmod(0o600)
        path.write_bytes(b'[]')
        self.assertEqual(detection.verify_report(self.store,self.pid,result['evidence']['id'])['status'],'stale')
        owner = detection.save(self.store,self.pid,self.rule())
        path = self.store.blobs / owner['evidence']['id']
        path.chmod(0o600)
        path.write_bytes(b'{}')
        with self.assertRaises(Problem):
            detection.library(self.store,self.pid)

    def test_new_revision_and_engine_changes_mark_old_report_stale(self):
        detection.save(self.store,self.pid,self.rule())
        inp = self.fixture()
        inp['expected_matches']['owner-login']=[0]
        result = self.execute(inp,['owner-login'])
        eid = result['evidence']['id']
        self.assertEqual(detection.verify_report(self.store,self.pid,eid)['status'],'supported')
        with patch.object(detection,'_engine',return_value='0'*64):
            self.assertEqual(detection.verify_report(self.store,self.pid,eid)['status'],'stale')
        detection.save(self.store,self.pid,self.rule(version='1.1.0'))
        self.assertEqual(detection.verify_report(self.store,self.pid,eid)['status'],'stale')

    def test_forged_report_boolean_and_math_replayed(self):
        result = self.execute(self.fixture(),['was-login-failure'])
        forged = copy.deepcopy(result['report'])
        forged['result']['rules'][0]['matched_event_indexes']=[1]
        blob = self.store.add_evidence(self.pid,'forged.json',encode(forged).encode(),'detection-test',result['report']['input_evidence'])
        self.assertEqual(detection.verify_report(self.store,self.pid,blob['id'])['status'],'stale')
        original = self.store.add_evidence(self.pid,'original.json',encode(result['report']).encode())
        self.assertEqual(detection.verify_report(self.store,self.pid,original['id'])['status'],'unverified')

    def test_revision_caps_and_rule_list_validation(self):
        for i in range(10):
            detection.save(self.store,self.pid,self.rule(version=f'1.0.{i}'))
        with self.assertRaises(Problem):
            detection.save(self.store,self.pid,self.rule(version='1.1.0'))
        inp = self.uploaded([])
        for ids in ([],['was-login-failure']*2,[{}],['unknown']):
            with self.subTest(ids=ids), self.assertRaises(Problem):
                detection.test(self.store,self.pid,inp['id'],ids)

    def test_audit_break_blocks_save_and_analysis(self):
        inp = self.uploaded([])
        with self.store.db:
            self.store.db.execute("UPDATE audit SET hash=? WHERE seq=1",('0'*64,))
        before = len(self.store.project_data(self.pid)['evidence'])
        with self.assertRaises(Problem):
            detection.save(self.store,self.pid,self.rule())
        with self.assertRaises(Problem):
            detection.test(self.store,self.pid,inp['id'],['was-login-failure'])
        self.assertEqual(len(self.store.project_data(self.pid)['evidence']),before)

    def test_transaction_failure_does_not_leave_blob_or_record(self):
        before = set(self.store.blobs.iterdir())
        with patch.object(self.store,'audit',side_effect=RuntimeError('synthetic failure')):
            with self.assertRaises(RuntimeError):
                detection.save(self.store,self.pid,self.rule())
        self.assertEqual(set(self.store.blobs.iterdir()),before)
        self.assertEqual(len(self.store.project_data(self.pid)['evidence']),0)
        self.assertEqual(self.store.setting(detection.PREFIX+self.pid),None)

    def test_normalized_wrapper_requires_verified_lineage(self):
        wrapped = {'schema':'was.event-evidence/1','result':{'schema':'was.event/1','events':self.fixture()['events']},'expected_matches':{'was-login-failure':[0]}}
        with self.assertRaises(Problem):
            self.execute(wrapped,['was-login-failure'])
        from cyber_platform import event_ingest
        original = self.uploaded([{'time':'2026-01-01T00:00:00Z','event_id':4625,'action':'login','outcome':'failure'}])
        normalized = event_ingest.normalize(self.store,self.pid,original['id'],'windows-json')
        result = detection.test(self.store,self.pid,normalized['evidence']['id'],['was-login-failure'])
        self.assertEqual(result['report']['evaluation_status'],'not_evaluated')
        self.assertEqual(detection.verify_report(self.store,self.pid,result['evidence']['id'])['status'],'unverified')
        path = self.store.blobs / original['id']
        path.chmod(0o600)
        path.write_bytes(b'[]')
        self.assertEqual(detection.verify_report(self.store,self.pid,result['evidence']['id'])['status'],'stale')

    def test_negative_only_math_pass_does_not_support_coverage(self):
        result = self.execute({'schema':'was.event/1','events':[{'action':'login','outcome':'success'}],'expected_matches':{'was-login-failure':[]}},['was-login-failure'])
        self.assertTrue(result['report']['passed'])
        self.assertEqual(detection.verify_report(self.store,self.pid,result['evidence']['id'])['status'],'unverified')

    def test_engine_change_during_execution_never_publishes_or_supports(self):
        inp = self.uploaded(self.fixture())
        before = len(self.store.project_data(self.pid)['evidence'])
        with patch.object(detection, '_engine', side_effect=['a'*64, 'b'*64]):
            with self.assertRaises(Problem):
                detection.test(self.store, self.pid, inp['id'], ['was-login-failure'])
        self.assertEqual(len(self.store.project_data(self.pid)['evidence']), before)
        tested = detection.test(self.store, self.pid, inp['id'], ['was-login-failure'])
        engine = tested['report']['engine_sha256']
        with patch.object(detection, '_engine', side_effect=[engine, 'f'*64]):
            self.assertEqual(detection.verify_report(self.store, self.pid, tested['evidence']['id'])['status'], 'stale')
