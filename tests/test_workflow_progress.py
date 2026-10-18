import copy
import json
import unittest
from unittest.mock import patch
import tests.test_platform as core
from cyber_platform import comparison, engine, worker
from cyber_platform.store import Problem, encode


class WorkflowResumeTests(core.StoreCase):
    def failed(self):
        original = self.evidence(b'abc')
        steps = [{'tool':'hashes','evidence_id':original['id'],'expect':{'bytes':3}},
                 {'tool':'hashes','from_step':0,'expect':{'bytes':-1}}]
        job = engine.run(self.store,self.pid,steps)
        self.assertEqual(job['status'],'failed')
        return original,steps,job

    def test_resume_reuses_verified_success_without_rerunning(self):
        original,steps,job=self.failed()
        corrected=copy.deepcopy(steps);corrected[1]['expect']={}
        with patch('cyber_platform.engine.worker.analyze',wraps=worker.analyze) as analyze:
            resumed=engine.run(self.store,self.pid,corrected,resume_id=job['id'])
            self.assertEqual(analyze.call_count,1)
        self.assertEqual(resumed['status'],'succeeded')
        self.assertEqual((resumed['reused'],resumed['executed'],resumed['completed']),(1,1,2))
        self.assertEqual(resumed['results'][0]['evidence_id'],job['results'][0]['evidence_id'])
        self.assertTrue(resumed['results'][0]['reused'])
        rows={j['id']:j for j in self.store.project_data(self.pid)['jobs']}
        self.assertEqual(rows[job['id']]['status'],'failed')
        self.assertEqual(rows[resumed['id']]['spec']['resumed_from'],job['id'])
        self.assertEqual(self.store.read_evidence(self.pid,original['id']),b'abc')

    def test_completed_step_changes_rejected(self):
        _,steps,job=self.failed()
        steps[0]['expect']={'bytes':999}
        with self.assertRaises(Problem) as result:
            engine.run(self.store,self.pid,steps,resume_id=job['id'])
        self.assertEqual(result.exception.status,409)

    def test_changed_engine_rejected(self):
        _,steps,job=self.failed()
        with patch('cyber_platform.engine.fingerprint',return_value='changed'):
            with self.assertRaises(Problem):
                engine.run(self.store,self.pid,steps,resume_id=job['id'])

    def test_tampered_original_rejected_before_new_job(self):
        original,steps,job=self.failed()
        path=self.store.blobs/original['id'];path.chmod(0o600);path.write_bytes(b'tampered')
        with self.assertRaises(Problem):
            engine.run(self.store,self.pid,steps,resume_id=job['id'])
        self.assertEqual(len(self.store.project_data(self.pid)['jobs']),1)

    def test_tampered_result_and_spec_rejected(self):
        _,steps,job=self.failed()
        output=self.store.blobs/job['results'][0]['evidence_id'];output.chmod(0o600);output.write_bytes(b'{}')
        with self.assertRaises(Problem):
            engine.run(self.store,self.pid,steps,resume_id=job['id'])
        with self.store.lock,self.store.db:
            row=self.store.rows('SELECT spec FROM jobs WHERE id=?',(job['id'],))[0]
            spec=json.loads(row['spec']);spec['steps'][0]['tool']='ioc'
            self.store.db.execute('UPDATE jobs SET spec=? WHERE id=?',(encode(spec),job['id']))
        with self.assertRaises(Problem):
            engine.run(self.store,self.pid,steps,resume_id=job['id'])

    def test_cross_project_and_completed_jobs_cannot_resume(self):
        e=self.evidence();steps=[{'tool':'hashes','evidence_id':e['id']}]
        job=engine.run(self.store,self.pid,steps)
        with self.assertRaises(Problem):
            engine.run(self.store,self.pid,steps,resume_id=job['id'])
        other=self.store.create_project('other')
        with self.assertRaises(Problem):
            engine.resume_prefix(self.store,other['id'],job['id'],steps,engine.fingerprint())


class ComparisonTests(core.StoreCase):
    def output(self,data):
        e=self.evidence(data)
        return engine.run(self.store,self.pid,[{'tool':'hashes','evidence_id':e['id']}])['results'][0]['evidence_id']

    def test_real_comparison_persisted_with_both_sources(self):
        left,right=self.output(b'a'),self.output(b'ab')
        result=comparison.compare(self.store,self.pid,left,right)
        self.assertFalse(result['result']['equal'])
        self.assertFalse(result['result']['same_input'])
        self.assertTrue(result['result']['same_engine'])
        self.assertIn('/bytes',[r['path'] for r in result['result']['changes']])
        artifact=json.loads(self.store.read_evidence(self.pid,result['evidence']['id']))
        self.assertEqual([r['id'] for r in artifact['sources']],[left,right])
        self.assertEqual(len([r for r in self.store.project_data(self.pid)['relations'] if r['target']==result['evidence']['id']]),2)

    def test_equal_and_truncated_are_distinct(self):
        self.assertTrue(comparison.differences({'a':1},{'a':1})['equal'])
        truncated=comparison.differences(list(range(1000)),list(range(1000)),max_nodes=10)
        self.assertTrue(truncated['truncated'])
        self.assertFalse(truncated['equal'])
        result=comparison.differences(list(range(200)),[999]*200,max_changes=3)
        self.assertEqual(result['changes_shown'],3)
        self.assertTrue(result['truncated'])

    def test_types_and_json_pointer_are_preserved(self):
        result=comparison.differences({'a/b~c':True},{'a/b~c':1})
        self.assertEqual(result['changes'][0]['path'],'/a~1b~0c')
        self.assertEqual(result['changes'][0]['kind'],'type_changed')

    def test_original_cross_project_and_tampered_evidence_rejected(self):
        e=self.evidence();output=self.output(b'a')
        with self.assertRaises(Problem):comparison.compare(self.store,self.pid,e['id'],output)
        other=self.store.create_project('other')
        with self.assertRaises(Problem):comparison.compare(self.store,other['id'],output,output)
        path=self.store.blobs/output;path.chmod(0o600);path.write_bytes(b'tampered')
        with self.assertRaises(Problem):comparison.compare(self.store,self.pid,output,output)


class AnalyzerWorkerTests(unittest.TestCase):
    def test_trusted_worker_success_and_bad_input_failure(self):
        self.assertEqual(worker.analyze('hashes',b'abc')['bytes'],3)
        with self.assertRaises(ValueError):
            worker.analyze('events',b'not json')
        with self.assertRaises(ValueError):
            worker.analyze('unregistered',b'input')

    def test_expensive_malformed_text_cannot_hold_the_server_forever(self):
        # The old email regex can scan this input quadratically. Either a quick
        # completed result or a controlled CPU/time limit is acceptable; the
        # parent must remain able to run the next trusted analyzer.
        try:
            result=worker.analyze('privacy',b'a'*500000+b'@.')
            self.assertIn('redacted',result)
        except ValueError as exc:
            self.assertTrue(any(word in str(exc).lower() for word in ('limit','resource','time','stopped')))
        self.assertEqual(worker.analyze('hashes',b'next')['bytes'],4)
