"""Bounded workflow DAGs preserve provenance and never silently repeat a node."""
import copy
import hashlib
import json
import threading
from unittest.mock import patch
from cyber_platform import plans, tools
from cyber_platform.store import Problem, Store, encode
from tests.test_platform import StoreCase


class PlanTests(StoreCase):
    def node(self,nid='scan',tool='ioc',**changes):
        inp=changes.pop('input',{'evidence_id':self.source['id']})
        return {'id':nid,'tool':tool,'input':inp,**changes}

    def plan(self,nodes=None):
        return {'schema':'was.plan/1','name':'Synthetic plan','nodes':nodes or [self.node()]}

    def setUp(self):
        super().setUp();self.source=self.evidence(b'192.0.2.1','source.txt')

    def finish(self,run):
        for _ in range(25):
            if run['status'] in ('completed','failed'):return run
            run=plans.advance(self.store,self.pid,run['id'])
        self.fail('plan did not terminate')

    def saved(self,run_id):return self.store.setting(plans.PREFIX+self.pid+'.'+run_id)

    def alter(self,run_id,callback):
        with self.store.lock,self.store.db:
            r=self.saved(run_id);callback(r)
            r['record_sha256']=plans._digest({k:v for k,v in r.items() if k!='record_sha256'})
            self.store.db.execute('UPDATE settings SET value=? WHERE key=?',(encode(r),plans.PREFIX+self.pid+'.'+run_id))

    def test_validate_toposorts_infers_dependencies_and_slots(self):
        child=self.node('child','hashes',input={'node_id':'scan'})
        plan=plans.validate(self.plan([child,self.node()]))
        self.assertEqual([n['id'] for n in plan['nodes']],['scan','child'])
        self.assertEqual(plan['nodes'][1]['depends_on'],['scan'])
        self.assertEqual(plan['nodes'][0]['expect'],{})
        template=self.plan([self.node(input={'slot':'source'})])
        self.assertEqual(plans.validate(template,allow_slots=True)['nodes'][0]['input'],{'slot':'source'})
        with self.assertRaises(Problem):plans.validate(template)

    def test_cycles_unknown_refs_tools_fields_and_types_rejected(self):
        values=[self.plan([self.node(input={'node_id':'missing'})]),self.plan([self.node(depends_on=['scan'])]),
                self.plan([self.node('a',depends_on=['b']),self.node('b',depends_on=['a'])]),
                self.plan([self.node(tool='shell')]),self.plan([self.node(command='rm')]),
                self.plan([self.node(expect={'x':float('nan')})]),self.plan([self.node(input={'slot':'../secret'})]),
                self.plan([self.node(),self.node()]),self.plan([self.node(when={'node_id':'x','status':'any'})])]
        for value in values:
            with self.subTest(value=value),self.assertRaises(Problem):plans.validate(value)
        self.assertEqual(self.store.rows("SELECT key FROM settings WHERE key LIKE 'plans.run.%'"),[])

    def test_real_dag_chain_uses_full_report_and_atomic_links(self):
        run=plans.start(self.store,self.pid,self.plan([self.node(expect={'ipv4.0':'192.0.2.1'}),self.node('hash','hashes',input={'node_id':'scan'})]))
        done=self.finish(run)
        self.assertEqual(done['status'],'completed');self.assertTrue(done['passed'])
        self.assertEqual(done['counts'],{'total':2,'completed':2,'succeeded':2,'failed':0,'skipped':0})
        first=self.store.read_evidence(self.pid,done['results'][0]['evidence_id'])
        second=json.loads(self.store.read_evidence(self.pid,done['results'][1]['evidence_id']))
        self.assertEqual(second['result']['sha256'],hashlib.sha256(first).hexdigest())
        self.assertEqual(plans.status(self.store,self.pid,run['id']),done)
        self.assertEqual(len(self.store.project_data(self.pid)['relations']),2)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_failure_branch_and_false_branch_are_distinct_from_success(self):
        run=plans.start(self.store,self.pid,self.plan([self.node(expect={'ipv4.0':'192.0.2.99'}),
            self.node('yes','hashes',when={'node_id':'scan','status':'succeeded'}),
            self.node('no','hashes',input={'node_id':'scan'},when={'node_id':'scan','status':'failed'})]))
        done=self.finish(run)
        self.assertEqual(done['status'],'completed');self.assertFalse(done['passed'])
        self.assertEqual(done['counts'],{'total':3,'completed':3,'succeeded':1,'failed':1,'skipped':1})
        self.assertEqual(done['results'][1]['reason'],'condition_not_met')
        self.assertEqual(done['results'][2]['status'],'succeeded')

    def test_skipped_dependency_propagates_without_running_analyzer(self):
        p=self.plan([self.node(),self.node('branch','hashes',when={'node_id':'scan','status':'failed'}),self.node('child','hashes',input={'node_id':'branch'})])
        done=self.finish(plans.start(self.store,self.pid,p))
        self.assertTrue(done['passed'])
        self.assertEqual([r['status'] for r in done['results']],['succeeded','skipped','skipped'])
        self.assertEqual(done['results'][2]['reason'],'dependency_not_succeeded')

    def test_pause_resume_reopen_and_batch_limit(self):
        p=self.plan([self.node('a'),self.node('b'),self.node('c')]);run=plans.start(self.store,self.pid,p)
        first=plans.advance(self.store,self.pid,run['id'])
        self.assertEqual(first['counts']['completed'],2)
        paused=plans.pause(self.store,self.pid,run['id']);self.assertEqual(paused['status'],'paused')
        self.assertEqual(plans.advance(self.store,self.pid,run['id']),paused)
        self.store.close();self.store=Store(self.store.root)
        self.assertEqual(plans.status(self.store,self.pid,run['id']),paused)
        resumed=plans.resume(self.store,self.pid,run['id']);self.assertEqual(resumed['status'],'running')
        self.assertTrue(self.finish(resumed)['passed'])
        self.assertEqual(len(plans.history(self.store,self.pid)['runs']),1)

    def test_worker_error_has_artifact_and_failure_branch_can_inspect_it(self):
        run=plans.start(self.store,self.pid,self.plan([self.node(),self.node('failure','hashes',input={'node_id':'scan'},when={'node_id':'scan','status':'failed'})]))
        original=plans.worker.analyze
        def fail_first(tool,data,**kwargs):
            if tool=='ioc':raise ValueError('synthetic timeout')
            return original(tool,data,**kwargs)
        with patch.object(plans.worker,'analyze',side_effect=fail_first):done=self.finish(run)
        self.assertEqual(done['results'][0]['error_code'],'worker_error')
        self.assertEqual(done['results'][1]['status'],'succeeded')
        self.assertFalse(done['passed'])
        self.assertEqual(json.loads(self.store.read_evidence(self.pid,done['results'][0]['evidence_id']))['acceptance'],'execution_failed')

    def test_crash_leaves_inflight_and_cannot_repeat_after_reopen(self):
        run=plans.start(self.store,self.pid,self.plan())
        with patch.object(plans.worker,'analyze',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):plans.advance(self.store,self.pid,run['id'])
        self.store.close();self.store=Store(self.store.root)
        with patch.object(plans.worker,'analyze') as worker:
            failed=plans.advance(self.store,self.pid,run['id']);worker.assert_not_called()
        self.assertEqual(failed['error_code'],'interrupted_node');self.assertFalse(failed['passed'])
        self.assertEqual(failed['counts']['completed'],0)

    def test_changed_root_and_output_block_reuse(self):
        run=plans.start(self.store,self.pid,self.plan([self.node(),self.node('b'),self.node('c')]))
        first=plans.advance(self.store,self.pid,run['id'])
        blob=self.store.blobs/first['results'][0]['evidence_id'];blob.chmod(0o600);blob.write_bytes(b'forged')
        with patch.object(plans.worker,'analyze') as worker:
            failed=plans.advance(self.store,self.pid,run['id']);worker.assert_not_called()
        self.assertEqual(failed['error_code'],'result_changed')
        run=plans.start(self.store,self.pid,self.plan())
        blob=self.store.blobs/self.source['id'];blob.chmod(0o600);blob.write_bytes(b'changed')
        self.assertEqual(plans.status(self.store,self.pid,run['id'])['error_code'],'source_changed')
        self.assertEqual(plans.advance(self.store,self.pid,run['id'])['error_code'],'source_changed')

    def test_engine_change_before_or_during_execution_cannot_publish(self):
        run=plans.start(self.store,self.pid,self.plan());fp=run['engine_sha256']
        with patch.object(plans,'fingerprint',return_value='f'*64):
            self.assertEqual(plans.advance(self.store,self.pid,run['id'])['error_code'],'engine_changed')
        run=plans.start(self.store,self.pid,self.plan())
        with patch.object(plans,'fingerprint',side_effect=[fp,fp,'e'*64]):
            failed=plans.advance(self.store,self.pid,run['id'])
        self.assertEqual(failed['error_code'],'engine_changed')
        self.assertEqual(self.store.rows("SELECT id FROM evidence WHERE kind='plan-result'"),[])

    def test_saved_false_pass_and_skip_forgery_rejected_even_with_record_hash(self):
        run=plans.start(self.store,self.pid,self.plan())
        self.alter(run['id'],lambda r:r.update(passed=True))
        with self.assertRaises(Problem):plans.status(self.store,self.pid,run['id'])
        self.alter(run['id'],lambda r:r.update(passed=False))
        run=plans.start(self.store,self.pid,self.plan())
        def forge(r):
            r.update(status='completed',results=[{'node_id':'scan','status':'skipped','reason':'condition_not_met','elapsed_ms':0}])
            r['counts']={'total':1,'completed':1,'succeeded':0,'failed':0,'skipped':1}
        self.alter(run['id'],forge)
        with self.assertRaises(Problem):plans.status(self.store,self.pid,run['id'])

    def test_cross_project_unknown_ids_and_oversized_sources_rejected(self):
        other=self.store.create_project('Other')['id']
        with self.assertRaises(Problem):plans.start(self.store,other,self.plan())
        run=plans.start(self.store,self.pid,self.plan())
        with self.assertRaises(Problem):plans.status(self.store,other,run['id'])
        with self.assertRaises(Problem):plans.status(self.store,self.pid,'../unsafe')
        huge=self.evidence(b'x'*(4*1024*1024+1))
        with self.assertRaises(Problem) as caught:plans.start(self.store,self.pid,self.plan([self.node(input={'evidence_id':huge['id']})]))
        self.assertEqual(caught.exception.status,413)

    def test_retention_never_evicts_active_and_preserves_old_artifacts(self):
        runs=[plans.start(self.store,self.pid,self.plan()) for _ in range(20)]
        with self.assertRaises(Problem):plans.start(self.store,self.pid,self.plan())
        done=self.finish(runs[0]);eid=done['results'][0]['evidence_id']
        newest=plans.start(self.store,self.pid,self.plan())
        self.assertEqual(len(plans.history(self.store,self.pid)['runs']),20)
        self.assertTrue(self.store.read_evidence(self.pid,eid))
        with self.assertRaises(Problem):plans.status(self.store,self.pid,done['id'])
        self.assertEqual(plans.status(self.store,self.pid,newest['id'])['status'],'pending')

    def test_atomic_publish_rollback_leaves_only_inflight_and_no_orphan(self):
        run=plans.start(self.store,self.pid,self.plan());before=set(self.store.blobs.iterdir())
        original=self.store.audit
        def fail(action,details):
            if action=='plan.node_finished':raise RuntimeError('synthetic publication failure')
            return original(action,details)
        with patch.object(self.store,'audit',side_effect=fail):
            with self.assertRaises(RuntimeError):plans.advance(self.store,self.pid,run['id'])
        self.assertEqual(set(self.store.blobs.iterdir()),before)
        self.assertEqual(self.store.rows("SELECT id FROM evidence WHERE kind='plan-result'"),[])
        self.assertEqual(self.store.project_data(self.pid)['relations'],[])
        self.assertEqual(self.saved(run['id'])['in_flight'],'scan')
        self.assertEqual(plans.advance(self.store,self.pid,run['id'])['error_code'],'interrupted_node')
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_broken_audit_and_replaced_storage_refuse_mutations(self):
        run=plans.start(self.store,self.pid,self.plan())
        db=self.store.root/'platform.db';old=self.store.root/'old.db';db.rename(old);db.write_bytes(old.read_bytes())
        with self.assertRaises(Problem):plans.advance(self.store,self.pid,run['id'])
        db.unlink();old.rename(db)
        with self.store.db:self.store.db.execute("UPDATE audit SET action='tampered' WHERE seq=1")
        with self.assertRaises(Problem):plans.advance(self.store,self.pid,run['id'])
        with self.assertRaises(Problem):plans.start(self.store,self.pid,self.plan())

    def test_concurrent_advances_never_repeat_a_node(self):
        run=plans.start(self.store,self.pid,self.plan());entered=threading.Event();release=threading.Event();errors=[]
        def analyze(tool,data,**kwargs):entered.set();release.wait(5);return tools.analyze(tool,data)
        def advance():
            try:plans.advance(self.store,self.pid,run['id'])
            except BaseException as exc:errors.append(exc)
        with patch.object(plans.worker,'analyze',side_effect=analyze):
            thread=threading.Thread(target=advance);thread.start();self.assertTrue(entered.wait(5))
            try:
                with self.assertRaises(Problem) as caught:plans.advance(self.store,self.pid,run['id'])
                self.assertEqual(caught.exception.status,409)
            finally:release.set();thread.join(5)
        self.assertFalse(errors)
        self.assertEqual(plans.status(self.store,self.pid,run['id'])['counts']['completed'],1)
        self.assertEqual(len(self.store.rows("SELECT id FROM evidence WHERE kind='plan-result'")),1)

    def test_instantiation_origin_retained_and_tampered_proof_fails_resume(self):
        from cyber_platform import plan_templates
        catalog=plan_templates.library(self.store,self.pid);fixture=catalog['fixtures'][0]
        bindings={slot:self.evidence(raw.encode(),slot+'.txt')['id'] for slot,raw in fixture['inputs'].items()}
        instantiated=plan_templates.instantiate(self.store,self.pid,fixture['template_id'],bindings)
        run=plans.start(self.store,self.pid,instantiated['plan'],instantiation_id=instantiated['evidence']['id'])
        self.assertEqual(run['template_origin']['evidence_id'],instantiated['evidence']['id'])
        self.assertEqual(run['template_origin']['revision'],1)
        plans.pause(self.store,self.pid,run['id'])
        path=self.store.blobs/instantiated['evidence']['id'];path.chmod(0o600);path.write_bytes(b'{}')
        self.assertEqual(plans.resume(self.store,self.pid,run['id'])['error_code'],'template_changed')

    def test_original_owner_template_revision_remains_valid_after_new_revision(self):
        from cyber_platform import plan_templates
        catalog=plan_templates.library(self.store,self.pid);fixture=catalog['fixtures'][0]
        builtin=next(t for t in catalog['templates'] if t['id']==fixture['template_id'])
        own={k:copy.deepcopy(builtin[k]) for k in plan_templates.FIELDS}
        own.update(id='owner-workflow',version='1.0.0')
        plan_templates.save(self.store,self.pid,own)
        bindings={slot:self.evidence(raw.encode(),slot+'.txt')['id'] for slot,raw in fixture['inputs'].items()}
        instantiated=plan_templates.instantiate(self.store,self.pid,own['id'],bindings)
        run=plans.start(self.store,self.pid,instantiated['plan'],instantiation_id=instantiated['evidence']['id'])
        plans.pause(self.store,self.pid,run['id'])
        own['version']='1.0.1';plan_templates.save(self.store,self.pid,own)
        resumed=plans.resume(self.store,self.pid,run['id'])
        self.assertEqual(resumed['status'],'pending')
        self.assertTrue(self.finish(resumed)['passed'])
