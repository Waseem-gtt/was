"""Data-only templates, immutable revision chains and concrete evidence binding."""
import copy
import json
from unittest.mock import patch
from cyber_platform import plan_templates as templates, plans
from cyber_platform.store import Problem, Store, encode
from tests.test_platform import StoreCase


class PlanTemplateTests(StoreCase):
    def template(self, **changes):
        value={'id':'owner-triage','title':'Owner triage','version':'1.0.0','description':'Synthetic data-only template',
               'plan':{'schema':'was.plan/1','name':'Owner plan','nodes':[{'id':'hash','tool':'hashes','input':{'slot':'source'},'depends_on':[],'when':None,'expect':{}}]}}
        value.update(changes);return value

    def fixture_bindings(self, fixture):
        return {slot:self.evidence(text.encode(),slot+'.txt')['id'] for slot,text in fixture['inputs'].items()}

    def test_all_builtin_templates_bind_and_execute_actual_workers(self):
        library=templates.library(self.store,self.pid)
        self.assertEqual(len(library['templates']),8)
        self.assertEqual(len(library['fixtures']),8)
        self.assertEqual(len(library['bundle_sha256']),64)
        for fixture in library['fixtures']:
            with self.subTest(template=fixture['template_id']):
                bindings=self.fixture_bindings(fixture)
                instantiated=templates.instantiate(self.store,self.pid,fixture['template_id'],bindings)
                self.assertEqual(set(instantiated['bindings']),set(fixture['inputs']))
                run=plans.start(self.store,self.pid,instantiated['plan'])
                for _ in range(20):
                    if run['status'] in ('completed','failed'):break
                    run=plans.advance(self.store,self.pid,run['id'])
                self.assertEqual(run['status'],'completed',run)
                self.assertTrue(run['passed'],run)
                for slot,eid in bindings.items():
                    self.assertEqual(self.store.read_evidence(self.pid,eid),fixture['inputs'][slot].encode())
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_binding_is_data_only_exact_scoped_and_original_verified(self):
        library=templates.library(self.store,self.pid)
        fixture=library['fixtures'][0];bindings=self.fixture_bindings(fixture)
        before=self.store.project_data(self.pid)
        value=templates.instantiate(self.store,self.pid,fixture['template_id'],bindings)
        after=self.store.project_data(self.pid)
        self.assertEqual(len(after['evidence']),len(before['evidence'])+1)
        self.assertEqual(after['evidence'][0]['kind'],'plan-instantiation')
        self.assertFalse(self.store.rows("SELECT key FROM settings WHERE key LIKE 'plans.run.%'"))
        self.assertNotIn('slot',encode(value['plan']))
        self.assertEqual(value['template_sha256'],library['templates'][0]['template_sha256'])
        value['plan']['name']='modified local result'
        self.assertEqual(templates.library(self.store,self.pid),library)
        for bad in ({},{**bindings,'extra':next(iter(bindings.values()))},{'source':True},{'source':'../escape'}):
            with self.subTest(binding=bad),self.assertRaises(Problem):
                templates.instantiate(self.store,self.pid,fixture['template_id'],bad)
        other=self.store.create_project('Other')['id']
        with self.assertRaises(Problem):templates.instantiate(self.store,other,fixture['template_id'],bindings)
        eid=bindings['source'];path=self.store.blobs/eid;path.chmod(0o600);path.write_bytes(b'tampered')
        with self.assertRaises(Problem):templates.instantiate(self.store,self.pid,fixture['template_id'],bindings)

    def test_owner_revisions_immutable_and_restart_chain_preserved(self):
        first=templates.save(self.store,self.pid,self.template())
        raw=self.store.read_evidence(self.pid,first['evidence']['id'])
        with self.assertRaises(Problem):templates.save(self.store,self.pid,self.template(title='overwrite'))
        second=templates.save(self.store,self.pid,self.template(version='1.0.1',title='New revision'))
        self.assertEqual(second['revision'],2)
        self.assertEqual(second['evidence']['parent_id'],first['evidence']['id'])
        self.assertEqual(self.store.read_evidence(self.pid,first['evidence']['id']),raw)
        self.store.close();self.store=Store(self.store.root)
        selected=next(t for t in templates.library(self.store,self.pid)['templates'] if t['id']=='owner-triage')
        self.assertEqual(selected,second['template'])
        eid=self.evidence()['id'];instantiated=templates.instantiate(self.store,self.pid,'owner-triage',{'source':eid})
        self.assertEqual(instantiated['revision'],2)
        self.assertEqual(instantiated['template_sha256'],selected['template_sha256'])
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_builtin_reserved_and_unknown_fields_never_write(self):
        invalid=[self.template(id='was-replacement'),self.template(id='../escape'),self.template(version='latest'),
                 self.template(permissions=['network']),self.template(source='arbitrary'),self.template(description='x'*1001),self.template(title='bad\nname')]
        for item in invalid:
            with self.subTest(item=item),self.assertRaises(Problem):templates.save(self.store,self.pid,item)
        self.assertEqual(self.store.project_data(self.pid)['evidence'],[])

    def test_concrete_evidence_cycles_missing_tools_and_code_rejected(self):
        cases=[]
        concrete=self.template();concrete['plan']['nodes'][0]['input']={'evidence_id':self.evidence()['id']};cases.append(concrete)
        badtool=self.template();badtool['plan']['nodes'][0]['tool']='shell';cases.append(badtool)
        cycle=self.template();cycle['plan']['nodes'][0]['depends_on']=['hash'];cases.append(cycle)
        unknown=self.template();unknown['plan']['nodes'][0]['command']='id';cases.append(unknown)
        missing=self.template();missing['plan']['nodes'][0]['input']={'node_id':'missing'};cases.append(missing)
        for item in cases:
            with self.subTest(item=item),self.assertRaises(Problem):templates.save(self.store,self.pid,item)
        self.assertFalse(self.store.rows("SELECT * FROM evidence WHERE kind='plan-template'"))

    def test_plan_and_template_size_bound_and_nonfinite_values(self):
        large=self.template();large['plan']['nodes'][0]['expect']={'x':'x'*65536}
        for item in (large,self.template(description='\ud800')):
            with self.assertRaises(Problem):templates.save(self.store,self.pid,item)
        invalid=self.template();invalid['plan']['nodes'][0]['expect']={'x':float('nan')}
        with self.assertRaises(Problem):templates.save(self.store,self.pid,invalid)

    def test_revision_cap_and_owner_count_cap(self):
        for i in range(10):templates.save(self.store,self.pid,self.template(version='1.0.'+str(i)))
        with self.assertRaises(Problem):templates.save(self.store,self.pid,self.template(version='1.1.0'))
        with patch.dict(templates.LIMITS,owner_templates=1):
            with self.assertRaises(Problem):templates.save(self.store,self.pid,self.template(id='owner-other'))
        self.assertEqual(len(next(t for t in templates._index(self.store,self.pid).values())),10)

    def test_tampered_revision_index_and_chain_never_return_latest(self):
        first=templates.save(self.store,self.pid,self.template())
        templates.save(self.store,self.pid,self.template(version='1.0.1'))
        with self.store.db:
            self.store.db.execute('UPDATE settings SET value=? WHERE key=?',(encode({'owner-triage':[first['evidence']['id'],first['evidence']['id']]}),templates.PREFIX+self.pid))
        with self.assertRaises(Problem):templates.library(self.store,self.pid)
        with self.store.db:self.store.db.execute('UPDATE settings SET value=? WHERE key=?',('null',templates.PREFIX+self.pid))
        with self.assertRaises(Problem):templates.library(self.store,self.pid)

    def test_saved_rule_blob_tamper_and_cross_project_do_not_bind(self):
        saved=templates.save(self.store,self.pid,self.template());blob=self.store.blobs/saved['evidence']['id'];blob.chmod(0o600);blob.write_bytes(b'{}')
        with self.assertRaises(Problem):templates.library(self.store,self.pid)
        other=self.store.create_project('Other')['id']
        with self.assertRaises(Problem):templates.instantiate(self.store,other,'owner-triage',{'source':self.evidence()['id']})

    def test_failed_publication_rolls_back_blob_index_relation_and_audit(self):
        before=self.store.project_data(self.pid);blobs=set(self.store.blobs.iterdir());audit=self.store.rows('SELECT * FROM audit')
        with patch.object(self.store,'audit',side_effect=RuntimeError('simulated failure')):
            with self.assertRaises(RuntimeError):templates.save(self.store,self.pid,self.template())
        self.assertEqual(self.store.project_data(self.pid),before)
        self.assertEqual(set(self.store.blobs.iterdir()),blobs)
        self.assertEqual(self.store.rows('SELECT * FROM audit'),audit)
        self.assertEqual(templates._index(self.store,self.pid),{})

    def test_broken_audit_and_replaced_database_block_writes_and_binding(self):
        source=self.evidence()
        with self.store.db:self.store.db.execute("UPDATE audit SET action='tampered' WHERE seq=1")
        with self.assertRaises(Problem):templates.save(self.store,self.pid,self.template())
        with self.assertRaises(Problem):templates.instantiate(self.store,self.pid,'was-file-triage',{'source':source['id']})

    def test_unknown_template_and_invalid_binding_types(self):
        for identifier,bindings in [('missing',{}),([],{}),('was-file-triage',[]),('was-file-triage',{'source':{}})]:
            with self.subTest(identifier=identifier),self.assertRaises(Problem):templates.instantiate(self.store,self.pid,identifier,bindings)

    def test_instantiation_proof_survives_new_owner_revision_but_not_plan_edits(self):
        first=templates.save(self.store,self.pid,self.template())
        source=self.evidence();instantiated=templates.instantiate(self.store,self.pid,'owner-triage',{'source':source['id']})
        proof=templates.verify_instantiation(self.store,self.pid,instantiated['evidence']['id'],instantiated['plan'])
        self.assertEqual(proof['revision'],1)
        self.assertEqual(proof['template_sha256'],first['template']['template_sha256'])
        templates.save(self.store,self.pid,self.template(version='1.0.1',title='Later owner revision'))
        self.assertEqual(templates.verify_instantiation(self.store,self.pid,instantiated['evidence']['id'],instantiated['plan']),proof)
        edited=copy.deepcopy(instantiated['plan']);edited['name']='edited concrete plan'
        with self.assertRaises(Problem):templates.verify_instantiation(self.store,self.pid,instantiated['evidence']['id'],edited)
        path=self.store.blobs/source['id'];path.chmod(0o600);path.write_bytes(b'changed')
        with self.assertRaises(Problem):templates.verify_instantiation(self.store,self.pid,instantiated['evidence']['id'],instantiated['plan'])

    def test_uploaded_or_tampered_instantiation_proof_rejected(self):
        fixture=templates.library(self.store,self.pid)['fixtures'][0]
        value=templates.instantiate(self.store,self.pid,fixture['template_id'],self.fixture_bindings(fixture))
        raw=self.store.read_evidence(self.pid,value['evidence']['id'])
        uploaded=self.evidence(raw)
        with self.assertRaises(Problem):templates.verify_instantiation(self.store,self.pid,uploaded['id'],value['plan'])
        path=self.store.blobs/value['evidence']['id'];path.chmod(0o600);path.write_bytes(b'{}')
        with self.assertRaises(Problem):templates.verify_instantiation(self.store,self.pid,value['evidence']['id'],value['plan'])
