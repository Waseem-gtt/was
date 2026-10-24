"""Real signed synthetic Wasm packages; no owner keys, files or network."""
import base64
import hashlib
import json
from pathlib import Path
from unittest.mock import patch
import wasmtime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cyber_platform import backup, plugin_installations as plugins
from cyber_platform.store import Problem, Store, encode
from tests.test_platform import StoreCase


def module(delta=0):
    return bytes(wasmtime.wat2wasm('''(module
      (memory (export "memory") 2)
      (data (i32.const 0) "{\\22length_mod10\\22:0}")
      (func (export "alloc") (param i32) (result i32) (i32.const 1024))
      (func (export "analyze") (param i32 i32) (result i64)
        (i32.store8 (i32.const 16) (i32.add (i32.const 48)
          (i32.rem_u (i32.add (local.get 1) (i32.const '''+str(delta)+''')) (i32.const 10))))
        (i64.const 18)))'''))


class PluginInstallationsTests(StoreCase):
    def setUp(self):
        super().setUp()
        self.key=Ed25519PrivateKey.generate()
        raw=self.key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.public=base64.b64encode(raw).decode()
        self.key_id=hashlib.sha256(raw).hexdigest()

    def package_value(self,version='1.0.0',delta=0,identifier='synthetic.length',dependencies=None,expected=None):
        code=module(delta)
        manifest={'id':identifier,'version':version,'license':'MIT','source':'https://example.test/synthetic',
                  'permissions':['selected_evidence.read','derived_evidence.write'],
                  'dependencies':dependencies or []}
        fixture={'input_base64':base64.b64encode(b'abcd').decode(),
                 'expected':{'length_mod10':(4+delta)%10} if expected is None else expected}
        signed={'schema':'was.plugin-package/1','manifest':manifest,'module_sha256':hashlib.sha256(code).hexdigest(),'fixtures':[fixture]}
        return {'signed':signed,'module_base64':base64.b64encode(code).decode(),'public_key':self.public,
                'signature':base64.b64encode(self.key.sign(encode(signed).encode())).decode()}

    def source(self,**kwargs):
        return self.evidence(encode(self.package_value(**kwargs)).encode(),'signed-package.json')

    def trust(self):
        return plugins.trust(self.store,self.pid,self.public)

    def install(self,**kwargs):
        source=self.source(**kwargs)
        return plugins.install(self.store,self.pid,source['id'])

    def activate(self,version='1.0.0',identifier='synthetic.length'):
        return plugins.transition(self.store,self.pid,identifier,'activate',version)

    def prepared(self):
        self.trust();self.install();self.activate()

    def test_install_requires_explicit_trust_and_never_automatically_activates(self):
        source=self.source()
        with patch.object(plugins.plugin_wasm,'execute_batch') as execute:
            with self.assertRaises(Problem):plugins.install(self.store,self.pid,source['id'])
            execute.assert_not_called()
        self.trust();saved=plugins.install(self.store,self.pid,source['id'])
        self.assertEqual(saved['record']['action'],'install')
        item=plugins.view(self.store,self.pid)['plugins'][0]
        self.assertEqual(item['state'],'disabled');self.assertIsNone(item['current_version'])
        with self.assertRaises(Problem):plugins.run(self.store,self.pid,'synthetic.length',self.evidence()['id'])

    def test_actual_variable_input_run_has_immutable_output_and_source_proof(self):
        self.prepared();source=self.evidence(b'12345678901')
        result=plugins.run(self.store,self.pid,'synthetic.length',source['id'])
        self.assertEqual(result['record']['result'],{'length_mod10':1})
        self.assertEqual(result['record']['input_sha256'],source['sha256'])
        self.assertEqual(result['record']['runtime_sha256'],plugins.fingerprint())
        self.assertEqual(result['evidence']['kind'],'plugin-installation')
        view=plugins.view(self.store,self.pid)
        self.assertTrue(view['runs'][0]['historical']);self.assertTrue(view['runs'][0]['current_runtime'])
        self.assertNotIn('module_base64',encode(view));self.assertNotIn('input_base64',encode(view))
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_replace_disable_reenable_and_explicit_rollback_execute_real_versions(self):
        self.prepared();source=self.evidence(b'abc')
        self.install(version='2.0.0',delta=1)
        self.assertEqual(plugins.run(self.store,self.pid,'synthetic.length',source['id'])['record']['result'],{'length_mod10':3})
        self.activate('2.0.0')
        self.assertEqual(plugins.run(self.store,self.pid,'synthetic.length',source['id'])['record']['result'],{'length_mod10':4})
        plugins.transition(self.store,self.pid,'synthetic.length','disable')
        with self.assertRaises(Problem):plugins.run(self.store,self.pid,'synthetic.length',source['id'])
        self.activate('2.0.0')
        with self.assertRaises(Problem):self.activate('1.0.0')
        plugins.transition(self.store,self.pid,'synthetic.length','rollback','1.0.0')
        self.assertEqual(plugins.run(self.store,self.pid,'synthetic.length',source['id'])['record']['result'],{'length_mod10':3})

    def test_invalid_signature_and_module_digest_execute_no_fixture(self):
        self.trust()
        for change in ('signature','module_sha256'):
            value=self.package_value()
            if change=='signature':value['signature']=base64.b64encode(b'\0'*64).decode()
            else:value['signed']['module_sha256']='0'*64
            source=self.evidence(encode(value).encode())
            with patch.object(plugins.plugin_wasm,'execute_batch') as execute:
                with self.assertRaises(Problem):plugins.install(self.store,self.pid,source['id'])
                execute.assert_not_called()
        self.assertEqual(plugins.view(self.store,self.pid)['plugins'],[])

    def test_reference_fixture_failure_does_not_install(self):
        self.trust()
        with self.assertRaises(Problem):self.install(expected={'length_mod10':9})
        self.assertEqual(plugins.view(self.store,self.pid)['plugins'],[])

    def test_expected_bool_is_not_integer_and_batch_shape_is_strict(self):
        self.trust();source=self.source(expected={'length_mod10':True})
        with patch.object(plugins.plugin_wasm,'execute_batch',return_value=[{'length_mod10':1}]):
            with self.assertRaises(Problem):plugins.install(self.store,self.pid,source['id'])
        with patch.object(plugins.plugin_wasm,'execute_batch',return_value=[]):
            with self.assertRaises(Problem):self.install()
        self.assertEqual(plugins.view(self.store,self.pid)['plugins'],[])

    def test_revocation_blocks_active_version_and_cannot_silently_retrust(self):
        self.prepared();plugins.revoke(self.store,self.pid,self.key_id)
        view=plugins.view(self.store,self.pid)
        self.assertEqual(view['plugins'][0]['effective_state'],'blocked')
        self.assertEqual(view['trust'][0]['state'],'revoked')
        with self.assertRaises(Problem):plugins.trust(self.store,self.pid,self.public)
        with self.assertRaises(Problem):plugins.run(self.store,self.pid,'synthetic.length',self.evidence()['id'])
        with self.assertRaises(Problem):self.activate()
        plugins.transition(self.store,self.pid,'synthetic.length','disable')

    def test_exact_active_dependencies_and_later_drift_block_execution(self):
        self.prepared()
        dependency=[{'id':'synthetic.length','version':'1.0.0'}]
        self.install(identifier='synthetic.consumer',dependencies=dependency)
        self.activate(identifier='synthetic.consumer')
        self.assertEqual(plugins.view(self.store,self.pid)['plugins'][1]['effective_state'],'active')
        self.install(version='2.0.0',delta=1);self.activate('2.0.0')
        consumer=next(i for i in plugins.view(self.store,self.pid)['plugins'] if i['id']=='synthetic.consumer')
        self.assertEqual(consumer['effective_state'],'blocked')
        with self.assertRaises(Problem):plugins.run(self.store,self.pid,'synthetic.consumer',self.evidence()['id'])

    def test_missing_or_self_dependency_and_incompatible_runtime_execute_nothing(self):
        self.trust()
        for dep in [[{'id':'absent','version':'1.0.0'}],[{'id':'synthetic.length','version':'1.0.0'}]]:
            with patch.object(plugins.plugin_wasm,'execute_batch') as execute:
                with self.assertRaises(Problem):self.install(dependencies=dep)
                execute.assert_not_called()
        value=self.package_value();value['signed']['manifest']['compatibility']={'python_min':'99.0','python_max':'99.1','platform':'linux'}
        value['signature']=base64.b64encode(self.key.sign(encode(value['signed']).encode())).decode()
        source=self.evidence(encode(value).encode())
        with patch.object(plugins.plugin_wasm,'execute_batch') as execute:
            with self.assertRaises(Problem):plugins.install(self.store,self.pid,source['id'])
            execute.assert_not_called()

    def test_dependency_cycle_is_rejected_before_fixture_execution(self):
        self.prepared()
        self.install(identifier='synthetic.consumer',dependencies=[{'id':'synthetic.length','version':'1.0.0'}])
        self.activate(identifier='synthetic.consumer')
        with patch.object(plugins.plugin_wasm,'execute_batch') as execute:
            with self.assertRaises(Problem):self.install(version='2.0.0',dependencies=[{'id':'synthetic.consumer','version':'1.0.0'}])
            execute.assert_not_called()

    def test_package_and_input_must_be_original_and_same_project(self):
        self.trust();source=self.source();other=self.store.create_project('other')['id']
        with self.assertRaises(Problem):plugins.install(self.store,other,source['id'])
        derived=self.store.add_evidence(self.pid,'derived.json',encode(self.package_value()).encode(),'result')
        with self.assertRaises(Problem):plugins.install(self.store,self.pid,derived['id'])
        plugins.install(self.store,self.pid,source['id']);self.activate()
        with self.assertRaises(Problem):plugins.run(self.store,self.pid,'synthetic.length',derived['id'])
        remote=self.store.add_evidence(other,'foreign.txt',b'foreign')
        with self.assertRaises(Problem):plugins.run(self.store,self.pid,'synthetic.length',remote['id'])

    def test_package_and_input_tampering_invalidate_read_and_execution(self):
        self.prepared();source=self.evidence(b'abc');plugins.run(self.store,self.pid,'synthetic.length',source['id'])
        path=self.store.blobs/source['id'];path.chmod(0o600);path.write_bytes(b'tampered')
        with self.assertRaises(Problem):plugins.view(self.store,self.pid)
        with self.assertRaises(Problem):plugins.run(self.store,self.pid,'synthetic.length',source['id'])

    def test_deleted_or_copied_receipt_cannot_rewrite_journal_membership(self):
        saved=self.trust();eid=saved['evidence']['id']
        self.store.db.execute('DELETE FROM evidence WHERE id=?',(eid,));self.store.db.commit()
        with self.assertRaises(Problem):plugins.view(self.store,self.pid)

    def test_copied_unenrolled_receipt_is_rejected(self):
        saved=self.trust();raw=self.store.read_evidence(self.pid,saved['evidence']['id'])
        self.store.add_evidence(self.pid,'copy.json',raw,'plugin-installation')
        with self.assertRaises(Problem):plugins.view(self.store,self.pid)

    def test_publication_failure_removes_blob_row_relation_and_audit(self):
        self.trust();source=self.source();before={p.name for p in self.store.blobs.iterdir()}
        original=self.store.audit
        def fail(action,details):
            original(action,details)
            if action=='plugin-installation.created':raise Problem('synthetic failure',409)
        with patch.object(self.store,'audit',fail):
            with self.assertRaises(Problem):plugins.install(self.store,self.pid,source['id'])
        self.assertEqual({p.name for p in self.store.blobs.iterdir()},before)
        self.assertEqual(plugins.view(self.store,self.pid)['plugins'],[])
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_source_change_during_audit_cannot_publish_installation(self):
        self.trust();source=self.source();before={p.name for p in self.store.blobs.iterdir()};original=self.store.audit
        def mutate(action,details):
            original(action,details)
            if action=='plugin-installation.created':
                path=self.store.blobs/source['id'];path.chmod(0o600);path.write_bytes(b'changed')
        with patch.object(self.store,'audit',mutate):
            with self.assertRaises(Problem):plugins.install(self.store,self.pid,source['id'])
        self.assertEqual({p.name for p in self.store.blobs.iterdir()},before)
        self.assertEqual(plugins.view(self.store,self.pid)['plugins'],[])

    def test_trust_change_during_execution_prevents_result_publication(self):
        self.prepared();source=self.evidence(b'abc');execute=plugins.plugin_wasm.execute
        def mutate(module_bytes,input_bytes):
            result=execute(module_bytes,input_bytes);plugins.revoke(self.store,self.pid,self.key_id);return result
        with patch.object(plugins.plugin_wasm,'execute',mutate):
            with self.assertRaises(Problem):plugins.run(self.store,self.pid,'synthetic.length',source['id'])
        self.assertEqual(plugins.view(self.store,self.pid)['runs'],[])

    def test_engine_change_after_execution_prevents_result_publication(self):
        self.prepared();source=self.evidence(b'abc');before=plugins.fingerprint()
        with patch.object(plugins,'fingerprint',side_effect=[before,'f'*64]):
            with self.assertRaises(Problem):plugins.run(self.store,self.pid,'synthetic.length',source['id'])
        self.assertEqual(plugins.view(self.store,self.pid)['runs'],[])

    def test_run_failure_never_publishes_success(self):
        self.prepared();source=self.evidence(b'abc')
        with patch.object(plugins.plugin_wasm,'execute',side_effect=ValueError('synthetic private error')):
            with self.assertRaises(Problem):plugins.run(self.store,self.pid,'synthetic.length',source['id'])
        self.assertEqual(plugins.view(self.store,self.pid)['runs'],[])

    def test_encrypted_restore_preserves_packages_trust_versions_and_real_execution(self):
        self.prepared();source=self.evidence(b'abc');plugins.run(self.store,self.pid,'synthetic.length',source['id'])
        exported=backup.export(self.store,'synthetic-backup-passphrase')
        target=Path(self.temp.name)/'restored';backup.restore(exported,'synthetic-backup-passphrase',target)
        restored=Store(target)
        try:
            self.assertEqual(plugins.view(restored,self.pid)['plugins'],plugins.view(self.store,self.pid)['plugins'])
            self.assertEqual(plugins.run(restored,self.pid,'synthetic.length',source['id'])['record']['result'],{'length_mod10':3})
        finally:restored.close()
