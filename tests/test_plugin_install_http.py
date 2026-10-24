"""Independent owner HTTP acceptance for explicitly trusted signed Wasm installs."""
import base64
import hashlib
import json
import threading
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cyber_platform import backup
from cyber_platform.server import App, Handler
from cyber_platform.store import Store, encode
from tests.test_platform import StoreCase
import tests.test_platform as core


def b64(raw):
    return base64.b64encode(raw).decode('ascii')


def module_bytes(value=1):
    import wasmtime
    raw=encode({'value':value}).encode()
    escaped=''.join('\\%02x'%byte for byte in raw)
    return bytes(wasmtime.wat2wasm('''(module
      (memory (export "memory") 2 512)
      (data (i32.const 1024) "'''+escaped+'''")
      (func (export "alloc") (param i32) (result i32) i32.const 4096)
      (func (export "analyze") (param i32 i32) (result i64)
        i64.const '''+str((1024<<32)|len(raw))+'''))'''))


class PluginInstallHTTPTests(StoreCase):
    request=core.HTTPTests.request
    login=core.HTTPTests.login

    def setUp(self):
        super().setUp()
        self.app=App(('127.0.0.1',0),self.store)
        self.thread=threading.Thread(target=self.app.serve_forever,daemon=True)
        self.thread.start()
        self.cookie,self.csrf='',''
        self.key=Ed25519PrivateKey.generate()
        self.public=self.key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.key_id=hashlib.sha256(self.public).hexdigest()
        self.input=self.evidence(b'private selected bytes, not a program','selected.txt')

    def tearDown(self):
        self.app.shutdown();self.app.server_close();self.thread.join()
        super().tearDown()

    def package(self,version='1.0.0',value=1,expected=None,changes=None):
        module=module_bytes(value)
        signed={'schema':'was.plugin-package/1','manifest':{
            'id':'review.fixture','version':version,'license':'MIT','source':'https://example.test/review-fixture',
            'permissions':['selected_evidence.read','derived_evidence.write'],
            'dependencies':[], 'compatibility':{'python_min':'3.11','python_max':'3.13','platform':'linux'}},
            'module_sha256':hashlib.sha256(module).hexdigest(),
            'fixtures':[{'input_base64':b64(b'fixture'),'expected':{'value':value} if expected is None else expected}]}
        if changes:signed.update(changes)
        result={'signed':signed,'module_base64':b64(module),'public_key':b64(self.public),'signature':b64(self.key.sign(encode(signed).encode()))}
        return result

    def original_package(self,**kwargs):
        return self.evidence(encode(self.package(**kwargs)).encode(),'signed-package.json')

    def post(self,path,**body):
        return self.request('/api/plugins/'+path,{'project_id':self.pid,**body})

    def success(self,path,**body):
        code,_,raw=self.post(path,**body)
        self.assertIn(code,(200,201),(path,code,raw))
        return json.loads(raw)

    def view(self,pid=None):
        code,_,raw=self.request('/api/plugins/installations?project='+(pid or self.pid))
        self.assertEqual(code,200,raw)
        return json.loads(raw)

    def install_active(self):
        self.success('trust',public_key=b64(self.public))
        package=self.original_package()
        result=self.success('install',evidence_id=package['id'])
        self.success('runtime/transition',plugin_id='review.fixture',action='activate',version='1.0.0')
        return package,result

    def test_owner_auth_precedes_all_plugin_state_and_execution(self):
        paths={'trust':{'public_key':b64(self.public)},'trust/revoke':{'key_id':self.key_id},
               'install':{'evidence_id':self.input['id']},
               'runtime/transition':{'plugin_id':'review.fixture','action':'activate','version':'1.0.0'},
               'runtime/run':{'plugin_id':'review.fixture','evidence_id':self.input['id']}}
        self.assertEqual(self.request('/api/plugins/installations?project='+self.pid)[0],401)
        for path,fields in paths.items():
            self.assertEqual(self.post(path,**fields)[0],401,path)

    def test_csrf_origin_and_unknown_fields_cannot_change_trust(self):
        self.login()
        path='/api/plugins/trust';body={'project_id':self.pid,'public_key':b64(self.public)}
        self.assertEqual(self.request(path,body,{'X-CSRF-Token':'bad'})[0],403)
        self.assertEqual(self.request(path,body,{'Origin':'https://invalid.test'})[0],403)
        self.assertEqual(self.request(path,{**body,'execute':True})[0],400)
        for invalid in (None,True,{},[],5):
            self.assertEqual(self.request(path,{**body,'project_id':invalid})[0],400)
        self.assertEqual(self.view()['trust'],[])

    def test_package_upload_and_metadata_review_do_not_grant_execution(self):
        self.login();source=self.original_package()
        manifest=self.evidence(encode(self.package()['signed']['manifest']).encode(),'manifest.json')
        self.success('register',evidence_id=manifest['id'])
        self.success('transition',plugin_id='review.fixture',action='approve',reason='Synthetic metadata review only')
        code,_,raw=self.post('install',evidence_id=source['id'])
        self.assertNotIn(code,(200,201),raw)
        self.assertEqual(self.view()['plugins'],[])
        self.assertNotIn(self.post('runtime/run',plugin_id='review.fixture',evidence_id=self.input['id'])[0],(200,201))

    def test_valid_signed_package_tests_installs_disabled_then_runs_after_activation(self):
        self.login();self.success('trust',public_key=b64(self.public))
        package=self.original_package()
        saved=self.success('install',evidence_id=package['id'])
        plugin=self.view()['plugins'][0]
        self.assertEqual(plugin['state'],'disabled')
        self.assertNotEqual(plugin['effective_state'],'active')
        self.assertNotIn(self.post('runtime/run',plugin_id='review.fixture',evidence_id=self.input['id'])[0],(200,201))
        self.success('runtime/transition',plugin_id='review.fixture',action='activate',version='1.0.0')
        run=self.success('runtime/run',plugin_id='review.fixture',evidence_id=self.input['id'])
        self.assertEqual(run['record']['result'],{'value':1})
        self.assertEqual(self.view()['plugins'][0]['current_version'],'1.0.0')
        self.assertTrue(self.store.verify_audit()['valid'])
        summary=encode(self.view())
        self.assertNotIn('private selected bytes',summary)
        self.assertNotIn(self.package()['module_base64'],summary)

    def test_failed_reference_fixture_never_installs_and_boolean_is_not_integer(self):
        self.login();self.success('trust',public_key=b64(self.public))
        for expected in ({'value':True},{'value':2}):
            package=self.original_package(value=1,expected=expected)
            self.assertNotIn(self.post('install',evidence_id=package['id'])[0],(200,201))
        self.assertEqual(self.view()['plugins'],[])

    def test_bad_signature_and_module_digest_cannot_install(self):
        self.login();self.success('trust',public_key=b64(self.public))
        bad=self.package();bad['signed']['manifest']['version']='2.0.0'
        digest=self.package(changes={'module_sha256':'0'*64})
        for package in (bad,digest):
            original=self.evidence(encode(package).encode(),'invalid-package.json')
            self.assertNotIn(self.post('install',evidence_id=original['id'])[0],(200,201))
        self.assertEqual(self.view()['plugins'],[])

    def test_undeclared_network_authority_is_rejected_before_install_execution(self):
        from cyber_platform import plugin_installations
        self.login();self.success('trust',public_key=b64(self.public))
        package=self.package()
        package['signed']['manifest']['permissions']=['network.connect']
        package['signature']=b64(self.key.sign(encode(package['signed']).encode()))
        original=self.evidence(encode(package).encode(),'network-authority.json')
        with patch.object(plugin_installations.plugin_wasm,'execute_batch') as execute:
            self.assertNotIn(self.post('install',evidence_id=original['id'])[0],(200,201))
        execute.assert_not_called()
        self.assertEqual(self.view()['plugins'],[])

    def test_disable_replace_and_explicit_rollback_use_actual_retained_versions(self):
        self.login();self.install_active()
        self.success('runtime/transition',plugin_id='review.fixture',action='disable',version=None)
        self.assertNotIn(self.post('runtime/run',plugin_id='review.fixture',evidence_id=self.input['id'])[0],(200,201))
        package=self.original_package(version='2.0.0',value=2)
        self.success('install',evidence_id=package['id'])
        self.success('runtime/transition',plugin_id='review.fixture',action='activate',version='2.0.0')
        self.assertEqual(self.success('runtime/run',plugin_id='review.fixture',evidence_id=self.input['id'])['record']['result'],{'value':2})
        self.success('runtime/transition',plugin_id='review.fixture',action='rollback',version='1.0.0')
        self.assertEqual(self.success('runtime/run',plugin_id='review.fixture',evidence_id=self.input['id'])['record']['result'],{'value':1})
        self.assertEqual(len(self.view()['plugins'][0]['versions']),2)

    def test_revoked_publisher_blocks_current_plugin_and_cannot_retrust(self):
        self.login();self.install_active()
        self.success('trust/revoke',key_id=self.key_id)
        self.assertEqual(self.view()['plugins'][0]['effective_state'],'blocked')
        self.assertNotIn(self.post('runtime/run',plugin_id='review.fixture',evidence_id=self.input['id'])[0],(200,201))
        self.assertNotIn(self.post('runtime/transition',plugin_id='review.fixture',action='activate',version='1.0.0')[0],(200,201))
        self.assertNotIn(self.post('trust',public_key=b64(self.public))[0],(200,201))

    def test_project_scope_applies_to_keys_packages_and_selected_inputs(self):
        self.login();package,_=self.install_active()
        other=self.store.create_project('independent')['id']
        self.assertEqual(self.view(other)['plugins'],[])
        fields={'project_id':other,'evidence_id':package['id']}
        self.assertNotIn(self.request('/api/plugins/install',fields)[0],(200,201))
        foreign=self.store.add_evidence(other,'foreign.txt',b'private other project')
        self.assertNotIn(self.post('runtime/run',plugin_id='review.fixture',evidence_id=foreign['id'])[0],(200,201))

    def test_source_package_or_selected_input_tampering_cannot_run_as_valid(self):
        self.login();package,_=self.install_active()
        selected=self.store.blobs/self.input['id'];selected.chmod(0o600);selected.write_bytes(b'tampered input')
        self.assertNotIn(self.post('runtime/run',plugin_id='review.fixture',evidence_id=self.input['id'])[0],(200,201))
        original=self.store.blobs/package['id'];original.chmod(0o600);original.write_bytes(b'tampered signed package')
        code,_,_=self.request('/api/plugins/installations?project='+self.pid)
        self.assertNotEqual(code,200)

    def test_input_changed_after_execution_cannot_publish_a_successful_run(self):
        from cyber_platform import plugin_installations
        self.login();self.install_active()
        execute=plugin_installations.plugin_wasm.execute
        before=len(self.view()['runs'])
        def altered(module,data):
            result=execute(module,data)
            path=self.store.blobs/self.input['id'];path.chmod(0o600);path.write_bytes(b'changed during run')
            return result
        with patch.object(plugin_installations.plugin_wasm,'execute',altered):
            self.assertNotIn(self.post('runtime/run',plugin_id='review.fixture',evidence_id=self.input['id'])[0],(200,201))
        # No journal enrollment was published for the failed run.
        self.assertEqual(len(self.view()['runs']),before)

    def test_publisher_revoked_during_execution_cannot_publish_success(self):
        from cyber_platform import plugin_installations
        self.login();self.install_active()
        execute=plugin_installations.plugin_wasm.execute
        def revoked(module,data):
            result=execute(module,data)
            plugin_installations.revoke(self.store,self.pid,self.key_id)
            return result
        with patch.object(plugin_installations.plugin_wasm,'execute',revoked):
            self.assertNotIn(self.post('runtime/run',plugin_id='review.fixture',evidence_id=self.input['id'])[0],(200,201))
        after=self.view()
        self.assertEqual(after['runs'],[])
        self.assertEqual(after['plugins'][0]['effective_state'],'blocked')

    def test_trust_publication_failure_rolls_back_blob_row_and_enrollment(self):
        from cyber_platform.store import Problem
        self.login()
        before={p.name for p in self.store.blobs.iterdir()}
        audit=self.store.audit
        def failed(action,details):
            if action=='plugin-installation.created':raise Problem('Synthetic audit failure',409)
            return audit(action,details)
        with patch.object(self.store,'audit',failed):
            self.assertEqual(self.post('trust',public_key=b64(self.public))[0],409)
        self.assertEqual({p.name for p in self.store.blobs.iterdir()},before)
        self.assertEqual(self.view()['trust'],[])
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_busy_gate_rejects_install_run_transition_and_trust_without_changes(self):
        self.login();self.app.execution_lock.acquire()
        try:
            self.assertEqual(self.post('trust',public_key=b64(self.public))[0],409)
            self.assertEqual(self.post('install',evidence_id=self.input['id'])[0],409)
            self.assertEqual(self.post('runtime/transition',plugin_id='review.fixture',action='disable',version=None)[0],409)
            self.assertEqual(self.post('runtime/run',plugin_id='review.fixture',evidence_id=self.input['id'])[0],409)
            self.assertEqual(self.request('/api/plugins/installations?project='+self.pid)[0],409)
        finally:self.app.execution_lock.release()

    def test_heavy_slot_is_released_before_publishing_owner_plugin_responses(self):
        self.login();observed=[];original=Handler.reply
        def checked(handler,*args,**kwargs):
            if handler.path.startswith('/api/plugins/'):
                observed.append(handler.server.execution_lock.locked())
            return original(handler,*args,**kwargs)
        with patch.object(Handler,'reply',checked):
            self.success('trust',public_key=b64(self.public))
            self.view()
        self.assertEqual(observed,[False,False])

    def test_encrypted_backup_restores_installed_code_proofs_and_actual_execution(self):
        from cyber_platform import plugin_installations
        self.login();self.install_active()
        before=self.view()
        encrypted=backup.export(self.store,'temporary-backup-password')
        destination=Path(self.temp.name)/'restored'
        backup.restore(encrypted,'temporary-backup-password',destination)
        restored=Store(destination)
        try:
            self.assertEqual(plugin_installations.view(restored,self.pid),before)
            result=plugin_installations.run(restored,self.pid,'review.fixture',self.input['id'])
            self.assertEqual(result['record']['result'],{'value':1})
            self.assertTrue(restored.verify_audit()['valid'])
        finally:restored.close()
