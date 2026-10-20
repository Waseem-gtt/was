"""Offline metadata governance, immutable history and dependency invalidation."""
import copy
import hashlib
from unittest.mock import patch
from cyber_platform import plugin_registry as registry
from cyber_platform.store import Problem, Store, encode
import tests.test_platform as core


class PluginRegistryTests(core.StoreCase):
    def manifest(self, **changes):
        value = {'id': 'owner.example', 'version': '1.0.0', 'license': 'MIT',
                 'source': 'https://example.test/plugin', 'permissions': ['selected_evidence.read'],
                 'dependencies': []}
        value.update(changes)
        return value

    def source(self, manifest=None):
        return self.evidence(encode(manifest or self.manifest()).encode(), 'manifest.json')

    def register(self, manifest=None):
        return registry.register(self.store, self.pid, self.source(manifest)['id'])

    def decide(self, identifier='owner.example', action='approve', reason='Reviewed source, license and permissions independently'):
        return registry.transition(self.store, self.pid, identifier, action, reason)

    def test_register_approve_disable_revoke_immutable_restart(self):
        source = self.source()
        original = self.store.read_evidence(self.pid, source['id'])
        first = registry.register(self.store, self.pid, source['id'])
        self.assertEqual(first['item']['state'], 'pending')
        self.assertEqual(first['evidence']['parent_id'], source['id'])
        first_bytes = self.store.read_evidence(self.pid, first['evidence']['id'])
        for action, state in [('approve', 'approved'), ('disable', 'disabled'), ('revoke', 'revoked')]:
            result = self.decide(action=action)
            self.assertEqual(result['item']['state'], state)
            self.assertEqual(result['item']['effective_state'], state)
        self.assertEqual(len(result['item']['history']), 4)
        self.assertEqual(self.store.read_evidence(self.pid, source['id']), original)
        self.assertEqual(self.store.read_evidence(self.pid, first['evidence']['id']), first_bytes)
        before = registry.view(self.store, self.pid)
        self.store.close(); self.store = Store(self.store.root)
        self.assertEqual(registry.view(self.store, self.pid), before)
        self.assertTrue(self.store.verify_audit()['valid'])
        for action in ('approve', 'disable', 'revoke'):
            with self.assertRaises(Problem): self.decide(action=action)
        higher = self.register(self.manifest(version='1.0.1'))
        self.assertEqual(higher['item']['state'], 'pending')
        self.assertEqual(higher['item']['revision'], 5)
        self.assertEqual(higher['evidence']['parent_id'], result['evidence']['id'])

    def test_dependencies_version_exact_and_disable_propagates_transitively(self):
        self.register(self.manifest(id='base')); self.decide('base')
        self.register(self.manifest(id='middle', dependencies=[{'id': 'base', 'version': '1.0.0'}])); self.decide('middle')
        self.register(self.manifest(id='top', dependencies=[{'id': 'middle', 'version': '1.0.0'}])); self.decide('top')
        self.decide('base', 'disable')
        items = {i['id']: i for i in registry.view(self.store, self.pid)['items']}
        self.assertEqual(items['middle']['state'], 'approved')
        self.assertEqual(items['middle']['effective_state'], 'blocked')
        self.assertEqual(items['top']['effective_state'], 'blocked')
        self.assertIn('dependency_blocked', {i['code'] for i in items['top']['issues']})
        self.decide('base')
        self.assertTrue(all(i['effective_state'] == 'approved' for i in registry.view(self.store, self.pid)['items']))
        self.register(self.manifest(id='base', version='2.0.0')); self.decide('base')
        items = {i['id']: i for i in registry.view(self.store, self.pid)['items']}
        self.assertIn('version_conflict', {i['code'] for i in items['middle']['issues']})
        self.assertEqual(items['top']['effective_state'], 'blocked')

    def test_missing_dependencies_cycles_and_graph_export(self):
        self.register(self.manifest(id='one', dependencies=[{'id': 'two', 'version': '1.0.0'}]))
        with self.assertRaises(Problem): self.decide('one')
        self.register(self.manifest(id='two', dependencies=[{'id': 'one', 'version': '1.0.0'}]))
        self.register(self.manifest(id='self', dependencies=[{'id': 'self', 'version': '1.0.0'}]))
        value = registry.view(self.store, self.pid)
        self.assertEqual(len(value['graph']['edges']), 3)
        self.assertEqual(len(value['graph']['nodes']), 3)
        self.assertTrue(all('dependency_cycle' in {issue['code'] for issue in item['issues']} for item in value['items']))
        for identifier in ('one', 'two', 'self'):
            with self.assertRaises(Problem): self.decide(identifier)

    def test_permissions_license_runtime_flags_block_approval(self):
        examples = [self.manifest(id='network', permissions=['network']),
                    self.manifest(id='shell', permissions=['shell.execute']),
                    self.manifest(id='license', license='unknown'),
                    self.manifest(id='runtime', compatibility={'python_min': '9.0', 'python_max': '9.2', 'platform': 'linux'})]
        for value in examples:
            with self.subTest(value=value):
                saved = self.register(value)
                self.assertTrue(saved['item']['issues'])
                with self.assertRaises(Problem): self.decide(value['id'])
                self.assertEqual(self.decide(value['id'], 'disable')['item']['state'], 'disabled')

    def test_manifest_exact_schema_and_invalid_values_never_publish(self):
        cases = [self.manifest(command='id'), self.manifest(id='../escape'), self.manifest(version='latest'),
                 self.manifest(version=True), self.manifest(license='\nMIT'), self.manifest(source='http://example.test'),
                 self.manifest(source='https://user:secret@example.test'), self.manifest(source='https://example.test/?token=x'),
                 self.manifest(source='https://example.test/#fragment'), self.manifest(source='https://example.test:8080/path'),
                 self.manifest(source='https://[bad'), self.manifest(permissions=['network', 'network']),
                 self.manifest(permissions=['a'*81]), self.manifest(dependencies=[{'id': 'x', 'version': '1.0', 'command': 'id'}]),
                 self.manifest(dependencies=[{'id': 'x', 'version': '1.0'}, {'id': 'x', 'version': '2.0'}]),
                 self.manifest(compatibility={'python_min': '3.13', 'python_max': '3.11', 'platform': 'linux'}),
                 self.manifest(compatibility={'python_min': '3.11', 'python_max': '3.13', 'platform': 'windows'})]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(Problem): self.register(value)
        self.assertEqual(registry.view(self.store, self.pid)['items'], [])
        self.assertFalse(self.store.rows("SELECT * FROM evidence WHERE kind='plugin-registry'"))

    def test_duplicate_keys_nonfinite_surrogates_and_size_rejected(self):
        for raw in (b'{"id":"a","id":"b"}', b'{"id":NaN}', b'{"id":"\\ud800"}', b'x'*16385):
            source = self.evidence(raw)
            with self.assertRaises(Problem): registry.register(self.store, self.pid, source['id'])
        value = self.manifest(permissions=['a'+str(i) for i in range(21)])
        with self.assertRaises(Problem): self.register(value)
        value = self.manifest(dependencies=[{'id': 'd'+str(i), 'version': '1.0'} for i in range(11)])
        with self.assertRaises(Problem): self.register(value)

    def test_cannot_reuse_or_downgrade_version_and_normalized_equal_rejected(self):
        self.register()
        for version in ('1.0', '1.0.0', '0.9.9'):
            with self.subTest(version=version), self.assertRaises(Problem): self.register(self.manifest(version=version))
        next_result = self.register(self.manifest(version='1.1'))
        self.assertEqual(next_result['item']['revision'], 2)
        self.assertEqual(next_result['item']['state'], 'pending')

    def test_project_isolation_unknown_ids_and_bad_transitions(self):
        saved = self.register()
        other = self.store.create_project('Other')['id']
        with self.assertRaises(Problem): registry.register(self.store, other, saved['item']['source_evidence'])
        with self.assertRaises(Problem): registry.transition(self.store, other, 'owner.example', 'approve', 'Reviewed')
        self.assertEqual(registry.view(self.store, other)['items'], [])
        for identifier, action, reason in [('missing', 'approve', 'Reviewed'), ('../escape', 'approve', 'Reviewed'),
                                           ('owner.example', 'run', 'Reviewed'), ('owner.example', 'approve', ''),
                                           ('owner.example', 'approve', '   '), ('owner.example', 'approve', 'x'*1001)]:
            with self.subTest(action=action), self.assertRaises(Problem): self.decide(identifier, action, reason)
        self.decide()
        with self.assertRaises(Problem): self.decide()

    def test_source_and_revision_tampering_fail_closed(self):
        saved = self.register()
        source_id = saved['item']['source_evidence']
        path = self.store.blobs/source_id; path.chmod(0o600); path.write_bytes(b'changed')
        with self.assertRaises(Problem): registry.view(self.store, self.pid)
        with self.assertRaises(Problem): self.decide()

    def test_settings_omission_and_forged_kind_are_not_adopted(self):
        self.register()
        with self.store.db:
            self.store.db.execute('DELETE FROM settings WHERE key=?', (registry.PREFIX+self.pid,))
        with self.assertRaises(Problem): registry.view(self.store, self.pid)
        other = self.store.create_project('Forged')['id']
        self.store.add_evidence(other, 'forged.json', b'{}', kind='plugin-registry')
        with self.assertRaises(Problem): registry.view(self.store, other)

    def test_revision_bytes_and_chain_identity_are_checked_even_with_new_file_hash(self):
        saved = self.register(); eid = saved['evidence']['id']
        raw = self.store.read_evidence(self.pid, eid)
        value = registry._json(raw); value['state'] = 'approved'
        changed = encode(value).encode()
        path = self.store.blobs/eid; path.chmod(0o600); path.write_bytes(changed)
        with self.store.db:
            self.store.db.execute('UPDATE evidence SET size=?,sha256=? WHERE id=?', (len(changed), hashlib.sha256(changed).hexdigest(), eid))
        with self.assertRaises(Problem): registry.view(self.store, self.pid)

    def test_forged_upload_cannot_supply_internal_creation_audit(self):
        saved = self.register(); record = saved['evidence']; raw = self.store.read_evidence(self.pid, record['id'])
        fake = self.store.add_evidence(self.pid, 'copy.json', raw, 'plugin-registry', saved['item']['source_evidence'])
        with self.store.db:
            self.store.db.execute('DELETE FROM evidence WHERE id=?', (record['id'],))
            self.store.db.execute('UPDATE settings SET value=? WHERE key=?', (encode({'owner.example': [fake['id']]}), registry.PREFIX+self.pid))
        with self.assertRaises(Problem): registry.view(self.store, self.pid)

    def test_failure_rolls_back_blob_index_and_audit(self):
        source = self.source(); before = set(p.name for p in self.store.blobs.iterdir())
        audit = self.store.verify_audit()
        with patch.object(self.store, 'audit', side_effect=RuntimeError('injected')):
            with self.assertRaises(RuntimeError): registry.register(self.store, self.pid, source['id'])
        self.assertEqual(set(p.name for p in self.store.blobs.iterdir()), before)
        self.assertEqual(self.store.verify_audit(), audit)
        self.assertEqual(registry.view(self.store, self.pid)['items'], [])

    def test_revision_and_inventory_limits_refuse_before_publication(self):
        self.register()
        with patch.dict(registry.LIMITS, revisions_per_plugin=1):
            with self.assertRaises(Problem): self.decide()
        with patch.dict(registry.LIMITS, plugins=1):
            with self.assertRaises(Problem): self.register(self.manifest(id='another'))
        self.assertEqual(len(registry.view(self.store, self.pid)['items']), 1)
        self.assertEqual(registry.view(self.store, self.pid)['items'][0]['revision'], 1)

    def test_proof_budget_next_revision_is_refused_before_commit(self):
        saved = self.register()
        current = self.store.evidence(self.pid, saved['item']['source_evidence'])['size'] + saved['evidence']['size']
        with patch.dict(registry.LIMITS, proof_bytes=current+10):
            with self.assertRaises(Problem): self.decide()
            self.assertEqual(registry.view(self.store, self.pid)['items'][0]['revision'], 1)
        self.assertEqual(len(self.store.rows("SELECT id FROM evidence WHERE kind='plugin-registry'")), 1)

    def test_data_only_no_worker_shell_network_or_installer(self):
        with patch('subprocess.Popen', side_effect=AssertionError('must not execute')), patch('urllib.request.urlopen', side_effect=AssertionError('must not fetch')):
            saved = self.register()
            result = self.decide()
            self.assertEqual(result['item']['state'], 'approved')
            self.assertEqual(self.store.rows('SELECT * FROM jobs'), [])
            self.assertIn('ليس تثبيتًا', registry.view(self.store, self.pid)['notice'])
            self.assertEqual(saved['item']['manifest']['source'], 'https://example.test/plugin')

    def test_default_normalization_and_content_digest(self):
        saved = self.register()
        manifest = saved['item']['manifest']
        self.assertEqual(manifest['compatibility']['platform'], 'linux')
        view = registry.view(self.store, self.pid)
        digest = view.pop('digest')
        self.assertEqual(digest, hashlib.sha256(encode(view).encode()).hexdigest())
        copied = copy.deepcopy(saved['item']); copied['manifest']['license'] = 'changed'
        self.assertEqual(registry.view(self.store, self.pid)['items'][0]['manifest']['license'], 'MIT')

    def test_malformed_retained_action_and_source_id_fail_as_problem(self):
        saved = self.register(); eid = saved['evidence']['id']
        original = self.store.read_evidence(self.pid, eid)
        for field, value in [('action', []), ('source_evidence', [])]:
            malformed = registry._json(original); malformed[field] = value
            changed = encode(malformed).encode()
            path = self.store.blobs/eid; path.chmod(0o600); path.write_bytes(changed)
            with self.store.db:
                self.store.db.execute('UPDATE evidence SET size=?,sha256=? WHERE id=?', (len(changed), hashlib.sha256(changed).hexdigest(), eid))
            with self.subTest(field=field), self.assertRaises(Problem): registry.view(self.store, self.pid)

    def test_symlink_source_and_database_swap_refused(self):
        saved = self.register(); source = saved['item']['source_evidence']
        path = self.store.blobs/source; original = path.read_bytes()
        target = self.store.root/'external-manifest.json'; target.write_bytes(original)
        path.unlink(); path.symlink_to(target)
        with self.assertRaises(Problem): registry.view(self.store, self.pid)
        path.unlink(); path.write_bytes(original); path.chmod(0o400)
        database = self.store.root/'platform.db'; database.rename(self.store.root/'saved.db')
        database.write_bytes(b'not the opened database')
        with self.assertRaises(Problem): registry.view(self.store, self.pid)
