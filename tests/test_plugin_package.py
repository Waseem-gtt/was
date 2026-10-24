"""Offline publisher tooling uses temporary keys and never establishes trust."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from cyber_platform import plugin_installations as installs, plugin_package, plugin_wasm
from cyber_platform.store import Problem, Store
from tests.test_plugin_wasm import length_module


class PluginPackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = self.root / 'publisher.pem'
        self.manifest = self.root / 'manifest.json'
        self.module = self.root / 'counter.wasm'
        self.fixtures = self.root / 'fixtures.json'
        self.output = self.root / 'package.json'
        self.manifest.write_text(json.dumps({'id': 'fixture.counter', 'version': '1.0.0', 'license': 'MIT',
            'source': 'https://example.test/counter', 'permissions': ['selected_evidence.read', 'derived_evidence.write']}))
        self.module.write_bytes(length_module())
        self.fixtures.write_text(json.dumps([{'input_base64': 'YWJj', 'expected': {'length_mod10': 3}}]))

    def build(self):
        return plugin_package.build(self.key, self.manifest, self.module, self.fixtures, self.output)

    def test_explicit_keygen_is_private_and_never_overwrites_existing_key(self):
        result = plugin_package.generate_key(self.key)
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('PRIVATE KEY', json.dumps(result))
        before = self.key.read_bytes()
        with self.assertRaises(FileExistsError):
            plugin_package.generate_key(self.key)
        self.assertEqual(self.key.read_bytes(), before)

    def test_signed_package_build_does_not_execute_or_implicitly_trust(self):
        public = plugin_package.generate_key(self.key)['public_key']
        with patch.object(plugin_wasm, 'execute_batch', side_effect=AssertionError('must not execute')):
            result = self.build()
        self.assertEqual(result['public_key'], public)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        package = installs._package(self.output.read_bytes())
        self.assertEqual(package['fixtures'][0][1], {'length_mod10': 3})
        self.assertNotIn(self.key.read_text(), self.output.read_text())

    def test_built_package_requires_trust_then_really_installs_and_runs(self):
        public = plugin_package.generate_key(self.key)['public_key']
        self.build()
        data = self.root / 'data'
        store = Store(data)
        self.addCleanup(store.close)
        pid = store.create_project('حزمة مؤقتة')['id']
        source = store.add_evidence(pid, 'signed.json', self.output.read_bytes())
        with self.assertRaises(Problem):
            installs.install(store, pid, source['id'])
        installs.trust(store, pid, public)
        installs.install(store, pid, source['id'])
        installs.transition(store, pid, 'fixture.counter', 'activate', '1.0.0')
        original = store.add_evidence(pid, 'input.txt', b'abcdefg')
        self.assertEqual(installs.run(store, pid, 'fixture.counter', original['id'])['record']['result'], {'length_mod10': 7})

    def test_private_key_with_public_permissions_or_symlink_is_rejected(self):
        plugin_package.generate_key(self.key)
        self.key.chmod(0o644)
        with self.assertRaises(Problem):
            self.build()
        self.key.chmod(0o600)
        link = self.root / 'link.pem'
        link.symlink_to(self.key)
        with self.assertRaises(Problem):
            plugin_package.build(link, self.manifest, self.module, self.fixtures, self.output)
        self.assertFalse(self.output.exists())

    def test_invalid_key_and_module_publish_no_package_or_sensitive_error(self):
        self.key.write_text('private sentinel, not a valid key')
        self.key.chmod(0o600)
        with self.assertRaises(Problem) as failure:
            self.build()
        self.assertNotIn('private sentinel', str(failure.exception))
        self.key.unlink()
        plugin_package.generate_key(self.key)
        self.module.write_text('print("not executable")')
        with self.assertRaises(Problem):
            self.build()
        self.assertFalse(self.output.exists())

    def test_invalid_fixtures_and_forbidden_permissions_are_not_signed_for_installation(self):
        plugin_package.generate_key(self.key)
        self.fixtures.write_text('[]')
        with self.assertRaises(Problem):
            self.build()
        self.fixtures.write_text('[{"input_base64":"","expected":{}}]')
        manifest = json.loads(self.manifest.read_text())
        manifest['permissions'].append('network.connect')
        self.manifest.write_text(json.dumps(manifest))
        with self.assertRaises(Problem):
            self.build()
        self.assertFalse(self.output.exists())

    def test_existing_output_or_symlink_is_never_replaced(self):
        plugin_package.generate_key(self.key)
        self.output.write_text('existing sentinel')
        with self.assertRaises(FileExistsError):
            self.build()
        self.assertEqual(self.output.read_text(), 'existing sentinel')

    def test_cli_keygen_and_package_do_not_start_server_or_create_owner_data(self):
        result = subprocess.run([sys.executable, '-m', 'cyber_platform', 'plugin-keygen', '--output', str(self.key)],
                                check=True, capture_output=True, text=True)
        public = json.loads(result.stdout)['public_key']
        self.assertNotIn('PRIVATE KEY', result.stdout)
        result = subprocess.run([sys.executable, '-m', 'cyber_platform', 'plugin-package', '--key', str(self.key),
            '--manifest', str(self.manifest), '--module', str(self.module), '--fixtures', str(self.fixtures), '--output', str(self.output)],
            check=True, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout)['public_key'], public)
        self.assertNotIn('PRIVATE KEY', result.stdout)
        self.assertEqual({p.name for p in self.root.iterdir()}, {'publisher.pem', 'manifest.json', 'counter.wasm', 'fixtures.json', 'package.json'})
