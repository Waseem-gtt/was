from concurrent.futures import ThreadPoolExecutor
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from cyber_platform import release_admin as admin
from cyber_platform import signed_release as core
from cyber_platform.store import Problem


class ReleaseAdminTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.key = self.root / 'owner.pem'
        self.trust = self.root / 'trust.json'
        self.state = self.root / 'state'
        self.commit = 'a' * 40
        self.password = 'test-owner-password-123'
        with patch.object(admin.getpass, 'getpass', return_value=self.password):
            admin.keygen(self.key, self.trust)
        self.payload = {'schema': 'was.release/1', 'repository': core.REPOSITORY,
                        'sequence': 1, 'version': '0.8.0', 'commit': self.commit,
                        'issued_at': int(time.time()) - 10, 'expires_at': int(time.time()) + 1000,
                        'artifacts': [{'name': 'package.whl', 'size': 7,
                                       'sha256': hashlib.sha256(b'package').hexdigest()}]}
        self.envelope = self.signed(self.payload)

    def tearDown(self):
        self.temp.cleanup()

    def signed(self, payload):
        name = 'release-' + str(payload['sequence']) + '-' + str(len(list(self.root.iterdir())))
        source, output = self.root / (name + '.input'), self.root / (name + '.json')
        source.write_bytes(core.canonical(payload))
        with patch.object(admin.getpass, 'getpass', return_value=self.password):
            admin.sign(source, self.key, output)
        return output

    def verify(self, **kwargs):
        return admin.run_verify(self.envelope, self.trust, self.commit, self.state, **kwargs)

    def test_key_encrypted_private_and_no_overwrite(self):
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.assertIn(b'ENCRYPTED PRIVATE KEY', self.key.read_bytes())
        self.assertNotIn(self.password.encode(), self.key.read_bytes())
        with patch.object(admin.getpass, 'getpass', return_value=self.password):
            with self.assertRaises(ValueError):
                admin.keygen(self.key, self.root / 'other-trust.json')
        self.assertFalse((self.root / 'other-trust.json').exists())

    def test_password_and_private_parent_required(self):
        with patch.object(admin.getpass, 'getpass', return_value='short'):
            with self.assertRaises(ValueError):
                admin.keygen(self.root / 'new.pem', self.root / 'new.json')
        shared = self.root / 'shared'
        shared.mkdir(mode=0o755)
        shared.chmod(0o755)
        with patch.object(admin.getpass, 'getpass', return_value=self.password):
            with self.assertRaises(ValueError):
                admin.keygen(shared / 'key.pem', self.root / 'new.json')

    def test_verify_does_not_advance_and_record_is_idempotent(self):
        verified = self.verify()
        self.assertFalse(verified['recorded'])
        self.assertEqual(verified['trust_digest'], hashlib.sha256(core.canonical(core.load_json(self.trust.read_bytes()))).hexdigest())
        self.assertFalse((self.state / 'release-state.json').exists())
        first = self.verify(record=True)
        second = self.verify(record=True)
        self.assertEqual(first, second)
        self.assertEqual((self.state / 'release-state.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)

    def test_artifacts_hash_and_size_verified_before_record(self):
        artifacts = self.root / 'artifacts'
        artifacts.mkdir()
        package = artifacts / 'package.whl'
        package.write_bytes(b'package')
        self.assertEqual(self.verify(artifacts=artifacts)['artifacts_verified'], 1)
        package.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.verify(artifacts=artifacts, record=True)
        self.assertFalse((self.state / 'release-state.json').exists())

    def test_pinned_trust_mismatch_does_not_record(self):
        digest = self.verify()['trust_digest']
        with self.assertRaises(ValueError):
            self.verify(record=True, expected_trust_digest='0' * 64)
        self.assertFalse((self.state / 'release-state.json').exists())
        with self.assertRaises(ValueError):
            self.verify(record=True, expected_trust_digest='malformed')
        self.assertFalse((self.state / 'release-state.json').exists())
        self.assertTrue(self.verify(record=True, expected_trust_digest=digest)['recorded'])

    def test_symlinked_artifact_and_ancestor_rejected(self):
        artifacts = self.root / 'artifacts'
        artifacts.mkdir()
        (artifacts / 'package.whl').symlink_to(self.key)
        with self.assertRaises(OSError):
            self.verify(artifacts=artifacts)
        linked = self.root / 'linked'
        linked.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            admin.run_verify(linked / self.envelope.name, self.trust, self.commit, self.state)

    def test_untrusted_permissions_private_key_and_trust_rejected(self):
        self.trust.chmod(0o622)
        with self.assertRaises(ValueError):
            self.verify()
        self.trust.chmod(0o644)
        self.assertTrue(self.verify()['digest'])
        self.key.chmod(0o644)
        source = self.root / 'payload.json'
        source.write_bytes(core.canonical(self.payload))
        with patch.object(admin.getpass, 'getpass', return_value=self.password):
            with self.assertRaises(ValueError):
                admin.sign(source, self.key, self.root / 'out')

    def test_wrong_password_and_sign_output_no_overwrite(self):
        source = self.root / 'payload.json'
        source.write_bytes(core.canonical(self.payload))
        with patch.object(admin.getpass, 'getpass', return_value='incorrect-password'):
            with self.assertRaises(ValueError):
                admin.sign(source, self.key, self.root / 'wrong.json')
        self.assertFalse((self.root / 'wrong.json').exists())
        with patch.object(admin.getpass, 'getpass', return_value=self.password):
            with self.assertRaises(FileExistsError):
                admin.sign(source, self.key, self.envelope)

    def test_corrupt_shared_symlink_and_nonregular_state_fail_closed(self):
        self.verify(record=True)
        state_file = self.state / 'release-state.json'
        state_file.write_text('{broken')
        with self.assertRaises(Problem):
            self.verify(record=True)
        state_file.unlink()
        state_file.symlink_to(self.envelope)
        with self.assertRaises(OSError):
            self.verify(record=True)
        state_file.unlink()
        os.mkfifo(state_file, 0o600)
        with self.assertRaises(ValueError):
            self.verify()
        state_file.unlink()
        self.state.chmod(0o755)
        with self.assertRaises(ValueError):
            self.verify()

    def test_rollback_rejected_and_mismatched_commit_not_recorded(self):
        newer = self.signed({**self.payload, 'sequence': 2})
        admin.run_verify(newer, self.trust, self.commit, self.state, record=True)
        with self.assertRaises(Problem):
            self.verify(record=True)
        with self.assertRaises(Problem):
            admin.run_verify(newer, self.trust, 'b' * 40, self.state, record=True)
        self.assertEqual(core.load_json((self.state / 'release-state.json').read_bytes())['sequence'], 2)

    def test_concurrent_records_preserve_highest_sequence(self):
        envelopes = [self.signed({**self.payload, 'sequence': number}) for number in (2, 3)]

        def record(envelope):
            try:
                return admin.run_verify(envelope, self.trust, self.commit, self.state, record=True)
            except Problem:
                return None  # Lower sequence is rejected if the higher writer won the lock first.

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(record, envelopes))
        self.assertTrue(any(item and item['sequence'] == 3 for item in results))
        self.assertEqual(core.load_json((self.state / 'release-state.json').read_bytes())['sequence'], 3)

    def test_oversized_json_and_symlinked_lock_rejected(self):
        self.envelope.write_bytes(b' ' * (admin.MAX_JSON + 1))
        with self.assertRaises(ValueError):
            self.verify()
        self.envelope = self.signed(self.payload)
        self.state.mkdir(mode=0o700)
        (self.state / 'release.lock').symlink_to(self.key)
        with self.assertRaises(OSError):
            self.verify(record=True)

    def test_cli_only_emits_safe_metadata_and_safe_failure(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            admin.main(['verify', str(self.envelope), str(self.trust), '--commit', self.commit, '--state', str(self.state)])
        metadata = json.loads(output.getvalue())
        self.assertEqual(metadata['commit'], self.commit)
        self.assertNotIn(self.password, output.getvalue())
        self.assertNotIn('PRIVATE KEY', output.getvalue())
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as result:
            admin.main(['verify', str(self.key), str(self.trust), '--commit', self.commit, '--state', str(self.state)])
        self.assertEqual(result.exception.code, 1)
        self.assertNotIn(self.password, errors.getvalue())


if __name__ == '__main__':
    unittest.main()
