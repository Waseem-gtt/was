import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cyber_platform import signed_release as signing
import tests.test_maintenance as legacy


class SignedPipelineTests(unittest.TestCase):
    setUp = legacy.LinuxReleaseTests.setUp
    tearDown = legacy.LinuxReleaseTests.tearDown
    ready = legacy.LinuxReleaseTests.ready

    def key(self, name='trusted'):
        key=Ed25519PrivateKey.generate()
        raw=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        trust={'schema':'was.trust/1','repository':signing.REPOSITORY,'threshold':1,
               'keys':[{'key_id':signing.key_id(raw),'public_key':base64.b64encode(raw).decode()}]}
        path=Path(self.temp.name)/(name+'.json')
        path.write_text(json.dumps(trust))
        path.chmod(0o600)
        return key,path,trust

    def envelope(self, key, sha, sequence=10, name='release', expires=None):
        now=int(time.time())
        payload={'schema':'was.release/1','repository':signing.REPOSITORY,'sequence':sequence,'version':'0.8.0','commit':sha,
                 'issued_at':now-100,'expires_at':now+3600 if expires is None else expires,
                 'artifacts':[{'name':'payload.bin','sha256':hashlib.sha256(b'synthetic-release').hexdigest(),'size':17}]}
        raw=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        value={'signed':payload,'signatures':[{'key_id':signing.key_id(raw),'signature':base64.b64encode(key.sign(signing.canonical(payload))).decode()}]}
        path=Path(self.temp.name)/(name+'.json')
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path,value

    def invoke(self, operation, sha=None, envelope=None, trust=None):
        args=['bash',self.script,operation]
        if operation!='rollback':
            args.append(sha)
        args.append(str(self.prefix))
        if envelope is not None:
            args.extend(['--signed',str(envelope),str(trust)])
        return subprocess.run(args,capture_output=True,text=True,timeout=15)

    def state(self):
        return json.loads((self.prefix/'signature-state/release-state.json').read_text())

    def test_signed_activation_pins_trust_and_blocks_unsigned_downgrade_and_conflict(self):
        first,second='a'*40,'b'*40
        self.ready(first);self.ready(second)
        key,trust,body=self.key()
        manifest,_=self.envelope(key,first)
        result=self.invoke('activate',first,manifest,trust)
        self.assertEqual(result.returncode,0,result.stderr)
        pin=(self.prefix/'.require-signatures').read_text().strip()
        self.assertEqual(pin,hashlib.sha256(signing.canonical(body)).hexdigest())
        self.assertNotEqual(self.invoke('activate',second).returncode,0)
        newer,_=self.envelope(key,second,11,'newer')
        self.assertEqual(self.invoke('activate',second,newer,trust).returncode,0)
        self.assertEqual(self.state()['sequence'],11)
        self.assertNotEqual(self.invoke('activate',first,manifest,trust).returncode,0)
        conflict,_=self.envelope(key,first,11,'conflict')
        self.assertNotEqual(self.invoke('activate',first,conflict,trust).returncode,0)
        self.assertEqual(self.invoke('activate',second,newer,trust).returncode,0)
        self.assertEqual(os.readlink(self.prefix/'current'),'releases/'+second)
        self.assertEqual(os.readlink(self.prefix/'previous'),'releases/'+first)

    def test_substituted_trust_tampering_and_expiry_do_not_advance_state(self):
        first,second='a'*40,'b'*40
        self.ready(first);self.ready(second)
        key,trust,_=self.key()
        manifest,_=self.envelope(key,first)
        self.assertEqual(self.invoke('activate',first,manifest,trust).returncode,0)
        original=self.state()
        attacker,bad_trust,_=self.key('different-trust')
        attack,_=self.envelope(attacker,second,99,'untrusted')
        self.assertNotEqual(self.invoke('activate',second,attack,bad_trust).returncode,0)
        damaged,value=self.envelope(key,second,12,'tampered')
        value['signed']['version']='0.9.0'
        damaged.write_text(json.dumps(value))
        self.assertNotEqual(self.invoke('activate',second,damaged,trust).returncode,0)
        expired,_=self.envelope(key,second,12,'expired',int(time.time())-1)
        self.assertNotEqual(self.invoke('activate',second,expired,trust).returncode,0)
        self.assertEqual(self.state(),original)
        self.assertEqual(os.readlink(self.prefix/'current'),'releases/'+first)

    def test_unready_release_and_user_file_preflight_never_record_sequence(self):
        first,second='a'*40,'b'*40
        self.ready(first)
        key,trust,_=self.key()
        manifest,_=self.envelope(key,first)
        self.assertEqual(self.invoke('activate',first,manifest,trust).returncode,0)
        newer,_=self.envelope(key,second,11,'newer')
        self.assertNotEqual(self.invoke('activate',second,newer,trust).returncode,0)
        self.assertEqual(self.state()['sequence'],10)
        self.ready(second)
        (self.prefix/'previous').write_text('owner file')
        self.assertNotEqual(self.invoke('activate',second,newer,trust).returncode,0)
        self.assertEqual(self.state()['sequence'],10)

    def test_explicit_local_rollback_preserves_high_water_mark(self):
        first,second='a'*40,'b'*40
        self.ready(first);self.ready(second)
        key,trust,_=self.key()
        older,_=self.envelope(key,first)
        newer,_=self.envelope(key,second,11,'newer')
        self.assertEqual(self.invoke('activate',first,older,trust).returncode,0)
        self.assertEqual(self.invoke('activate',second,newer,trust).returncode,0)
        before=self.state()
        self.assertEqual(self.invoke('rollback').returncode,0)
        self.assertEqual(self.state(),before)
        self.assertEqual(os.readlink(self.prefix/'current'),'releases/'+first)
        self.assertNotEqual(self.invoke('activate',first,older,trust).returncode,0)

    def test_signed_prepare_pins_policy_before_refusing_unknown_commit(self):
        key,trust,_=self.key()
        manifest,_=self.envelope(key,'d'*40)
        self.assertNotEqual(self.invoke('prepare','d'*40,manifest,trust).returncode,0)
        self.assertTrue((self.prefix/'.require-signatures').is_file())
        self.assertFalse((self.prefix/'signature-state/release-state.json').exists())
        self.ready('a'*40)
        self.assertNotEqual(self.invoke('activate','a'*40).returncode,0)
