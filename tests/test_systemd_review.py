"""Service hardening review never runs or reveals command/credential text."""
import json
import unittest
from unittest.mock import patch
from cyber_platform import systemd_review as s


class SystemdReviewTests(unittest.TestCase):
    def review(self,text):return s.analyze(text.encode())
    def codes(self,text):return {f['code'] for f in self.review(text)['findings']}

    def test_fixed_sample_baseline_is_known_and_inert(self):
        r=self.review(s.sample());self.assertEqual(r['summary'],{'findings':15,'high':1,'medium':14,'low':0})
        self.assertFalse(r['network']);self.assertFalse(r['applied']);self.assertTrue(r['exec_start_present'])

    def test_hardened_documented_fields_pass_only_this_baseline(self):
        text='[Service]\nExecStart=/not/executed\nUser=service\n'+''.join(k+'=yes\n' for k in s._BOOL-{'DynamicUser'})+'PrivateTmp=disconnected\nProtectSystem=strict\nProtectHome=read-only\nRestrictNamespaces=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n'
        self.assertEqual(self.review(text)['findings'],[])

    def test_command_env_secret_and_account_names_never_exported(self):
        text='[Service]\nExecStart=/SECRET_COMMAND\nEnvironment=SECRET_ENV\nLoadCredential=SECRET_CREDENTIAL\nUser=SECRET_USER\nUnknownDirective=SECRET_UNKNOWN\n'
        r=self.review(text);serialized=json.dumps(r)
        for value in ('SECRET_COMMAND','SECRET_ENV','SECRET_CREDENTIAL','SECRET_USER','SECRET_UNKNOWN'):self.assertNotIn(value,serialized)
        self.assertTrue(r['environment_present']);self.assertEqual(r['unknown_directive_count'],1)

    def test_scalar_last_assignment_and_empty_reset(self):
        r=self.review('[Service]\nNoNewPrivileges=no\nNoNewPrivileges=yes\n')
        self.assertEqual(r['directives']['NoNewPrivileges'],'yes')
        self.assertNotIn('NoNewPrivileges',self.review('[Service]\nNoNewPrivileges=yes\nNoNewPrivileges=\n')['directives'])

    def test_capabilities_union_and_empty_list_reset(self):
        text='[Service]\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_CHOWN\n'
        r=self.review(text);self.assertEqual(r['directives']['CapabilityBoundingSet']['capabilities'],['CAP_CHOWN','CAP_NET_BIND_SERVICE'])
        self.assertEqual(self.review(text+'CapabilityBoundingSet=\n')['directives']['CapabilityBoundingSet'],[])

    def test_mixed_capability_complements_refused(self):
        with self.assertRaises(ValueError):self.review('[Service]\nCapabilityBoundingSet=CAP_CHOWN\nCapabilityBoundingSet=~CAP_SYS_ADMIN\n')

    def test_capability_values_are_validated(self):
        for value in ('root','CAP_VALID;command','~','CAP_ONE '+('CAP_X '*65)):
            with self.subTest(value=value),self.assertRaises(ValueError):self.review('[Service]\nAmbientCapabilities='+value+'\n')

    def test_boolean_aliases_and_bad_values(self):
        for value in ('yes','true','on','1','no','false','off','0'):
            with self.subTest(value=value):self.review('[Service]\nNoNewPrivileges='+value+'\n')
        for value in ('maybe','-1','yes #inline comment'):
            with self.subTest(value=value),self.assertRaises(ValueError):self.review('[Service]\nNoNewPrivileges='+value+'\n')

    def test_enum_modes_and_invalid_values(self):
        for line in ('PrivateTmp=disconnected','ProtectHome=tmpfs','ProtectSystem=full'):
            self.review('[Service]\n'+line+'\n')
        with self.assertRaises(ValueError):self.review('[Service]\nProtectSystem=hostile\n')

    def test_root_uid_leading_zero_is_still_root(self):
        for user in ('root','0','00','000'):
            with self.subTest(user=user):self.assertIn('root_or_unspecified_user',self.codes('[Service]\nUser='+user+'\n'))

    def test_explicit_root_is_not_cured_by_dynamic_user(self):
        self.assertIn('root_or_unspecified_user',self.codes('[Service]\nUser=root\nDynamicUser=yes\n'))
        self.assertNotIn('root_or_unspecified_user',self.codes('[Service]\nDynamicUser=yes\n'))

    def test_namespace_lists_combine_and_not_treated_as_full_restriction(self):
        r=self.review('[Service]\nRestrictNamespaces=net\nRestrictNamespaces=user\n')
        self.assertEqual(r['directives']['RestrictNamespaces']['namespaces'],['net','user'])
        self.assertIn('namespaces_not_fully_restricted',{f['code'] for f in r['findings']})

    def test_namespace_values_and_mixed_complements_are_rejected(self):
        for value in ('unknown','~'):
            with self.assertRaises(ValueError):self.review('[Service]\nRestrictNamespaces='+value+'\n')
        with self.assertRaises(ValueError):self.review('[Service]\nRestrictNamespaces=net\nRestrictNamespaces=~user\n')

    def test_line_continuation_without_execution(self):
        r=self.review('[Service]\nCapabilityBoundingSet=CAP_CHOWN \\\n CAP_NET_BIND_SERVICE\nExecStart=/SECRET_PATH \\\n --SECRET_ARG\n')
        self.assertEqual(len(r['directives']['CapabilityBoundingSet']['capabilities']),2)
        self.assertNotIn('SECRET',json.dumps(r))

    def test_dangling_and_excessive_continuations_rejected(self):
        with self.assertRaises(ValueError):self.review('[Service]\nExecStart=/command\\')
        with patch.dict(s.LIMITS,continuations=1),self.assertRaises(ValueError):self.review('[Service]\nExecStart=a\\\nb\\\nc\n')

    def test_final_piece_of_continued_logical_line_also_respects_budget(self):
        with patch.dict(s.LIMITS,line_bytes=30),self.assertRaises(ValueError):
            self.review('[Service]\nExecStart=first_long_value\\\nsecond_long_value\n')

    def test_comments_and_other_section_values_are_not_exported(self):
        r=self.review('[Unit]\nDescription=SECRET_DESCRIPTION\n# comment\n[Service]\n;ignored\nExecStart=/SECRET_COMMAND\n[Install]\nWantedBy=SECRET_TARGET\n')
        self.assertNotIn('SECRET',json.dumps(r))

    def test_bad_sections_outside_directives_and_missing_service_refused(self):
        for text in ('[Unit]\nDescription=x\n','NoNewPrivileges=yes\n[Service]\n','[Service]\nbroken\n','[Service] trailing\n','[Socket]\nListenStream=1\n'):
            with self.subTest(text=text),self.assertRaises(ValueError):self.review(text)

    def test_control_non_utf8_and_line_size_rejected(self):
        for data in (b'[Service]\nExecStart=bad\x00',b'\xff',b'[Service]\n'+b'X'*8193):
            with self.subTest(data=data[:20]),self.assertRaises(ValueError):s.analyze(data)

    def test_aggregate_line_directive_and_input_limits_are_not_truncation(self):
        for key,value,text in [('lines',1,'[Service]\nExecStart=x\n'),('directives',1,'[Service]\nExecStart=x\nUser=root\n'),('input_bytes',5,'[Service]\n')]:
            with self.subTest(key=key),patch.dict(s.LIMITS,{key:value}),self.assertRaises(ValueError):self.review(text)

    def test_environment_and_exec_reset_do_not_export_old_value(self):
        r=self.review('[Service]\nExecStart=/SECRET\nExecStart=\nEnvironment=SECRET\nEnvironment=\n')
        self.assertFalse(r['exec_start_present']);self.assertNotIn('SECRET',json.dumps(r))

    def test_source_hash_binds_ignored_command_changes_without_export(self):
        a=self.review('[Service]\nExecStart=/first\n');b=self.review('[Service]\nExecStart=/second\n')
        self.assertNotEqual(a['source_sha256'],b['source_sha256']);self.assertEqual(a['directives'],b['directives'])

    def test_actual_worker_accepts_and_refuses_without_execution(self):
        from cyber_platform import tools,worker
        self.assertIn('systemd',tools.REGISTRY)
        r=worker.analyze('systemd',s.sample().encode(),timeout=3)
        self.assertEqual(r['schema'],'was.systemd-review/1')
        with self.assertRaises(ValueError):worker.analyze('systemd',b'[Socket]\nX=1',timeout=3)
