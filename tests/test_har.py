"""Offline HAR validation, redaction and complete safe-metadata comparison."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch
from cyber_platform import har
from cyber_platform.store import encode


class HARTests(unittest.TestCase):
    def raw(self, value=None):
        return encode(har.sample() if value is None else value).encode()

    def entry(self, value): return value['log']['entries'][0]

    def diff(self, left, right): return har.analyze_diff(self.raw({'left':left,'right':right}))

    def test_synthetic_sample_is_metadata_only(self):
        result = har.analyze(self.raw())
        self.assertEqual(result['entry_count'], 1)
        self.assertEqual(result['origins'], [{'origin':'https://example.test','entries':1}])
        self.assertEqual([f['code'] for f in result['findings']], ['missing_csp'])
        self.assertFalse(result['network']); self.assertFalse(result['content_exported'])

    def test_original_byte_hash_is_not_reencoded(self):
        raw = json.dumps(har.sample(), indent=2).encode()
        self.assertEqual(har.analyze(raw)['source_sha256'], hashlib.sha256(raw).hexdigest())

    def test_every_sensitive_location_is_excluded(self):
        value = har.sample(); entry = self.entry(value); secret = 'PRIVATE_CANARY_29472'
        entry['request']['url'] = 'https://' + secret + ':password@example.test/' + secret + '?token=' + secret + '#' + secret
        entry['request']['headers'] = [{'name':'X-' + secret,'value':secret}]
        entry['request']['cookies'] = [{'name':secret,'value':secret}]
        entry['request']['postData'] = {'mimeType':'text/plain','text':secret,'params':[{'name':secret,'value':secret}]}
        entry['response']['headers'].append({'name':'X-' + secret,'value':secret})
        entry['response']['cookies'] = [{'name':secret,'value':secret}]
        entry['response']['content'] = {'text':secret,'encoding':'base64'}
        result = encode(har.analyze(self.raw(value)))
        self.assertNotIn(secret, result); self.assertNotIn('password', result)
        self.assertNotIn('postData', result)

    def test_default_ports_and_host_case_normalize(self):
        value = har.sample(); self.entry(value)['request']['url'] = 'https://EXAMPLE.test:443/a'
        self.assertEqual(har.analyze(self.raw(value))['entries'][0]['origin'], 'https://example.test')
        self.entry(value)['request']['url'] = 'http://example.test:8080/a'
        self.assertEqual(har.analyze(self.raw(value))['entries'][0]['origin'], 'http://example.test:8080')

    def test_ipv6_origin_and_idna_are_bounded_metadata(self):
        value = har.sample(); self.entry(value)['request']['url'] = 'https://[2001:db8::1]:8443/private'
        self.assertEqual(har.analyze(self.raw(value))['entries'][0]['origin'], 'https://[2001:db8::1]:8443')
        self.entry(value)['request']['url'] = 'https://bücher.example/a'
        self.assertEqual(har.analyze(self.raw(value))['entries'][0]['origin'], 'https://xn--bcher-kva.example')

    def test_non_http_urls_bad_hosts_ports_and_controls_are_rejected(self):
        for url in ('file:///etc/passwd','javascript:alert(1)','https://bad_host.test','https://example.test:99999','https://example.test:0','https://example.test/\nprivate'):
            value=har.sample();self.entry(value)['request']['url']=url
            with self.subTest(url=url), self.assertRaises(ValueError):har.analyze(self.raw(value))

    def test_invalid_json_duplicate_keys_nonfinite_and_wrong_root(self):
        for raw in (b'not json',b'{"log":{},"log":{}}',b'{"n":NaN}',b'{"n":1e999}',b'[]',b'\xff'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):har.analyze(raw)

    def test_unpaired_surrogate_keys_and_values_are_rejected(self):
        for raw in (b'{"\\ud800":1}',b'{"a":"\\ud800"}'):
            with self.assertRaises(ValueError):har.analyze(raw)

    def test_wrong_version_and_entry_structure_are_rejected(self):
        for version, entries in [('1.1',[]),('1.2',{}),('1.2',[{}]),('1.2',[{'request':[],'response':{}}])]:
            with self.assertRaises(ValueError):har.analyze(self.raw({'log':{'version':version,'entries':entries}}))

    def test_method_and_protocol_cannot_be_arbitrary_export_channels(self):
        for key, value in [('method','SECRET_CUSTOM'),('method',[]),('httpVersion','SECRET_PROTOCOL'),('httpVersion',True)]:
            sample=har.sample();target=self.entry(sample)['request' if key=='method' else 'response'];target[key]=value
            with self.assertRaises(ValueError):har.analyze(self.raw(sample))

    def test_status_exact_integer_range(self):
        for status in (True,-1,99,600,200.0,'200'):
            value=har.sample();self.entry(value)['response']['status']=status
            with self.assertRaises(ValueError):har.analyze(self.raw(value))

    def test_duration_exact_finite_bounded_number(self):
        for duration in (True,-2,86400001,'1'):
            value=har.sample();self.entry(value)['time']=duration
            with self.assertRaises(ValueError):har.analyze(self.raw(value))

    def test_status_zero_never_invents_missing_response_security_headers(self):
        value=har.sample();self.entry(value)['response'].update(status=0,headers=[])
        result=har.analyze(self.raw(value));self.assertEqual(result['findings'],[])
        self.assertFalse(result['entries'][0]['response_recorded'])

    def test_plain_http_credential_presence_without_values(self):
        value=har.sample();entry=self.entry(value);entry['request']['url']='http://example.test/'
        entry['request']['headers']=[{'name':'Authorization','value':'Bearer PRIVATE_AUTH_CANARY'}]
        result=har.analyze(self.raw(value));codes={f['code'] for f in result['findings']}
        self.assertIn('insecure_transport',codes);self.assertIn('credentials_over_http',codes)
        self.assertNotIn('PRIVATE_AUTH_CANARY',encode(result))

    def test_cors_observation_is_explicit_fixed_claim(self):
        value=har.sample();self.entry(value)['response']['headers'] += [{'name':'Access-Control-Allow-Origin','value':'*'},{'name':'Access-Control-Allow-Credentials','value':'true'}]
        self.assertIn('cors_wildcard_credentials',{f['code'] for f in har.analyze(self.raw(value))['findings']})

    def test_structured_cookie_attribute_observations_are_redacted(self):
        value=har.sample();self.entry(value)['response']['cookies']=[{'name':'session_private','value':'PRIVATE_SESSION','sameSite':'None'}]
        result=har.analyze(self.raw(value));codes={f['code'] for f in result['findings']}
        self.assertTrue({'cookie_without_secure','cookie_without_http_only','same_site_none_without_secure'} <= codes)
        self.assertNotIn('PRIVATE_SESSION',encode(result));self.assertNotIn('session_private',encode(result))

    def test_set_cookie_attributes_and_structured_preference_do_not_duplicate(self):
        value=har.sample();entry=self.entry(value);entry['response']['headers'].append({'name':'Set-Cookie','value':'secret=value; Secure; HttpOnly; SameSite=Lax'})
        result=har.analyze(self.raw(value));self.assertEqual(result['entries'][0]['response_cookie_attributes'],[{'secure':True,'http_only':True,'same_site':'lax'}])
        entry['response']['cookies']=[{'name':'secret','value':'value','secure':True,'httpOnly':True,'sameSite':'Strict'}]
        self.assertEqual(har.analyze(self.raw(value))['entries'][0]['response_cookie_count'],1)

    def test_bad_cookie_types_flags_and_headers_fail(self):
        invalid=[{'name':'x','value':'x','secure':'true'},{'name':'x','value':'x','sameSite':'secret'},[],{'name':5,'value':'x'}]
        for cookie in invalid:
            value=har.sample();self.entry(value)['response']['cookies']=[cookie]
            with self.assertRaises(ValueError):har.analyze(self.raw(value))
        for header in ({'name':'bad\nname','value':'x'},{'name':'X-Test','value':'x\r\nPrivate: v'},{}):
            value=har.sample();self.entry(value)['response']['headers']=[header]
            with self.assertRaises(ValueError):har.analyze(self.raw(value))

    def test_multiple_origins_and_entry_order_preserved(self):
        value=har.sample();second=copy.deepcopy(self.entry(value));second['request']['url']='https://other.example/a';value['log']['entries'].append(second)
        result=har.analyze(self.raw(value));self.assertEqual(result['summary']['origins'],2)
        self.assertEqual([e['index'] for e in result['entries']],[0,1])

    def test_late_bad_entry_never_returns_partial_success(self):
        value=har.sample();value['log']['entries'].append({'request':{},'response':{}})
        with self.assertRaises(ValueError):har.analyze(self.raw(value))

    def test_entry_header_cookie_limits(self):
        for limit, number in [('entries',0),('headers',1)]:
            with patch.dict(har.LIMITS,{limit:number}),self.assertRaises(ValueError):har.analyze(self.raw())
        value=har.sample();self.entry(value)['request']['cookies']=[{'name':'x','value':'y'}]
        with patch.dict(har.LIMITS,{'cookies':0}),self.assertRaises(ValueError):har.analyze(self.raw(value))

    def test_input_depth_node_and_output_budgets(self):
        for limits in ({'input_bytes':1},{'json_depth':1},{'json_nodes':1},{'output_bytes':1}):
            with patch.dict(har.LIMITS,limits),self.assertRaises(ValueError):har.analyze(self.raw())

    def test_large_integer_rejected_even_in_ignored_field(self):
        value=har.sample();value['ignored']=2**64
        with self.assertRaises(ValueError):har.analyze(self.raw(value))

    def test_errors_do_not_echo_owner_content(self):
        value=har.sample();self.entry(value)['request']['url']='secret://PRIVATE_OWNER_TOKEN'
        with self.assertRaises(ValueError) as caught:har.analyze(self.raw(value))
        self.assertNotIn('PRIVATE_OWNER_TOKEN',str(caught.exception))

    def test_complete_same_metadata_comparison(self):
        result=self.diff(har.sample(),har.sample());self.assertTrue(result['complete']);self.assertTrue(result['normalized_metadata_equal'])
        self.assertEqual(result['changed_entries'],[])

    def test_changed_status_detected(self):
        result=har.analyze_diff(self.raw(har.diff_sample()))
        self.assertFalse(result['normalized_metadata_equal']);self.assertEqual(result['changed_entries'],[{'index':0,'fields':['status']}])

    def test_duplicate_entries_are_counted_not_collapsed(self):
        left=har.sample();right=har.sample();right['log']['entries'].append(copy.deepcopy(self.entry(right)))
        result=self.diff(left,right);self.assertFalse(result['normalized_metadata_equal']);self.assertEqual(result['added_entry_indexes'],[1])
        self.assertEqual(self.diff(right,left)['removed_entry_indexes'],[1])

    def test_reordering_distinct_entries_is_not_equal(self):
        left=har.sample();second=copy.deepcopy(self.entry(left));second['response']['status']=404;left['log']['entries'].append(second)
        right=copy.deepcopy(left);right['log']['entries'].reverse()
        self.assertEqual(len(self.diff(left,right)['changed_entries']),2)

    def test_hidden_values_are_excluded_from_comparison_scope(self):
        left=har.sample();right=har.sample();self.entry(right)['request']['url']='https://example.test/PRIVATE_TOKEN?secret=PRIVATE_TOKEN'
        result=self.diff(left,right);self.assertTrue(result['normalized_metadata_equal']);self.assertNotIn('PRIVATE_TOKEN',encode(result))

    def test_diff_envelope_exact_fields_and_document_types(self):
        for value in ({'left':har.sample()},{'left':[], 'right':har.sample()},{'left':har.sample(),'right':har.sample(),'execute':'no'}):
            with self.assertRaises(ValueError):har.analyze_diff(self.raw(value))

    def test_diff_hashes_bind_canonical_documents_and_original_bundle(self):
        value=har.diff_sample();raw=json.dumps(value,indent=2).encode();result=har.analyze_diff(raw)
        self.assertEqual(result['source_bundle_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['left_sha256'],hashlib.sha256(encode(value['left']).encode()).hexdigest())
        self.assertEqual(result['embedded_document_encoding'],'canonical_json')

    def test_no_network_or_file_execution(self):
        with patch('socket.create_connection',side_effect=AssertionError('network')),patch('subprocess.run',side_effect=AssertionError('execution')):
            self.assertEqual(har.analyze(self.raw())['entry_count'],1)

    def test_registered_bounded_workers_execute_analysis_and_comparison(self):
        from cyber_platform import worker
        self.assertEqual(worker.analyze('har',self.raw())['entry_count'],1)
        self.assertFalse(worker.analyze('har-diff',self.raw(har.diff_sample()))['normalized_metadata_equal'])
