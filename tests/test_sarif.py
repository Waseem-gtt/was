"""SARIF claims retain identity, severity and duplicate multiplicity without execution."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from cyber_platform import sarif
from cyber_platform.store import encode


class SarifTests(unittest.TestCase):
    def data(self, value=None):
        return encode(sarif.sample() if value is None else value).encode()

    def result(self, value):
        return value['runs'][0]['results'][0]

    def compare(self, left, right):
        return sarif.analyze_diff(self.data({'left':left,'right':right}))

    def test_reference_finding_preserves_level_location_and_identity(self):
        result = sarif.analyze(self.data())
        self.assertEqual(result['finding_count'], 1)
        finding = result['findings'][0]
        self.assertEqual(finding['rule_id'], 'SYN001')
        self.assertEqual(finding['locations'][0]['start_line'], 12)
        self.assertEqual(finding['tool']['version'], '1.0.0')
        self.assertEqual(len(finding['fingerprint']),64)
        self.assertEqual(result['summary'],{'error':0,'warning':1,'note':0,'none':0})

    def test_sarif_version_and_runs_are_strict(self):
        for v in ({}, {'version':'2.0.0','runs':[]}, {'version':'2.1.0','runs':{}}, {'version':'2.1.0','runs':[]}):
            with self.subTest(value=v), self.assertRaises(ValueError):sarif.analyze(self.data(v))

    def test_duplicate_json_and_nonfinite_invalid_utf8_refused(self):
        for raw in (b'{"version":1,"version":2}',b'{"n":NaN}',b'{"n":1e999}',b'\xff'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):sarif.analyze(raw)

    def test_missing_plain_text_and_template_arguments_are_not_silently_dropped(self):
        for message in ({'id':'missing'}, {'markdown':'canary'}, {'text':'{0}','arguments':['different']}):
            v=sarif.sample();self.result(v)['message']=message
            with self.subTest(message=message),self.assertRaises(ValueError):sarif.analyze(self.data(v))

    def test_supplied_partial_fingerprints_cannot_merge_distinct_messages(self):
        v=sarif.sample();a=self.result(v);a['partialFingerprints']={'claimed':'same'}
        b=copy.deepcopy(a);b['message']['text']='A distinct finding';v['runs'][0]['results'].append(b)
        report=sarif.analyze(self.data(v))
        self.assertEqual(len({r['fingerprint'] for r in report['findings']}),2)

    def test_duplicate_findings_are_retained_and_not_unique_counted(self):
        v=sarif.sample();v['runs'][0]['results']*=3
        report=sarif.analyze(self.data(v));self.assertEqual(report['finding_count'],3)
        self.assertEqual(report['summary']['warning'],3)

    def test_rule_index_resolves_and_conflicting_id_rejected(self):
        v=sarif.sample();r=self.result(v);del r['ruleId'];r['ruleIndex']=0
        self.assertEqual(sarif.analyze(self.data(v))['findings'][0]['rule_id'],'SYN001')
        r['ruleId']='OTHER'
        with self.assertRaises(ValueError):sarif.analyze(self.data(v))

    def test_rule_index_bool_negative_and_unknown_rule_refused(self):
        for index in (True,-1,1,1.0):
            v=sarif.sample();self.result(v)['ruleIndex']=index
            with self.subTest(index=index),self.assertRaises(ValueError):sarif.analyze(self.data(v))
        v=sarif.sample();self.result(v)['ruleId']='OTHER'
        with self.assertRaises(ValueError):sarif.analyze(self.data(v))

    def test_duplicate_rule_identifiers_are_rejected(self):
        v=sarif.sample();v['runs'][0]['tool']['driver']['rules']*=2
        with self.assertRaises(ValueError):sarif.analyze(self.data(v))

    def test_rule_default_level_is_used_and_explicit_level_overrides(self):
        v=sarif.sample();v['runs'][0]['tool']['driver']['rules'][0]['defaultConfiguration']['level']='note'
        self.assertEqual(sarif.analyze(self.data(v))['findings'][0]['level'],'note')
        self.result(v)['level']='error'
        self.assertEqual(sarif.analyze(self.data(v))['findings'][0]['level'],'error')

    def test_invalid_level_kind_and_rule_reference_object_refused(self):
        for key,val in [('level','fatal'),('level',False),('kind','evil'),('rule',{'id':'SYN001'})]:
            v=sarif.sample();self.result(v)[key]=val
            with self.subTest(key=key),self.assertRaises(ValueError):sarif.analyze(self.data(v))

    def test_artifact_index_resolves_without_file_read_or_network(self):
        v=sarif.sample();v['runs'][0]['artifacts']=[{'location':{'uri':'file:///private/does-not-exist.py'}}]
        self.result(v)['locations'][0]['physicalLocation']['artifactLocation']={'index':0}
        with patch.object(Path,'read_bytes',side_effect=AssertionError('file read')),patch('socket.create_connection',side_effect=AssertionError('network')):
            r=sarif.analyze(self.data(v))
        self.assertEqual(r['findings'][0]['locations'][0]['uri'],'file:///private/does-not-exist.py')

    def test_artifact_index_range_and_uri_conflicts_refused(self):
        for artifact in ({'index':0},{'index':True},{'uri':'a','uriBaseId':'ROOT'}):
            v=sarif.sample();self.result(v)['locations'][0]['physicalLocation']['artifactLocation']=artifact
            with self.subTest(artifact=artifact),self.assertRaises(ValueError):sarif.analyze(self.data(v))
        v=sarif.sample();v['runs'][0]['artifacts']=[{'location':{'uri':'a'}}]
        self.result(v)['locations'][0]['physicalLocation']['artifactLocation']={'index':0,'uri':'b'}
        with self.assertRaises(ValueError):sarif.analyze(self.data(v))

    def test_unsupported_coordinates_and_reversed_regions_refused(self):
        for region in ({'startLine':0},{'startLine':True},{'startLine':5,'endLine':4},{'startLine':1,'startColumn':9,'endColumn':3},{'byteOffset':10},{'charLength':3},{'startColumn':2}):
            v=sarif.sample();self.result(v)['locations'][0]['physicalLocation']['region']=region
            with self.subTest(region=region),self.assertRaises(ValueError):sarif.analyze(self.data(v))

    def test_logical_only_locations_are_refused(self):
        v=sarif.sample();self.result(v)['locations']=[{'logicalLocations':[{'name':'function'}]}]
        with self.assertRaises(ValueError):sarif.analyze(self.data(v))

    def test_snippets_fixes_markdown_and_code_flows_never_exported(self):
        v=sarif.sample();r=self.result(v);secret='DO_NOT_EXPORT_SNIPPET_CANARY'
        r['message']['markdown']=secret;r['fixes']=[{'description':{'text':secret}}];r['codeFlows']=[{'data':secret}]
        r['locations'][0]['physicalLocation']['region']['snippet']={'text':secret}
        report=sarif.analyze(self.data(v));self.assertNotIn(secret,encode(report));self.assertFalse(report['snippets_exported'])

    def test_scanner_version_and_automation_namespaces_change_identity(self):
        baseline=sarif.sample()
        for key in ('name','version','semanticVersion','organization'):
            v=sarif.sample();v['runs'][0]['tool']['driver'][key]='different'
            self.assertFalse(self.compare(baseline,v)['normalized_findings_equal'])
        for key in ('id','guid'):
            v=sarif.sample();v['runs'][0]['automationDetails']={key:'different'}
            self.assertFalse(self.compare(baseline,v)['normalized_findings_equal'])

    def test_equal_normalized_findings_ignore_json_key_order(self):
        v=sarif.sample();same=json.loads(json.dumps(v))
        r=self.compare(v,same);self.assertTrue(r['normalized_findings_equal']);self.assertEqual(r['counts']['unchanged'],1)
        self.assertEqual(r['embedded_document_encoding'],'canonical_json')

    def test_severity_change_is_not_added_and_resolved(self):
        r=sarif.analyze_diff(self.data(sarif.diff_sample()))
        self.assertEqual(r['counts'],{'added':0,'resolved':0,'unchanged':0,'severity_changed':1})
        self.assertEqual(r['severity_changed'][0]['from_level'],'warning')
        self.assertEqual(r['severity_changed'][0]['to_level'],'error')

    def test_multiset_comparison_matches_common_levels_then_pairs_changed_counts(self):
        left,right=sarif.sample(),sarif.sample()
        original=copy.deepcopy(self.result(left));left['runs'][0]['results']=[copy.deepcopy(original) for _ in range(3)]
        left['runs'][0]['results'][2]['level']='error'
        right['runs'][0]['results']=[copy.deepcopy(original) for _ in range(3)]
        right['runs'][0]['results'][1]['level']='error';right['runs'][0]['results'][2]['level']='error'
        self.assertEqual(self.compare(left,right)['counts'],{'added':0,'resolved':0,'unchanged':2,'severity_changed':1})

    def test_duplicate_removal_and_addition_counts_are_complete(self):
        left,right=sarif.sample(),sarif.sample();left['runs'][0]['results']*=4
        r=self.compare(left,right);self.assertEqual(r['counts']['resolved'],3);self.assertEqual(r['counts']['unchanged'],1)
        self.assertEqual(self.compare(right,left)['counts']['added'],3)

    def test_change_to_message_or_location_is_a_distinct_claim(self):
        left,right=sarif.sample(),sarif.sample();self.result(right)['message']['text']='different'
        r=self.compare(left,right);self.assertEqual(r['counts']['added'],1);self.assertEqual(r['counts']['resolved'],1)
        right=sarif.sample();self.result(right)['locations'][0]['physicalLocation']['region']['startLine']=13
        self.assertFalse(self.compare(left,right)['normalized_findings_equal'])

    def test_empty_results_are_allowed_but_not_a_security_pass(self):
        v=sarif.sample();v['runs'][0]['results']=[]
        report=sarif.analyze(self.data(v));self.assertEqual(report['finding_count'],0);self.assertNotIn('passed',report)

    def test_multiple_runs_keep_distinct_scanner_identities(self):
        v=sarif.sample();second=copy.deepcopy(v['runs'][0]);second['tool']['driver']['name']='second';v['runs'].append(second)
        report=sarif.analyze(self.data(v));self.assertEqual(report['run_count'],2);self.assertEqual(len({f['fingerprint'] for f in report['findings']}),2)

    def test_input_depth_nodes_and_byte_limits(self):
        with patch.dict(sarif.LIMITS,input_bytes=1),self.assertRaises(ValueError):sarif.analyze(self.data())
        with patch.dict(sarif.LIMITS,json_depth=2),self.assertRaises(ValueError):sarif.analyze(self.data())
        with patch.dict(sarif.LIMITS,json_nodes=2),self.assertRaises(ValueError):sarif.analyze(self.data())

    def test_run_rule_finding_and_location_caps(self):
        with patch.dict(sarif.LIMITS,runs=0),self.assertRaises(ValueError):sarif.analyze(self.data())
        with patch.dict(sarif.LIMITS,rules=0),self.assertRaises(ValueError):sarif.analyze(self.data())
        with patch.dict(sarif.LIMITS,findings=0),self.assertRaises(ValueError):sarif.analyze(self.data())
        with patch.dict(sarif.LIMITS,locations_per_finding=0),self.assertRaises(ValueError):sarif.analyze(self.data())

    def test_aggregate_output_bound_is_enforced(self):
        with patch.dict(sarif.LIMITS,output_bytes=10),self.assertRaises(ValueError):sarif.analyze(self.data())
        with patch.dict(sarif.LIMITS,output_bytes=10),self.assertRaises(ValueError):sarif.analyze_diff(self.data(sarif.diff_sample()))

    def test_comparison_envelope_is_exact_and_all_or_nothing(self):
        for v in ({'left':sarif.sample()}, {'left':sarif.sample(),'right':sarif.sample(),'extra':1}, {'left':sarif.sample(),'right':{}}, {'left':[],'right':{}}):
            with self.subTest(value=v),self.assertRaises(ValueError):sarif.analyze_diff(self.data(v))

    def test_malformed_later_result_prevents_partial_success(self):
        v=sarif.sample();v['runs'][0]['results'].append({'ruleId':'SYN001','message':{'id':'unresolved'}})
        with self.assertRaises(ValueError):sarif.analyze(self.data(v))

    def test_actual_worker_executes_analysis_and_severity_comparison(self):
        from cyber_platform import worker
        self.assertEqual(worker.analyze('sarif',self.data())['finding_count'],1)
        self.assertEqual(worker.analyze('sarif-diff',self.data(sarif.diff_sample()))['counts']['severity_changed'],1)
