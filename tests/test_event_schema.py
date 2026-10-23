"""Versioned event language preserves source/timing and explicitly reports gaps."""
import copy
import hashlib
import json
from unittest.mock import patch
from cyber_platform import event_adapters, event_ingest, event_schema, worker
from cyber_platform.store import Problem
from tests.test_platform import StoreCase


def windows(time='2026-01-01T01:02:03.1234567+03:00', **changes):
    row={'time':time,'event_id':4625,'actor':'owner','action':'login','outcome':'failure'}
    row.update(changes)
    return json.dumps([row],ensure_ascii=False)


class EventSchemaTests(StoreCase):
    def test_all_adapters_emit_schema_version_dictionary_and_verified_quality(self):
        for adapter in event_adapters.catalog():
            with self.subTest(adapter=adapter['id']):
                normalized=event_adapters.normalize(adapter['id'],adapter['example_content'])
                self.assertEqual(normalized['schema_version'],'1.0.0')
                self.assertEqual(normalized['dictionary_sha256'],event_schema.describe()['dictionary_sha256'])
                self.assertEqual(normalized['quality']['records'],normalized['count'])
                self.assertTrue(event_schema.verify(normalized))

    def test_dictionary_is_self_contained_and_describe_does_not_mutate_registry(self):
        first=event_schema.describe();first['fields'][0]['name']='mutated'
        current=event_schema.describe()
        self.assertEqual(current['fields'][0]['name'],'time')
        self.assertEqual(set(current['json_schema']['$defs']),{a['id'] for a in event_adapters.catalog()})
        self.assertEqual(current['supported_versions'],['1.0.0'])
        branches=current['json_schema']['oneOf']
        self.assertEqual({branch['properties']['adapter']['const'] for branch in branches},{a['id'] for a in event_adapters.catalog()})
        self.assertTrue(all('quality' in branch['required'] and branch['additionalProperties'] is False for branch in branches))
        self.assertTrue(all(branch['properties']['events']['items']['$ref'].startswith('#/$defs/') for branch in branches))
        self.assertTrue(all(value['additionalProperties'] is False for value in current['json_schema']['$defs'].values()))

    def test_dictionary_digest_binds_published_schema_and_is_reproducible(self):
        description=event_schema.describe()
        content={key:description[key] for key in description['digest_scope']}
        canonical=json.dumps(content,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        self.assertEqual(hashlib.sha256(canonical).hexdigest(),description['dictionary_sha256'])
        original=event_schema._event_schema
        def changed(adapter):
            schema=original(adapter);schema['description']='simulated change';return schema
        with patch.object(event_schema,'_event_schema',side_effect=changed):
            self.assertNotEqual(event_schema.digest(),description['dictionary_sha256'])

    def test_complete_record_has_no_missing_information_flags(self):
        result=event_adapters.normalize('windows-json',windows())
        quality=result['quality']
        self.assertEqual(quality['records_with_gaps'],0)
        self.assertEqual(quality['unknown_counts'],{'time':0,'actor':0,'action':0,'outcome':0})
        self.assertEqual(quality['flags'],[])

    def test_unknown_fields_are_quality_gaps_not_invented_claims(self):
        content='[{"time":"2026-01-01T00:00:00Z","event_id":4625}]'
        result=event_adapters.normalize('windows-json',content)
        self.assertEqual(result['events'][0]['action'],'unknown')
        self.assertEqual(result['events'][0]['outcome'],'unknown')
        self.assertEqual(result['quality']['unknown_counts'],{'time':0,'actor':1,'action':1,'outcome':1})
        self.assertEqual(result['quality']['flags'],[{'index':0,'codes':['unknown_actor','unknown_action','unknown_outcome']}])
        self.assertEqual(result['failed'],0)

    def test_fractional_precision_and_offset_preserved_exactly(self):
        timestamp='2026-01-01T01:02:03.1234567+03:00'
        result=event_adapters.normalize('windows-json',windows(timestamp))
        self.assertEqual(result['events'][0]['time'],timestamp)
        self.assertEqual(result['quality']['timestamps'],[{'index':0,'original':timestamp,'offset':'+03:00','offset_known':True,'fraction_digits':7}])

    def test_negative_zero_offset_is_preserved_and_marked_unspecified(self):
        result=event_adapters.normalize('windows-json',windows('2026-01-01T01:02:03-00:00'))
        time=result['quality']['timestamps'][0]
        self.assertFalse(time['offset_known'])
        self.assertEqual(time['offset'],'-00:00')
        self.assertEqual(result['quality']['flags'],[{'index':0,'codes':['offset_unspecified']}])

    def test_syslog_nilvalue_time_stays_unknown(self):
        result=event_adapters.normalize('syslog-rfc5424','<34>1 - - app 123 ID47 - message')
        self.assertEqual(result['events'][0]['time'],'unknown')
        self.assertEqual(result['quality']['unknown_counts']['time'],1)
        self.assertEqual(result['quality']['timestamps'][0]['offset'],None)

    def test_record_order_and_duplicate_records_retained(self):
        rows=json.loads(windows());rows.append({**rows[0],'actor':'second'});rows.append(rows[0])
        result=event_adapters.normalize('windows-json',json.dumps(rows))
        self.assertEqual([e['actor'] for e in result['events']],['owner','second','owner'])
        self.assertEqual([t['index'] for t in result['quality']['timestamps']],[0,1,2])
        self.assertTrue(result['quality']['order_preserved'])

    def test_shape_wrong_types_extra_fields_and_wrong_totals_rejected(self):
        original=event_adapters.normalize('windows-json',windows())
        mutations=[lambda r:r['events'][0].update(surprise='ignored?'),
                   lambda r:r['events'][0].update(event_id=True),
                   lambda r:r['events'][0].update(original=[]),
                   lambda r:r.update(count=True),lambda r:r.update(failed=0),
                   lambda r:r['events'][0].update(time='2026-02-30T00:00:00Z'),
                   lambda r:r['events'][0].pop('actor')]
        for mutate in mutations:
            value=copy.deepcopy(original);mutate(value)
            with self.subTest(value=value):
                with self.assertRaises(ValueError):event_schema.verify(value)

    def test_false_quality_claims_or_unknown_version_rejected(self):
        original=event_adapters.normalize('windows-json',windows())
        for key,value in [('schema_version','2.0.0'),('dictionary_sha256','f'*64),('quality',{'records':1})]:
            altered={**original,key:value}
            with self.assertRaises(ValueError):event_schema.verify(altered)
        altered=copy.deepcopy(original);altered['quality']['source_bytes_preserved']=False
        with self.assertRaises(ValueError):event_schema.verify(altered)

    def test_ingest_retains_exact_original_bytes_and_source_relation(self):
        raw=(windows()+'\n').encode();source=self.evidence(raw,'windows.json')
        result=event_ingest.normalize(self.store,self.pid,source['id'],'windows-json')
        self.assertEqual(self.store.read_evidence(self.pid,source['id']),raw)
        self.assertEqual(result['report']['input_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['evidence']['parent_id'],source['id'])
        self.assertEqual(event_ingest.verify(self.store,self.pid,result['evidence']['id']),result['report'])

    def test_worker_bad_normalized_shape_cannot_be_persisted(self):
        raw=windows().encode();source=self.evidence(raw)
        result=event_adapters.normalize('windows-json',raw.decode());result['events'][0]['undocumented']='bad'
        with patch.object(worker,'analyze',return_value=result):
            with self.assertRaises(Problem):event_ingest.normalize(self.store,self.pid,source['id'],'windows-json')
        self.assertFalse(self.store.rows("SELECT * FROM evidence WHERE kind='events'"))

    def test_quality_tamper_breaks_replay_even_when_blob_hash_is_updated(self):
        source=self.evidence(windows().encode());result=event_ingest.normalize(self.store,self.pid,source['id'],'windows-json')
        report=result['report'];report['result']['quality']['unknown_counts']['actor']=99
        raw=json.dumps(report).encode();path=self.store.blobs/result['evidence']['id'];path.chmod(0o600);path.write_bytes(raw);path.chmod(0o400)
        with self.store.db:self.store.db.execute('UPDATE evidence SET sha256=?,size=? WHERE id=?',(hashlib.sha256(raw).hexdigest(),len(raw),result['evidence']['id']))
        with self.assertRaises(Problem):event_ingest.verify(self.store,self.pid,result['evidence']['id'])

    def test_dictionary_change_changes_ingest_provenance(self):
        before=event_ingest.fingerprint()
        original=event_ingest.Path.read_bytes
        def changed(file):
            data=original(file)
            return data+b'\n# simulated parser change' if file.name=='event_schema.py' else data
        with patch.object(event_ingest.Path,'read_bytes',changed):
            after=event_ingest.fingerprint()
        self.assertNotEqual(before,after)

    def test_legacy_bare_event_array_contract_is_unchanged(self):
        from cyber_platform import tools
        result=tools.events(b'[{"user":"demo","outcome":"failure"}]')
        self.assertNotIn('quality',result)
        self.assertEqual(result['events'][0]['outcome'],'failure')
