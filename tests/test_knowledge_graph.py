"""F06 acceptance uses retained synthetic sources, not real owner data."""
import json
from unittest.mock import patch
from cyber_platform import knowledge_graph as graph
from cyber_platform.store import Problem, Store, encode
from tests.test_platform import StoreCase


class KnowledgeGraphTests(StoreCase):
    def setUp(self):
        super().setUp()
        self.source=self.evidence(b'synthetic source, not executed')

    def entity_data(self,kind='asset',**changes):
        data={'type':kind,'label':'جهاز تجريبي','description':'ادعاء موثق','source_evidence':self.source['id'],
              'confidence':80,'observed_at':'2026-10-23T12:00:00+03:00','valid_from':None,'valid_until':None,
              'reference_evidence':self.source['id'] if kind in ('evidence','experiment') else None}
        return {**data,**changes}

    def entity(self,kind='asset',**changes):
        return graph.create_entity(self.store,self.pid,self.entity_data(kind,**changes))['entity']

    def relation_data(self,left,right,**changes):
        return {'source':left['id'],'target':right['id'],'type':'supports','description':'دليل العلاقة',
                'source_evidence':self.source['id'],'confidence':90,'observed_at':'2026-10-23T09:00:00Z',
                'valid_from':None,'valid_until':None,'conflicts_with':None,**changes}

    def test_all_six_entity_types_have_source_observation_confidence_and_actual_references(self):
        for kind in graph.ENTITY_TYPES:self.entity(kind)
        value=graph.status(self.store,self.pid)
        self.assertEqual({item['type'] for item in value['entities']},set(graph.ENTITY_TYPES))
        self.assertEqual(value['relations'],[])
        for item in value['entities']:
            self.assertEqual(item['source_sha256'],self.source['sha256'])
            self.assertEqual(item['observed_at'],'2026-10-23T12:00:00+03:00')
            self.assertEqual(item['confidence'],80)
            self.assertEqual(item['validity'],'unbounded')
            self.assertEqual(item['reference_sha256'],self.source['sha256'] if item['type'] in ('evidence','experiment') else None)
        self.assertNotIn('synthetic source',encode(value))

    def test_all_relationship_types_and_meanings_are_preserved(self):
        left,right=self.entity(),self.entity('software')
        for kind in graph.RELATION_TYPES:
            graph.create_relation(self.store,self.pid,self.relation_data(left,right,type=kind))
        value=graph.status(self.store,self.pid)
        self.assertEqual({item['type'] for item in value['relations']},set(graph.RELATION_TYPES))
        self.assertTrue(any(c['kind']=='opposed_assertions' for c in value['conflicts']))
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_explicit_conflicts_survive_even_for_different_relation_types(self):
        left,right=self.entity(),self.entity('vulnerability')
        first=graph.create_relation(self.store,self.pid,self.relation_data(left,right,type='affects'))['relation']
        second=graph.create_relation(self.store,self.pid,self.relation_data(left,right,type='related_to',conflicts_with=first['id']))['relation']
        value=graph.status(self.store,self.pid)
        self.assertIn({'relations':sorted([first['id'],second['id']]),'kind':'explicit'},value['conflicts'])
        self.assertEqual(len(value['relations']),2)

    def test_validity_at_explicit_time_retains_expired_and_future_assertions(self):
        self.entity(valid_from='2026-11-01T00:00:00Z')
        self.entity(valid_until='2026-01-01T00:00:00Z')
        self.entity(valid_from='2026-10-23T00:00:00Z',valid_until='2026-10-24T00:00:00Z')
        value=graph.status(self.store,self.pid,'2026-10-23T10:00:00+03:00')
        self.assertEqual({item['validity'] for item in value['entities']},{'future','expired','active'})

    def test_conflicting_assertions_do_not_silently_merge_or_overwrite(self):
        self.entity(confidence=0);self.entity(confidence=100)
        items=graph.status(self.store,self.pid)['entities']
        self.assertEqual(len(items),2)
        self.assertNotEqual(items[0]['id'],items[1]['id'])
        self.assertEqual({item['confidence'] for item in items},{0,100})

    def test_evidence_and_experiment_must_reference_retained_sameproject_file(self):
        for kind in ('evidence','experiment'):
            with self.assertRaises(Problem):self.entity(kind,reference_evidence=None)
            with self.assertRaises(Problem):self.entity(kind,reference_evidence='a'*32)
        derived=self.store.add_evidence(self.pid,'result.json',b'{"result":"synthetic"}','result',self.source['id'])
        item=self.entity('experiment',reference_evidence=derived['id'])
        self.assertEqual(item['reference_sha256'],derived['sha256'])

    def test_crossproject_source_reference_endpoints_and_conflicts_rejected(self):
        other=self.store.create_project('other')['id']
        alien=self.store.add_evidence(other,'other.txt',b'other')
        for changes in ({'source_evidence':alien['id']},{'reference_evidence':alien['id']}):
            with self.assertRaises(Problem):self.entity(**changes)
        foreign=graph.create_entity(self.store,other,{**self.entity_data(),'source_evidence':alien['id']})['entity']
        own=self.entity()
        with self.assertRaises(Problem):graph.create_relation(self.store,self.pid,self.relation_data(own,foreign))
        with self.assertRaises(Problem):graph.create_relation(self.store,other,self.relation_data(own,foreign,source_evidence=alien['id']))
        with self.assertRaises(Problem):graph.create_relation(self.store,self.pid,self.relation_data(own,self.entity(),conflicts_with='a'*32))

    def test_strict_fields_types_unicode_and_empty_values(self):
        for data in ({**self.entity_data(),'unknown':1},{k:v for k,v in self.entity_data().items() if k!='confidence'},
                     self.entity_data(confidence=True),self.entity_data(confidence=-1),self.entity_data(confidence=101),
                     self.entity_data(type=[]),self.entity_data(label=' '),self.entity_data(label='\ud800'),self.entity_data(description='x'*2001)):
            with self.assertRaises(Problem):graph.create_entity(self.store,self.pid,data)
        self.assertEqual(graph.status(self.store,self.pid)['entities'],[])

    def test_invalid_and_unknownoffset_dates_are_rejected(self):
        for date in ('2026-02-30T00:00:00Z','2026-10-23','2026-10-23T00:00:00-00:00',
                     '2026-10-23T00:00:00+03:75','2026-10-23T00:00:00+24:00','2026-10-23T00:00:00.1234567Z'):
            with self.assertRaises(Problem):self.entity(observed_at=date)
        with self.assertRaises(Problem):self.entity(valid_from='2026-10-24T00:00:00Z',valid_until='2026-10-23T00:00:00Z')

    def test_source_must_be_original_and_size_is_bounded(self):
        derived=self.store.add_evidence(self.pid,'result',b'{}','result',self.source['id'])
        with self.assertRaises(Problem):self.entity(source_evidence=derived['id'])
        oversized=self.evidence(b'x'*(graph.LIMITS['source_bytes']+1))
        with self.assertRaises(Problem):self.entity(source_evidence=oversized['id'])

    def test_source_tampering_blocks_display_and_new_assertion(self):
        self.entity();path=self.store.blobs/self.source['id'];path.chmod(0o600);path.write_bytes(b'changed')
        with self.assertRaises(Problem):graph.status(self.store,self.pid)
        with self.assertRaises(Problem):self.entity()

    def test_reference_tampering_blocks_display(self):
        ref=self.store.add_evidence(self.pid,'result',b'{}','result',self.source['id'])
        self.entity('experiment',reference_evidence=ref['id'])
        path=self.store.blobs/ref['id'];path.chmod(0o600);path.write_bytes(b'xx')
        with self.assertRaises(Problem):graph.status(self.store,self.pid)

    def test_changed_graph_receipt_hash_cannot_reenroll_itself(self):
        item=self.entity();raw=json.loads(self.store.read_evidence(self.pid,item['id']))
        raw['data']['confidence']=1
        encoded=encode(raw).encode();path=self.store.blobs/item['id'];path.chmod(0o600);path.write_bytes(encoded)
        import hashlib
        with self.store.db:self.store.db.execute('UPDATE evidence SET sha256=?,size=? WHERE id=?',(hashlib.sha256(encoded).hexdigest(),len(encoded),item['id']))
        with self.assertRaises(Problem):graph.status(self.store,self.pid)

    def test_deleted_artifact_cannot_rewind_graph_membership(self):
        first=self.entity();second=self.entity()
        with self.store.db:self.store.db.execute('DELETE FROM evidence WHERE id=?',(second['id'],))
        with self.assertRaises(Problem):graph.status(self.store,self.pid)
        self.assertTrue(self.store.evidence(self.pid,first['id']))

    def test_unenrolled_copied_graph_file_is_rejected(self):
        item=self.entity();raw=self.store.read_evidence(self.pid,item['id'])
        self.store.add_evidence(self.pid,'copied.json',raw,'graph-entity',self.source['id'])
        with self.assertRaises(Problem):graph.status(self.store,self.pid)

    def test_publication_audit_failure_rolls_back_blob_rows_relations_and_audit(self):
        before=self.store.project_data(self.pid);blobs=set(self.store.blobs.iterdir());audit=self.store.rows('SELECT * FROM audit')
        with patch.object(self.store,'audit',side_effect=RuntimeError('test failure')):
            with self.assertRaises(RuntimeError):self.entity()
        self.assertEqual(self.store.project_data(self.pid),before)
        self.assertEqual(set(self.store.blobs.iterdir()),blobs)
        self.assertEqual(self.store.rows('SELECT * FROM audit'),audit)

    def test_source_changed_during_publication_cannot_publish_success(self):
        audit=self.store.audit
        def changed(action,details):
            audit(action,details)
            path=self.store.blobs/self.source['id'];path.chmod(0o600);path.write_bytes(b'changed')
        with patch.object(self.store,'audit',side_effect=changed):
            with self.assertRaises(Problem):self.entity()
        self.assertEqual(self.store.rows("SELECT id FROM evidence WHERE kind='graph-entity'"),[])
        self.assertEqual(self.store.rows("SELECT id FROM relations"),[])

    def test_read_after_store_reopen_and_independent_write_connections(self):
        first=self.entity();other=Store(self.store.root)
        try:
            second=graph.create_entity(other,self.pid,self.entity_data('software'))['entity']
            self.assertEqual({item['id'] for item in graph.status(self.store,self.pid)['entities']},{first['id'],second['id']})
        finally:other.close()

    def test_entity_limit_rejects_without_partial_artifact(self):
        with patch.dict(graph.LIMITS,{'entities':1}):
            self.entity()
            with self.assertRaises(Problem):self.entity()
            self.assertEqual(len(graph.status(self.store,self.pid)['entities']),1)
