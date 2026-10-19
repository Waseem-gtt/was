"""Derived event provenance and atomic publication use only temporary evidence."""
import json
from unittest.mock import patch
from cyber_platform import event_ingest, event_adapters
from cyber_platform.store import Problem, encode
from tests.test_platform import StoreCase


class EventIngestTests(StoreCase):
    def source(self):
        sample = next(a['example_content'] for a in event_adapters.catalog() if a['id']=='windows-json')
        return self.evidence(sample.encode(), 'windows.json')

    def test_real_normalization_provenance_and_replay(self):
        source = self.source()
        before = self.store.read_evidence(self.pid, source['id'])
        out = event_ingest.normalize(self.store, self.pid, source['id'], 'windows-json')
        self.assertEqual(out['evidence']['kind'], 'events')
        self.assertEqual(out['evidence']['parent_id'], source['id'])
        self.assertEqual(out['report']['input_sha256'], source['sha256'])
        self.assertEqual(self.store.read_evidence(self.pid, source['id']), before)
        self.assertEqual(event_ingest.verify(self.store, self.pid, out['evidence']['id']), out['report'])
        self.assertTrue(any(r['source']==source['id'] and r['target']==out['evidence']['id'] for r in self.store.project_data(self.pid)['relations']))
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_changed_source_and_forged_wrapper_rejected(self):
        source = self.source()
        out = event_ingest.normalize(self.store, self.pid, source['id'], 'windows-json')
        forged = self.evidence(encode(out['report']).encode(), 'forged.json')
        with self.assertRaises(Problem):
            event_ingest.verify(self.store, self.pid, forged['id'])
        path = self.store.blobs/source['id']; path.chmod(0o600); path.write_bytes(b'changed')
        with self.assertRaises(Problem):
            event_ingest.verify(self.store, self.pid, out['evidence']['id'])

    def test_invalid_input_cross_project_and_limits_publish_nothing(self):
        source = self.source()
        other = self.store.create_project('Other')['id']
        for pid,eid,adapter in [(other,source['id'],'windows-json'),(self.pid,source['id'],{}),(self.pid,source['id'],'../../secret')]:
            with self.assertRaises(Problem):event_ingest.normalize(self.store,pid,eid,adapter)
        oversized=self.evidence(b'x'*(1024*1024+1))
        with self.assertRaises(Problem) as caught:event_ingest.normalize(self.store,self.pid,oversized['id'],'windows-json')
        self.assertEqual(caught.exception.status,413)
        invalid=self.evidence(b'not-json')
        with self.assertRaises(Problem):event_ingest.normalize(self.store,self.pid,invalid['id'],'windows-json')
        self.assertEqual(self.store.rows("SELECT id FROM evidence WHERE kind='events'"),[])

    def test_publish_failure_rolls_back_blob_metadata_relation_and_audit(self):
        source=self.source(); before=self.store.project_data(self.pid); blobs=set(self.store.blobs.iterdir()); audit=self.store.rows('SELECT * FROM audit')
        with patch.object(self.store,'audit',side_effect=RuntimeError('simulated persistence failure')):
            with self.assertRaises(RuntimeError):event_ingest.normalize(self.store,self.pid,source['id'],'windows-json')
        self.assertEqual(self.store.project_data(self.pid),before)
        self.assertEqual(set(self.store.blobs.iterdir()),blobs)
        self.assertEqual(self.store.rows('SELECT * FROM audit'),audit)

    def test_engine_changes_during_execution_or_verification_fail_closed(self):
        source=self.source()
        with patch.object(event_ingest,'fingerprint',side_effect=['a'*64,'b'*64]):
            with self.assertRaises(Problem):event_ingest.normalize(self.store,self.pid,source['id'],'windows-json')
        self.assertEqual(self.store.rows("SELECT id FROM evidence WHERE kind='events'"),[])
        out=event_ingest.normalize(self.store,self.pid,source['id'],'windows-json')
        with patch.object(event_ingest,'fingerprint',return_value='a'*64):
            with self.assertRaises(Problem):event_ingest.verify(self.store,self.pid,out['evidence']['id'])
