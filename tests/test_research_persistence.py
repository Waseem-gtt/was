"""Encrypted backup retains the new rule, event and defense evidence graph."""
from pathlib import Path
from cyber_platform import backup, coverage, detection, event_adapters, event_ingest
from cyber_platform.store import Store, encode
from tests.test_platform import StoreCase


class ResearchPersistenceTests(StoreCase):
    def test_encrypted_restore_preserves_rules_events_and_supported_coverage(self):
        rule={'id':'owner-restored','title':'Restored owner rule','version':'1.0.0','source':'synthetic fixture','license':'Private','selection':{'action':'login'}}
        saved=detection.save(self.store,self.pid,rule)
        sample=next(a for a in event_adapters.catalog() if a['id']=='windows-json')
        original=self.evidence(sample['example_content'].encode())
        normalized=event_ingest.normalize(self.store,self.pid,original['id'],sample['id'])
        library=detection.library(self.store,self.pid)
        source=self.evidence(encode(library['fixtures'][0]['input']).encode())
        tested=detection.test(self.store,self.pid,source['id'],['was-login-failure'])
        asset=coverage.asset(self.store,self.pid,'Restored service','service')
        assessment=coverage.assess(self.store,self.pid,asset['id'],'Synthetic login threat','Synthetic control',tested['evidence']['id'])
        password='Temporary-backup-fixture-123'
        payload=backup.export(self.store,password)
        destination=Path(self.temp.name)/'restored-research'
        backup.restore(payload,password,destination)
        restored=Store(destination)
        try:
            self.assertEqual(detection.library(restored,self.pid),library)
            self.assertEqual(restored.read_evidence(self.pid,saved['evidence']['id']),self.store.read_evidence(self.pid,saved['evidence']['id']))
            self.assertEqual(event_ingest.verify(restored,self.pid,normalized['evidence']['id']),normalized['report'])
            view=coverage.view(restored,self.pid)
            self.assertEqual(view['summary']['supported'],1)
            self.assertEqual(view['assessments'][0]['id'],assessment['id'])
            self.assertEqual(view['assessments'][0]['status'],'supported')
            self.assertTrue(restored.verify_audit()['valid'])
        finally:
            restored.close()
