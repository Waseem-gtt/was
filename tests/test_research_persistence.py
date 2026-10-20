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

    def test_restore_preserves_template_origin_plan_scan_and_project_report(self):
        from cyber_platform import plans,plan_templates,coverage_scans,case_reports
        library=plan_templates.library(self.store,self.pid);fixture=library['fixtures'][0]
        bindings={slot:self.evidence(data.encode())['id'] for slot,data in fixture['inputs'].items()}
        bound=plan_templates.instantiate(self.store,self.pid,fixture['template_id'],bindings)
        run=plans.start(self.store,self.pid,bound['plan'],instantiation_id=bound['evidence']['id'])
        for _ in range(20):
            if run['status']=='completed':break
            run=plans.advance(self.store,self.pid,run['id'])
        self.assertTrue(run['passed'])
        scan=coverage_scans.start(self.store,self.pid)
        for _ in range(10):
            if scan['status']=='completed':break
            scan=coverage_scans.advance(self.store,self.pid,scan['id'])
        report=case_reports.build(self.store,self.pid,'Restorable report',list(bindings.values()),[run['id']],scan['id'])
        password='Temporary-workflow-backup-123';payload=backup.export(self.store,password);destination=Path(self.temp.name)/'restored-plans'
        backup.restore(payload,password,destination);restored=Store(destination)
        try:
            reloaded=plans.status(restored,self.pid,run['id']);self.assertTrue(reloaded['passed']);self.assertEqual(reloaded['template_origin'],run['template_origin'])
            self.assertEqual(coverage_scans.status(restored,self.pid,scan['id'])['status'],'completed')
            self.assertEqual(case_reports.read(restored,self.pid,report['evidence']['id']),report['report'])
            self.assertTrue(case_reports.verify(restored,self.pid,report['evidence']['id'])['passed'])
            self.assertTrue(restored.verify_audit()['valid'])
        finally:restored.close()
