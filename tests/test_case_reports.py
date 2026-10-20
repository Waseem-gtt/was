"""Private metadata reports preserve provenance without exporting source contents."""
import hashlib
import json
from unittest.mock import patch
from cyber_platform import case_reports, coverage_scans, plans
from cyber_platform.store import Problem, encode
from tests.test_platform import StoreCase


class CaseReportTests(StoreCase):
    def source(self):return self.evidence(b'PRIVATE_SYNTHETIC_FIXTURE_NOT_FOR_REPORT','sensitive.txt')
    def build(self,eid,**kw):
        return case_reports.build(self.store,self.pid,kw.get('title','Synthetic report'),[eid],kw.get('runs',[]),kw.get('scan'))
    def plan(self,eid,nodes=1):
        return {'schema':'was.plan/1','name':'Synthetic plan','nodes':[{'id':'step-'+str(i),'tool':'hashes','input':{'evidence_id':eid}} for i in range(nodes)]}
    def finish(self,run):
        for _ in range(30):
            if run['status'] in ('completed','failed'):return run
            run=plans.advance(self.store,self.pid,run['id'])
        self.fail('plan failed to finish')

    def test_report_is_immutable_metadata_only_and_references_verify(self):
        source=self.source();before=self.store.read_evidence(self.pid,source['id']);out=self.build(source['id'])
        report=case_reports.read(self.store,self.pid,out['evidence']['id'])
        self.assertEqual(report,out['report']);self.assertEqual(out['evidence']['kind'],'project-report')
        self.assertNotIn(before.decode(),encode(report));self.assertEqual(report['evidence'][0]['sha256'],source['sha256'])
        with patch('cyber_platform.worker.analyze',side_effect=AssertionError('unexpected execution')):
            self.assertTrue(case_reports.verify(self.store,self.pid,out['evidence']['id'])['passed'])
        self.assertEqual(self.store.read_evidence(self.pid,source['id']),before)
        self.assertTrue(self.store.verify_audit()['valid']);self.assertEqual(case_reports.history(self.store,self.pid)['reports'][0]['id'],out['evidence']['id'])

    def test_html_escapes_all_owner_strings_and_has_no_executable_script(self):
        source=self.evidence(b'data','<svg_onload_fixture>.txt');report=self.build(source['id'],title='<script>alert(1)</script>')['report']
        html=case_reports.render_html(report).decode()
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;',html);self.assertNotIn('<script',html.lower())
        self.assertIn('Content-Security-Policy',html);self.assertIn('default-src',html);self.assertNotIn('src="http',html)

    def test_changed_source_fails_verification_without_modifying_report(self):
        source=self.source();out=self.build(source['id']);saved=self.store.read_evidence(self.pid,out['evidence']['id'])
        path=self.store.blobs/source['id'];path.chmod(0o600);path.write_bytes(b'changed')
        checked=case_reports.verify(self.store,self.pid,out['evidence']['id']);self.assertFalse(checked['passed']);self.assertEqual(checked['issues'][0]['type'],'evidence')
        self.assertEqual(self.store.read_evidence(self.pid,out['evidence']['id']),saved)

    def test_cross_project_and_recursive_report_sources_rejected(self):
        source=self.source();other=self.store.create_project('Other')['id'];out=self.build(source['id'])
        with self.assertRaises(Problem):case_reports.build(self.store,other,'Cross',[source['id']],[])
        with self.assertRaises(Problem):self.build(out['evidence']['id'])
        with self.assertRaises(Problem):case_reports.read(self.store,other,out['evidence']['id'])

    def test_invalid_selectors_titles_empty_and_duplicate_refs_rejected(self):
        eid=self.source()['id']
        bad=[('',[eid],[]),('x',[],[]),('bad\nname',[eid],[]),('x',[eid,eid],[]),('x',['../path'],[]),('x',[eid],[True])]
        for title,ids,runs in bad:
            with self.subTest(title=title,ids=ids),self.assertRaises(Problem):case_reports.build(self.store,self.pid,title,ids,runs)
        self.assertEqual(case_reports.history(self.store,self.pid)['reports'],[])

    def test_saved_plan_and_completed_coverage_are_explicit_snapshots(self):
        eid=self.source()['id'];run=self.finish(plans.start(self.store,self.pid,self.plan(eid)))
        self.assertTrue(run['passed']);scan=coverage_scans.start(self.store,self.pid)
        for _ in range(10):
            if scan['status']=='completed':break
            scan=coverage_scans.advance(self.store,self.pid,scan['id'])
        out=self.build(eid,runs=[run['id']],scan=scan['id']);report=out['report']
        self.assertEqual(report['plans'][0]['snapshot']['id'],run['id']);self.assertEqual(report['coverage']['current_validity'],'snapshot_only')
        self.assertTrue(case_reports.verify(self.store,self.pid,out['evidence']['id'])['passed'])

    def test_plan_progress_changes_reference_but_keeps_original_report(self):
        eid=self.source()['id'];run=plans.start(self.store,self.pid,self.plan(eid))
        out=self.build(eid,runs=[run['id']]);self.finish(run)
        checked=case_reports.verify(self.store,self.pid,out['evidence']['id']);self.assertFalse(checked['passed']);self.assertTrue(any(i['type']=='plan' for i in checked['issues']))
        self.assertEqual(case_reports.read(self.store,self.pid,out['evidence']['id'])['plans'][0]['snapshot']['status'],'pending')

    def test_unfinished_scan_not_exported_as_completed(self):
        eid=self.source()['id'];scan=coverage_scans.start(self.store,self.pid)
        with self.assertRaises(Problem):self.build(eid,scan=scan['id'])

    def test_aggregate_plan_proof_budget_rejects_large_repeated_inputs(self):
        eid=self.evidence(b'x'*(4*1024*1024))['id'];run=self.finish(plans.start(self.store,self.pid,self.plan(eid,8)))
        self.assertTrue(run['passed'])
        with self.assertRaises(Problem) as caught:case_reports.build(self.store,self.pid,'Too large',[],[run['id']])
        self.assertEqual(caught.exception.status,413);self.assertEqual(case_reports.history(self.store,self.pid)['reports'],[])

    def test_failure_rolls_back_report_file_database_relation_and_audit(self):
        eid=self.source()['id'];before=self.store.project_data(self.pid);blobs=set(self.store.blobs.iterdir())
        with patch.object(self.store,'audit',side_effect=RuntimeError('simulated')):
            with self.assertRaises(RuntimeError):self.build(eid)
        self.assertEqual(self.store.project_data(self.pid),before);self.assertEqual(set(self.store.blobs.iterdir()),blobs)

    def test_report_retention_limit_never_silently_deletes_history(self):
        eid=self.source()['id']
        originals=[self.build(eid)['evidence']['id'] for _ in range(50)]
        with self.assertRaises(Problem) as caught:self.build(eid)
        self.assertEqual(caught.exception.status,413);self.assertEqual(len(case_reports.history(self.store,self.pid)['reports']),50)
        self.assertTrue(self.store.read_evidence(self.pid,originals[0]))

    def test_resigned_malformed_reference_cannot_bypass_budget(self):
        eid=self.source()['id'];out=self.build(eid);record=out['evidence'];report=out['report'];report['evidence'][0]['size']=-1
        report['digest']=case_reports._digest({k:v for k,v in report.items() if k!='digest'});raw=encode(report).encode()
        path=self.store.blobs/record['id'];path.chmod(0o600);path.write_bytes(raw)
        with self.store.db:self.store.db.execute('UPDATE evidence SET size=?,sha256=? WHERE id=?',(len(raw),hashlib.sha256(raw).hexdigest(),record['id']))
        with self.assertRaises(Problem):case_reports.read(self.store,self.pid,record['id'])

    def test_modified_metadata_rejected_before_any_source_read(self):
        eid=self.source()['id'];out=self.build(eid);read=self.store.read_evidence
        with self.store.db:self.store.db.execute('UPDATE evidence SET size=? WHERE id=?',(16*1024*1024,eid))
        def bounded(pid,item):
            if item==eid:raise AssertionError('changed metadata read before rejection')
            return read(pid,item)
        with patch.object(self.store,'read_evidence',side_effect=bounded):self.assertFalse(case_reports.verify(self.store,self.pid,out['evidence']['id'])['passed'])
