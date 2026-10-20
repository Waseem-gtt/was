"""Coverage checks complete all references while preserving explicit snapshot limits."""
from unittest.mock import patch
from cyber_platform import coverage, coverage_scans as scans, detection
from cyber_platform.store import Problem, Store, encode
from tests.test_platform import StoreCase


class CoverageScanTests(StoreCase):
    def regular(self, count=1):
        asset = coverage.asset(self.store, self.pid, 'service', 'service')
        records = []
        for i in range(count):
            evidence = self.evidence(('ordinary reference ' + str(i)).encode())
            records.append(evidence)
            coverage.assess(self.store, self.pid, asset['id'], 'threat ' + str(i), 'control', evidence['id'])
        return asset, records

    def finish(self, scan):
        for _ in range(100):
            if scan['status'] in ('completed', 'failed'):
                return scan
            scan = scans.advance(self.store, self.pid, scan['id'])
        self.fail('coverage scan did not terminate')

    def test_more_than_three_real_detection_reports_complete_with_full_proofs(self):
        asset = coverage.asset(self.store, self.pid, 'service', 'service')
        library = detection.library(self.store, self.pid)
        source = self.evidence(encode(library['fixtures'][0]['input']).encode())
        for i in range(4):
            tested = detection.test(self.store, self.pid, source['id'], ['was-login-failure'])
            coverage.assess(self.store, self.pid, asset['id'], 'threat ' + str(i), 'control', tested['evidence']['id'])
        started = scans.start(self.store, self.pid)
        first = scans.advance(self.store, self.pid, started['id'])
        self.assertLessEqual(first['counts']['processed'], 3)
        self.assertFalse(first['complete'])
        self.assertFalse(first['all_supported'])
        self.assertEqual(first['total'], 4)
        self.store.close(); self.store = Store(self.store.root)
        final = self.finish(scans.status(self.store, self.pid, started['id']))
        self.assertEqual(final['status'], 'completed')
        self.assertTrue(final['complete'])
        self.assertTrue(final['all_supported'])
        self.assertEqual(final['summary']['supported'], 4)
        self.assertEqual(final['proof_counts']['remaining'], 0)
        self.assertEqual(final['current_validity'], 'snapshot_only')
        self.assertNotIn('passed', final)
        self.assertEqual(len(final['results']), 4)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_regular_evidence_is_unverified_even_after_completion(self):
        self.regular(4)
        result = self.finish(scans.start(self.store, self.pid))
        self.assertTrue(result['complete'])
        self.assertFalse(result['all_supported'])
        self.assertEqual(result['summary']['unverified'], 4)
        self.assertEqual(result['counts'], {'processed':4, 'total':4, 'remaining':0})
        self.assertEqual(len(result['gaps']),4)

    def test_asset_without_assessments_and_empty_scope_never_claim_support(self):
        empty = self.finish(scans.start(self.store, self.pid))
        self.assertTrue(empty['complete']); self.assertFalse(empty['all_supported'])
        coverage.asset(self.store,self.pid,'untested','host')
        done = self.finish(scans.start(self.store,self.pid))
        self.assertEqual(done['summary']['untested'],1)
        self.assertEqual(done['gaps'][0]['reason'],'no_assessment')
        self.assertFalse(done['all_supported'])

    def test_scope_change_after_partial_verification_fails_closed(self):
        asset, _ = self.regular(4)
        run = scans.advance(self.store,self.pid,scans.start(self.store,self.pid)['id'])
        coverage.asset(self.store,self.pid,'new scope','data')
        failed = scans.advance(self.store,self.pid,run['id'])
        self.assertEqual(failed['status'],'failed')
        self.assertEqual(failed['error_code'],'scope_changed')
        self.assertFalse(failed['complete']);self.assertFalse(failed['all_supported'])

    def test_earlier_evidence_changed_between_batches_is_rejected(self):
        _, records = self.regular(4)
        run = scans.advance(self.store,self.pid,scans.start(self.store,self.pid)['id'])
        path = self.store.blobs/records[0]['id'];path.chmod(0o600);path.write_bytes(b'changed')
        failed=scans.advance(self.store,self.pid,run['id'])
        self.assertEqual(failed['error_code'],'evidence_changed')
        self.assertFalse(failed['complete'])

    def test_tamper_during_finalization_is_not_hidden_by_prior_replay(self):
        _, records = self.regular()
        run = scans.advance(self.store,self.pid,scans.start(self.store,self.pid)['id'])
        self.assertEqual(run['phase'],'finalize')
        path=self.store.blobs/records[0]['id'];path.chmod(0o600);path.write_bytes(b'changed')
        final=scans.advance(self.store,self.pid,run['id'])
        self.assertEqual(final['status'],'failed')
        self.assertEqual(final['error_code'],'evidence_changed')

    def test_completion_is_historical_and_status_never_rereads_owner_files(self):
        _, records=self.regular()
        done=self.finish(scans.start(self.store,self.pid))
        with patch.object(self.store,'read_evidence',side_effect=AssertionError('unbounded status read')):
            self.assertEqual(scans.status(self.store,self.pid,done['id']),done)
            self.assertEqual(scans.history(self.store,self.pid)['scans'][0]['id'],done['id'])
        path=self.store.blobs/records[0]['id'];path.chmod(0o600);path.write_bytes(b'changed')
        self.assertEqual(scans.status(self.store,self.pid,done['id'])['current_validity'],'snapshot_only')

    def test_interrupted_check_is_never_silently_reexecuted(self):
        self.regular()
        started=scans.start(self.store,self.pid)
        with patch.object(coverage,'_reference',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):scans.advance(self.store,self.pid,started['id'])
        self.store.close();self.store=Store(self.store.root)
        with patch.object(coverage,'_reference',side_effect=AssertionError('must not rerun')):
            result=scans.advance(self.store,self.pid,started['id'])
        self.assertEqual(result['error_code'],'interrupted_check')
        self.assertEqual(result['counts']['processed'],0)

    def test_engine_or_rule_index_change_cannot_mix_generations(self):
        self.regular()
        started=scans.start(self.store,self.pid)
        with patch.object(scans,'_engine',return_value='a'*64):
            failed=scans.advance(self.store,self.pid,started['id'])
        self.assertEqual(failed['error_code'],'engine_changed')
        started=scans.start(self.store,self.pid)
        detection.save(self.store,self.pid,{'id':'owner-test','title':'test','version':'1.0.0','source':'synthetic','license':'Private','selection':{'action':'test'}})
        self.assertEqual(scans.advance(self.store,self.pid,started['id'])['error_code'],'engine_changed')

    def test_direct_read_budget_and_final_proof_batches_are_bounded(self):
        self.regular(4)
        started=scans.start(self.store,self.pid)
        with patch.object(scans,'MAX_CHECKS',1):
            run=scans.advance(self.store,self.pid,started['id'])
        self.assertEqual(run['counts']['processed'],1)
        while run['phase']=='verify':run=scans.advance(self.store,self.pid,run['id'])
        with patch.object(scans,'MAX_FINAL_FILES',1):
            run=scans.advance(self.store,self.pid,run['id'])
        self.assertEqual(run['proof_counts']['checked'],1)
        self.assertFalse(run['complete'])
        self.assertLessEqual(run['last_batch']['proof_bytes'],scans.MAX_BYTES)
        self.assertTrue(self.finish(run)['complete'])

    def test_oversized_proof_scope_is_explicit_failure_not_stall(self):
        self.regular()
        started=scans.start(self.store,self.pid)
        with patch.object(scans,'MAX_BYTES',1):
            failed=scans.advance(self.store,self.pid,started['id'])
        self.assertEqual(failed['error_code'],'proof_scope_overflow')
        self.assertFalse(failed['complete'])

    def test_invalid_ids_cross_project_and_corrupt_saved_state_rejected(self):
        self.regular();started=scans.start(self.store,self.pid)
        with self.assertRaises(Problem):scans.status(self.store,self.pid,'../bad')
        other=self.store.create_project('other')['id']
        with self.assertRaises(Problem):scans.status(self.store,other,started['id'])
        key=scans._prefix(self.pid)+started['id']
        saved=self.store.setting(key);saved['cursor']=True
        saved['record_sha256']=scans._digest({k:v for k,v in saved.items() if k!='record_sha256'})
        with self.store.db:self.store.db.execute('UPDATE settings SET value=? WHERE key=?',(encode(saved),key))
        with self.assertRaises(Problem):scans.status(self.store,self.pid,started['id'])

    def test_retention_preserves_active_scans(self):
        started=[scans.start(self.store,self.pid) for _ in range(20)]
        with self.assertRaises(Problem):scans.start(self.store,self.pid)
        self.finish(started[0]);new=scans.start(self.store,self.pid)
        history=scans.history(self.store,self.pid)['scans']
        self.assertEqual(len(history),20)
        self.assertNotIn(started[0]['id'],[r['id'] for r in history])
        self.assertIn(new['id'],[r['id'] for r in history])

    def test_audit_corruption_storage_swap_and_parallel_slot_refuse_mutation(self):
        self.regular();started=scans.start(self.store,self.pid)
        self.assertTrue(scans._LOCK.acquire(False))
        try:
            with self.assertRaises(Problem):scans.advance(self.store,self.pid,started['id'])
        finally:scans._LOCK.release()
        db=self.store.root/'platform.db';old=self.store.root/'original.db';db.rename(old);db.write_bytes(old.read_bytes())
        with self.assertRaises(Problem):scans.advance(self.store,self.pid,started['id'])
        db.unlink();old.rename(db)
        with self.store.db:self.store.db.execute("UPDATE audit SET action='changed' WHERE seq=1")
        with self.assertRaises(Problem):scans.advance(self.store,self.pid,started['id'])
        self.assertEqual(scans.status(self.store,self.pid,started['id'])['counts']['processed'],0)

    def test_resigned_but_incomplete_proof_or_malformed_scope_is_rejected(self):
        self.regular();done=self.finish(scans.start(self.store,self.pid))
        key=scans._prefix(self.pid)+done['id']
        pristine=self.store.setting(key)
        import copy
        for corruption in ('proofs','asset','assessment'):
            bad=copy.deepcopy(pristine)
            if corruption=='proofs':
                bad.update(proofs={},proof_order=[],proof_cursor=0)
            elif corruption=='asset':
                bad['scope']['assets'][0]['name']=[]
                bad['scope_sha256']=scans._digest(bad['scope'])
            else:
                bad['scope']['assessments'].append(copy.deepcopy(bad['scope']['assessments'][0]))
                bad['scope_sha256']=scans._digest(bad['scope'])
            bad['record_sha256']=scans._digest({k:v for k,v in bad.items() if k!='record_sha256'})
            with self.store.db:self.store.db.execute('UPDATE settings SET value=? WHERE key=?',(encode(bad),key))
            with self.subTest(corruption=corruption),self.assertRaises(Problem):scans.status(self.store,self.pid,done['id'])

    def test_conflicting_verified_results_remain_explicit_gaps(self):
        asset=coverage.asset(self.store,self.pid,'conflict service','service')
        fixture=detection.library(self.store,self.pid)['fixtures'][0]['input']
        good=self.evidence(encode(fixture).encode())
        passed=detection.test(self.store,self.pid,good['id'],['was-login-failure'])
        fixture['expected_matches']['was-login-failure']=[1]
        bad=self.evidence(encode(fixture).encode())
        failed=detection.test(self.store,self.pid,bad['id'],['was-login-failure'])
        for tested in (passed,failed):
            coverage.assess(self.store,self.pid,asset['id'],'same threat','same control',tested['evidence']['id'])
        result=self.finish(scans.start(self.store,self.pid))
        self.assertTrue(result['complete']);self.assertFalse(result['all_supported'])
        self.assertEqual(result['summary']['conflict'],2)
        self.assertEqual(result['assets'][0]['status'],'conflict')
        self.assertEqual(len(result['gaps']),2)

    def test_normalized_original_parent_is_included_in_final_proof_closure(self):
        from cyber_platform import event_adapters,event_ingest
        asset=coverage.asset(self.store,self.pid,'normalized service','service')
        sample=next(a for a in event_adapters.catalog() if a['id']=='windows-json')
        original=self.evidence(sample['example_content'].encode())
        normalized=event_ingest.normalize(self.store,self.pid,original['id'],sample['id'])
        tested=detection.test(self.store,self.pid,normalized['evidence']['id'],['was-login-failure'])
        coverage.assess(self.store,self.pid,asset['id'],'threat','control',tested['evidence']['id'])
        started=scans.start(self.store,self.pid)
        checking=scans.advance(self.store,self.pid,started['id'])
        saved=self.store.setting(scans._prefix(self.pid)+started['id'])
        self.assertIn(original['id'],saved['proofs'])
        self.assertIn(normalized['evidence']['id'],saved['proofs'])
        self.assertFalse(checking['complete'])
        path=self.store.blobs/original['id'];path.chmod(0o600);path.write_bytes(b'changed')
        failed=scans.advance(self.store,self.pid,started['id'])
        self.assertEqual(failed['error_code'],'evidence_changed')
