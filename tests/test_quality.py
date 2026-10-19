"""Synthetic quality runs must preserve progress, provenance and honest failures."""
import threading
from unittest.mock import patch
from cyber_platform import quality, tools
from cyber_platform.store import Problem, Store, encode
from tests.test_platform import StoreCase


class QualityTests(StoreCase):
    def finish(self, run):
        while run['status'] not in ('completed', 'failed'):
            run = quality.advance(self.store, run['id'])
        return run

    def change_saved(self, run_id, callback, resign=True):
        with self.store.lock, self.store.db:
            saved = self.store.setting(quality.PREFIX + run_id)
            callback(saved)
            if resign:
                saved['record_sha256'] = quality._digest({k:v for k,v in saved.items() if k != 'record_sha256'})
            self.store.db.execute('UPDATE settings SET value=? WHERE key=?', (encode(saved), quality.PREFIX + run_id))

    def test_real_workers_all_tools_and_independent_edges(self):
        before = self.evidence(b'owner evidence must not be analyzed')
        catalog = quality.catalog()
        self.assertEqual({c['tool'] for c in catalog['cases']}, set(tools.REGISTRY))
        self.assertEqual(len(catalog['cases']), 48)
        self.assertNotIn('input_utf8', encode(catalog))
        run = quality.start(self.store)
        self.assertFalse(run['passed'])
        first = quality.advance(self.store, run['id'])
        self.assertGreater(first['counts']['completed'], 0)
        self.assertLessEqual(first['counts']['completed'], 3)
        self.store.close()
        self.store = Store(self.store.root)
        self.assertEqual(quality.status(self.store, run['id']), first)
        run = self.finish(first)
        self.assertEqual(run['status'], 'completed')
        self.assertTrue(run['passed'], [r for r in run['results'] if r['status'] != 'passed'])
        self.assertEqual(run['counts'], {'total':48, 'completed':48, 'passed':48, 'failed':0})
        self.assertEqual(len(run['results']), 48)
        self.assertTrue(all(type(r['elapsed_ms']) is int and len(r['result_sha256']) == 64 for r in run['results']))
        self.assertEqual(self.store.read_evidence(self.pid, before['id']), b'owner evidence must not be analyzed')
        self.assertTrue(self.store.verify_audit()['valid'])
        self.assertEqual(quality.advance(self.store, run['id']), run)
        comparison = quality.compare(self.store, run['id'], run['id'])
        self.assertEqual(len(comparison['unchanged']),48)
        self.assertEqual(comparison['regressions'], [])

    def test_subset_strict_types_lists_and_extra_findings(self):
        self.assertTrue(quality._matches({'n':1,'detail':'extra'}, {'n':1}))
        self.assertFalse(quality._matches({'n':True}, {'n':1}))
        self.assertFalse(quality._matches({'n':1}, {'n':True}))
        self.assertFalse(quality._matches({'x':[1,1]}, {'x':[1]}))
        self.assertFalse(quality._matches({'x':[]}, {'x':[1]}))
        self.assertFalse(quality._matches({}, {'x':[]}))

    def test_exact_rejection_not_timeout_or_crash(self):
        cases, _ = quality._suite()
        case = next(c for c in cases if c['id'] == 'events-object-rejected')
        manifest = quality._manifest([case])[0]
        with patch.object(quality.worker, 'analyze', side_effect=ValueError(case['error_message'])):
            self.assertEqual(quality._execute(case,manifest)['status'], 'passed')
        for error in (ValueError('Analyzer exceeded its execution time limit'), ValueError('Analyzer stopped at a resource limit or failed'), RuntimeError('secret detail')):
            with self.subTest(error=type(error).__name__), patch.object(quality.worker, 'analyze', side_effect=error):
                result = quality._execute(case,manifest)
                self.assertEqual(result['error_code'], 'worker_error')
                self.assertNotIn('secret',encode(result))
        with patch.object(quality.worker, 'analyze', return_value={}):
            self.assertEqual(quality._execute(case,manifest)['error_code'],'expected_rejection_missing')

    def test_wrong_result_completes_without_false_pass_and_compares(self):
        with patch.object(quality.worker, 'analyze', side_effect=lambda tool,data,**kwargs:tools.analyze(tool,data)):
            good = self.finish(quality.start(self.store))
        self.assertTrue(good["passed"])
        engine = quality._engine()
        with patch.object(quality.worker, 'analyze', return_value={}), patch.object(quality, '_engine', return_value='a'*64):
            bad = self.finish(quality.start(self.store))
        self.assertEqual(bad['status'], 'completed')
        self.assertFalse(bad['passed'])
        self.assertEqual(bad['counts']['failed'],48)
        comparison = quality.compare(self.store,good['id'],bad['id'])
        self.assertTrue(comparison['engine_changed'])
        self.assertEqual(len(comparison['regressions']),48)
        reverse = quality.compare(self.store,bad['id'],good['id'])
        self.assertEqual(len(reverse['improvements']),48)
        self.assertEqual(good['engine_sha256'],engine)

    def test_corrupt_state_and_forged_counts_fail_closed(self):
        for field, value in [('counts',{'total':48,'completed':48,'passed':48,'failed':0}), ('status','completed'), ('manifest',[]), ('passed',True), ('in_flight','bogus')]:
            run=quality.start(self.store)
            self.change_saved(run['id'],lambda r:r.update({field:value}))
            with self.subTest(field=field),self.assertRaises(Problem):
                quality.status(self.store,run['id'])
            with self.store.db:
                self.store.db.execute('DELETE FROM settings WHERE key=?',(quality.PREFIX+run['id'],))
        run=quality.start(self.store)
        self.change_saved(run['id'],lambda r:r.update(version='9.9.9'),resign=False)
        with self.assertRaises(Problem):quality.advance(self.store,run['id'])

    def test_interrupted_case_never_reexecuted(self):
        run=quality.start(self.store)
        def interrupt(r):
            r['status']='running';r['in_flight']=r['manifest'][0]['case_id']
        self.change_saved(run['id'],interrupt)
        with patch.object(quality.worker,'analyze') as analyze:
            failed=quality.advance(self.store,run['id'])
            analyze.assert_not_called()
        self.assertEqual(failed['status'],'failed')
        self.assertEqual(failed['error_code'],'interrupted_case')
        self.assertFalse(failed['passed'])
        self.assertEqual(failed['counts']['completed'],0)
        self.assertEqual(quality.status(self.store,run['id']),failed)

    def test_engine_suite_changes_before_or_during_case(self):
        run=quality.start(self.store)
        with patch.object(quality,'_engine',return_value='0'*64):
            result=quality.advance(self.store,run['id'])
        self.assertEqual(result['error_code'],'engine_changed')
        run=quality.start(self.store)
        cases, _ = quality._suite()
        with patch.object(quality,'_suite',return_value=(cases,'0'*64)):
            result=quality.advance(self.store,run['id'])
        self.assertEqual(result['error_code'],'suite_changed')
        run=quality.start(self.store)
        old_engine=quality._engine()
        with patch.object(quality,'_engine',side_effect=[old_engine,old_engine,'f'*64]), patch.object(quality.worker,'analyze',side_effect=lambda tool,data,**kwargs:tools.analyze(tool,data)):
            result=quality.advance(self.store,run['id'])
        self.assertEqual(result['error_code'],'engine_changed')
        self.assertEqual(result['counts']['completed'],0)

    def test_retention_does_not_evict_active_run(self):
        runs=[quality.start(self.store) for _ in range(20)]
        with self.assertRaises(Problem):quality.start(self.store)
        def fail(r):r.update(status='failed',error_code='engine_changed')
        self.change_saved(runs[0]['id'],fail)
        newest=quality.start(self.store)
        listed=quality.history(self.store)['runs']
        self.assertEqual(len(listed),20)
        self.assertNotIn(runs[0]['id'],[r['id'] for r in listed])
        self.assertIn(newest['id'],[r['id'] for r in listed])
        self.assertNotIn('results',listed[0])

    def test_busy_incomplete_comparison_and_scope_mismatch(self):
        run=quality.start(self.store)
        self.assertTrue(quality._LOCK.acquire(False))
        try:
            with self.assertRaises(Problem):quality.advance(self.store,run['id'])
        finally:quality._LOCK.release()
        with self.assertRaises(Problem):quality.compare(self.store,run['id'],run['id'])
        with patch.object(quality.worker,'analyze',side_effect=lambda tool,data,**kwargs:tools.analyze(tool,data)):
            left=self.finish(run);right=self.finish(quality.start(self.store))
        self.change_saved(right['id'],lambda r:r.update(suite_sha256='f'*64))
        with self.assertRaises(Problem):quality.compare(self.store,left['id'],right['id'])
        with self.assertRaises(Problem):quality.status(self.store,'../unsafe')

    def test_broken_audit_or_replaced_storage_blocks_writes(self):
        run=quality.start(self.store)
        with self.store.db:self.store.db.execute("UPDATE audit SET action='tampered' WHERE seq=1")
        with self.assertRaises(Problem):quality.advance(self.store,run['id'])
        with self.assertRaises(Problem):quality.start(self.store)
        self.assertEqual(quality.status(self.store,run['id'])['counts']['completed'],0)

    def test_replaced_database_blocks_start_advance(self):
        run=quality.start(self.store)
        db=self.store.root/'platform.db'; original=self.store.root/'original.db'
        db.rename(original);db.write_bytes(original.read_bytes())
        for operation in (lambda:quality.start(self.store),lambda:quality.advance(self.store,run['id'])):
            with self.assertRaises(Problem):operation()
        db.unlink();original.rename(db)
        self.assertEqual(quality.status(self.store,run['id'])['status'],'pending')

    def test_per_case_progress_committed_before_worker_crash(self):
        run=quality.start(self.store)
        with patch.object(quality.worker,'analyze',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):quality.advance(self.store,run['id'])
        self.store.close();self.store=Store(self.store.root)
        failed=quality.advance(self.store,run['id'])
        self.assertEqual(failed['error_code'],'interrupted_case')
        self.assertEqual(failed['counts']['completed'],0)

    def test_soft_deadline_checked_between_cases(self):
        run=quality.start(self.store)
        times=iter([0,0,0,0,4000,4000])
        # Deadline expires after one case; no repeated execution in same batch.
        with patch.object(quality.time,'monotonic',side_effect=lambda:next(times)),patch.object(quality.worker,'analyze',side_effect=lambda tool,data,**kwargs:tools.analyze(tool,data)):
            advanced=quality.advance(self.store,run['id'])
        self.assertEqual(advanced['counts']['completed'],1)
        self.assertFalse(advanced['passed'])

    def test_concurrent_advance_never_duplicates_cases(self):
        run = quality.start(self.store)
        entered, resume = threading.Event(), threading.Event()
        results, errors = [], []
        def paused_worker(tool, data, **kwargs):
            entered.set()
            if not resume.wait(5):
                raise RuntimeError("test synchronization timeout")
            return tools.analyze(tool, data)
        def advance_thread():
            try:
                results.append(quality.advance(self.store, run['id']))
            except Exception as exc:
                errors.append(exc)
        with patch.object(quality.worker, 'analyze', side_effect=paused_worker):
            thread = threading.Thread(target=advance_thread)
            thread.start()
            try:
                self.assertTrue(entered.wait(5))
                with self.assertRaises(Problem) as raised:
                    quality.advance(self.store, run['id'])
                self.assertEqual(raised.exception.status, 409)
            finally:
                resume.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results[0]['counts']['completed'], 3)
        self.assertEqual(len({r['case_id'] for r in results[0]['results']}), 3)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_storage_replaced_during_case_never_commits_success(self):
        run = quality.start(self.store)
        db, original = self.store.root/'platform.db', self.store.root/'original.db'
        def replace_worker(tool, data, **kwargs):
            db.rename(original)
            db.write_bytes(original.read_bytes())
            return tools.analyze(tool, data)
        try:
            with patch.object(quality.worker, 'analyze', side_effect=replace_worker):
                with self.assertRaises((OSError, Problem)):
                    quality.advance(self.store, run['id'])
        finally:
            if original.exists():
                db.unlink()
                original.rename(db)
        saved = quality.status(self.store, run['id'])
        self.assertEqual(saved['counts']['completed'], 0)
        self.assertFalse(saved['passed'])
        failed = quality.advance(self.store, run['id'])
        self.assertEqual(failed['error_code'], 'interrupted_case')
