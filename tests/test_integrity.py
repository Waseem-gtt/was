"""Integrity batches must not become a repair or skip failed evidence."""
import os
from unittest.mock import patch
from cyber_platform import integrity
from cyber_platform.store import Problem, Store
from tests.test_platform import StoreCase


class IntegrityTests(StoreCase):
    def test_batches_resume_after_reopen_and_preserve_contents(self):
        records = [self.evidence(bytes([i]) * 4) for i in range(3)]
        before = {r['id']: (self.store.blobs / r['id']).stat() for r in records}
        scan = integrity.start(self.store, self.pid)
        self.assertNotIn('manifest', scan)
        self.assertFalse(scan['passed'])
        scan = integrity.advance(self.store, scan['id'], max_files=1)
        self.assertEqual((scan['cursor'], scan['verified'], scan['last_batch']['bytes']), (1, 1, 4))
        self.assertTrue(scan['last_batch']['incomplete'])
        self.store.close()
        self.store = Store(self.store.root)
        self.assertEqual(integrity.status(self.store, scan['id']), scan)
        scan = integrity.advance(self.store, scan['id'], max_bytes=4)
        self.assertEqual(scan['cursor'], 2)
        scan = integrity.advance(self.store, scan['id'])
        self.assertTrue(scan['passed'])
        self.assertEqual(scan['status'], 'completed')
        self.assertEqual(scan['scanned'], 3)
        for r in records:
            path = self.store.blobs / r['id']
            self.assertEqual(path.read_bytes(), bytes([records.index(r)]) * 4)
            after = path.stat()
            self.assertEqual((after.st_mode, after.st_mtime_ns), (before[r['id']].st_mode, before[r['id']].st_mtime_ns))
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_missing_corrupt_symlink_hardlink_continue_without_changes(self):
        missing, corrupt, symlink, hardlink, healthy = [self.evidence() for _ in range(5)]
        (self.store.blobs / missing['id']).unlink()
        corrupt_path = self.store.blobs / corrupt['id']
        corrupt_path.chmod(0o600)
        corrupt_path.write_bytes(b'evil')
        link = self.store.blobs / symlink['id']
        link.unlink()
        link.symlink_to(corrupt_path)
        os.link(self.store.blobs / hardlink['id'], self.store.root / 'extra')
        scan = integrity.advance(self.store, integrity.start(self.store)['id'])
        self.assertEqual((scan['failed'], scan['verified'], scan['cursor']), (4, 1, 5))
        self.assertFalse(scan['passed'])
        self.assertEqual(scan['status'], 'failed')
        self.assertEqual(corrupt_path.read_bytes(), b'evil')
        self.assertTrue(link.is_symlink())
        self.assertTrue((self.store.root / 'extra').exists())
        self.assertEqual(self.store.read_evidence(self.pid, healthy['id']), b'test')

    def test_metadata_scope_changes_never_pass(self):
        self.evidence()
        scan = integrity.start(self.store)
        self.evidence(b'new')
        done = integrity.advance(self.store, scan['id'])
        self.assertTrue(done['scope_changed'])
        self.assertFalse(done['passed'])
        self.assertEqual(done['total'], 1)

    def test_project_snapshot_ignores_other_project_changes(self):
        self.evidence()
        scan = integrity.start(self.store, self.pid)
        project = self.store.create_project('other')
        self.store.add_evidence(project['id'], 'other', b'x')
        self.assertTrue(integrity.advance(self.store, scan['id'])['passed'])

    def test_parent_swap_blocks_start_and_advance(self):
        self.evidence()
        scan = integrity.start(self.store)
        saved = self.store.root / 'previous-evidence'
        self.store.blobs.rename(saved)
        self.store.blobs.mkdir(mode=0o700)
        with self.assertRaises(Problem):
            integrity.start(self.store)
        done = integrity.advance(self.store, scan['id'])
        self.assertEqual(done['cursor'], 0)
        self.assertFalse(done['passed'])
        self.assertEqual(done['status'], 'failed')
        self.assertEqual(done['issues'][0]['reason'], 'storage_replaced_or_unsafe')

    def test_budget_too_small_does_not_skip_file(self):
        self.evidence(b'long')
        scan = integrity.start(self.store)
        paused = integrity.advance(self.store, scan['id'], max_bytes=3)
        self.assertEqual(paused['cursor'], 0)
        self.assertEqual(paused['last_batch']['bytes'], 0)
        self.assertTrue(paused['last_batch']['incomplete'])
        self.assertTrue(integrity.advance(self.store, scan['id'])['passed'])

    def test_timeout_midread_keeps_cursor_and_bytes_truthful(self):
        self.evidence(b'a' * 131072)
        scan = integrity.start(self.store)
        with patch('cyber_platform.integrity.time.monotonic', side_effect=[0, 0, 0, 4]):
            partial = integrity.advance(self.store, scan['id'])
        self.assertEqual(partial['cursor'], 0)
        self.assertEqual(partial['last_batch']['bytes'], 65536)
        self.assertTrue(partial['last_batch']['incomplete'])
        self.assertTrue(integrity.advance(self.store, scan['id'])['passed'])

    def test_invalid_limits_unknown_id_and_bad_project(self):
        scan = integrity.start(self.store)
        for options in ({'max_files': True}, {'max_files': 101}, {'max_bytes': 0}, {'max_bytes': integrity.MAX_BYTES + 1}, {'max_seconds': float('nan')}, {'max_seconds': 4}):
            with self.assertRaises(Problem):
                integrity.advance(self.store, scan['id'], **options)
        for value in ('no', 'f' * 32, [], None):
            with self.assertRaises(Problem) as caught:
                integrity.status(self.store, value)
            self.assertEqual(caught.exception.status, 404)
        for value in ([], True, '../abc'):
            with self.assertRaises(Problem):
                integrity.start(self.store, value)

    def test_scan_retention_never_evicts_active(self):
        scans = [integrity.start(self.store) for _ in range(20)]
        with self.assertRaises(Problem):
            integrity.start(self.store)
        integrity.advance(self.store, scans[3]['id'])
        integrity.start(self.store)
        with self.assertRaises(Problem):
            integrity.status(self.store, scans[3]['id'])
        self.assertEqual(integrity.status(self.store, scans[0]['id'])['status'], 'pending')
        self.assertEqual(len(self.store.rows('SELECT key FROM settings WHERE key LIKE ?', ('integrity_scan:%',))), 20)

    def test_record_cap_and_invalid_audit_block_writes(self):
        rows = [{'id': '0' * 32, 'project_id': self.pid, 'sha256': '0' * 64, 'size': 0}] * 10001
        original = self.store.rows
        def capped(sql, args=()):
            return rows if sql.startswith('SELECT id,project_id,sha256,size') else original(sql, args)
        with patch.object(self.store, 'rows', side_effect=capped):
            with self.assertRaises(Problem) as caught:
                integrity.start(self.store)
            self.assertEqual(caught.exception.status, 413)
        scan = integrity.start(self.store)
        with self.store.db:
            self.store.db.execute("UPDATE audit SET hash='bad' WHERE seq=1")
        before = self.store.setting(integrity.PREFIX + scan['id'])
        with self.assertRaises(Problem):
            integrity.advance(self.store, scan['id'])
        with self.assertRaises(Problem):
            integrity.start(self.store)
        self.assertEqual(self.store.setting(integrity.PREFIX + scan['id']), before)

    def test_collection_beyond_maintenance_file_cap_finishes_in_batches(self):
        # One transaction avoids coupling this test to upload quota bookkeeping.
        import hashlib
        from cyber_platform.store import uid
        with self.store.db:
            for _ in range(601):
                identifier = uid()
                path = self.store.blobs / identifier
                path.write_bytes(b'x')
                path.chmod(0o400)
                self.store.db.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?)',
                    (identifier, self.pid, 'x', hashlib.sha256(b'x').hexdigest(), 1, 'original', None, 0))
        scan = integrity.start(self.store)
        for _ in range(7):
            scan = integrity.advance(self.store, scan['id'])
            self.assertLessEqual(scan['last_batch']['checked'], 100)
        self.assertTrue(scan['passed'])
        self.assertEqual(scan['verified'], 601)

    def test_collection_beyond_byte_cap_finishes_without_overshoot(self):
        raw = b'x' * (16 * 1024 * 1024)
        for _ in range(5):
            self.evidence(raw)
        scan = integrity.advance(self.store, integrity.start(self.store)['id'])
        self.assertEqual(scan['last_batch']['bytes'], 64 * 1024 * 1024)
        self.assertEqual(scan['cursor'], 4)
        self.assertFalse(scan['passed'])
        self.assertTrue(integrity.advance(self.store, scan['id'])['passed'])

    def test_storage_swapped_during_read_cannot_pass(self):
        self.evidence()
        scan = integrity.start(self.store)
        read = os.read
        def swap(fd, count):
            value = read(fd, count)
            self.store.blobs.rename(self.store.root / 'old-evidence')
            self.store.blobs.mkdir(mode=0o700)
            return value
        with patch('cyber_platform.integrity.os.read', side_effect=swap):
            result = integrity.advance(self.store, scan['id'])
        self.assertFalse(result['passed'])
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['issues'][-1]['reason'], 'storage_replaced_or_unsafe')

    def test_invalid_size_metadata_terminates_instead_of_stalling(self):
        record = self.evidence()
        with self.store.db:
            self.store.db.execute('UPDATE evidence SET size=? WHERE id=?', (integrity.MAX_BYTES + 1, record['id']))
        result = integrity.advance(self.store, integrity.start(self.store)['id'])
        self.assertEqual(result['cursor'], 1)
        self.assertEqual(result['failed'], 1)
        self.assertEqual(result['last_batch']['bytes'], 0)
        self.assertFalse(result['passed'])

    def test_database_replacement_blocks_persistence_without_audit_write(self):
        self.evidence()
        scan = integrity.start(self.store)
        stored = self.store.setting(integrity.PREFIX + scan['id'])
        old_db = self.store.root / 'old-platform.db'
        (self.store.root / 'platform.db').rename(old_db)
        (self.store.root / 'platform.db').write_bytes(b'replacement')
        before = old_db.read_bytes()
        audit = self.store.verify_audit()
        result = integrity.advance(self.store, scan['id'])
        self.assertFalse(result['passed'])
        self.assertEqual(result['persistence'], 'blocked_unsafe_storage')
        self.assertEqual(old_db.read_bytes(), before)
        self.assertEqual((self.store.root / 'platform.db').read_bytes(), b'replacement')
        self.assertEqual(self.store.verify_audit(), audit)
        self.assertEqual(self.store.setting(integrity.PREFIX + scan['id']), stored)
        with self.assertRaises(Problem):
            integrity.start(self.store)

    def test_root_rename_never_writes_to_old_database(self):
        self.evidence()
        scan = integrity.start(self.store)
        old_root = self.store.root.parent / 'old-root'
        self.store.root.rename(old_root)
        self.store.root.mkdir(mode=0o700)
        self.store.blobs.mkdir(mode=0o700)
        (self.store.root / 'platform.db').write_bytes(b'unrelated')
        before = (old_root / 'platform.db').read_bytes()
        audit = self.store.verify_audit()
        result = integrity.advance(self.store, scan['id'])
        self.assertEqual(result['persistence'], 'blocked_unsafe_storage')
        self.assertFalse(result['passed'])
        self.assertEqual((old_root / 'platform.db').read_bytes(), before)
        self.assertEqual(self.store.verify_audit(), audit)
        self.assertEqual(integrity.status(self.store, scan['id'])['status'], 'pending')

    def test_snapshot_fingerprint_and_counter_tampering_rejected(self):
        from cyber_platform.store import encode
        self.evidence()
        scan = integrity.start(self.store)
        for field, value in (('manifest_sha256', '0' * 64), ('cursor', 1), ('total', 0)):
            stored = self.store.setting(integrity.PREFIX + scan['id'])
            changed = {**stored, field: value}
            with self.store.db:
                self.store.db.execute('UPDATE settings SET value=? WHERE key=?', (encode(changed), integrity.PREFIX + scan['id']))
            with self.assertRaises(Problem):
                integrity.advance(self.store, scan['id'])
            with self.store.db:
                self.store.db.execute('UPDATE settings SET value=? WHERE key=?', (encode(stored), integrity.PREFIX + scan['id']))
