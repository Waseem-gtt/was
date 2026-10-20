"""Independent regression checks for assessment enrollment and history drift."""
import copy
import hashlib
import json
from unittest.mock import patch

from cyber_platform import curriculum, learning
from cyber_platform.store import Problem, encode
from tests.test_platform import StoreCase


class AssessmentReviewTests(StoreCase):
    def assessment(self, correct=True):
        lesson = next(item for item in learning.lessons() if item['id'] == 'lesson.04')
        answer = lesson['choices'].index(lesson['defense'])
        if not correct:
            answer = (answer + 1) % len(lesson['choices'])
        return curriculum.attempt(self.store, self.pid, 'foundations', lesson['id'], answer)

    def set_index(self, index):
        with self.store.lock, self.store.db:
            self.store.db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',
                                  (curriculum.PREFIX + self.pid, encode(index)))

    def test_rehashed_wrong_assessment_cannot_be_promoted_without_creation_proof(self):
        assessment = self.assessment(correct=False)
        eid = assessment['evidence']['id']
        value = copy.deepcopy(assessment['result'])
        answer = value['lesson']['choices'].index(value['lesson']['defense'])
        value['answer_index'], value['correct'] = answer, True
        value['exercise']['answer_index'], value['exercise']['correct'] = answer, True
        value['exercise_sha256'] = curriculum._digest(value['exercise'])
        value['record_sha256'] = curriculum._digest({key: item for key, item in value.items()
                                                     if key != 'record_sha256'})
        raw = encode(value).encode()
        path = self.store.blobs / eid
        path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(0o400)
        with self.store.lock, self.store.db:
            self.store.db.execute('UPDATE evidence SET sha256=?,size=? WHERE id=?',
                                  (hashlib.sha256(raw).hexdigest(), len(raw), eid))
        self.assertTrue(self.store.verify_audit()['valid'])
        with self.assertRaises(Problem):
            curriculum.progress(self.store, self.pid)

    def test_reenrolled_copy_with_valid_bytes_is_not_a_created_assessment(self):
        assessment = self.assessment()
        raw = self.store.read_evidence(self.pid, assessment['evidence']['id'])
        copied = self.store.add_evidence(self.pid, 'copied.json', raw, 'learning-assessment')
        index = self.store.setting(curriculum.PREFIX + self.pid)
        index['lesson.04'].append(copied['id'])
        self.set_index(index)
        self.assertTrue(self.store.verify_audit()['valid'])
        with self.assertRaises(Problem):
            curriculum.progress(self.store, self.pid)

    def test_dropped_index_cannot_hide_attempts_or_reopen_quota(self):
        self.assessment()
        with self.store.lock, self.store.db:
            self.store.db.execute('DELETE FROM settings WHERE key=?',
                                  (curriculum.PREFIX + self.pid,))
        with self.assertRaises(Problem):
            curriculum.progress(self.store, self.pid)
        with self.assertRaises(Problem):
            curriculum.history(self.store, self.pid)
        with self.assertRaises(Problem):
            self.assessment()

    def test_reorganized_path_keeps_history_but_marks_old_membership_stale(self):
        original = self.assessment()
        paths = list(curriculum.PATHS)
        first, second = paths[:2]
        paths[0] = (*first[:3], (5, 1, 2, 3))
        paths[1] = (*second[:3], (4, 6, 7, 8))
        with patch.object(curriculum, 'PATHS', tuple(paths)):
            progress = curriculum.progress(self.store, self.pid)
            history = curriculum.history(self.store, self.pid)['attempts']
        self.assertEqual(progress['counts']['passed'], 0)
        moved = next(row for path in progress['paths'] for row in path['lessons']
                     if row['lesson_id'] == 'lesson.04')
        self.assertEqual(moved['status'], 'stale')
        self.assertEqual(history[0]['path_id'], 'foundations')
        self.assertFalse(history[0]['current'])
        self.assertEqual(history[0]['evidence_id'], original['evidence']['id'])
        self.assertEqual(json.loads(self.store.read_evidence(self.pid, original['evidence']['id'])),
                         original['result'])
