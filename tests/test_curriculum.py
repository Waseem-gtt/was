"""Functional and failure-boundary checks for ordered synthetic learning."""
import json
from unittest import mock

from cyber_platform import curriculum, learning
from cyber_platform.store import Problem, Store, encode
import tests.test_platform as core


class CurriculumTests(core.StoreCase):
    def correct(self, lesson_id="lesson.04"):
        lesson = next(l for l in learning.lessons() if l["id"] == lesson_id)
        return lesson["choices"].index(lesson["defense"])

    def attempt(self, lesson_id="lesson.04", path_id="foundations", answer=None):
        return curriculum.attempt(self.store, self.pid, path_id, lesson_id,
                                  self.correct(lesson_id) if answer is None else answer)

    def test_catalog_covers_each_existing_lesson_once_and_initial_locks(self):
        catalog = curriculum.catalog()
        ids = [lid for path in catalog["paths"] for lid in path["lesson_ids"]]
        self.assertEqual(len(ids), 20)
        self.assertEqual(set(ids), {l["id"] for l in learning.lessons()})
        progress = curriculum.progress(self.store, self.pid)
        self.assertEqual(progress["counts"]["available"], 5)
        self.assertEqual(progress["counts"]["locked"], 15)
        self.assertEqual(progress["counts"]["passed"], 0)

    def test_wrong_answer_is_retained_then_correct_unlocks_next(self):
        wrong = (self.correct() + 1) % 3
        result = self.attempt(answer=wrong)
        self.assertFalse(result["result"]["correct"])
        rows = result["progress"]["paths"][0]["lessons"]
        self.assertEqual(rows[0]["status"], "attempted")
        self.assertEqual(rows[1]["status"], "locked")
        result = self.attempt()
        rows = result["progress"]["paths"][0]["lessons"]
        self.assertEqual(rows[0]["status"], "passed")
        self.assertEqual(rows[0]["attempts"], 2)
        self.assertEqual(rows[0]["correct_attempts"], 1)
        self.assertEqual(rows[1]["status"], "available")
        self.assertTrue(self.store.verify_audit()["valid"])

    def test_prerequisites_reject_execution_and_full_path_is_completable(self):
        with mock.patch.object(learning.worker, "analyze") as worker:
            with self.assertRaises(Problem):
                self.attempt("lesson.01")
            worker.assert_not_called()
        for lesson in curriculum.catalog()["paths"][0]["lesson_ids"]:
            result = self.attempt(lesson)
        self.assertEqual(result["progress"]["paths"][0]["counts"]["passed"], 4)

    def test_legacy_attempts_remain_independent_and_not_enrolled(self):
        learning.attempt(self.store, self.pid, "lesson.01", self.correct("lesson.01"))
        self.assertEqual(curriculum.history(self.store, self.pid)["attempts"], [])
        self.assertEqual(curriculum.progress(self.store, self.pid)["counts"]["passed"], 0)

    def test_artifact_hash_and_history_survive_store_reopen(self):
        result = self.attempt()
        eid = result["evidence"]["id"]
        raw = self.store.read_evidence(self.pid, eid)
        self.assertEqual(json.loads(raw), result["result"])
        self.store.close()
        self.store = Store(self.store.root)
        history = curriculum.history(self.store, self.pid)["attempts"]
        self.assertEqual(history[0]["evidence_id"], eid)
        self.assertTrue(history[0]["current"])
        self.assertEqual(curriculum.progress(self.store, self.pid)["counts"]["passed"], 1)

    def test_changed_engine_keeps_history_stale_and_relocks_prerequisite(self):
        self.attempt()
        with mock.patch.object(curriculum, "_engine", return_value="a" * 64):
            value = curriculum.progress(self.store, self.pid)
            self.assertEqual(value["paths"][0]["lessons"][0]["status"], "stale")
            self.assertEqual(value["counts"]["passed"], 0)
            self.assertFalse(curriculum.history(self.store, self.pid)["attempts"][0]["current"])
            with self.assertRaises(Problem):
                self.attempt("lesson.01")

    def test_changed_artifact_bytes_refused(self):
        result = self.attempt()
        path = self.store.blobs / result["evidence"]["id"]
        path.chmod(0o600)
        path.write_bytes(b"{}")
        with self.assertRaises(Problem):
            curriculum.progress(self.store, self.pid)

    def test_cross_project_index_cannot_reuse_other_owner_project_attempt(self):
        result = self.attempt()
        other = self.store.create_project("other")
        with self.store.db:
            self.store.db.execute("INSERT INTO settings VALUES(?,?)",
                                  (curriculum.PREFIX + other["id"], encode({"lesson.04": [result["evidence"]["id"]]})))
        with self.assertRaises(Problem):
            curriculum.history(self.store, other["id"])
        self.assertEqual(curriculum.progress(self.store, self.pid)["counts"]["passed"], 1)

    def test_invalid_path_lesson_and_answer_do_not_call_worker(self):
        values = [(None, "lesson.04", 0), ([], "lesson.04", 0), ("missing", "lesson.04", 0),
                  ("foundations", "lesson.20", 0), ("foundations", [], 0),
                  ("foundations", "lesson.04", True), ("foundations", "lesson.04", -1),
                  ("foundations", "lesson.04", "0"), ("foundations", "lesson.04", 3)]
        with mock.patch.object(learning.worker, "analyze") as worker:
            for path, lesson, answer in values:
                with self.subTest(path=path, lesson=lesson, answer=answer), self.assertRaises(Problem):
                    curriculum.attempt(self.store, self.pid, path, lesson, answer)
            worker.assert_not_called()

    def test_worker_failure_does_not_publish_or_fallback(self):
        with mock.patch.object(learning.worker, "analyze", side_effect=ValueError("worker stopped")) as worker:
            with self.assertRaises(Problem):
                self.attempt()
            worker.assert_called_once()
        self.assertEqual(self.store.rows("SELECT id FROM evidence"), [])
        self.assertEqual(curriculum.history(self.store, self.pid)["attempts"], [])

    def test_engine_change_during_execution_does_not_publish(self):
        original = curriculum._engine()
        with mock.patch.object(curriculum, "_engine", side_effect=[original, "f" * 64]):
            with self.assertRaises(Problem):
                self.attempt()
        self.assertEqual(self.store.rows("SELECT id FROM evidence"), [])

    def test_publication_failure_rolls_back_checkpoint_blob_and_audit(self):
        before = self.store.verify_audit()
        with mock.patch.object(self.store, "audit", side_effect=RuntimeError("write failure")):
            with self.assertRaises(RuntimeError):
                self.attempt()
        self.assertEqual(list(self.store.blobs.iterdir()), [])
        self.assertEqual(self.store.rows("SELECT id FROM evidence"), [])
        self.assertEqual(curriculum.history(self.store, self.pid)["attempts"], [])
        self.assertEqual(self.store.verify_audit(), before)

    def test_limit_refuses_new_attempt_without_evicting_old_evidence(self):
        result = self.attempt()
        with mock.patch.dict(curriculum.LIMITS, {"attempts_per_lesson": 1}):
            with self.assertRaises(Problem):
                self.attempt()
        self.assertEqual(len(curriculum.history(self.store, self.pid)["attempts"]), 1)
        self.assertEqual(self.store.read_evidence(self.pid, result["evidence"]["id"]), encode(result["result"]).encode())

    def test_corrupt_index_json_is_problem_not_unhandled_decode_error(self):
        with self.store.db:
            self.store.db.execute("INSERT INTO settings VALUES(?,?)", (curriculum.PREFIX + self.pid, "{"))
        with self.assertRaises(Problem):
            curriculum.progress(self.store, self.pid)

    def test_invalid_audit_blocks_analysis_before_worker(self):
        with self.store.db:
            self.store.db.execute("UPDATE audit SET action='changed' WHERE seq=1")
        with mock.patch.object(learning.worker, "analyze") as worker:
            with self.assertRaises(Problem):
                self.attempt()
            worker.assert_not_called()
