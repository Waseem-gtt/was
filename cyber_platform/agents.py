"""Bounded advisory roles using one local model; never execute model output.

Two worker threads consume an explicit role queue. Model text is evidence for
human review, not authority to change files, run tools, or repair the host.
"""
import json
import threading
import time
from . import __version__, local_ai
from .agent_roles import ROLES
from .store import Problem, encode, uid


class Coordinator:
    def __init__(self, store, ai_url, ai_model, execution_lock):
        self.store, self.ai_url, self.ai_model = store, ai_url, ai_model
        self.execution_lock = execution_lock
        self.lock = threading.RLock()
        self.cancel = threading.Event()
        self.thread = None
        self.closed = False

    def status(self, project_id, job_id):
        self.store.project(project_id)
        rows = self.store.rows("SELECT * FROM jobs WHERE project_id=? AND id=?", (project_id, job_id))
        if not rows:
            raise Problem("مهمة الوكلاء غير موجودة", 404)
        job = rows[0]
        job["spec"], job["results"] = json.loads(job["spec"]), json.loads(job["results"])
        if job["spec"].get("schema") != "was.agents/1":
            raise Problem("هذه ليست مهمة وكلاء", 404)
        job["report_evidence_id"] = job["spec"].get("report_evidence_id")
        job["completed"] = sum(r["status"] in ("succeeded", "failed", "cancelled") for r in job["results"])
        job["planned"] = len(job["results"])
        return job

    def start(self, project_id, question, evidence_ids, role_ids=None):
        if not isinstance(project_id, str):
            raise Problem("معرف المشروع غير صالح")
        self.store.project(project_id)
        if not isinstance(question, str) or not 1 <= len(question) <= 4000 or not question.strip():
            raise Problem("السؤال يحتاج 1–4000 حرف")
        if not isinstance(evidence_ids, list) or len(evidence_ids) > 4 or any(not isinstance(e, str) for e in evidence_ids) or len(set(evidence_ids)) != len(evidence_ids):
            raise Problem("اختر حتى أربعة أدلة مختلفة من المشروع")
        roles = {r["id"]: r for r in ROLES}
        selected = ["researcher", "defender", "reviewer"] if role_ids is None else role_ids
        if not isinstance(selected, list) or not 1 <= len(selected) <= 40 or any(not isinstance(r, str) or r not in roles for r in selected) or len(set(selected)) != len(selected):
            raise Problem("اختر 1–40 دورًا مختلفًا من القائمة")
        citations = []
        for eid in evidence_ids:
            record = self.store.evidence(project_id, eid)
            self.store.read_evidence(project_id, eid)
            citations.append({"id": eid, "sha256": record["sha256"], "excerpt_bytes": min(record["size"], 6000)})
        with self.lock:
            if self.closed:
                raise Problem("منسق الوكلاء متوقف", 503)
            if not self.execution_lock.acquire(blocking=False):
                raise Problem("عملية أخرى قيد التنفيذ؛ حاول لاحقًا", 409)
            job_id = uid()
            try:
                spec = {"schema": "was.agents/1", "version": __version__, "question": question,
                        "roles": list(selected), "evidence": citations, "model": self.ai_model,
                        "max_parallel": 2, "request_timeout_seconds": 20,
                        "limitation": "أدوار مستقلة تستخدم نموذجًا محليًا واحدًا؛ لا تنفيذ أو إصلاح آلي. النتائج تتطلب مراجعة بشرية."}
                results = [{"role_id": r, "status": "queued"} for r in selected]
                with self.store.lock, self.store.db:
                    self.store.db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?)", (job_id, project_id, "فريق مراجعة محلي", "queued", encode(spec), encode(results), time.time()))
                    self.store.audit("agents.started", {"id": job_id, "project": project_id, "roles": len(selected)})
                self.cancel.clear()
                self.thread = threading.Thread(target=self._run, args=(project_id, job_id, spec, results, list(evidence_ids), roles), daemon=True)
                self.thread.start()
            except BaseException:
                self.execution_lock.release()
                raise
            return self.status(project_id, job_id)

    def _save(self, job_id, status, spec, results):
        with self.store.lock, self.store.db:
            self.store.db.execute("UPDATE jobs SET status=?,spec=?,results=? WHERE id=?", (status, encode(spec), encode(results), job_id))

    def _run(self, project_id, job_id, spec, results, evidence_ids, roles):
        progress = threading.Lock()
        next_index = 0
        worker_errors = []
        started_workers = []

        def work():
            nonlocal next_index
            while True:
                with progress:
                    if self.cancel.is_set() or next_index >= len(results):
                        return
                    index = next_index
                    next_index += 1
                    item = results[index]
                    item["status"] = "running"
                    self._save(job_id, "running", spec, results)
                try:
                    response = local_ai.chat(self.store, project_id, spec["question"], evidence_ids,
                                             self.ai_url, self.ai_model, timeout=20,
                                             role_instruction=roles[item["role_id"]]["instructions"])
                    outcome = {"status": "succeeded", "answer": response["answer"], "evidence": response["evidence"]}
                except Exception:
                    # Do not copy endpoint errors or model server internals into reports.
                    outcome = {"status": "failed", "error": "تعذر إكمال طلب النموذج المحلي؛ تحقق من المحرك والأدلة"}
                with progress:
                    item.update(outcome)
                    self._save(job_id, "running", spec, results)

        def guarded_work():
            try:
                work()
            except Exception:
                with progress:
                    worker_errors.append(True)
                    self.cancel.set()

        try:
            workers = [threading.Thread(target=guarded_work, daemon=True) for _ in range(min(2, len(results)))]
            try:
                for worker in workers:
                    worker.start()
                    started_workers.append(worker)
            except Exception:
                self.cancel.set()
                # A successfully started sibling may still own a model request.
                # Keep the shared execution gate until that request has stopped.
                for worker in started_workers:
                    worker.join()
                raise
            for worker in workers:
                worker.join()
            for item in results:
                if item["status"] in ("queued", "running"):
                    item["status"] = "cancelled"
            succeeded = sum(item["status"] == "succeeded" for item in results)
            final = "interrupted" if self.cancel.is_set() or worker_errors else "succeeded" if succeeded == len(results) else "partial" if succeeded else "failed"
            report = {"schema": "was.agent-report/1", "job_id": job_id, "project_id": project_id,
                      "spec": spec, "results": results, "status": final,
                      "provenance": {"model": self.ai_model, "version": __version__, "citations": spec["evidence"]},
                      "human_review_required": True, "execution_authority": False}
            evidence = self.store.add_evidence(project_id, f"agent-report-{job_id}.json", encode(report).encode(), "agent-report")
            for eid in evidence_ids:
                self.store.link(project_id, eid, evidence["id"], "مقتطف مرجعي لتقرير فريق محلي")
            spec["report_evidence_id"] = evidence["id"]
            self._save(job_id, final, spec, results)
            with self.store.lock, self.store.db:
                self.store.audit("agents.finished", {"id": job_id, "status": final, "succeeded": succeeded})
        except Exception:
            # A persistence/quota failure must never appear as a successful run.
            for item in results:
                if item["status"] in ("queued", "running"):
                    item["status"] = "cancelled"
            self._save(job_id, "interrupted", spec, results)
        finally:
            for worker in started_workers:
                worker.join()
            self.execution_lock.release()

    def close(self):
        with self.lock:
            self.closed = True
            self.cancel.set()
            thread = self.thread
        if thread:
            thread.join(timeout=45)
            if thread.is_alive():
                raise RuntimeError("local model requests have not stopped; keep Store open")
