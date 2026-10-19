"""Loopback-only HTTP application with owner authentication and CSRF protection."""
import base64
import hashlib
import json
import mimetypes
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from . import __version__, backup, comparison, engine, integrity, knowledge, learning, local_ai, maintenance, quality, requirements, sandbox, tools
from .store import Problem, encode

STATIC = Path(__file__).parent / "static"
CATALOG = json.loads((Path(__file__).parent / "catalog.json").read_text())


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("Non-finite JSON number")


class App(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, store, ai_url="http://127.0.0.1:8081/v1", ai_model="local"):
        if address[0] != "127.0.0.1":
            raise Problem("الخادم محلي فقط؛ استخدم نفق SSH خاصًا للوصول البعيد")
        self.store, self.ai_url, self.ai_model = store, ai_url, ai_model
        self.setup_digest = hashlib.sha256(store.setup_token().encode()).hexdigest() if not store.setting("owner") else None
        self.sessions, self.failures = {}, []
        self.auth_lock, self.execution_lock = threading.Lock(), threading.Lock()
        self.worker_slots = threading.BoundedSemaphore(16)
        self.stop_scheduler = threading.Event()
        super().__init__(address, Handler)
        # Recover interrupted tasks without claiming successful completion.
        with store.lock, store.db:
            count = store.db.execute("UPDATE jobs SET status='interrupted' WHERE status IN ('queued','running')").rowcount
            if count:
                store.audit("jobs.interrupted", {"count": count})
        self.scheduler = threading.Thread(target=self.schedule_loop, daemon=True)
        self.scheduler.start()

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        return connection, address

    def process_request(self, request, client_address):
        if not self.worker_slots.acquire(blocking=False):
            body = b'{"error":"Service busy"}'
            try:
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.worker_slots.release()

    def schedule_loop(self):
        while not self.stop_scheduler.wait(1):
            self.run_scheduled_tick()

    def run_scheduled_tick(self):
        # An idle/disabled scheduler must not briefly reject owner operations.
        config = self.store.setting("knowledge_schedule", {})
        if not config.get("enabled") or config.get("next_at", 0) > time.time():
            return False
        if not self.execution_lock.acquire(blocking=False):
            return False
        try:
            # Recheck the persisted schedule under the execution gate.
            return knowledge.scheduled_tick(self.store)
        finally:
            self.execution_lock.release()

    def server_close(self):
        self.stop_scheduler.set()
        if hasattr(self, "scheduler"):
            self.scheduler.join(timeout=25)
        super().server_close()


class Handler(BaseHTTPRequestHandler):
    server_version = "WAS"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    @property
    def store(self):
        return self.server.store

    def log_message(self, *_):
        pass  # Request URLs, questions and filenames must not become access logs.

    def reply(self, data, status=200, content_type="application/json; charset=utf-8", headers=None):
        payload = encode(data).encode() if not isinstance(data, bytes) else data
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def session(self, csrf=False):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            value = cookie.get("was_session")
            token = value.value if value else ""
        except Exception:
            # Invalid-cookie sentinel, never a usable session credential.
            token = ""  # nosec B105
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.server.auth_lock:
            session = self.server.sessions.get(digest)
            if not session or session["expires"] < time.time():
                self.server.sessions.pop(digest, None)
                raise Problem("سجّل الدخول أولًا", 401)
        if csrf and not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), session["csrf"]):
            raise Problem("رفض حماية الطلب؛ حدّث الصفحة", 403)
        return session

    def validate_request(self):
        expected = f"127.0.0.1:{self.server.server_port}"
        if len(self.headers.get_all("Host", [])) != 1 or len(self.headers.get_all("Origin", [])) > 1:
            raise Problem("ترويسات المضيف أو المصدر ملتبسة", 400)
        if self.headers.get("Host") not in (expected, f"localhost:{self.server.server_port}"):
            raise Problem("عنوان المضيف غير مسموح", 403)
        origin = self.headers.get("Origin")
        if origin and origin != "http://" + self.headers.get("Host", ""):
            raise Problem("مصدر الطلب غير مسموح", 403)
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            raise Problem("طلب من موقع آخر مرفوض", 403)

    def do_GET(self):
        try:
            self.connection.settimeout(20)
            self.validate_request()
            path = urlsplit(self.path).path
            query = parse_qs(urlsplit(self.path).query)
            if path == "/api/status":
                return self.reply({"version": __version__, "initialized": bool(self.store.setting("owner")), "local_only": True})
            if path == "/healthz":
                return self.reply({"status": "ok", "database": self.store.rows("SELECT 1 AS ready")[0]["ready"] == 1})
            if path in ("/", "/app.js", "/style.css"):
                filename = "index.html" if path == "/" else path[1:]
                mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
                return self.reply((STATIC / filename).read_bytes(), content_type=mime + "; charset=utf-8")
            session = self.session()
            if path == "/api/bootstrap":
                return self.reply({"csrf": session["csrf"], "catalog": CATALOG, "tools": tools.describe(), "lessons": learning.lessons(),
                                   "projects": self.store.rows("SELECT * FROM projects ORDER BY created DESC"),
                                   "resources": self.store.resources(), "audit": self.store.verify_audit(),
                                   "capabilities": {"offline_analysis": True, "ai": "requires_local_model", "workshop": "requires_linux_namespaces",
                                                    "vm_image": "not_built", "live_hardware": "not_configured"}})
            if path == "/api/project":
                return self.reply(self.store.project_data(query.get("id", [""])[0]))
            if path == "/api/maintenance":
                return self.reply(maintenance.history(self.store))
            if path == "/api/quality/catalog":
                return self.reply(quality.catalog())
            if path == "/api/quality/history":
                return self.reply(quality.history(self.store))
            if path == "/api/quality":
                return self.reply(quality.status(self.store, query.get("run", [""])[0]))
            if path == "/api/integrity":
                return self.reply(integrity.status(self.store, query.get("scan", [""])[0]))
            if path == "/api/integrity/history":
                rows = self.store.rows("SELECT key FROM settings WHERE key LIKE ?", (integrity.PREFIX + "%",))
                scans = [integrity.status(self.store, r["key"][len(integrity.PREFIX):]) for r in rows]
                return self.reply({"scans": sorted(scans, key=lambda s: s["created"], reverse=True)[:20]})
            if path == "/api/requirements":
                return self.reply(requirements.view(query.get("q", [""])[0], query.get("status", [""])[0],
                                                    int(query.get("page", ["1"])[0]), query.get("mode", ["requirements"])[0]))
            if path == "/api/requirements/block":
                return self.reply(requirements.block(query.get("id", [""])[0]))
            if path == "/api/requirements/source":
                return self.reply(requirements.source_bytes(), content_type="text/markdown; charset=utf-8",
                                  headers={"Content-Disposition": 'attachment; filename="Cyber-Platform-Requirements.md"', "X-Source-SHA256": requirements.DATA["source"]["sha256"]})
            if path == "/api/requirements/export":
                return self.reply(requirements.DATA, headers={"Content-Disposition": 'attachment; filename="requirements-register.json"'})
            if path == "/api/knowledge":
                return self.reply(knowledge.status(self.store, query.get("project", [""])[0]))
            if path == "/api/knowledge/search":
                return self.reply(knowledge.search(self.store, query.get("project", [""])[0], query.get("q", [""])[0]))
            if path == "/api/evidence":
                project_id, eid = query.get("project", [""])[0], query.get("id", [""])[0]
                record = self.store.evidence(project_id, eid)
                return self.reply(self.store.read_evidence(project_id, eid), content_type="application/octet-stream",
                                  headers={"Content-Disposition": f'attachment; filename="evidence-{eid}.bin"', "X-Evidence-SHA256": record["sha256"]})
            if path == "/api/audit":
                return self.reply({"verification": self.store.verify_audit(), "events": self.store.rows("SELECT * FROM audit ORDER BY seq DESC LIMIT 200")})
            if path == "/api/report":
                project_id = query.get("project", [""])[0]
                data = self.store.project_data(project_id)
                # Do not include original evidence contents or owner account records.
                raw = encode({"schema": "was.report/1", "project": data["project"], "evidence": data["evidence"],
                              "jobs": [{"id": j["id"], "status": j["status"], "name": j["name"]} for j in data["jobs"]], "relations": data["relations"]})
                clean = tools.privacy(raw.encode())
                return self.reply({"report": json.loads(clean["redacted"]), "redaction_matches": clean["matches"], "limitation": clean["limitations"]})
            raise Problem("المسار غير موجود", 404)
        except Problem as exc:
            self.reply({"error": str(exc)}, exc.status)
        except (ValueError, TypeError):
            self.reply({"error": "مرشحات غير صالحة"}, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.reply({"error": "فشل الطلب؛ راجع سلامة الخدمة والبيانات"}, 500)

    def do_POST(self):
        try:
            self.connection.settimeout(20)
            self.validate_request()
            path = urlsplit(self.path).path
            public = path in ("/api/setup", "/api/login")
            if not public:
                self.session(csrf=True)
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise Problem("JSON مطلوب", 415)
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                raise Problem("صيغة طول الطلب ملتبسة", 400)
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= (4096 if public else 24 * 1024 * 1024):
                raise Problem("حجم الطلب غير مسموح", 413)
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise Problem("الطلب مبتور", 400)
            body = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
            if not isinstance(body, dict):
                raise Problem("صيغة الطلب غير صالحة")
            if path in ("/api/setup", "/api/login"):
                with self.server.auth_lock:
                    self.server.failures = [t for t in self.server.failures if t > time.time() - 60]
                    if len(self.server.failures) >= 8:
                        raise Problem("محاولات كثيرة؛ انتظر دقيقة", 429)
                    self.server.failures.append(time.time())
                if path == "/api/setup":
                    if self.store.setting("owner"):
                        raise Problem("تم إعداد حساب المالك مسبقًا", 409)
                    provided = body.get("setup_token")
                    if not isinstance(provided, str) or not self.server.setup_digest or not secrets.compare_digest(hashlib.sha256(provided.encode()).hexdigest(), self.server.setup_digest):
                        raise Problem("رمز التهيئة المحلي مطلوب؛ اقرأ ملف setup-token من مجلد بيانات التطبيق على جهازك", 403)
                    self.store.initialize(body.get("password"))
                    self.server.setup_digest = None
                    (self.store.root / "setup-token").unlink(missing_ok=True)
                elif not self.store.check_password(body.get("password")):
                    with self.store.lock, self.store.db:
                        self.store.audit("owner.login_failed", {})
                    raise Problem("بيانات الدخول غير صحيحة", 401)
                token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                with self.server.auth_lock:
                    self.server.sessions = {k: v for k, v in self.server.sessions.items() if v["expires"] > time.time()}
                    self.server.sessions[hashlib.sha256(token.encode()).hexdigest()] = {"expires": time.time() + 8 * 3600, "csrf": csrf}
                with self.store.lock, self.store.db:
                    self.store.audit("owner.login", {})
                return self.reply({"csrf": csrf}, headers={"Set-Cookie": f"was_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"})
            if path == "/api/logout":
                token = SimpleCookie(self.headers.get("Cookie", ""))["was_session"].value
                with self.server.auth_lock:
                    self.server.sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)
                return self.reply({"ok": True}, headers={"Set-Cookie": "was_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
            if path == "/api/projects":
                return self.reply(self.store.create_project(body.get("name"), body.get("description", "")), 201)
            if path == "/api/development":
                return self.reply(maintenance.task(self.store, body))
            if path == "/api/knowledge/settings":
                if set(body) != {"project_id", "enabled", "interval_seconds"}:
                    raise Problem("إعدادات الجدولة غير صالحة")
                return self.reply(knowledge.configure(self.store, body["project_id"], body["enabled"], body["interval_seconds"]))
            if path == "/api/upload":
                try:
                    data = base64.b64decode(body.get("base64", ""), validate=True)
                except (ValueError, TypeError):
                    raise Problem("ترميز الملف غير صالح") from None
                return self.reply(self.store.add_evidence(body.get("project_id"), body.get("name"), data), 201)
            if path == "/api/relations":
                self.store.link(body.get("project_id"), body.get("source"), body.get("target"), body.get("label"))
                return self.reply({"ok": True}, 201)
            if path in ("/api/run", "/api/workflows/resume", "/api/results/compare", "/api/workshop", "/api/chat", "/api/backup", "/api/learning/attempt", "/api/knowledge/refresh", "/api/requirements/import", "/api/maintenance", "/api/integrity/start", "/api/integrity/advance", "/api/quality/start", "/api/quality/advance", "/api/quality/compare"):
                if not self.server.execution_lock.acquire(blocking=False):
                    raise Problem("مهمة أخرى قيد التنفيذ؛ حاول بعد انتهائها", 409)
                try:
                    if path == "/api/quality/start":
                        if body:
                            raise Problem("اختبار الجودة يستخدم الحالات المرجعية المرفقة فقط")
                        return self.reply(quality.start(self.store))
                    if path == "/api/quality/advance":
                        if set(body) != {"run_id"}:
                            raise Problem("حدد معرف اختبار الجودة المحفوظ فقط")
                        return self.reply(quality.advance(self.store, body["run_id"]))
                    if path == "/api/quality/compare":
                        if set(body) != {"left_id", "right_id"}:
                            raise Problem("اختر اختباري الجودة للمقارنة فقط")
                        return self.reply(quality.compare(self.store, body["left_id"], body["right_id"]))
                    if path == "/api/integrity/start":
                        if set(body) != {"project_id"}:
                            raise Problem("حدد مشروع الفحص أو جميع المشاريع فقط")
                        return self.reply(integrity.start(self.store, body["project_id"]))
                    if path == "/api/integrity/advance":
                        if set(body) != {"scan_id"}:
                            raise Problem("الفحص يقبل معرف العملية المحفوظة فقط")
                        return self.reply(integrity.advance(self.store, body["scan_id"]))
                    if path == "/api/maintenance":
                        if set(body) != {"operation", "section_id"}:
                            raise Problem("حقول الصيانة غير صالحة")
                        return self.reply(maintenance.check(self.store, body["operation"], body["section_id"]))
                    if path == "/api/workflows/resume":
                        if not {"project_id", "source_job_id", "steps"} <= set(body) or set(body) - {"project_id", "source_job_id", "steps", "name"}:
                            raise Problem("حقول الاستكمال غير صالحة")
                        if not isinstance(body["source_job_id"], str) or not body["source_job_id"]:
                            raise Problem("حدد المهمة الأصلية للاستكمال")
                        originals = self.store.rows("SELECT spec FROM jobs WHERE id=? AND project_id=?", (body["source_job_id"], body["project_id"]))
                        if originals and json.loads(originals[0]["spec"]).get("schema") == "was.agents/1":
                            raise Problem("مهام الوكلاء القديمة محفوظة للقراءة فقط ولا يمكن استكمالها", 409)
                        return self.reply(engine.run(self.store, body["project_id"], body["steps"], body.get("name", "استكمال سير عمل"), resume_id=body["source_job_id"]))
                    if path == "/api/results/compare":
                        if set(body) != {"project_id", "left_id", "right_id"}:
                            raise Problem("اختر المشروع ونتيجتي التحليل فقط")
                        return self.reply(comparison.compare(self.store, body["project_id"], body["left_id"], body["right_id"]))
                    if path == "/api/requirements/import":
                        if set(body) != {"project_id"}:
                            raise Problem("الاستيراد يقبل معرف المشروع فقط")
                        return self.reply(requirements.import_source(self.store, body["project_id"]))
                    if path == "/api/knowledge/refresh":
                        if set(body) != {"project_id", "source_id"}:
                            raise Problem("الجلب يقبل معرف مصدر مسجل فقط")
                        return self.reply(knowledge.refresh(self.store, body["project_id"], body["source_id"]))
                    if path == "/api/learning/attempt":
                        if set(body) != {"project_id", "lesson_id", "answer_index"}:
                            raise Problem("المحاولة تقبل مشروعًا ودرسًا واختيار إجابة فقط")
                        return self.reply(learning.attempt(self.store, body["project_id"], body["lesson_id"], body["answer_index"]))
                    if path == "/api/run":
                        return self.reply(engine.run(self.store, body.get("project_id"), body.get("steps"), body.get("name", "تحليل محلي")))
                    if path == "/api/workshop":
                        project_id = body.get("project_id")
                        self.store.project(project_id)
                        result = sandbox.run(body.get("code"))
                        evidence = self.store.add_evidence(project_id, "workshop-result.json", encode({"code": body["code"], "result": result}).encode(), "workshop")
                        return self.reply({"result": result, "evidence": evidence})
                    if path == "/api/chat":
                        self.store.project(body.get("project_id"))
                        return self.reply(local_ai.chat(self.store, body.get("project_id"), body.get("question"), body.get("evidence_ids", []), self.server.ai_url, self.server.ai_model))
                    return self.reply(backup.export(self.store, body.get("password")), content_type="application/octet-stream",
                                      headers={"Content-Disposition": 'attachment; filename="platform.cyberbackup"'})
                finally:
                    self.server.execution_lock.release()
            raise Problem("المسار غير موجود", 404)
        except Problem as exc:
            self.reply({"error": str(exc)}, exc.status)
        except (ValueError, TypeError, KeyError, RecursionError):
            self.reply({"error": "مدخلات غير صالحة"}, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.reply({"error": "فشل الطلب؛ لم يُعلن نجاح المهمة"}, 500)
