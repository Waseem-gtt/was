"""UI integration against a synthetic loopback completion fixture, not real inference.

Run: .state/browser-ci/bin/python -m tests.browser_agents
"""
import json
import os
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from playwright.sync_api import expect, sync_playwright

from cyber_platform.server import App
from cyber_platform.store import Store


class CompletionFixture(BaseHTTPRequestHandler):
    active = 0
    maximum = 0
    calls = 0
    lock = threading.Lock()

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert self.path == "/v1/chat/completions"
        assert payload["model"] == "synthetic-fixture"
        with self.lock:
            type(self).active += 1
            type(self).maximum = max(self.maximum, self.active)
            type(self).calls += 1
        try:
            time.sleep(.06)
            body = json.dumps({"choices": [{"message": {"content": "Synthetic review <script>window.injected=true</script>"}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        finally:
            with self.lock:
                type(self).active -= 1

    def log_message(self, *_args):
        pass


def main():
    errors = []
    fixture = ThreadingHTTPServer(("127.0.0.1", 0), CompletionFixture)
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(tmp)
        project = store.create_project("Synthetic agents project")
        for index in range(5):
            store.add_evidence(project["id"], f"synthetic-{index}.txt", b"Example evidence 192.0.2.1")
        app = App(("127.0.0.1", 0), store, ai_url=f"http://127.0.0.1:{fixture.server_port}/v1", ai_model="synthetic-fixture")
        threading.Thread(target=app.serve_forever, daemon=True).start()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(executable_path=os.environ.get("WAS_CHROMIUM", "/usr/bin/chromium"), headless=True, args=["--no-sandbox"])
                page = browser.new_page(viewport={"width": 1200, "height": 900}, accept_downloads=True)
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto(f"http://127.0.0.1:{app.server_port}")
                page.get_by_label("كلمة المرور", exact=True).fill("Synthetic-owner-12345")
                page.get_by_label("رمز التهيئة", exact=True).fill(store.setup_token())
                page.get_by_role("button", name="إنشاء حساب المالك").click()
                page.get_by_role("link", name="فريق الوكلاء", exact=True).click()
                expect(page.get_by_role("heading", name="فريق من 40 دورًا تخصصيًا")).to_be_visible()
                roles = page.get_by_role("group", name="الأدوار المشاركة", exact=True)
                expect(roles.locator('input[type="checkbox"]')).to_have_count(40)
                page.get_by_role("button", name="اختيار جميع الأدوار").click()
                expect(roles.locator("input:checked")).to_have_count(40)
                page.get_by_role("button", name="إلغاء اختيار الأدوار").click()
                expect(roles.locator("input:checked")).to_have_count(0)
                page.get_by_role("button", name="اختيار جميع الأدوار").click()
                page.get_by_label("المهمة المشتركة", exact=True).fill("Review this synthetic evidence from your specialty")
                evidence_boxes = page.get_by_role("group", name="الأدلة المسموح بمشاركتها (حتى 4)", exact=True).locator("input")
                for index in range(4):
                    evidence_boxes.nth(index).check()
                evidence_boxes.nth(4).click()
                expect(evidence_boxes.nth(4)).not_to_be_checked()
                page.get_by_role("button", name="توزيع المهمة على الوكلاء").click()
                expect(page.get_by_role("status").filter(has_text="حالة الفريق: اكتملت")).to_be_visible(timeout=30000)
                expect(page.locator("pre").filter(has_text="Synthetic review")).to_have_count(40)
                assert page.evaluate("window.injected === undefined")
                assert CompletionFixture.calls == 40
                assert 1 <= CompletionFixture.maximum <= 2
                with page.expect_download() as downloaded:
                    page.get_by_role("button", name="تنزيل تقرير الفريق").click()
                assert downloaded.value.suggested_filename.endswith(".json")
                page.reload()
                expect(page.get_by_role("status").filter(has_text="حالة الفريق: اكتملت")).to_be_visible(timeout=15000)
                expect(page.locator("pre").filter(has_text="Synthetic review")).to_have_count(40)
                page.get_by_role("link", name="سير العمل", exact=True).click()
                expect(page.get_by_role("button", name="استكمال", exact=True)).to_have_count(0)
                page.goto(f"http://127.0.0.1:{app.server_port}/#agents")
                for width in (390, 320):
                    page.set_viewport_size({"width": width, "height": 850})
                    expect(page.get_by_role("heading", name="فريق من 40 دورًا تخصصيًا")).to_be_visible()
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
                assert not errors, errors
                browser.close()
                print(json.dumps({"checks": ["40 specialty roles selectable", "selection limited to 4 evidence files", "40 fixture completions persisted", "at most 2 concurrent fixture requests", "model output rendered as text", "report download", "reload restores history", "agent jobs excluded from workflow resume", "320px and 390px layout"], "javascript_errors": errors, "real_model_inference": False}, ensure_ascii=False))
        finally:
            app.shutdown()
            app.server_close()
            store.db.close()
            fixture.shutdown()
            fixture.server_close()


if __name__ == "__main__":
    main()
