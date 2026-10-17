"""Real Chromium checks against a fresh local server and synthetic data only.

Run separately: python3 -m tests.browser_smoke
Requires playwright and a local Chromium executable (WAS_CHROMIUM optional).
"""
import json
import os
import tempfile
import threading
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
from cyber_platform.server import App
from cyber_platform.store import Store


def main():
    output = Path(".state/qa")
    output.mkdir(parents=True, exist_ok=True)
    checks, errors = [], []
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(tmp)
        app = App(("127.0.0.1", 0), store)
        thread = threading.Thread(target=app.serve_forever, daemon=True)
        thread.start()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(executable_path=os.environ.get("WAS_CHROMIUM", "/usr/bin/chromium"), headless=True, args=["--no-sandbox"])
                page = browser.new_page(viewport={"width": 1440, "height": 1000}, accept_downloads=True)
                page.set_default_timeout(10000)
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(f"http://127.0.0.1:{app.server_port}")
                page.get_by_label("كلمة المرور", exact=True).fill("Synthetic-test-123456")
                page.get_by_role("button", name="إنشاء حساب المالك").click()
                expect(page.get_by_role("heading", name="نظرة عامة", exact=True)).to_be_visible()
                checks.append("owner setup and login")
                page.get_by_role("button", name="＋ مشروع جديد").click()
                dialog = page.get_by_role("dialog")
                dialog.get_by_label("اسم المشروع", exact=True).fill("اختبار مختبر محلي")
                dialog.get_by_label("الوصف", exact=True).fill("بيانات اصطناعية لاختبار الواجهة")
                dialog.get_by_role("button", name="إنشاء المشروع", exact=True).click()
                expect(page.get_by_role("heading", name="الأدلة والملفات", exact=True)).to_be_visible()
                checks.append("project creation")
                page.get_by_label("اختر ملف الدليل").set_input_files({"name": "synthetic.txt", "mimeType": "text/plain", "buffer": b"192.0.2.123"})
                page.get_by_role("button", name="رفع وحفظ الأصل").click()
                expect(page.get_by_role("cell", name="synthetic.txt", exact=False)).to_be_visible()
                checks.append("original file upload")
                page.get_by_role("link", name="أدوات التحليل").click()
                card = page.locator("article.card").filter(has=page.get_by_role("heading", name="استخراج المؤشرات"))
                card.get_by_role("button", name="تحليل", exact=True).click()
                dialog = page.get_by_role("dialog")
                dialog.get_by_label("الدليل المختار", exact=True).select_option(index=1)
                dialog.get_by_label("معايير قبول اختيارية", exact=False).fill('{"ipv4.0":"192.0.2.123"}')
                dialog.get_by_role("button", name="تشغيل التحليل").click()
                expect(dialog.get_by_text("نجحت", exact=True)).to_be_visible()
                expect(dialog.locator("pre")).to_contain_text('192.0.2.123')
                dialog.get_by_role("button", name="إغلاق ×").click()
                checks.append("real IOC analysis and acceptance")
                page.get_by_role("link", name="سير العمل").click()
                spec = json.loads(page.get_by_label("خطوات JSON").input_value())
                spec[0]["expect"] = {"bytes": 999}
                page.get_by_label("خطوات JSON").fill(json.dumps(spec))
                page.get_by_role("button", name="تشغيل الخطوات").click()
                expect(page.locator(".result-head").get_by_text("فشلت", exact=True)).to_be_visible()
                checks.append("failed workflow visible with preserved result")
                page.get_by_role("link", name="خريطة الأدلة").click()
                expect(page.locator("svg.graph circle")).to_have_count(3)
                page.locator("svg.graph circle").first.click()
                expect(page.get_by_role("dialog")).to_be_visible()
                page.get_by_role("button", name="إغلاق ×").click()
                checks.append("evidence graph and inspection")
                page.get_by_role("link", name="الأقسام والتخصصات").click()
                expect(page.locator("article.card")).to_have_count(20)
                for i in range(20):
                    page.locator("article.card").nth(i).get_by_role("button").click()
                    expect(page.locator("details.lab").first).to_be_visible()
                    page.locator("details.lab").first.locator("summary").click()
                    expect(page.locator("details.lab").first.locator(".lab-content")).to_be_visible()
                    page.get_by_role("button", name="→ جميع الأقسام").click()
                checks.append("all 20 department pages and nested labs")
                for name in ("المشاريع", "الأدلة والملفات", "أدوات التحليل", "سير العمل", "خريطة الأدلة", "ورشة البرمجة", "المساعد المحلي", "سجل التدقيق", "إدارة المنظومة"):
                    page.get_by_role("link", name=name, exact=False).click()
                    expect(page.get_by_role("heading", name=name, exact=True)).to_be_visible()
                page.get_by_label("كلمة حماية النسخة", exact=True).fill("Backup-browser-test-123")
                with page.expect_download() as dl:
                    page.get_by_role("button", name="تنزيل نسخة مشفرة").click()
                path = output / "synthetic.cyberbackup"
                dl.value.save_as(path)
                assert path.read_bytes().startswith(b"WASBACKUP1\0")
                path.unlink()
                checks.append("encrypted backup download")
                page.get_by_role("link", name="نظرة عامة").click()
                page.screenshot(path=str(output / "desktop.png"), full_page=True)
                for width in (390, 320):
                    page.set_viewport_size({"width": width, "height": 844})
                    for view in ("dashboard", "sections", "evidence", "tools", "workflows", "map", "assistant", "workshop", "settings"):
                        page.evaluate("hash => location.hash=hash", view)
                        page.wait_for_timeout(80)
                        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (width, view)
                    page.screenshot(path=str(output / f"mobile-{width}.png"), full_page=True)
                    checks.append(f"no page overflow at {width}px across 9 pages")
                page.get_by_role("button", name="خروج", exact=True).click()
                expect(page.get_by_role("button", name="دخول مساحة العمل")).to_be_visible()
                checks.append("logout revokes session")
                assert not errors, errors
                browser.close()
        finally:
            app.shutdown()
            app.server_close()
            thread.join()
            store.close()
    report = {"checks": checks, "count": len(checks), "javascript_errors": errors}
    (output / "browser-results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
