"""Browser checks for event provenance and exact-match defensive rules."""
import json
from pathlib import Path
from tests.browser_helpers import wait_for_idle


def run_research_checks(page, expect, checks):
    """Use only synthetic fixtures in the smoke suite's temporary project."""
    page.get_by_role("link", name="توحيد الأحداث", exact=True).click()
    page.get_by_label("صيغة الأحداث", exact=True).select_option("windows-json")
    page.get_by_role("button", name="استيراد عينة أحداث اصطناعية", exact=True).click()
    expect(page.get_by_label("دليل الأحداث الأصلي", exact=True)).not_to_have_value("")
    page.get_by_role("button", name="توحيد الأحداث وحفظ النتيجة", exact=True).click()
    expect(page.get_by_text("أحداث موحدة:", exact=False)).to_be_visible()
    with page.expect_download() as result:
        page.get_by_role("button", name="تنزيل تقرير توحيد الأحداث JSON", exact=True).click()
    report = json.loads(Path(result.value.path()).read_text())
    assert report["input_sha256"] and report["adapter_sha256"]
    assert report["result"]["count"] > 0
    assert report["result"]["failed"] == 1
    checks.append("file event normalization retains original provenance and downloadable report")

    page.get_by_role("link", name="مكتبة الكشف", exact=True).click()
    fixture = page.get_by_role("button", name="استيراد عينة الكشف:", exact=False).first
    expect(fixture).to_be_visible()
    fixture.click()
    expect(page.get_by_label("دليل اختبار الكشف", exact=True)).not_to_have_value("")
    page.get_by_role("button", name="اختبار القواعد المختارة وحفظ التقرير", exact=True).click()
    expect(page.get_by_text("اجتازت التوقعات المرجعية", exact=True)).to_be_visible()
    with page.expect_download() as result:
        page.get_by_role("button", name="تنزيل تقرير اختبار الكشف JSON", exact=True).click()
    report = json.loads(Path(result.value.path()).read_text())
    assert report["evaluation_status"] == "passed"
    assert report["evaluated_rules"] == 8
    assert len(report["result"]["rules"]) == 8
    assert report["input_sha256"] and report["rules_sha256"] and report["engine_sha256"]
    checks.append("eight builtin defensive rules pass explicit synthetic truth and export fingerprints")

    editor = page.get_by_label("قاعدة المالك JSON", exact=True)
    rule = json.loads(editor.input_value())
    rule["id"] = "owner-browser-login"
    editor.fill(json.dumps(rule, ensure_ascii=False))
    page.get_by_role("button", name="حفظ مراجعة القاعدة", exact=True).click()
    expect(page.get_by_text("حُفظت مراجعة القاعدة: 1", exact=True)).to_be_visible()
    rule["version"] = "1.0.1"
    editor.fill(json.dumps(rule, ensure_ascii=False))
    page.get_by_role("button", name="حفظ مراجعة القاعدة", exact=True).click()
    expect(page.get_by_text("حُفظت مراجعة القاعدة: 2", exact=True)).to_be_visible()
    for checkbox in page.locator('input[name="detection-rule"]').all():
        checkbox.uncheck()
    page.locator('input[name="detection-rule"][value="owner-browser-login"]').check()
    page.get_by_role("button", name="اختبار القواعد المختارة وحفظ التقرير", exact=True).click()
    expect(page.get_by_text("غير مقيّمة: لا توجد توقعات مرجعية", exact=True)).to_be_visible()
    with page.expect_download() as result:
        page.get_by_role("button", name="تنزيل تقرير اختبار الكشف JSON", exact=True).click()
    report = json.loads(Path(result.value.path()).read_text())
    assert report["evaluation_status"] == "not_evaluated"
    assert report["evaluated_rules"] == 0
    assert report["result"]["rules"][0]["metrics"] is None
    assert report["rules"][0]["revision"] == 2
    checks.append("owner detection revisions persist and missing truth is unknown rather than passed")
