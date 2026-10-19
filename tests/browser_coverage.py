"""Browser coverage workflow using only the fresh smoke-test project's fixtures."""
import json
from pathlib import Path
from tests.browser_helpers import wait_for_idle


def run_coverage_checks(page, expect, checks):
    """Run after the research checks have created a passing detection report."""
    passing = page.evaluate("""async () => {
      const project = await api('project?id=' + state.project.project.id);
      for (const item of project.evidence.filter(e => e.kind === 'detection-test')) {
        const response = await fetch('/api/evidence?project=' + project.project.id + '&id=' + item.id);
        if (!response.ok) throw Error('fixture evidence unavailable');
        const report = await response.json();
        if (report.evaluation_status === 'passed' && report.passed === true)
          return {id:item.id, project_id:project.project.id, count:project.evidence.length};
      }
      throw Error('research checks must create a passing detection-test fixture');
    }""")
    page.get_by_role("link", name="التغطية الدفاعية", exact=True).click()
    expect(page.get_by_role("heading", name="ملخص التغطية المحفوظة", exact=True)).to_be_visible()
    page.get_by_label("اسم أصل التغطية", exact=True).fill("خدمة اختبار تغطية اصطناعية")
    page.get_by_label("نوع أصل التغطية", exact=True).select_option("service")
    with page.expect_response(lambda response: response.url.endswith("/api/coverage/asset")) as created:
        page.get_by_role("button", name="إضافة أصل للتغطية", exact=True).click()
    assert created.value.status == 200, created.value.text()
    asset_id = created.value.json()["id"]
    assets = page.locator("section.panel").filter(has=page.get_by_role("heading", name="الأصول وحالة اختبارها", exact=True))
    asset_row = assets.get_by_role("row").filter(has=page.get_by_role("cell", name="خدمة اختبار تغطية اصطناعية", exact=True))
    expect(asset_row).to_contain_text("لم يُختبر")
    gaps = page.locator("section.panel").filter(has=page.get_by_role("heading", name="الفجوات وما يحتاج مراجعة", exact=True))
    expect(gaps).to_contain_text("لا يوجد تقييم مرتبط")
    page.get_by_label("أصل تقييم التغطية", exact=True).select_option(asset_id)
    page.get_by_label("تهديد التغطية", exact=True).fill("محاولات دخول متكررة في عينة")
    page.get_by_label("إجراء الحماية", exact=True).fill("كشف محاولات الدخول الاصطناعية")
    page.get_by_label("دليل تقييم التغطية", exact=True).select_option(passing["id"])
    with page.expect_response(lambda response: response.url.endswith("/api/coverage/assessment")) as assessed:
        page.get_by_role("button", name="إضافة تقييم التغطية", exact=True).click()
    assert assessed.value.status == 200, assessed.value.text()
    assert assessed.value.json()["status"] == "supported"
    expect(asset_row).to_contain_text("مدعوم باختبار محفوظ")
    with page.expect_download() as exported:
        page.get_by_role("button", name="تنزيل خريطة التغطية JSON", exact=True).click()
    snapshot = json.loads(Path(exported.value.path()).read_text())
    assert snapshot["schema"] == "was.coverage-view/1"
    assert any(item["asset_id"] == asset_id and item["evidence_id"] == passing["id"] and item["status"] == "supported" for item in snapshot["assessments"])
    assert any(item["source"] == asset_id for item in snapshot["edges"])
    wait_for_idle(page)
    with page.expect_response(lambda response: response.url.endswith("/api/coverage/remove")) as removed:
        page.get_by_role("button", name="إزالة تقييم كشف محاولات الدخول الاصطناعية", exact=True).click()
    assert removed.value.json()["evidence_preserved"] is True
    expect(asset_row).to_contain_text("لم يُختبر")
    expect(gaps).to_contain_text("لا يوجد تقييم مرتبط")
    retained = page.evaluate("""async id => {
      const project = await api('project?id=' + id);
      return project.evidence.map(item => item.id);
    }""", passing["project_id"])
    assert len(retained) == passing["count"] and passing["id"] in retained
    page.reload()
    expect(page.get_by_role("heading", name="ملخص التغطية المحفوظة", exact=True)).to_be_visible()
    expect(assets.get_by_role("cell", name="خدمة اختبار تغطية اصطناعية", exact=True)).to_be_visible()
    expect(asset_row).to_contain_text("لم يُختبر")
    checks.append("static defense coverage links verified detection evidence, exports relationships, persists assets and removes metadata while preserving evidence")
