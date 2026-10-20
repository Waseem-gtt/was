"""Saved branching workflow and data-template browser acceptance checks."""
import json
from pathlib import Path
from tests.browser_helpers import wait_for_idle


def run_plan_checks(page, expect, checks):
    """Run against the smoke suite's fresh project and synthetic inputs only."""
    page.get_by_role("link", name="خطط التحليل", exact=True).click()
    template_select = page.get_by_label("قالب خطة التحليل", exact=True)
    expect(template_select.locator("option")).to_have_count(8)
    page.get_by_role("button", name="استيراد عينة القالب:", exact=False).first.click()
    slots = page.locator('select[aria-label^="دليل مدخل الخطة: "]')
    expect(slots.first).not_to_have_value("")
    wait_for_idle(page)
    page.get_by_role("button", name="إنشاء خطة من القالب دون تشغيل", exact=True).click()
    expect(page.get_by_text("أُنشئت الخطة للمراجعة؛ لم يبدأ التنفيذ", exact=True)).to_be_visible()
    wait_for_idle(page)
    editor = page.get_by_label("خطة التحليل JSON", exact=True)
    bound_plan = json.loads(editor.input_value())
    assert len(bound_plan["nodes"]) >= 3
    assert all("slot" not in node["input"] for node in bound_plan["nodes"])
    with page.expect_response(lambda response: response.url.endswith("/api/plans/start")) as created:
        page.get_by_role("button", name="بدء تشغيل خطة التحليل", exact=True).click()
    assert created.value.status == 200, created.value.text()
    started_run = created.value.json()
    run_id = started_run["id"]
    assert started_run["template_origin"]["evidence_id"]
    wait_for_idle(page)
    with page.expect_response(lambda response: response.url.endswith("/api/plans/advance")) as advanced:
        page.get_by_role("button", name="تنفيذ دفعة الخطة التالية", exact=True).click()
    first = advanced.value.json()
    assert 0 < first["counts"]["completed"] <= 2
    assert first["counts"]["completed"] < first["counts"]["total"]
    wait_for_idle(page)
    page.get_by_role("button", name="إيقاف الخطة مؤقتًا", exact=True).click()
    expect(page.get_by_text("متوقفة مؤقتًا", exact=True)).to_be_visible()
    wait_for_idle(page)
    page.reload()
    saved = page.get_by_label("خطة تشغيل محفوظة", exact=True)
    expect(saved.locator('option[value="' + run_id + '"]')).to_have_count(1)
    saved.select_option(run_id)
    page.get_by_role("button", name="عرض تشغيل الخطة المحفوظ", exact=True).click()
    expect(page.get_by_text("متوقفة مؤقتًا", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="تنفيذ دفعة الخطة التالية", exact=True)).to_be_disabled()
    wait_for_idle(page)
    page.get_by_role("button", name="استكمال الخطة المتوقفة", exact=True).click()
    expect(page.get_by_role("button", name="تنفيذ دفعة الخطة التالية", exact=True)).to_be_enabled()
    wait_for_idle(page)
    for _ in range(20):
        with page.expect_response(lambda response: response.url.endswith("/api/plans/advance")) as advanced:
            page.get_by_role("button", name="تنفيذ دفعة الخطة التالية", exact=True).click()
        run = advanced.value.json()
        assert advanced.value.status == 200, run
        wait_for_idle(page)
        if run["status"] in ("completed", "failed"):
            break
    assert run["id"] == run_id and run["status"] == "completed" and run["passed"] is True, run
    assert run["counts"]["failed"] == 0 and run["counts"]["skipped"] == 0
    expect(page.get_by_text("اجتازت الخطة خطواتها المنفذة", exact=True)).to_be_visible()
    with page.expect_download() as downloaded:
        page.get_by_role("button", name="تنزيل تقرير خطة التحليل JSON", exact=True).click()
    exported = json.loads(Path(downloaded.value.path()).read_text())
    assert exported["id"] == run_id and exported["plan_sha256"] and exported["engine_sha256"]
    assert exported["template_origin"]["evidence_id"] == started_run["template_origin"]["evidence_id"]
    assert all(result["evidence_id"] for result in exported["results"])
    checks.append("analysis template binds synthetic inputs without execution and durable plan pauses, reloads, resumes, completes and exports")

    owner_editor = page.get_by_label("قالب المالك JSON", exact=True)
    owner_template = json.loads(owner_editor.input_value())
    owner_template["id"] = "owner-browser-template"
    owner_editor.fill(json.dumps(owner_template, ensure_ascii=False))
    page.get_by_role("button", name="حفظ مراجعة قالب المالك", exact=True).click()
    expect(page.get_by_text("حُفظت مراجعة قالب المالك: 1", exact=True)).to_be_visible()
    wait_for_idle(page)
    owner_template["version"] = "1.0.1"
    owner_editor.fill(json.dumps(owner_template, ensure_ascii=False))
    page.get_by_role("button", name="حفظ مراجعة قالب المالك", exact=True).click()
    expect(page.get_by_text("حُفظت مراجعة قالب المالك: 2", exact=True)).to_be_visible()
    expect(template_select.locator('option[value="owner-browser-template"]')).to_have_count(1)
    wait_for_idle(page)
    checks.append("owner analysis template revisions are saved and selectable without starting jobs")

    evidence_id = page.evaluate("""async () => {
      const evidence = await researchUpload(state.project.project.id, 'synthetic-branch.txt', 'Host 192.0.2.11 contacted example.test');
      return evidence.id;
    }""")
    # Bind again on this page, then edit the plan: the old proof must be omitted.
    original_source = bound_plan["nodes"][0]["input"]["evidence_id"]
    for selector in page.locator('select[aria-label^="دليل مدخل الخطة: "]').all():
        selector.select_option(original_source)
    page.get_by_role("button", name="إنشاء خطة من القالب دون تشغيل", exact=True).click()
    expect(page.get_by_text("أُنشئت الخطة للمراجعة؛ لم يبدأ التنفيذ", exact=True)).to_be_visible()
    wait_for_idle(page)
    plan = {"schema":"was.plan/1", "name":"فروع قبول اصطناعية", "nodes":[
        {"id":"inspect", "tool":"ioc", "input":{"evidence_id":evidence_id}, "depends_on":[], "when":None, "expect":{"ipv4.0":"192.0.2.250"}},
        {"id":"failure_path", "tool":"hashes", "input":{"node_id":"inspect"}, "depends_on":["inspect"], "when":{"node_id":"inspect","status":"failed"}, "expect":{}},
        {"id":"success_path", "tool":"hashes", "input":{"node_id":"inspect"}, "depends_on":["inspect"], "when":{"node_id":"inspect","status":"succeeded"}, "expect":{}},
    ]}
    editor.fill(json.dumps(plan, ensure_ascii=False))
    expect(page.get_by_text("الخطة معدلة يدويًا؛ لن تُنسب إلى إثبات القالب السابق عند التشغيل", exact=True)).to_be_visible()
    with page.expect_response(lambda response: response.url.endswith("/api/plans/start")) as started:
        page.get_by_role("button", name="بدء تشغيل خطة التحليل", exact=True).click()
    assert started.value.status == 200, started.value.text()
    assert started.value.json().get("template_origin") is None
    wait_for_idle(page)
    for _ in range(20):
        with page.expect_response(lambda response: response.url.endswith("/api/plans/advance")) as advanced:
            page.get_by_role("button", name="تنفيذ دفعة الخطة التالية", exact=True).click()
        run = advanced.value.json()
        assert advanced.value.status == 200, run
        wait_for_idle(page)
        if run["status"] in ("completed", "failed"):
            break
    assert run["status"] == "completed" and run["passed"] is False, run
    assert run["counts"] == {"total":3,"completed":3,"succeeded":1,"failed":1,"skipped":1}, run
    outcomes = {result["node_id"]:result["status"] for result in run["results"]}
    assert outcomes == {"inspect":"failed","failure_path":"succeeded","success_path":"skipped"}
    expect(page.get_by_text("اكتمل تنفيذ الخطة مع إخفاقات أو دون نجاح كافٍ؛ لا تُعد العقد المتخطاة نجاحًا.", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="تنفيذ دفعة الخطة التالية", exact=True)).to_be_disabled()
    checks.append("branching plan follows explicit failure condition, skips its success branch and never reports the failed plan as passed")
