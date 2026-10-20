"""Owner plugin metadata reviews never install or execute uploaded code."""
import json
from pathlib import Path
from tests.browser_helpers import wait_for_idle


def run_plugins_checks(page, expect, checks):
    page.get_by_role("link", name="إدارة الإضافات", exact=True).click()
    expect(page.get_by_role("heading", name="مراجعة الإضافات دون تشغيلها", exact=True)).to_be_visible()
    page.get_by_role("button", name="إنشاء بيان إضافة تجريبي", exact=True).click()
    expect(page.get_by_label("ملف بيان الإضافة", exact=True)).not_to_have_value("")
    wait_for_idle(page)
    with page.expect_response(lambda response: response.url.endswith("/api/plugins/register")) as registered:
        page.get_by_role("button", name="تسجيل بيان الإضافة", exact=True).click()
    assert registered.value.status == 200, registered.value.text()
    item = registered.value.json()["item"]
    assert item["id"] == "owner.example" and item["state"] == "pending"
    expect(page.get_by_role("heading", name="owner.example", exact=True)).to_be_visible()
    wait_for_idle(page)
    reason = page.get_by_label("سبب قرار الإضافة", exact=True)
    decisions = [
        ("approve", "اعتماد بيانات الإضافة", "راجعت بيانات العينة الاصطناعية فقط", "approved"),
        ("disable", "تعطيل اعتماد الإضافة", "إيقاف إداري تجريبي مع حفظ أصل القرار", "disabled"),
        ("revoke", "سحب اعتماد الإضافة", "سحب الاعتماد في اختبار اصطناعي", "revoked"),
    ]
    for decision, label, explanation, expected_state in decisions:
        reason.fill(explanation)
        with page.expect_response(lambda response: response.url.endswith("/api/plugins/transition")) as changed:
            page.get_by_role("button", name=label, exact=True).click()
        assert changed.value.status == 200, changed.value.text()
        assert changed.value.json()["item"]["state"] == expected_state
        wait_for_idle(page)
        expect(reason).to_have_value("")
    expect(page.get_by_role("button", name="اعتماد بيانات الإضافة", exact=True)).to_be_disabled()
    with page.expect_download() as exported:
        page.get_by_role("button", name="تنزيل سجل الإضافات JSON", exact=True).click()
    snapshot = json.loads(Path(exported.value.path()).read_text())
    assert snapshot["schema"] == "was.plugin-registry/1"
    saved = next(row for row in snapshot["items"] if row["id"] == "owner.example")
    assert saved["state"] == "revoked" and len(saved["history"]) == 4
    assert [row["action"] for row in saved["history"]][-3:] == ["approve", "disable", "revoke"]
    assert saved["source_sha256"] and snapshot["graph"]["nodes"]
    page.reload()
    expect(page.get_by_label("الإضافة المسجلة", exact=True).locator("option")).to_have_count(2)
    page.get_by_label("الإضافة المسجلة", exact=True).select_option("owner.example")
    expect(page.get_by_role("heading", name="owner.example", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="اعتماد بيانات الإضافة", exact=True)).to_be_disabled()
    checks.append("offline plugin metadata registration preserves original hashes and immutable approve/disable/revoke reasons, exports its dependency inventory and survives reload without code activation")

    source = page.evaluate("""async () => {
      const pid = state.project.project.id;
      const manifest = {id:'owner.missing-dependency',version:'1.0.0',license:'MIT',
        source:'https://example.test/missing',permissions:['selected_evidence.read'],
        dependencies:[{id:'owner.not-registered',version:'1.0.0'}]};
      return researchUpload(pid,'synthetic-missing-plugin.json',JSON.stringify(manifest));
    }""")
    page.get_by_role("button", name="تحديث سجل الإضافات", exact=True).click()
    expect(page.get_by_label("ملف بيان الإضافة", exact=True).locator('option[value="' + source["id"] + '"]')).to_have_count(1)
    wait_for_idle(page)
    page.get_by_label("ملف بيان الإضافة", exact=True).select_option(source["id"])
    with page.expect_response(lambda response: response.url.endswith("/api/plugins/register")) as registered:
        page.get_by_role("button", name="تسجيل بيان الإضافة", exact=True).click()
    assert registered.value.status == 200, registered.value.text()
    assert registered.value.json()["item"]["issues"]
    wait_for_idle(page)
    expect(page.get_by_role("heading", name="owner.missing-dependency", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="اعتماد بيانات الإضافة", exact=True)).to_be_disabled()
    with page.expect_download() as exported:
        page.get_by_role("button", name="تنزيل سجل الإضافات JSON", exact=True).click()
    graph = json.loads(Path(exported.value.path()).read_text())["graph"]
    assert any(row["source"] == "owner.missing-dependency" and row["target"] == "owner.not-registered" for row in graph["edges"])
    assert any(row["plugin_id"] == "owner.missing-dependency" for row in graph["issues"])
    checks.append("unresolved plugin dependencies remain visible in the exported graph and prevent metadata approval in the UI")
