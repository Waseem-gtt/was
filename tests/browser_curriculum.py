"""Private learning path progress, prerequisites and immutable attempt acceptance."""
import json
from pathlib import Path
from tests.browser_helpers import wait_for_idle


def run_curriculum_checks(page, expect, checks):
    page.get_by_role("link", name="مسارات التعلم", exact=True).click()
    paths = page.get_by_label("مسار التعلم", exact=True)
    expect(paths.locator("option")).to_have_count(5)
    paths.select_option("foundations")
    lessons = page.get_by_label("درس المسار", exact=True)
    expect(lessons.locator("option")).to_have_count(4)
    lessons.select_option("lesson.01")
    expect(page.get_by_text("اجتز تقييم الدرس السابق في هذا المسار أولًا.", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="تقييم درس المسار وحفظ المحاولة", exact=True)).to_be_disabled()
    lessons.select_option("lesson.04")
    expect(page.get_by_role("button", name="تقييم درس المسار وحفظ المحاولة", exact=True)).to_be_enabled()
    # This uses the public fixed curriculum's answer for a synthetic fixture only.
    fixture = page.evaluate("""async () => {
      const data=await api('curriculum');
      const item=data.lessons.find(item=>item.id==='lesson.04');
      const right=item.choices.indexOf(item.defense);
      return {right,wrong:(right+1)%item.choices.length};
    }""")
    page.locator('input[name="curriculum-answer"]').nth(fixture["wrong"]).check()
    with page.expect_response(lambda response: response.url.endswith("/api/curriculum/attempt")) as attempt:
        page.get_by_role("button", name="تقييم درس المسار وحفظ المحاولة", exact=True).click()
    assert attempt.value.status == 200, attempt.value.text()
    result = attempt.value.json()
    assert result["result"]["correct"] is False and result["evidence"]["id"]
    expect(page.get_by_text("إجابة المسار تحتاج مراجعة", exact=True)).to_be_visible()
    wait_for_idle(page)
    page.locator('input[name="curriculum-answer"]').nth(fixture["right"]).check()
    with page.expect_response(lambda response: response.url.endswith("/api/curriculum/attempt")) as attempt:
        page.get_by_role("button", name="تقييم درس المسار وحفظ المحاولة", exact=True).click()
    assert attempt.value.status == 200, attempt.value.text()
    result = attempt.value.json()
    assert result["result"]["correct"] is True
    expect(page.get_by_text("إجابة المسار صحيحة", exact=True)).to_be_visible()
    wait_for_idle(page)
    lessons.select_option("lesson.01")
    expect(page.get_by_role("button", name="تقييم درس المسار وحفظ المحاولة", exact=True)).to_be_enabled()
    checks.append("private learning paths enforce prerequisites and preserve incorrect and correct synthetic assessments as evidence")

    page.reload()
    paths = page.get_by_label("مسار التعلم", exact=True)
    expect(paths.locator("option")).to_have_count(5)
    paths.select_option("foundations")
    lessons = page.get_by_label("درس المسار", exact=True)
    expect(lessons.locator("option")).to_have_count(4)
    lessons.select_option("lesson.01")
    expect(page.get_by_role("button", name="تقييم درس المسار وحفظ المحاولة", exact=True)).to_be_enabled()
    with page.expect_download() as downloaded:
        page.get_by_role("button", name="تنزيل تقدم التعلم JSON", exact=True).click()
    progress = json.loads(Path(downloaded.value.path()).read_text())
    foundation = next(path for path in progress["paths"] if path["id"] == "foundations")
    first = next(lesson for lesson in foundation["lessons"] if lesson["lesson_id"] == "lesson.04")
    assert first["status"] == "passed" and first["attempts"] == 2 and first["correct_attempts"] == 1
    assert first["latest_evidence_id"] == result["evidence"]["id"]
    page.get_by_role("button", name="إعادة التحقق من تقدم التعلم", exact=True).click()
    wait_for_idle(page)
    checks.append("learning progress survives reload and exports per-project verified assessment counts without certification claims")
