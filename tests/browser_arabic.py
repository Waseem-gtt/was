"""Arabic display labels must not rewrite source records or exported results."""
import json
from pathlib import Path
from tests.browser_helpers import wait_for_idle


def run_arabic_checks(page, expect, checks):
    page.get_by_role('link', name='توحيد الأحداث', exact=True).click()
    select = page.get_by_label('دليل الأحداث الأصلي', exact=True)
    originals = page.evaluate("state.project.evidence.filter(item => item.kind === 'original').map(item => item.id)")
    assert originals, 'This check needs an original input in the synthetic project'
    original = select.locator('option[value="' + originals[0] + '"]')
    expect(original).to_contain_text('ملف أصلي')
    assert ' · original' not in original.text_content()
    select.select_option(originals[0])
    assert select.input_value() == originals[0]
    page.get_by_role('link', name='التحليل التقني', exact=True).click()
    page.get_by_label('القدرة التقنية', exact=True).select_option('sarif')
    saved_id = page.evaluate("state.project.jobs.flatMap(job => job.results || []).find(item => item.tool === 'sarif' && item.status === 'succeeded').evidence_id")
    page.get_by_label('نتيجة تقنية محفوظة', exact=True).select_option(saved_id)
    page.get_by_role('button', name='عرض النتيجة التقنية المحفوظة', exact=True).click()
    wait_for_idle(page)
    expect(page.get_by_role('cell', name='تحذير', exact=True)).to_be_visible()
    expect(page.get_by_role('cell', name='warning', exact=True)).to_have_count(0)
    with page.expect_download() as downloaded:
        page.get_by_role('button', name='تنزيل نتيجة التحليل التقني JSON', exact=True).click()
    report = json.loads(Path(downloaded.value.path()).read_text())
    assert report['result']['findings'][0]['level'] == 'warning'
    assert report['tool'] == 'sarif'
    expect(page.get_by_text('واس / مساحة العمل', exact=True)).to_be_visible()
    checks.append('Arabic evidence choices and SARIF severity retain source identifiers and unchanged machine JSON export')
