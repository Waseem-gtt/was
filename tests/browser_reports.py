"""Project report acceptance: private metadata, offline exports and reference checks."""
import json
from pathlib import Path
from tests.browser_helpers import wait_for_idle


def run_report_checks(page,expect,checks):
    source=page.evaluate('''async () => {
      const pid=state.project.project.id;
      const item=await researchUpload(pid,'private-report-source.txt','SYNTHETIC_SOURCE_CONTENT_MUST_NOT_BE_EMBEDDED');
      state.project=await api('project?id='+pid);
      return item;
    }''')
    page.get_by_role('link',name='تقارير المشروع',exact=True).click()
    page.get_by_label('عنوان تقرير المشروع',exact=True).fill('تقرير مشروع اصطناعي متحقق')
    page.locator('input[name="report-evidence"][value="'+source['id']+'"]').check()
    expect(page.locator('input[name="report-plan"]').first).to_be_visible()
    page.locator('input[name="report-plan"]').first.check()
    scans=page.get_by_label('لقطة تغطية التقرير',exact=True)
    expect(scans.locator('option')).to_have_count(2)
    scan_id=scans.locator('option').nth(1).get_attribute('value');scans.select_option(scan_id)
    with page.expect_response(lambda r:r.url.endswith('/api/case-reports/build')) as built:
        page.get_by_role('button',name='إنشاء تقرير المشروع وحفظه',exact=True).click()
    data=built.value.json();assert built.value.status==200,data
    report_id=data['evidence']['id'];report=data['report']
    assert report['evidence'][0]['id']==source['id'] and report['plans'] and report['coverage']
    assert 'SYNTHETIC_SOURCE_CONTENT_MUST_NOT_BE_EMBEDDED' not in json.dumps(report)
    wait_for_idle(page)
    expect(page.get_by_role('heading',name='تقرير مشروع اصطناعي متحقق',exact=True)).to_be_visible()
    with page.expect_download() as exported:
        page.get_by_role('button',name='تنزيل تقرير المشروع JSON',exact=True).click()
    assert json.loads(Path(exported.value.path()).read_text())==report
    with page.expect_download() as exported:
        page.get_by_role('button',name='تنزيل تقرير المشروع HTML',exact=True).click()
    html=Path(exported.value.path()).read_text();assert '<script' not in html.lower() and 'Content-Security-Policy' in html
    assert 'SYNTHETIC_SOURCE_CONTENT_MUST_NOT_BE_EMBEDDED' not in html
    wait_for_idle(page)
    page.get_by_role('button',name='إعادة فحص مراجع التقرير',exact=True).click()
    expect(page.get_by_text('مراجع التقرير مطابقة عند الفحص',exact=True)).to_be_visible();wait_for_idle(page)
    page.reload()
    saved=page.get_by_label('تقرير مشروع محفوظ',exact=True);expect(saved.locator('option')).to_have_count(2)
    saved.select_option(report_id);page.get_by_role('button',name='عرض تقرير المشروع المحفوظ',exact=True).click()
    expect(page.get_by_role('heading',name='تقرير مشروع اصطناعي متحقق',exact=True)).to_be_visible();wait_for_idle(page)
    checks.append('private project report preserves plan and coverage snapshots, excludes raw source content, verifies references, exports JSON and script-free HTML and survives reload')
