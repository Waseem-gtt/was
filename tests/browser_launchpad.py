"""Opening map -> platform -> guide -> own-file upload -> bounded analysis."""
from tests.browser_helpers import wait_for_idle


def run_launchpad_checks(page, expect, checks):
    page.get_by_role('link', name='خريطة المنظومة', exact=True).click()
    expect(page.locator('.launch-node')).to_have_count(22)
    expect(page.locator('.launch-lines path')).to_have_count(22)
    page.get_by_label('بحث خريطة المنظومة', exact=True).fill('الاستخبارات')
    expect(page.locator('.launch-node')).to_have_count(1)
    expect(page.locator('.launch-lines path')).to_have_count(1)
    page.locator('.launch-node').focus()
    page.keyboard.press('Enter')
    page.get_by_role('button', name='فتح منصة: استخبارات التهديدات', exact=True).click()
    expect(page.get_by_text('هذه منصة ضمن نطاق المشروع؛ لم تُربط بها أداة تشغيل بعد.', exact=True)).to_be_visible()
    expect(page.locator('.launch-detail').get_by_role('button', name='طريقة التشغيل:', exact=False)).to_have_count(0)
    page.get_by_role('button', name='→ منصات الاستخبارات', exact=True).click()
    page.get_by_role('button', name='فتح منصة: المصادر وOSINT', exact=True).click()
    guide = page.locator('.launch-detail').get_by_role('button', name='طريقة التشغيل:', exact=False)
    guide.click()
    dialog = page.get_by_role('dialog')
    expect(dialog.get_by_role('heading', name='طريقة التشغيل', exact=True)).to_be_visible()
    dialog.locator('input[type=file]').set_input_files({'name':'launchpad-owner-file.txt','mimeType':'text/plain','buffer':b'192.0.2.151'})
    with page.expect_response(lambda response: response.url.endswith('/api/upload') and response.request.method == 'POST') as uploaded:
        dialog.get_by_role('button', name='رفع ملفي لهذه الأداة', exact=True).click()
    assert uploaded.value.status == 201
    wait_for_idle(page)
    evidence = uploaded.value.json()
    with page.expect_response(lambda response: response.url.endswith('/api/run') and response.request.method == 'POST') as executed:
        dialog.get_by_role('button', name='تشغيل التحليل', exact=True).click()
    result = executed.value.json()
    assert result['status'] == 'succeeded', result
    assert result['results'][0]['output']['input_evidence'] == evidence['id']
    assert result['results'][0]['output']['result']['ipv4'] == ['192.0.2.151']
    wait_for_idle(page)
    expect(dialog.get_by_text('نجحت', exact=True)).to_be_visible()
    dialog.get_by_role('button', name='إغلاق ×', exact=True).click()
    checks.append('opening map keyboard/search and unavailable platform; guide uploads original file and executes linked analyzer with provenance')
    for width in (320, 390):
        page.set_viewport_size({'width':width,'height':844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.set_viewport_size({'width':1440,'height':1000})
    checks.append('populated opening map and selected platform fit 320 and 390px')
