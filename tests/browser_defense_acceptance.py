"""Browser acceptance for event dictionaries/quality and replayable rule fixtures."""
import json
from pathlib import Path
from tests.browser_helpers import wait_for_idle


def run_defense_acceptance_checks(page, expect, checks):
    page.get_by_role('link',name='توحيد الأحداث',exact=True).click()
    expect(page.get_by_role('heading',name='قاموس الأحداث وإصدار المخطط',exact=True)).to_be_visible()
    expect(page.get_by_role('cell',name='time',exact=True)).to_be_visible()
    page.get_by_label('صيغة الأحداث',exact=True).select_option('windows-xml')
    page.get_by_role('button',name='استيراد عينة أحداث اصطناعية',exact=True).click()
    wait_for_idle(page)
    with page.expect_response(lambda response:response.url.endswith('/api/events/normalize')) as normalized:
        page.get_by_role('button',name='توحيد الأحداث وحفظ النتيجة',exact=True).click()
    report=normalized.value.json()['report']
    assert report['result']['schema_version']=='1.0.0'
    assert report['result']['quality']['timestamps'][0]['fraction_digits']==7
    assert report['result']['quality']['timestamps'][0]['original'].endswith('.1234567Z')
    assert report['result']['dictionary_sha256']
    wait_for_idle(page)
    expect(page.get_by_role('heading',name='جودة تحويل الأحداث والتوقيت',exact=True)).to_be_visible()
    checks.append('versioned event dictionary and seven-digit original timestamp quality render after real bounded normalization')

    page.get_by_role('link',name='مكتبة الكشف',exact=True).click()
    # Use the existing owner rule when the complete smoke workflow made one.
    rules=page.evaluate("async () => (await api('detection/acceptance?project='+state.project.project.id)).library")
    owners=[item for item in rules if item['origin']=='owner']
    if not owners:
        page.evaluate("async () => await api('detection/save',{project_id:state.project.project.id,rule:{id:'owner-browser-acceptance',title:'قاعدة مرجعية اصطناعية',version:'1.0.0',license:'Private',source:'Synthetic browser fixture',selection:{action:'login',outcome:'failure'}}})")
        page.reload()
        expect(page.get_by_role('heading',name='عينات القواعد وتغطيتها وإعادة اختبارها',exact=True)).to_be_visible()
        rules=page.evaluate("async () => (await api('detection/acceptance?project='+state.project.project.id)).library")
        owners=[item for item in rules if item['origin']=='owner']
    # A fresh acceptance run must identify owner rules without fixtures as gaps.
    with page.expect_response(lambda response:response.url.endswith('/api/detection/acceptance/run'),timeout=60000) as initial:
        page.get_by_role('button',name='إعادة اختبار جميع القواعد وقياس التغطية',exact=True).click()
    initial_report=initial.value.json()['report']
    assert any(item['status'] in ('missing_fixture','stale_fixture') for item in initial_report['rows'] if item['id'] in {owner['id'] for owner in owners})
    assert initial_report['passed'] is False
    wait_for_idle(page,timeout=60)
    expect(page.get_by_text('توجد قواعد تحتاج عينة أو مراجعة',exact=True)).to_be_visible()
    checks.append('rule library acceptance reports owner fixture gaps rather than declaring an untested rule passed')

    # The simple fixture has one positive and one negative event for login/failure.
    target=next((item for item in owners if item['id']=='owner-browser-login'),owners[0])
    page.get_by_text('عينة مرجعية لقاعدة المالك',exact=True).click()
    page.get_by_label('قاعدة العينة المرجعية',exact=True).select_option(target['id'])
    file=page.get_by_label('رفع ملف أحداث للعينة المرجعية',exact=True)
    sample=[{'action':'login','outcome':'failure'},{'action':'login','outcome':'success'}]
    file.set_input_files({'name':'rule-owner-synthetic.json','mimeType':'application/json','buffer':json.dumps(sample).encode()})
    page.get_by_label('فهارس الأحداث المطابقة المتوقعة',exact=True).fill('[0]')
    with page.expect_response(lambda response:response.url.endswith('/api/detection/fixtures/register')) as registered:
        page.get_by_role('button',name='ربط العينة بقاعدة المالك',exact=True).click()
    assert registered.value.status in (200,201),registered.value.text()
    wait_for_idle(page)
    with page.expect_response(lambda response:response.url.endswith('/api/detection/acceptance/run'),timeout=60000) as executed:
        page.get_by_role('button',name='إعادة اختبار جميع القواعد وقياس التغطية',exact=True).click()
    result=executed.value.json()['report']
    row=next(item for item in result['rows'] if item['id']==target['id'])
    assert row['status']=='passed',row
    assert row['metrics']['true_positive']==1 and row['metrics']['false_positive']==0
    wait_for_idle(page,timeout=60)
    with page.expect_download() as downloaded:
        page.get_by_role('button',name='تنزيل تقرير تغطية القواعد JSON',exact=True).click()
    exported=json.loads(Path(downloaded.value.path()).read_text())
    assert exported['rows']==result['rows']
    expect(page.get_by_role('heading',name='نتيجة تغطية واختبار مكتبة القواعد',exact=True)).to_be_visible()
    for width in (320,390):
        page.set_viewport_size({'width':width,'height':844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.set_viewport_size({'width':1440,'height':1000})
    page.reload()
    saved=page.get_by_label('تقرير تغطية قواعد محفوظ',exact=True)
    expect(saved.locator('option')).not_to_have_count(1)
    saved.select_option(index=1)
    page.get_by_role('button',name='عرض تقرير تغطية القواعد المحفوظ',exact=True).click()
    wait_for_idle(page,timeout=60)
    expect(page.get_by_role('heading',name='نتيجة تغطية واختبار مكتبة القواعد',exact=True)).to_be_visible()
    checks.append('owner fixture original file and explicit labels persist, current rule replays with metrics, immutable report exports/reloads; 320/390px')

    # A late response must not become the result for a newly changed selection.
    pending=[]
    pattern='**/api/detection/acceptance/report?*'
    page.route(pattern,lambda route:pending.append(route))
    try:
        with page.expect_request(lambda request:'/api/detection/acceptance/report?' in request.url):
            page.get_by_role('button',name='عرض تقرير تغطية القواعد المحفوظ',exact=True).click()
        assert pending
        saved.select_option('')
        pending[0].fulfill(status=200,content_type='application/json',body=json.dumps({'report':result}))
        wait_for_idle(page,timeout=60)
        expect(page.get_by_role('button',name='تنزيل تقرير تغطية القواعد JSON',exact=True)).to_be_disabled()
        expect(page.get_by_role('heading',name='نتيجة تغطية واختبار مكتبة القواعد',exact=True)).to_have_count(0)
    finally:
        page.unroute(pattern)
    checks.append('delayed library acceptance report cannot render or enable export after the saved report selection changes')
