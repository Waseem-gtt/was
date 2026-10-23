"""Owner UI acceptance for original-backed F06 entities and conflicting claims."""
import json
from pathlib import Path
from tests.browser_helpers import wait_for_idle


def run_knowledge_graph_checks(page, expect, checks):
    page.get_by_role('link',name='خريطة الأدلة',exact=True).click()
    expect(page.get_by_role('heading',name='خريطة الكيانات والمصادر والثقة',exact=True)).to_be_visible()
    panel=page.locator('section.knowledge-graph')
    source=page.evaluate("state.project.evidence.find(item=>item.kind==='original').id")
    reference=page.evaluate("(state.project.evidence.find(item=>item.kind!=='original') || state.project.evidence[0]).id")
    panel.get_by_text('إضافة كيان ومصدره وثقته',exact=True).click()
    created=[]
    for kind,name in [('asset','أصل مرجعي للخريطة'),('software','برنامج مرجعي للخريطة'),('vulnerability','ثغرة مرجعية للخريطة'),('event','حدث مرجعي للخريطة'),('evidence','دليل مرجعي للخريطة'),('experiment','تجربة مرجعية للخريطة')]:
        panel.get_by_label('نوع كيان الخريطة',exact=True).select_option(kind)
        panel.get_by_label('اسم كيان الخريطة',exact=True).fill(name)
        panel.get_by_label('وصف كيان الخريطة',exact=True).fill('ادعاء اصطناعي موثق لاختبار الخريطة')
        panel.get_by_label('المصدر الأصلي لكيان الخريطة',exact=True).select_option(source)
        panel.get_by_label('الدليل أو نتيجة التجربة المرتبطة بكيان الخريطة',exact=True).select_option(reference if kind in ('evidence','experiment') else '')
        panel.get_by_label('ثقة كيان الخريطة',exact=True).fill('75')
        panel.get_by_label('وقت ملاحظة كيان الخريطة',exact=True).fill('2026-10-23T12:00:00+03:00')
        panel.get_by_label('بداية صلاحية كيان الخريطة',exact=True).fill('2099-01-01T00:00:00Z')
        panel.get_by_label('نهاية صلاحية كيان الخريطة',exact=True).fill('2100-01-01T00:00:00Z')
        with page.expect_response(lambda response:response.url.endswith('/api/graph/entities')) as saved:
            panel.get_by_role('button',name='حفظ كيان موثق',exact=True).click()
        assert saved.value.status in (200,201),saved.value.text()
        entity=saved.value.json()['entity']
        assert entity['type']==kind and entity['confidence']==75
        assert entity['source_evidence']==source
        assert entity['reference_evidence']==(reference if kind in ('evidence','experiment') else None)
        created.append(entity)
        wait_for_idle(page)
        expect(panel.get_by_role('button',name=name,exact=True)).to_be_visible()
    checks.append('all six F06 entity types save through the owner UI with original sources, confidence, observation and validity; evidence/experiment bind retained files')

    # Keyboard and table inspect the same immutable source-backed record.
    node=panel.get_by_role('button',name='تفاصيل الكيان: أصل مرجعي للخريطة',exact=True)
    node.focus();node.press('Enter')
    expect(panel.get_by_role('heading',name='تفاصيل الكيان ومصدره',exact=True)).to_be_visible()
    expect(panel.get_by_text('الثقة المعلنة: 75 / 100 · لم تبدأ الصلاحية',exact=True)).to_be_visible()
    panel.get_by_label('بحث كيانات خريطة الأدلة',exact=True).fill('برنامج مرجعي')
    expect(panel.get_by_role('button',name='أصل مرجعي للخريطة',exact=True)).to_have_count(0)
    expect(panel.get_by_role('button',name='برنامج مرجعي للخريطة',exact=True)).to_be_visible()
    panel.get_by_label('بحث كيانات خريطة الأدلة',exact=True).fill('')
    panel.get_by_text('إضافة علاقة ومعناها وتعارضها',exact=True).click()
    panel.get_by_label('كيان بداية العلاقة',exact=True).select_option(created[0]['id'])
    panel.get_by_label('كيان نهاية العلاقة',exact=True).select_option(created[1]['id'])
    panel.get_by_label('شرح علاقة الخريطة',exact=True).fill('ربط مرجعي من المصدر نفسه مع حفظ الادعاء المقابل')
    panel.get_by_label('المصدر الأصلي لعلاقة الخريطة',exact=True).select_option(source)
    panel.get_by_label('ثقة علاقة الخريطة',exact=True).fill('60')
    panel.get_by_label('وقت ملاحظة علاقة الخريطة',exact=True).fill('2026-10-23T13:00:00+03:00')
    panel.get_by_label('نوع علاقة الخريطة',exact=True).select_option('supports')
    with page.expect_response(lambda response:response.url.endswith('/api/graph/relations')) as first:
        panel.get_by_role('button',name='حفظ علاقة موثقة وتعارضها',exact=True).click()
    assert first.value.status in (200,201),first.value.text()
    supporting=first.value.json()['relation']
    wait_for_idle(page)
    panel.get_by_label('نوع علاقة الخريطة',exact=True).select_option('contradicts')
    panel.get_by_label('العلاقة المتعارضة مع الادعاء الجديد',exact=True).select_option(supporting['id'])
    with page.expect_response(lambda response:response.url.endswith('/api/graph/relations')) as second:
        panel.get_by_role('button',name='حفظ علاقة موثقة وتعارضها',exact=True).click()
    assert second.value.status in (200,201),second.value.text()
    wait_for_idle(page)
    expect(panel.get_by_role('cell',name='تعارض معلن',exact=True).first).to_be_visible()
    edge=panel.get_by_role('button',name='تفاصيل العلاقة: يتعارض مع',exact=True)
    edge.focus();edge.press('Enter')
    expect(panel.get_by_role('heading',name='معنى العلاقة ودليلها',exact=True)).to_be_visible()
    expect(panel.get_by_text('تعارض معلن مع العلاقة: '+supporting['id'],exact=True)).to_be_visible()
    with page.expect_download() as downloaded:
        panel.get_by_role('button',name='تنزيل خريطة الكيانات ومصادرها JSON',exact=True).click()
    exported=json.loads(Path(downloaded.value.path()).read_text())
    assert len(exported['entities'])>=6 and len(exported['relations'])>=2
    assert exported['conflicts']
    for width in (320,390):
        page.set_viewport_size({'width':width,'height':844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.set_viewport_size({'width':1440,'height':1000})
    page.reload()
    panel=page.locator('section.knowledge-graph')
    expect(panel.get_by_role('button',name='أصل مرجعي للخريطة',exact=True)).to_be_visible()
    expect(panel.get_by_role('cell',name='تعارض معلن',exact=True).first).to_be_visible()
    checks.append('F06 graph and equivalent tables inspect node/edge provenance by keyboard, preserve opposed claims, export/reload and fit 320/390px')

    # Changing the requested validity time invalidates a pending response.
    pending=[]
    pattern='**/api/graph?*'
    page.route(pattern,lambda route:pending.append(route))
    try:
        with page.expect_request(lambda request:'/api/graph?' in request.url):
            panel.get_by_role('button',name='تحديث خريطة الكيانات والتحقق',exact=True).click()
        assert pending
        panel.get_by_label('وقت تقييم صلاحية خريطة الأدلة',exact=True).fill('2099-06-01T00:00:00Z')
        pending[0].fulfill(status=200,content_type='application/json',body=json.dumps(exported))
        wait_for_idle(page)
        expect(panel.get_by_role('heading',name='جدول الكيانات المكافئ',exact=True)).to_have_count(0)
    finally:
        page.unroute(pattern)
    with page.expect_response(lambda response:'/api/graph?' in response.url) as updated:
        panel.get_by_role('button',name='تحديث خريطة الكيانات والتحقق',exact=True).click()
    assert updated.value.status==200
    wait_for_idle(page)
    expect(panel.get_by_role('cell',name='صالح في وقت العرض',exact=True).first).to_be_visible()
    checks.append('late graph result cannot render for a changed validity time; explicit refresh evaluates requested time')

    page.route(pattern,lambda route:route.fulfill(status=409,content_type='application/json',body=json.dumps({'error':'مصدر الخريطة تغير — رفض مرجعي اصطناعي'})))
    try:
        panel.get_by_role('button',name='تحديث خريطة الكيانات والتحقق',exact=True).click()
        wait_for_idle(page)
        expect(panel.get_by_role('heading',name='جدول الكيانات المكافئ',exact=True)).to_have_count(0)
        expect(panel.get_by_role('button',name='تنزيل خريطة الكيانات ومصادرها JSON',exact=True)).to_be_disabled()
    finally:
        page.unroute(pattern)
    panel.get_by_role('button',name='تحديث خريطة الكيانات والتحقق',exact=True).click()
    wait_for_idle(page)
    expect(panel.get_by_role('heading',name='جدول الكيانات المكافئ',exact=True)).to_be_visible()
    checks.append('failed source revalidation clears previous current graph and disables export until successful verification')
