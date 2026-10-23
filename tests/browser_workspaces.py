"""Identity settings, stable links, graph, and actual linked tool navigation."""
from tests.browser_helpers import wait_for_idle


def run_workspace_checks(page, expect, checks):
    sections = page.evaluate("state.boot.catalog.map(section => ({id:section.id, name:section.name, platforms:section.platforms.map(p=>({id:p.id,name:p.name}))}))")
    workspaces = [(item['id'], item['name']) for item in sections]
    workspaces += [(platform['id'], platform['name']) for section in sections for platform in section['platforms']]
    for identifier, title in workspaces:
        page.evaluate("id => goWorkspace(id)", identifier)
        expect(page.locator('.workspace-identity').get_by_role('heading', name=title, exact=True)).to_be_visible()
        expect(page.locator('.workspace-identity .code')).to_have_text(identifier)
    assert len(workspaces) == 131
    checks.append('all22 section and109 platform workspace identities open with their stable catalog identifiers')

    page.evaluate("goWorkspace('01')")
    expect(page.locator('.workspace-identity').get_by_role('heading',name='الاستخبارات',exact=True)).to_be_visible()
    page.get_by_role('tab',name='خريطة المساحة',exact=True).click()
    expect(page.locator('.workspace-map-node')).to_have_count(3)
    page.locator('.workspace-map-node').first.click()
    expect(page.locator('.workspace-identity .code')).to_have_text('platform.01.01')
    page.get_by_role('tab',name='أدوات المساحة',exact=True).click()
    page.get_by_role('button',name='طريقة التشغيل: استخراج المؤشرات',exact=True).click()
    expect(page.get_by_role('dialog').get_by_role('heading',name='طريقة التشغيل',exact=True)).to_be_visible()
    page.get_by_role('dialog').get_by_role('button',name='إغلاق ×',exact=True).click()
    checks.append('workspace section map opens platform and linked working analyzer guide')

    page.get_by_role('tab',name='إعدادات الهوية',exact=True).click()
    original = {'title':page.get_by_label('عنوان مساحة العمل',exact=True).input_value(),
                'description':page.get_by_label('وصف مساحة العمل',exact=True).input_value(),
                'color':page.get_by_label('لون مساحة العمل',exact=True).input_value(),
                'icon':page.get_by_label('أيقونة مساحة العمل',exact=True).input_value(),
                'landing':page.get_by_label('صفحة افتتاح المساحة',exact=True).input_value()}
    page.get_by_label('عنوان مساحة العمل',exact=True).fill('مساحة استخبارات مخصصة للاختبار')
    page.get_by_label('وصف مساحة العمل',exact=True).fill('إعدادات اصطناعية للتحقق من الحفظ مع ثبات المعرف')
    page.get_by_label('لون مساحة العمل',exact=True).select_option('violet')
    page.get_by_label('أيقونة مساحة العمل',exact=True).select_option('✧')
    page.get_by_label('صفحة افتتاح المساحة',exact=True).select_option('map')
    with page.expect_response(lambda response:response.url.endswith('/api/workspaces/settings')) as saved:
        page.get_by_role('button',name='حفظ هوية مساحة العمل',exact=True).click()
    assert saved.value.status == 200
    updated = saved.value.json()['workspace']
    assert updated['id'] == 'platform.01.01' and updated['title'] == 'مساحة استخبارات مخصصة للاختبار'
    wait_for_idle(page)
    page.reload()
    expect(page.locator('.workspace-identity').get_by_role('heading',name=updated['title'],exact=True)).to_be_visible()
    expect(page.get_by_role('tab',name='خريطة المساحة',exact=True)).to_have_attribute('aria-selected','true')
    expect(page.locator('.workspace-page')).to_have_class('workspace-page stack workspace-color-violet')
    expect(page.locator('.workspace-identity .code')).to_have_text('platform.01.01')
    for width in (320,390):
        page.set_viewport_size({'width':width,'height':844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.set_viewport_size({'width':1440,'height':1000})
    checks.append('workspace owner title description icon color landing persist after reload while stable id remains; 320/390px')

    page.get_by_role('tab',name='إعدادات الهوية',exact=True).click()
    for label,key in [('عنوان مساحة العمل','title'),('وصف مساحة العمل','description')]:
        page.get_by_label(label,exact=True).fill(original[key])
    for label,key in [('لون مساحة العمل','color'),('أيقونة مساحة العمل','icon'),('صفحة افتتاح المساحة','landing')]:
        page.get_by_label(label,exact=True).select_option(original[key])
    page.get_by_role('button',name='حفظ هوية مساحة العمل',exact=True).click()
    wait_for_idle(page)
