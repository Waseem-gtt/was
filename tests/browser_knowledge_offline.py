"""An owner imports a real JSON file, searches offline, and retains last good data."""
import json
from pathlib import Path
from tests.browser_helpers import wait_for_idle
from tests.test_knowledge_files import fixture


def run_offline_knowledge_checks(page,expect,checks):
    page.get_by_role('link',name='المعرفة العالمية',exact=True).click()
    file=page.get_by_label('ملف فهرس الثغرات دون إنترنت',exact=True)
    file.set_input_files({'name':'owner-catalog.json','mimeType':'application/json','buffer':json.dumps(fixture()).encode()})
    with page.expect_response(lambda r:r.url.endswith('/api/knowledge/offline/import')) as imported:
        page.get_by_role('button',name='استيراد فهرس الثغرات والتحقق منه',exact=True).click()
    assert imported.value.status==200,imported.value.text()
    receipt=imported.value.json()['receipt']
    assert receipt['network'] is False and receipt['count']==2
    wait_for_idle(page)
    expect(page.get_by_text('جاهز للبحث دون إنترنت',exact=True)).to_be_visible()
    page.get_by_label('بحث فهرس الثغرات المستورد',exact=True).fill('Router')
    page.get_by_role('button',name='بحث في الفهرس المستورد',exact=True).click()
    expect(page.get_by_role('cell',name='CVE-2026-10001',exact=True)).to_be_visible()
    wait_for_idle(page)
    with page.expect_download() as downloaded:
        page.get_by_role('button',name='تنزيل إثبات استيراد الفهرس',exact=True).click()
    proof=json.loads(Path(downloaded.value.path()).read_text())
    assert proof['input_sha256']==receipt['input_sha256'] and proof['source_authenticity']=='not_verified'
    wait_for_idle(page)
    page.reload()
    expect(page.get_by_text('جاهز للبحث دون إنترنت',exact=True)).to_be_visible()
    page.get_by_label('ملف فهرس الثغرات دون إنترنت',exact=True).set_input_files({'name':'invalid-catalog.json','mimeType':'application/json','buffer':b'{}'})
    with page.expect_response(lambda r:r.url.endswith('/api/knowledge/offline/import')) as rejected:
        page.get_by_role('button',name='استيراد فهرس الثغرات والتحقق منه',exact=True).click()
    assert rejected.value.status==400
    wait_for_idle(page)
    page.get_by_label('بحث فهرس الثغرات المستورد',exact=True).fill('Router')
    page.get_by_role('button',name='بحث في الفهرس المستورد',exact=True).click()
    expect(page.get_by_role('cell',name='CVE-2026-10001',exact=True)).to_be_visible()
    wait_for_idle(page)
    for width in (320,390):
        page.set_viewport_size({'width':width,'height':844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.set_viewport_size({'width':1440,'height':1000})
    checks.append('offline catalog original import, bounded search, receipt export, reload and invalid replacement preserving last good catalog; 320/390px')
