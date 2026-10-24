"""Real owner flows for signed Wasm packages. Keys and inputs are ephemeral fixtures."""
import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.browser_helpers import wait_for_idle

# Minimal modules export only memory, alloc and analyze, import nothing, and
# write a JSON count derived from the actual input length. V2 uses modulo5.
_MODULES = {
    '1.0.0': 'AGFzbQEAAAABDAJgAX8Bf2ACf38BfgMDAgABBQMBAAIHHAMGbWVtb3J5AgAFYWxsb2MAAAdhbmFseXplAAEKGQIFAEGACAsRAEEQQTAgAUEKcGo6AABCEgsLGAEAQQALEnsibGVuZ3RoX21vZDEwIjowfQ==',
    '2.0.0': 'AGFzbQEAAAABDAJgAX8Bf2ACf38BfgMDAgABBQMBAAIHHAMGbWVtb3J5AgAFYWxsb2MAAAdhbmFseXplAAEKGQIFAEGACAsRAEEQQTAgAUEFcGo6AABCEgsLGAEAQQALEnsibGVuZ3RoX21vZDA1IjowfQ==',
}


def _package(key, version):
    from cyber_platform.store import encode
    public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    module=base64.b64decode(_MODULES[version])
    signed={'schema':'was.plugin-package/1','manifest':{
        'id':'ui.length-counter','version':version,'license':'CC0-1.0','source':'https://example.test/isolated-ui-fixture',
        'permissions':['derived_evidence.write','selected_evidence.read'],'dependencies':[],
        'compatibility':{'python_min':'3.11','python_max':'3.13','platform':'linux'}},
        'module_sha256':hashlib.sha256(module).hexdigest(),
        'fixtures':[{'input_base64':base64.b64encode(b'abcdef').decode(),
                     'expected':{'length_mod10':6} if version=='1.0.0' else {'length_mod05':1}}]}
    value={'signed':signed,'module_base64':_MODULES[version],'public_key':base64.b64encode(public).decode(),
           'signature':base64.b64encode(key.sign(encode(signed).encode())).decode()}
    return encode(value).encode()


def run_plugin_installations_checks(page,expect,checks):
    key=Ed25519PrivateKey.generate()
    public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    public_b64=base64.b64encode(public).decode()
    publisher=hashlib.sha256(public).hexdigest()
    sources=page.evaluate("""async () => {
      const pid=state.project.project.id;
      return [await researchUpload(pid,'synthetic-plugin-input.txt','abcdef'),
              await researchUpload(pid,'synthetic-plugin-other-input.txt','xyz')];
    }""")
    page.get_by_role('link',name='إدارة الإضافات',exact=True).click()
    panel=page.locator('section.plugin-installations')
    expect(panel.get_by_role('heading',name='تثبيت الإضافات الموقعة وتشغيلها',exact=True)).to_be_visible()
    panel.get_by_text('ثقة ناشر الإضافة ومفتاحه العام',exact=True).click()
    panel.get_by_label('المفتاح العام لناشر الإضافة',exact=True).fill(public_b64)
    with page.expect_response(lambda response:response.url.endswith('/api/plugins/trust')) as trusted:
        panel.get_by_role('button',name='اعتماد المفتاح العام لناشر الإضافة',exact=True).click()
    assert trusted.value.status in (200,201),trusted.value.text()
    wait_for_idle(page,20)
    panel.get_by_text('تثبيت حزمة أو إصدار بديل',exact=True).click()

    def install(version):
        panel.get_by_label('رفع حزمة إضافة موقعة',exact=True).set_input_files({
            'name':'synthetic-signed-plugin-'+version+'.json','mimeType':'application/json','buffer':_package(key,version)})
        with page.expect_response(lambda response:response.url.endswith('/api/plugins/install'),timeout=30000) as installed:
            panel.get_by_role('button',name='التحقق من الحزمة واختبارها وتثبيتها',exact=True).click()
        assert installed.value.status in (200,201),installed.value.text()
        wait_for_idle(page,30)
        panel.get_by_label('الإضافة التنفيذية المثبتة',exact=True).select_option('ui.length-counter')
        panel.get_by_label('ملف الإدخال الأصلي للإضافة',exact=True).select_option(sources[0]['id'])

    def transition(label,version=None):
        if version:panel.get_by_label('إصدار الإضافة للتفعيل أو الاستعادة',exact=True).select_option(version)
        with page.expect_response(lambda response:response.url.endswith('/api/plugins/runtime/transition'),timeout=30000) as changed:
            panel.get_by_role('button',name=label,exact=True).click()
        assert changed.value.status in (200,201),changed.value.text()
        wait_for_idle(page,30)

    def execute(expected):
        with page.expect_response(lambda response:response.url.endswith('/api/plugins/runtime/run'),timeout=30000) as ran:
            panel.get_by_role('button',name='تشغيل الإضافة المعزولة على الملف المحدد',exact=True).click()
        assert ran.value.status in (200,201),ran.value.text()
        value=ran.value.json()
        assert value['record']['result']==expected,value
        wait_for_idle(page,30)
        expect(panel.get_by_role('heading',name='نتيجة تشغيل الإضافة المحفوظة',exact=True)).to_be_visible()
        with page.expect_download() as downloaded:
            panel.get_by_role('button',name='تنزيل نتيجة تشغيل الإضافة JSON',exact=True).click()
        assert json.loads(Path(downloaded.value.path()).read_text())['record']['result']==expected
        return value

    install('1.0.0')
    expect(panel.get_by_role('button',name='تشغيل الإضافة المعزولة على الملف المحدد',exact=True)).to_be_disabled()
    transition('تفعيل إصدار الإضافة المختار','1.0.0')
    expect(panel.get_by_role('button',name='تفعيل إصدار الإضافة المختار',exact=True)).to_be_disabled()
    first=execute({'length_mod10':6})
    transition('إيقاف الإضافة التنفيذية')
    expect(panel.get_by_role('button',name='إيقاف الإضافة التنفيذية',exact=True)).to_be_disabled()
    expect(panel.get_by_role('button',name='تشغيل الإضافة المعزولة على الملف المحدد',exact=True)).to_be_disabled()
    transition('تفعيل إصدار الإضافة المختار','1.0.0')
    checks.append('explicit owner public-key trust and signed-package upload run isolated reference fixtures before installation; activation is separate and actual input output is immutable/exportable; disable prevents execution')

    install('2.0.0')
    transition('تفعيل إصدار الإضافة المختار','2.0.0')
    execute({'length_mod05':1})
    transition('استعادة إصدار إضافة سابق','1.0.0')
    first=execute({'length_mod10':6})
    checks.append('installing a real second module preserves version history, replacement executes changed code and explicit rollback restores previous executable behavior')

    pending=[];pattern='**/api/plugins/runtime/run'
    page.route(pattern,lambda route:pending.append(route))
    try:
        with page.expect_request(lambda request:request.url.endswith('/api/plugins/runtime/run')):
            panel.get_by_role('button',name='تشغيل الإضافة المعزولة على الملف المحدد',exact=True).click()
        assert pending
        panel.get_by_label('ملف الإدخال الأصلي للإضافة',exact=True).select_option(sources[1]['id'])
        pending[0].fulfill(status=200,content_type='application/json',body=json.dumps(first))
        wait_for_idle(page,20)
        expect(panel.get_by_role('heading',name='نتيجة تشغيل الإضافة المحفوظة',exact=True)).to_have_count(0)
        expect(panel.get_by_role('button',name='تنزيل نتيجة تشغيل الإضافة JSON',exact=True)).to_be_disabled()
    finally:page.unroute(pattern)
    panel.get_by_label('ملف الإدخال الأصلي للإضافة',exact=True).select_option(sources[0]['id'])
    checks.append('late plugin execution response cannot render or export under a different selected input')

    pattern='**/api/plugins/installations?*'
    page.route(pattern,lambda route:route.fulfill(status=409,content_type='application/json',body=json.dumps({'error':'اختبار رفض مصدر حزمة متغير'})))
    try:
        panel.get_by_role('button',name='تحديث الحزم الموقعة والتحقق',exact=True).click()
        wait_for_idle(page,20)
        expect(panel.get_by_role('button',name='تنزيل سجل الحزم الموقعة JSON',exact=True)).to_be_disabled()
        expect(panel.get_by_role('button',name='تشغيل الإضافة المعزولة على الملف المحدد',exact=True)).to_be_disabled()
    finally:page.unroute(pattern)
    panel.get_by_role('button',name='تحديث الحزم الموقعة والتحقق',exact=True).click()
    wait_for_idle(page,20)
    panel.get_by_label('ناشر الإضافات لسحب الثقة',exact=True).select_option(publisher)
    with page.expect_response(lambda response:response.url.endswith('/api/plugins/trust/revoke')) as revoked:
        panel.get_by_role('button',name='سحب الثقة من ناشر الإضافات',exact=True).click()
    assert revoked.value.status in (200,201),revoked.value.text()
    wait_for_idle(page,20)
    expect(panel.get_by_role('button',name='تشغيل الإضافة المعزولة على الملف المحدد',exact=True)).to_be_disabled()
    expect(panel.get_by_role('button',name='سحب الثقة من ناشر الإضافات',exact=True)).to_be_disabled()
    with page.expect_download() as downloaded:
        panel.get_by_role('button',name='تنزيل سجل الحزم الموقعة JSON',exact=True).click()
    saved=json.loads(Path(downloaded.value.path()).read_text())
    item=next(item for item in saved['plugins'] if item['id']=='ui.length-counter')
    assert len(item['versions'])==2 and item['effective_state']!='active'
    assert any(row['key_id']==publisher and row['state']=='revoked' for row in saved['trust'])
    assert len(saved['runs'])>=3 and all(row['historical'] for row in saved['runs'])
    expect(panel.get_by_text('هذه نتائج محفوظة بتاريخها؛ عرض السجل أو تنزيله لا يعيد تنفيذ الإضافة.',exact=True)).to_be_visible()
    page.reload()
    panel=page.locator('section.plugin-installations')
    expect(panel.get_by_label('الإضافة التنفيذية المثبتة',exact=True).locator('option[value="ui.length-counter"]')).to_have_count(1)
    panel.get_by_label('الإضافة التنفيذية المثبتة',exact=True).select_option('ui.length-counter')
    expect(panel.get_by_role('button',name='تشغيل الإضافة المعزولة على الملف المحدد',exact=True)).to_be_disabled()
    for width in (320,390):
        page.set_viewport_size({'width':width,'height':844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'),width
    page.set_viewport_size({'width':1440,'height':1000})
    checks.append('failed package revalidation invalidates previous current view/export, publisher revocation blocks execution and signed version history survives reload at320/390px')
