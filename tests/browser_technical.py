"""Actual offline technical worker samples, privacy and UI request-context checks."""
import json
import time
from pathlib import Path
from tests.browser_helpers import wait_for_idle


def run_technical_checks(page, expect, checks):
    page.get_by_role("link", name="التحليل التقني", exact=True).click()
    expect(page.get_by_role("heading", name="التحليل التقني للملفات", exact=True)).to_be_visible()
    capability = page.get_by_label("القدرة التقنية", exact=True)
    expect(capability.locator("option")).to_have_count(15)
    records = {}
    for tool, schema in [('pcap', 'was.pcap-analysis/1'),
                         ('certificate', 'was.certificate-analysis/1'),
                         ('supply-chain', 'was.supply-chain/1'),
                         ('supply-chain-diff', 'was.supply-chain-diff/1'),
                         ('har', 'was.har-analysis/1'),
                         ('har-diff', 'was.har-diff/1'),
                         ('email', 'was.email-analysis/1'),
                         ('kubernetes', 'was.kubernetes-review/1'),
                         ('kubernetes-diff', 'was.kubernetes-diff/1'),
                         ('systemd', 'was.systemd-review/1'),
                         ('sarif', 'was.sarif-analysis/1'),
                         ('sarif-diff', 'was.sarif-diff/1'),
                         ('archive', 'was.archive-review/1'),
                         ('ssh-keys', 'was.ssh-key-review/1'),
                         ('dns', 'was.dns-analysis/1')]:
        capability.select_option(tool)
        with page.expect_response(lambda response: response.url.endswith('/api/upload')) as uploaded:
            page.get_by_role("button", name="إنشاء عينة تقنية اصطناعية", exact=True).click()
        assert uploaded.value.status == 201, uploaded.value.text()
        original = uploaded.value.json()
        expect(page.get_by_label("ملف التحليل التقني", exact=True)).to_have_value(original['id'])
        wait_for_idle(page)
        with page.expect_response(lambda response: response.url.endswith('/api/run')) as analyzed:
            page.get_by_role("button", name="تشغيل التحليل التقني وحفظ النتيجة", exact=True).click()
        assert analyzed.value.status == 200, analyzed.value.text()
        job = analyzed.value.json()
        assert job['status'] == 'succeeded', job
        result = job['results'][0]
        assert result['tool'] == tool and result['output']['result']['schema'] == schema
        assert result['output']['input_evidence'] == original['id']
        assert result['output']['input_sha256'] == original['sha256']
        expect(page.get_by_text('اكتمل تحليل الملف', exact=True)).to_be_visible()
        wait_for_idle(page)
        with page.expect_download() as exported:
            page.get_by_role("button", name="تنزيل نتيجة التحليل التقني JSON", exact=True).click()
        report = json.loads(Path(exported.value.path()).read_text())
        assert report == result['output']
        if tool == 'pcap':
            assert report['result']['packet_count'] >= 1
            assert report['result']['live_capture'] is False
            assert report['result']['payload_exported'] is False
        elif tool == 'certificate':
            assert report['result']['certificate_count'] >= 1
            assert report['result']['trust'] == 'not_evaluated'
        elif tool == 'supply-chain':
            assert report['result']['component_count'] >= 1
        elif tool == 'supply-chain-diff':
            assert report['result']['complete'] is True
            assert report['result']['normalized_inventory_equal'] is False
            assert report['result']['changed_components']
        elif tool == 'har':
            assert report['result']['entry_count'] >= 1
            assert report['result']['content_exported'] is False
        elif tool == 'har-diff':
            assert report['result']['complete'] is True
            assert report['result']['normalized_metadata_equal'] is False
        elif tool == 'email':
            assert report['result']['part_count'] >= 1
            assert report['result']['content_exported'] is False
        elif tool == 'kubernetes':
            assert report['result']['resource_count'] >= 1
            assert report['result']['applied'] is False
        elif tool == 'kubernetes-diff':
            assert report['result']['complete'] is True
            assert report['result']['normalized_review_equal'] is False
        elif tool == 'systemd':
            assert report['result']['applied'] is False
            assert isinstance(report['result']['summary'], dict)
        elif tool == 'sarif':
            assert report['result']['finding_count'] >= 1
            assert report['result']['snippets_exported'] is False
        elif tool == 'sarif-diff':
            assert report['result']['complete'] is True
            assert report['result']['normalized_findings_equal'] is False
        elif tool == 'archive':
            assert report['result']['member_count'] >= 1
            assert report['result']['extracted'] is False
            assert report['result']['crc_verified'] is False
        elif tool == 'ssh-keys':
            assert report['result']['key_count'] >= 1
            assert report['result']['authenticated'] is False
        elif tool == 'dns':
            assert report['result']['question_count'] >= 1
            assert report['result']['network'] is False
            assert report['result']['dnssec_verified'] is False
        previous_viewport = page.viewport_size
        for width in (390, 320):
            page.set_viewport_size({'width':width,'height':844})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), (tool,width)
        page.set_viewport_size(previous_viewport)
        records[tool] = result
        checks.append('technical ' + tool + ' sample executes in a bounded worker and exports immutable result/source provenance')

    page.reload()
    capability = page.get_by_label("القدرة التقنية", exact=True)
    capability.select_option('supply-chain')
    saved = page.get_by_label('نتيجة تقنية محفوظة', exact=True)
    saved.select_option(records['supply-chain']['evidence_id'])
    page.get_by_role('button', name='عرض النتيجة التقنية المحفوظة', exact=True).click()
    expect(page.get_by_text('نتيجة تاريخية محفوظة', exact=True)).to_be_visible()
    wait_for_idle(page)
    with page.expect_download() as exported:
        page.get_by_role('button', name='تنزيل نتيجة التحليل التقني JSON', exact=True).click()
    assert json.loads(Path(exported.value.path()).read_text()) == records['supply-chain']['output']
    checks.append('technical results survive reload and reread original/result evidence hashes before historical display')

    capability.select_option('pcap')
    page.get_by_label('رفع ملف للتحليل التقني', exact=True).set_input_files({
        'name':'invalid-synthetic.pcap', 'mimeType':'application/octet-stream',
        'buffer':b'not a packet capture',
    })
    wait_for_idle(page)
    with page.expect_response(lambda response: response.url.endswith('/api/run')) as rejected:
        page.get_by_role('button', name='تشغيل التحليل التقني وحفظ النتيجة', exact=True).click()
    assert rejected.value.status == 200, rejected.value.text()
    assert rejected.value.json()['status'] == 'failed'
    expect(page.get_by_role('heading', name='تعذر تحليل الملف', exact=True)).to_be_visible()
    expect(page.get_by_role('button', name='تنزيل نتيجة التحليل التقني JSON', exact=True)).to_be_disabled()
    wait_for_idle(page)
    checks.append('malformed binary capture is retained as original evidence while the UI refuses a successful report')

    capability.select_option('har')
    canary = 'PRIVATE_HAR_BROWSER_CANARY_014'
    har = page.evaluate("""() => JSON.parse(state.boot.tools.find(tool => tool.id === 'har').sample)""")
    entry = har['log']['entries'][0]
    entry['request']['url'] = 'https://example.test/' + canary + '?token=' + canary
    entry['request']['headers'] = [{'name':'Authorization','value':canary}]
    entry['request']['cookies'] = [{'name':canary,'value':canary}]
    entry['request']['postData'] = {'mimeType':'text/plain','text':canary}
    entry['response']['content'] = {'size':len(canary),'mimeType':'text/plain','text':canary}
    page.get_by_label('رفع ملف للتحليل التقني', exact=True).set_input_files({
        'name':'private-synthetic-session.har','mimeType':'application/json',
        'buffer':json.dumps(har).encode(),
    })
    wait_for_idle(page)
    with page.expect_response(lambda response: response.url.endswith('/api/run')) as private_result:
        page.get_by_role('button', name='تشغيل التحليل التقني وحفظ النتيجة', exact=True).click()
    private_job = private_result.value.json()
    assert private_job['status'] == 'succeeded', private_job
    assert canary not in json.dumps(private_job['results'][0]['output']['result'])
    expect(page.get_by_text('اكتمل تحليل الملف', exact=True)).to_be_visible()
    wait_for_idle(page)
    assert canary not in page.locator('#app').inner_text()
    entry['response']['status'] = canary
    page.get_by_label('رفع ملف للتحليل التقني', exact=True).set_input_files({
        'name':'invalid-synthetic-session.har','mimeType':'application/json',
        'buffer':json.dumps(har).encode(),
    })
    wait_for_idle(page)
    with page.expect_response(lambda response: response.url.endswith('/api/run')) as invalid_har:
        page.get_by_role('button', name='تشغيل التحليل التقني وحفظ النتيجة', exact=True).click()
    assert invalid_har.value.json()['status'] == 'failed'
    expect(page.get_by_role('heading', name='تعذر تحليل الملف', exact=True)).to_be_visible()
    expect(page.get_by_role('button', name='تنزيل نتيجة التحليل التقني JSON', exact=True)).to_be_disabled()
    wait_for_idle(page)
    assert canary not in page.locator('#app').inner_text()
    checks.append('HAR report excludes private URL/header/cookie/body canaries and invalid HAR cannot export stale success')

    capability.select_option('har')
    page.get_by_label('ملف التحليل التقني', exact=True).select_option(records['har']['output']['input_evidence'])
    page.evaluate("""() => {
      window.technicalOriginalApi = api;
      window.technicalRelease = null;
      api = async (path, ...args) => {
        const result = await window.technicalOriginalApi(path, ...args);
        if (path === 'run') await new Promise(resolve => { window.technicalRelease = resolve; });
        return result;
      };
    }""")
    try:
        page.get_by_role('button', name='تشغيل التحليل التقني وحفظ النتيجة', exact=True).click()
        deadline = time.monotonic() + 10
        while not page.evaluate("() => typeof window.technicalRelease === 'function'"):
            if time.monotonic() >= deadline:
                raise AssertionError('technical API response did not arrive')
            page.wait_for_timeout(20)
        capability.select_option('dns')
        page.evaluate('() => window.technicalRelease()')
        wait_for_idle(page)
        expect(page.get_by_role('button', name='تنزيل نتيجة التحليل التقني JSON', exact=True)).to_be_disabled()
        expect(page.get_by_text('اكتمل تحليل الملف', exact=True)).to_have_count(0)
        assert capability.input_value() == 'dns'
    finally:
        page.evaluate('() => { api = window.technicalOriginalApi; delete window.technicalOriginalApi; delete window.technicalRelease; }')
    checks.append('late worker response stays in history without rendering or exporting under a changed technical selection')

    page.get_by_role('link', name='توحيد الأحداث', exact=True).click()
    page.get_by_label('صيغة الأحداث', exact=True).select_option('windows-xml')
    page.get_by_role('button', name='استيراد عينة أحداث اصطناعية', exact=True).click()
    expect(page.get_by_label('دليل الأحداث الأصلي', exact=True)).not_to_have_value('')
    wait_for_idle(page)
    page.get_by_role('button', name='توحيد الأحداث وحفظ النتيجة', exact=True).click()
    expect(page.get_by_text('أحداث موحدة:', exact=False)).to_be_visible()
    wait_for_idle(page)
    with page.expect_download() as downloaded:
        page.get_by_role('button', name='تنزيل تقرير توحيد الأحداث JSON', exact=True).click()
    normalized = json.loads(Path(downloaded.value.path()).read_text())
    assert normalized['result']['adapter'] == 'windows-xml'
    assert normalized['result']['events'][0]['outcome'] == 'unknown'
    assert '.1234567' in normalized['result']['events'][0]['time']
    assert normalized['input_sha256'] and normalized['adapter_sha256']
    checks.append('Windows XML normalization preserves 100ns source timestamps and hashes without inventing security outcomes')
