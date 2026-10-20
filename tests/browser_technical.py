"""Actual worker analysis of PCAP, X.509 and SBOM samples through the UI."""
import json
from pathlib import Path
from tests.browser_helpers import wait_for_idle


def run_technical_checks(page, expect, checks):
    page.get_by_role("link", name="التحليل التقني", exact=True).click()
    expect(page.get_by_role("heading", name="التحليل التقني للملفات", exact=True)).to_be_visible()
    capability = page.get_by_label("القدرة التقنية", exact=True)
    expect(capability.locator("option")).to_have_count(4)
    records = {}
    for tool, schema in [('pcap', 'was.pcap-analysis/1'),
                         ('certificate', 'was.certificate-analysis/1'),
                         ('supply-chain', 'was.supply-chain/1'),
                         ('supply-chain-diff', 'was.supply-chain-diff/1')]:
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
        else:
            assert report['result']['complete'] is True
            assert report['result']['normalized_inventory_equal'] is False
            assert report['result']['changed_components']
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
