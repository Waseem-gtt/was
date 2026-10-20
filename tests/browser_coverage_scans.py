"""A full historical coverage scan verifies beyond the three-report preview."""
import json
from pathlib import Path
from tests.browser_helpers import wait_for_idle


def run_coverage_scan_checks(page, expect, checks):
    """Run after ordinary coverage checks; only fresh synthetic project data."""
    wait_for_idle(page)
    fixture = page.evaluate("""async () => {
      const projectId = state.project.project.id;
      const catalog = await api('detection/library?project=' + projectId);
      const sample = catalog.fixtures[0].input;
      const content = JSON.stringify(sample);
      const bytes = new TextEncoder().encode(content);
      let text = '';
      for (const byte of bytes) text += String.fromCharCode(byte);
      const original = await api('upload', {project_id:projectId, name:'synthetic-full-coverage.json', base64:btoa(text)});
      const preview = await api('coverage?project=' + projectId);
      const asset = preview.assets[0] || await api('coverage/asset', {project_id:projectId, name:'Synthetic full coverage asset', kind:'service'});
      const reports = [];
      for (let i = 0; i < 4; i++) {
        const tested = await api('detection/test', {project_id:projectId, evidence_id:original.id, rule_ids:['was-login-failure']});
        if (!tested.report.passed) throw Error('Synthetic test did not pass its reference labels');
        reports.push(tested.evidence.id);
        const linked = await api('coverage/assessment', {project_id:projectId, asset_id:asset.id, threat:'Synthetic full-scan threat ' + i, control:'Synthetic full-scan control ' + i, evidence_id:tested.evidence.id});
        if (linked.status !== 'supported') throw Error('Synthetic coverage link not supported');
      }
      return {project_id:projectId, reports};
    }""")
    assert len(set(fixture['reports'])) == 4
    page.get_by_role("link", name="التغطية الدفاعية", exact=True).click()
    expect(page.get_by_role('heading', name='ملخص التغطية المحفوظة', exact=True)).to_be_visible()
    expect(page.get_by_role('heading', name='فحص التغطية الشامل على دفعات', exact=True)).to_be_visible()
    with page.expect_response(lambda response: response.url.endswith('/api/coverage/scans/start')) as started:
        page.get_by_role('button', name='بدء فحص تغطية شامل', exact=True).click()
    assert started.value.status == 200, started.value.text()
    scan = started.value.json()
    scan_id = scan['id']
    assert scan['total'] == 4 and scan['complete'] is False
    wait_for_idle(page)
    with page.expect_response(lambda response: response.url.endswith('/api/coverage/scans/advance')) as advanced:
        page.get_by_role('button', name='تشغيل دفعة التغطية الشاملة التالية', exact=True).click()
    assert advanced.value.status == 200, advanced.value.text()
    scan = advanced.value.json()
    assert 0 < scan['counts']['processed'] <= 3
    assert scan['complete'] is False
    wait_for_idle(page)
    page.reload()
    expect(page.get_by_role('heading', name='ملخص التغطية المحفوظة', exact=True)).to_be_visible()
    saved = page.get_by_label('فحص تغطية شامل محفوظ', exact=True)
    expect(saved.locator('option[value="' + scan_id + '"]')).to_have_count(1)
    saved.select_option(scan_id)
    page.get_by_role('button', name='عرض فحص التغطية الشامل المحفوظ', exact=True).click()
    expect(page.get_by_role('button', name='تشغيل دفعة التغطية الشاملة التالية', exact=True)).to_be_enabled()
    wait_for_idle(page)
    for _ in range(60):
        with page.expect_response(lambda response: response.url.endswith('/api/coverage/scans/advance')) as advanced:
            page.get_by_role('button', name='تشغيل دفعة التغطية الشاملة التالية', exact=True).click()
        assert advanced.value.status == 200, advanced.value.text()
        scan = advanced.value.json()
        wait_for_idle(page)
        if scan['status'] not in ('pending', 'running'):
            break
        expect(page.get_by_role('button', name='تشغيل دفعة التغطية الشاملة التالية', exact=True)).to_be_enabled()
    assert scan['status'] == 'completed' and scan['complete'] is True, scan
    assert scan['counts'] == {'processed':4, 'total':4, 'remaining':0}
    assert scan['proof_counts']['remaining'] == 0
    assert scan['all_supported'] is True
    assert scan['current_validity'] == 'snapshot_only'
    assert len(scan['results']) == 4
    assert all(item['status'] == 'supported' for item in scan['results'])
    assert {item['evidence_id'] for item in scan['results']} == set(fixture['reports'])
    expect(page.get_by_text('اكتمل التحقق من اللقطة المحفوظة', exact=True)).to_be_visible()
    expect(page.get_by_role('button', name='تشغيل دفعة التغطية الشاملة التالية', exact=True)).to_be_disabled()
    with page.expect_download() as downloaded:
        page.get_by_role('button', name='تنزيل تقرير فحص التغطية الشامل JSON', exact=True).click()
    exported = json.loads(Path(downloaded.value.path()).read_text())
    assert exported['id'] == scan_id and exported['complete'] is True
    assert exported['current_validity'] == 'snapshot_only'
    assert len(exported['results']) == 4
    checks.append('full historical coverage scan verifies four distinct reports over persisted batches, resumes after reload, finalizes proofs and exports snapshot-only results')
