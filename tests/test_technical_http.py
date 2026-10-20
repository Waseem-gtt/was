"""Technical analyzers integrate with private evidence, plans and restoration."""
import json
from pathlib import Path
import threading
from unittest.mock import patch
import tests.test_platform as core
from cyber_platform import backup, engine, event_adapters, event_ingest, plans, tools
from cyber_platform.server import App
from cyber_platform.store import Store

TECHNICAL = {'pcap':'was.pcap-analysis/1', 'certificate':'was.certificate-analysis/1',
             'supply-chain':'was.supply-chain/1', 'supply-chain-diff':'was.supply-chain-diff/1'}


class TechnicalHTTPTests(core.StoreCase):
    request = core.HTTPTests.request
    login = core.HTTPTests.login

    def setUp(self):
        super().setUp()
        self.app = App(('127.0.0.1', 0), self.store)
        self.thread = threading.Thread(target=self.app.serve_forever, daemon=True)
        self.thread.start()
        self.cookie, self.csrf = '', ''

    def tearDown(self):
        self.app.shutdown()
        self.app.server_close()
        self.thread.join()
        super().tearDown()

    def post(self, route, body):
        code, _, raw = self.request('/api/' + route, body)
        self.assertEqual(code, 200, (route, raw))
        return json.loads(raw)

    def source(self, tool):
        sample = next(t['sample'] for t in tools.describe() if t['id'] == tool)
        return self.evidence(sample.encode(), 'synthetic-' + tool + '.json')

    def run_source(self, tool, source):
        return self.post('run', {'project_id':self.pid, 'steps':[{'tool':tool, 'evidence_id':source['id']}]})

    def test_catalog_and_local_asset_have_registered_formats_without_new_execution_authority(self):
        code, headers, raw = self.request('/technical.js')
        self.assertEqual(code, 200)
        self.assertIn('javascript', headers['Content-Type'])
        self.assertTrue(raw)
        self.assertEqual(self.request('/api/bootstrap')[0], 401)
        self.login()
        catalog = json.loads(self.request('/api/bootstrap')[2])['tools']
        self.assertEqual(len(catalog), 25)
        selected = [t for t in catalog if t['id'] in TECHNICAL]
        self.assertEqual(len(selected), 4)
        self.assertTrue(all(t['network'] is False and t['section'] in {'06','09','11'} for t in selected))

    def test_all_four_tools_preserve_original_and_derived_provenance_over_http(self):
        self.login()
        for tool, schema in TECHNICAL.items():
            with self.subTest(tool=tool):
                source = self.source(tool)
                job = self.run_source(tool, source)
                self.assertEqual(job['status'], 'succeeded', job)
                result = job['results'][0]
                output = result['output']
                self.assertEqual(output['result']['schema'], schema)
                self.assertEqual(output['input_evidence'], source['id'])
                self.assertEqual(output['input_sha256'], source['sha256'])
                self.assertEqual(output['acceptance'], 'not_evaluated')
                record = self.store.evidence(self.pid, result['evidence_id'])
                self.assertEqual(record['parent_id'], source['id'])
                self.assertEqual(json.loads(self.store.read_evidence(self.pid, record['id'])), output)
                self.assertEqual(self.store.evidence(self.pid, source['id']), source)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_malformed_inputs_are_recorded_failures_without_derived_success(self):
        self.login()
        for tool in TECHNICAL:
            with self.subTest(tool=tool):
                source = self.evidence(b'not an accepted format')
                job = self.run_source(tool, source)
                self.assertEqual(job['status'], 'failed')
                self.assertNotIn('evidence_id', job['results'][0])
                self.assertNotIn('output', job['results'][0])
                self.assertEqual(self.store.read_evidence(self.pid, source['id']), b'not an accepted format')

    def test_bounded_dag_runs_all_four_technical_tools_with_saved_results(self):
        self.login()
        nodes = [{'id':'step' + str(i), 'tool':tool, 'input':{'evidence_id':self.source(tool)['id']}}
                 for i, tool in enumerate(TECHNICAL)]
        value = self.post('plans/start', {'project_id':self.pid, 'plan':{'schema':'was.plan/1', 'name':'Technical fixture DAG', 'nodes':nodes}})
        first = self.post('plans/advance', {'project_id':self.pid, 'run_id':value['id']})
        self.assertLessEqual(first['counts']['completed'], 2)
        value = first
        for _ in range(10):
            if value['status'] in ('completed','failed'):
                break
            value = self.post('plans/advance', {'project_id':self.pid, 'run_id':value['id']})
        self.assertEqual(value['status'], 'completed', value)
        self.assertTrue(value['passed'])
        self.assertEqual(plans.status(self.store, self.pid, value['id']), value)

    def test_windows_xml_http_keeps_original_and_unknown_semantics_with_100ns_time(self):
        self.login()
        adapter = next(a for a in event_adapters.catalog() if a['id'] == 'windows-xml')
        source = self.evidence(adapter['example_content'].encode(), 'synthetic-windows.xml')
        value = self.post('events/normalize', {'project_id':self.pid, 'evidence_id':source['id'], 'adapter':adapter['id']})
        self.assertEqual(value['report']['input_sha256'], source['sha256'])
        self.assertEqual(event_ingest.verify(self.store, self.pid, value['evidence']['id']), value['report'])
        self.assertEqual(value['report']['result']['events'][0]['outcome'], 'unknown')
        self.assertIn('.1234567', value['report']['result']['events'][0]['time'])

    def test_shared_execution_slot_and_project_scope_apply_to_new_tools(self):
        self.login()
        source = self.source('certificate')
        body = {'project_id':self.pid, 'steps':[{'tool':'certificate', 'evidence_id':source['id']}]}
        with self.app.execution_lock:
            self.assertEqual(self.request('/api/run', body)[0], 409)
        self.assertEqual(self.request('/api/run', body, {'X-CSRF-Token':'bad'})[0], 403)
        other = self.store.create_project('Other')['id']
        self.assertEqual(self.request('/api/run', {**body, 'project_id':other})[0], 404)
        self.assertEqual(self.store.project_data(other)['jobs'], [])

    def test_encrypted_restore_keeps_four_technical_results_and_xml_derivative(self):
        self.login()
        results = []
        for tool in TECHNICAL:
            result = self.run_source(tool, self.source(tool))['results'][0]
            results.append(result)
        adapter = next(a for a in event_adapters.catalog() if a['id'] == 'windows-xml')
        source = self.evidence(adapter['example_content'].encode())
        normalized = self.post('events/normalize', {'project_id':self.pid, 'evidence_id':source['id'], 'adapter':adapter['id']})
        password = 'Temporary-technical-backup-123'
        data = backup.export(self.store, password)
        target = Path(self.temp.name) / 'restored-technical'
        backup.restore(data, password, target)
        restored = Store(target)
        try:
            for result in results:
                self.assertEqual(json.loads(restored.read_evidence(self.pid, result['evidence_id'])), result['output'])
            self.assertEqual(event_ingest.verify(restored, self.pid, normalized['evidence']['id']), normalized['report'])
            self.assertTrue(restored.verify_audit()['valid'])
        finally:
            restored.close()


class TechnicalExecutionProvenanceTests(core.StoreCase):
    def test_engine_change_during_worker_execution_cannot_publish_success(self):
        source = self.evidence(b'192.0.2.1')
        with patch.object(engine, 'fingerprint', side_effect=['a' * 64, 'b' * 64]), patch.object(engine.worker, 'analyze', return_value={'ipv4':['192.0.2.1']}):
            result = engine.run(self.store, self.pid, [{'tool':'ioc', 'evidence_id':source['id']}])
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('evidence_id', result['results'][0])
        self.assertEqual(len(self.store.project_data(self.pid)['evidence']), 1)
