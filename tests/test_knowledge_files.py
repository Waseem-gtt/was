"""Offline KEV import is immutable, project-bound, and uses a bounded worker."""
import copy
import json
from pathlib import Path
from unittest.mock import patch
from cyber_platform import backup, knowledge_files, worker
from cyber_platform.store import Problem, Store
from tests.test_platform import StoreCase
import tests.test_platform as core
from cyber_platform.server import App
import threading


def fixture():
    return {'catalogVersion':'synthetic-1','dateReleased':'2026-10-23T00:00:00Z','count':2,'vulnerabilities':[
        {'cveID':'CVE-2026-10001','vendorProject':'Example','product':'Router','vulnerabilityName':'Synthetic flaw','requiredAction':'Apply vendor update','dueDate':'2026-11-01'},
        {'cveID':'CVE-2026-10002','vendorProject':'Other','product':'Web','vulnerabilityName':'Other synthetic flaw','cwes':['CWE-79']} ]}


def raw(value=None):
    return json.dumps(fixture() if value is None else value).encode()


class KnowledgeFileTests(StoreCase):
    def imported(self):
        evidence = self.evidence(raw(), 'kev.json')
        return knowledge_files.import_file(self.store,self.pid,evidence['id'])

    def test_real_worker_import_search_provenance_and_original(self):
        with patch('cyber_platform.knowledge.download', side_effect=AssertionError('network must not run')):
            imported = self.imported()
            self.assertFalse(imported['reused'])
            self.assertEqual(imported['receipt']['source_authenticity'],'not_verified')
            self.assertFalse(imported['receipt']['network'])
            result = knowledge_files.search(self.store,self.pid,'router')
        self.assertEqual(result['total_matches'],1)
        self.assertEqual(result['items'][0]['cveID'],'CVE-2026-10001')
        self.assertEqual(self.store.read_evidence(self.pid,imported['receipt']['input_evidence']), raw())
        self.assertEqual(knowledge_files.status(self.store,self.pid)['current']['count'],2)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_reimport_same_source_reuses_receipt(self):
        first=self.imported()
        second=knowledge_files.import_file(self.store,self.pid,first['receipt']['input_evidence'])
        self.assertTrue(second['reused'])
        self.assertEqual(first['evidence']['id'],second['evidence']['id'])
        self.assertEqual(knowledge_files.status(self.store,self.pid)['imports'],1)

    def test_bad_import_preserves_last_good_index(self):
        before=self.imported()
        bad=self.evidence(b'{"count":true}', 'bad.json')
        with self.assertRaises(Problem): knowledge_files.import_file(self.store,self.pid,bad['id'])
        self.assertEqual(knowledge_files.status(self.store,self.pid)['receipt_id'],before['evidence']['id'])
        self.assertEqual(knowledge_files.search(self.store,self.pid,'router')['total_matches'],1)

    def test_cross_project_source_rejected(self):
        source=self.evidence(raw())
        other=self.store.create_project('other')
        with self.assertRaises(Problem): knowledge_files.import_file(self.store,other['id'],source['id'])
        self.assertIsNone(knowledge_files.status(self.store,other['id'])['current'])

    def test_tampered_source_blocks_status_and_search(self):
        item=self.imported(); path=self.store.blobs/item['receipt']['input_evidence'];path.chmod(0o600);path.write_bytes(b'changed')
        for function,args in ((knowledge_files.status,()),(knowledge_files.search,('',))):
            with self.assertRaises(Problem): function(self.store,self.pid,*args)

    def test_uploaded_receipt_cannot_become_current(self):
        item=self.imported(); forged=self.evidence(self.store.read_evidence(self.pid,item['evidence']['id']))
        with self.store.db:
            self.store.db.execute('UPDATE settings SET value=? WHERE key=?',(json.dumps({'catalogs':[forged['id']]}),knowledge_files.PREFIX+self.pid))
        with self.assertRaises(Problem):knowledge_files.status(self.store,self.pid)

    def test_audit_failure_rolls_back_receipt_index_and_relation(self):
        source=self.evidence(raw());count=len(list(self.store.blobs.iterdir())); audit=self.store.audit
        def fail(action,*args):
            if action=='knowledge-file.created':raise RuntimeError('synthetic failure')
            return audit(action,*args)
        with patch.object(self.store,'audit',side_effect=fail):
            with self.assertRaises(RuntimeError):knowledge_files.import_file(self.store,self.pid,source['id'])
        self.assertEqual(len(list(self.store.blobs.iterdir())),count)
        self.assertIsNone(knowledge_files.status(self.store,self.pid)['current'])
        self.assertFalse(self.store.rows('SELECT * FROM relations'))

    def test_parser_change_rejects_current_until_reimport(self):
        item=self.imported()
        with patch.object(knowledge_files,'fingerprint',return_value='f'*64):
            with self.assertRaises(Problem):knowledge_files.status(self.store,self.pid)
        self.assertEqual(knowledge_files.status(self.store,self.pid)['receipt_id'],item['evidence']['id'])

    def test_oversize_and_wrong_evidence_kind_rejected(self):
        for data,kind in ((b'x'*(knowledge_files.MAX_BYTES+1),'original'),(raw(),'result')):
            evidence=self.store.add_evidence(self.pid,'source',data,kind)
            with self.assertRaises(Problem):knowledge_files.import_file(self.store,self.pid,evidence['id'])

    def test_worker_failure_does_not_change_index(self):
        before=self.imported(); source=self.evidence(raw())
        with patch.object(worker,'analyze',side_effect=ValueError('timeout')):
            with self.assertRaises(Problem):knowledge_files.import_file(self.store,self.pid,source['id'])
        self.assertEqual(knowledge_files.status(self.store,self.pid)['receipt_id'],before['evidence']['id'])

    def test_encrypted_restore_retains_search_and_receipt(self):
        item=self.imported(); data=backup.export(self.store,'test-backup-password-123')
        dest=Path(self.temp.name)/'restored';backup.restore(data,'test-backup-password-123',dest);restored=Store(dest)
        try:
            self.assertEqual(knowledge_files.status(restored,self.pid)['receipt_id'],item['evidence']['id'])
            self.assertEqual(knowledge_files.search(restored,self.pid,'Router')['total_matches'],1)
        finally:restored.close()

    def test_invalid_queries_and_empty_project(self):
        self.assertEqual(knowledge_files.search(self.store,self.pid,'')['items'],[])
        for query in (None,True,'a'*121):
            with self.assertRaises(Problem):knowledge_files.search(self.store,self.pid,query)

    def test_parser_rejects_ambiguous_or_malformed_documents(self):
        cases=[b'[]',b'{"count":0,"count":0}',b'{"x":NaN}']
        for field,value in [('count',True),('count',3),('dateReleased','2026-10-23'),('catalogVersion','')]:
            data=fixture();data[field]=value;cases.append(raw(data))
        for field,value in [('cveID','bad'),('vendorProject',{}),('dueDate','2026-02-30'),('cwes',['bad'])]:
            data=fixture();data['vulnerabilities'][0][field]=value;cases.append(raw(data))
        data=fixture();data['vulnerabilities'][1]['cveID']=data['vulnerabilities'][0]['cveID'];cases.append(raw(data))
        for data in cases:
            with self.subTest(data=data[:50]):
                with self.assertRaises(ValueError):knowledge_files.parse(data)

    def test_unpaired_surrogates_are_rejected_before_receipt_or_http_encoding(self):
        for field in ('catalogVersion', 'vendorProject', 'product', 'vulnerabilityName', 'notes'):
            data=fixture()
            if field=='catalogVersion':data[field]='\ud800'
            else:data['vulnerabilities'][0][field]='\ud800'
            with self.subTest(field=field):
                with self.assertRaises(ValueError):knowledge_files.parse(raw(data))

    def test_parser_change_during_worker_cannot_publish_receipt(self):
        source=self.evidence(raw())
        before=knowledge_files.fingerprint()
        with patch.object(knowledge_files,'fingerprint',side_effect=[before,'f'*64]):
            with self.assertRaises(Problem):knowledge_files.import_file(self.store,self.pid,source['id'])
        self.assertIsNone(knowledge_files.status(self.store,self.pid)['current'])
        self.assertFalse(self.store.rows("SELECT * FROM evidence WHERE kind='knowledge-file'"))

    def test_original_change_during_worker_cannot_publish_receipt(self):
        source=self.evidence(raw())
        def changed_input(*args,**kwargs):
            value=knowledge_files.parse(raw())
            path=self.store.blobs/source['id'];path.chmod(0o600);path.write_bytes(b'changed')
            return value
        with patch.object(worker,'analyze',side_effect=changed_input):
            with self.assertRaises(Problem):knowledge_files.import_file(self.store,self.pid,source['id'])
        self.assertFalse(self.store.rows("SELECT * FROM evidence WHERE kind='knowledge-file'"))
        self.assertIsNone(knowledge_files.status(self.store,self.pid)['current'])

    def test_created_receipt_without_creation_proof_is_not_current(self):
        item=self.imported()
        source=item['receipt']['input_evidence']
        forged=self.store.add_evidence(self.pid,'copied-receipt.json',
            self.store.read_evidence(self.pid,item['evidence']['id']),'knowledge-file',source)
        with self.store.db:
            self.store.db.execute('UPDATE settings SET value=? WHERE key=?',
                (json.dumps({'catalogs':[forged['id']]}),knowledge_files.PREFIX+self.pid))
        with self.assertRaisesRegex(Problem,'إثبات إنشاء'):
            knowledge_files.status(self.store,self.pid)

    def test_search_caps_results_and_reports_total(self):
        data=fixture();data['vulnerabilities']=[{**data['vulnerabilities'][0],'cveID':f'CVE-2026-{10000+i}'} for i in range(60)];data['count']=60
        source=self.evidence(raw(data));knowledge_files.import_file(self.store,self.pid,source['id'])
        result=knowledge_files.search(self.store,self.pid,'Router')
        self.assertEqual(result['total_matches'],60);self.assertEqual(len(result['items']),50)


class KnowledgeFileHTTPTests(StoreCase):
    request=core.HTTPTests.request
    login=core.HTTPTests.login
    def setUp(self):
        super().setUp();self.app=App(('127.0.0.1',0),self.store);self.thread=threading.Thread(target=self.app.serve_forever,daemon=True);self.thread.start();self.cookie,self.csrf='',''
    def tearDown(self):
        self.app.shutdown();self.app.server_close();self.thread.join();super().tearDown()
    def test_auth_csrf_and_import_then_search(self):
        self.assertEqual(self.request('/api/knowledge/offline?project='+self.pid)[0],401)
        self.assertEqual(self.request('/api/knowledge/offline/search?project='+self.pid)[0],401)
        self.login();source=self.evidence(raw())
        self.assertEqual(self.request('/api/knowledge/offline/import',{'project_id':self.pid,'evidence_id':source['id'],'url':'https://invalid.test'})[0],400)
        self.assertEqual(self.request('/api/knowledge/offline/import',{'project_id':self.pid,'evidence_id':source['id']},{'X-CSRF-Token':'bad'})[0],403)
        status,_,body=self.request('/api/knowledge/offline/import',{'project_id':self.pid,'evidence_id':source['id']})
        self.assertEqual(status,200);self.assertEqual(json.loads(body)['receipt']['count'],2)
        status,_,body=self.request('/api/knowledge/offline/search?project='+self.pid+'&q=router')
        self.assertEqual(status,200);self.assertEqual(json.loads(body)['total_matches'],1)
    def test_search_and_import_respect_execution_slot(self):
        self.login();source=self.evidence(raw());self.app.execution_lock.acquire()
        try:
            self.assertEqual(self.request('/api/knowledge/offline/search?project='+self.pid)[0],409)
            self.assertEqual(self.request('/api/knowledge/offline/import',{'project_id':self.pid,'evidence_id':source['id']})[0],409)
        finally:self.app.execution_lock.release()
    def test_consecutive_searches_release_slot_before_reply(self):
        self.login();source=self.evidence(raw());knowledge_files.import_file(self.store,self.pid,source['id'])
        for _ in range(5):self.assertEqual(self.request('/api/knowledge/offline/search?project='+self.pid+'&q=router')[0],200)
