import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path
from cyber_platform import requirements
from cyber_platform.store import Problem
import threading
import tests.test_platform as core
from cyber_platform.server import App

ROOT = Path(__file__).resolve().parents[1]


class RequirementsTests(unittest.TestCase):
    def test_all_source_bytes_and_lines_preserved(self):
        original = (ROOT / "docs/Requirements-Source.md").read_bytes()
        self.assertEqual(requirements.source_bytes(), original)
        self.assertEqual(hashlib.sha256(original).hexdigest(), requirements.DATA["source"]["sha256"])
        lines = original.decode().splitlines(keepends=True)
        previous = 0
        for block in requirements.DATA["blocks"]:
            self.assertEqual(block["line_start"], previous + 1)
            self.assertEqual(block["text"], "".join(lines[block["line_start"] - 1:block["line_end"]]))
            previous = block["line_end"]
        self.assertEqual(previous, len(lines))

    def test_generation_reproducible_without_modifying_original(self):
        source = ROOT / "docs/Requirements-Source.md"
        output = ROOT / "cyber_platform/requirements.json"
        before, original = output.read_bytes(), source.read_bytes()
        subprocess.run([sys.executable, "scripts/build_requirements.py", "--check"], cwd=ROOT, check=True, capture_output=True)
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(source.read_bytes(), original)

    def test_every_review_has_real_source_and_evidence_paths(self):
        blocks = {b["id"]: b for b in requirements.DATA["blocks"]}
        ids = set()
        for record in requirements.DATA["requirements"]:
            self.assertNotIn(record["id"], ids)
            ids.add(record["id"])
            self.assertTrue(record["source_ids"])
            for bid in record["source_ids"]:
                self.assertIn(bid, blocks)
            for path in record["evidence_paths"]:
                self.assertTrue((ROOT / path).is_file(), path)
        for prefix, count in [("F", 6), ("E", 5), ("N", 6), ("Q", 5)]:
            self.assertEqual(len([r for r in ids if r.startswith(prefix) and "." not in r]), count)
        self.assertEqual(len([r for r in ids if r.startswith("SECTION.")]), 20)

    def test_search_and_pagination_cover_source_tail_and_all_records(self):
        all_items = []
        for page in range(1, 30):
            result = requirements.view(mode="source", page=page)
            all_items.extend(result["items"])
            if not result["items"]:
                break
        self.assertEqual(all_items, requirements.DATA["blocks"])
        self.assertTrue(requirements.view("0.13", mode="source")["matches"])
        update = requirements.view("F05")["items"][0]
        self.assertEqual(update["status"], "partial")
        self.assertTrue(all(r["status"] == "blocked" for r in requirements.view(status="blocked")["items"]))

    def test_historical_claims_do_not_mark_features_complete(self):
        self.assertTrue(any(b["kind"] == "historical" and "OVA" in b["text"] for b in requirements.DATA["blocks"]))
        records = {r["id"]: r for r in requirements.DATA["requirements"]}
        self.assertEqual(records["N02"]["status"], "superseded")
        self.assertEqual(records["N03"]["status"], "partial")
        self.assertIn("cyber_platform/agents.py", records["N03"]["evidence_paths"])
        self.assertEqual(records["E01"]["status"], "blocked")
        self.assertTrue(any("35GB" in o for o in requirements.DATA["overrides"]))

    def test_invalid_parameters(self):
        for kwargs in [{"query":"x"*201},{"page":0},{"page":True},{"mode":"eval"},{"status":"completed"}]:
            with self.assertRaises(Problem):
                requirements.view(**kwargs)
        with self.assertRaises(Problem):
            requirements.block("missing")


# Reuse only the HTTP fixture methods, not inherited test cases.
class RequirementsHTTPTests(core.StoreCase):
    request = core.HTTPTests.request
    login = core.HTTPTests.login

    def setUp(self):
        super().setUp()
        self.app = App(('127.0.0.1',0), self.store)
        self.thread = threading.Thread(target=self.app.serve_forever,daemon=True)
        self.thread.start()
        self.cookie, self.csrf = '', ''

    def tearDown(self):
        self.app.shutdown(); self.app.server_close(); self.thread.join()
        super().tearDown()

    def test_source_register_and_export_require_auth(self):
        for path in ['/api/requirements','/api/requirements/source','/api/requirements/export','/api/requirements/block?id=source.0001']:
            self.assertEqual(self.request(path)[0],401)
        self.login()
        status,_,body=self.request('/api/requirements?q=F05')
        self.assertEqual(status,200)
        record=json.loads(body)['items'][0]
        self.assertEqual(record['status'],'partial')
        status,_,body=self.request('/api/requirements/block?id='+record['source_ids'][0])
        self.assertEqual(status,200)
        self.assertIn('F05',json.loads(body)['block']['text'])
        status,headers,body=self.request('/api/requirements/source')
        self.assertEqual(status,200)
        self.assertEqual(body,(ROOT/'docs/Requirements-Source.md').read_bytes())
        self.assertEqual(headers['X-Source-SHA256'],hashlib.sha256(body).hexdigest())
        status,_,body=self.request('/api/requirements/export')
        self.assertEqual(status,200)
        exported=json.loads(body)
        self.assertEqual(len(exported['blocks']),411)
        self.assertEqual(len(exported['requirements']),61)
        self.assertTrue(exported['references'])
        self.assertTrue(exported['mentioned_files'])

    def test_invalid_filters_and_unknown_blocks(self):
        self.login()
        for path in ['/api/requirements?page=not-a-number','/api/requirements?mode=bad','/api/requirements?page=0','/api/requirements?status=complete']:
            self.assertEqual(self.request(path)[0],400)
        self.assertEqual(self.request('/api/requirements/block?id=missing')[0],404)

    def test_project_import_exact_deduplicated_and_authenticated(self):
        path, data = '/api/requirements/import', {'project_id':self.pid}
        self.assertEqual(self.request(path,data)[0],401)
        self.login()
        self.assertEqual(self.request(path,{**data,'path':'/etc/passwd'})[0],400)
        status,_,body=self.request(path,data)
        self.assertEqual(status,200)
        first=json.loads(body)
        self.assertFalse(first['reused'])
        self.assertEqual(self.store.read_evidence(self.pid,first['evidence']['id']),requirements.source_bytes())
        status,_,body=self.request(path,data)
        self.assertEqual(status,200)
        second=json.loads(body)
        self.assertTrue(second['reused'])
        self.assertEqual(first['evidence']['id'],second['evidence']['id'])
        self.assertEqual(self.request(path,data,{'X-CSRF-Token':'bad'})[0],403)
        self.assertEqual(self.request(path,{'project_id':'missing'})[0],404)
