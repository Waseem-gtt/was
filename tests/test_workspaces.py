"""Acceptance of stable section/platform workspace identities and owner settings."""
import json
import threading
from pathlib import Path
from unittest.mock import patch
from cyber_platform import backup, tools, workspaces
from cyber_platform.server import App
from cyber_platform.store import Problem, Store, encode
from tests.test_platform import StoreCase
import tests.test_platform as core


def preferences(store, identifier='01', **changes):
    current = workspaces.describe(store, identifier)['workspace']
    body = {key:current[key] for key in ('id','revision','title','description','icon','color','landing')}
    body.update(changes)
    return body


class WorkspaceTests(StoreCase):
    def test_all_131_catalog_workspaces_have_complete_stable_identity(self):
        identifiers = []
        real_tools = {item['id'] for item in tools.describe()}
        for section in workspaces.CATALOG:
            section_view = workspaces.describe(self.store, section['id'])
            current = section_view['workspace']
            identifiers.append(current['id'])
            self.assertEqual(current['id'], section['id'])
            self.assertEqual(current['title'], section['name'])
            self.assertIsNone(current['parent_id'])
            self.assertEqual(current['type'], 'section')
            self.assertEqual({child['id'] for child in current['children']}, {p['id'] for p in section['platforms']})
            self.assertEqual({item['id'] for item in current['tools']}, {tid for p in section['platforms'] for tid in p['tool_ids']} & real_tools)
            for platform in section['platforms']:
                result = workspaces.describe(self.store, platform['id'])
                child = result['workspace']; identifiers.append(child['id'])
                self.assertEqual(child['id'], platform['id'])
                self.assertEqual(child['title'], platform['name'])
                self.assertEqual(child['parent_id'], section['id'])
                self.assertEqual(child['type'], 'platform')
                self.assertEqual({item['id'] for item in child['tools']}, set(platform['tool_ids']) & real_tools)
                self.assertFalse(child['children'])
                for view in (section_view, result):
                    workspace = view['workspace']
                    self.assertTrue(workspace['description'].strip())
                    self.assertIn(workspace['icon'], view['icons'])
                    self.assertIn(workspace['color'], view['colors'])
                    self.assertIn(workspace['landing'], view['landings'])
                    self.assertEqual(workspace['revision'], 0)
                    self.assertIsInstance(workspace['references'], list)
                    self.assertIsInstance(workspace['topics'], list)
        self.assertEqual(len(identifiers), 131)
        self.assertEqual(len(set(identifiers)), 131)

    def test_owner_can_customize_every_registered_workspace(self):
        identifiers = [identifier for section in workspaces.CATALOG for identifier in (section['id'], *(p['id'] for p in section['platforms']))]
        bindings = {identifier:[tool['id'] for tool in workspaces.describe(self.store,identifier)['workspace']['tools']] for identifier in identifiers}
        for index,identifier in enumerate(identifiers):
            body=preferences(self.store,identifier,title='مساحة '+identifier,description='إعدادات المالك لمساحة '+identifier,
                             color=workspaces.COLORS[index % len(workspaces.COLORS)],
                             icon=workspaces.ICONS[index % len(workspaces.ICONS)],
                             landing=workspaces.LANDINGS[index % len(workspaces.LANDINGS)])
            saved=workspaces.save(self.store,body)['workspace']
            self.assertEqual(saved['id'],identifier)
            self.assertEqual(saved['revision'],1)
        for identifier in identifiers:
            current=workspaces.describe(self.store,identifier)['workspace']
            self.assertEqual(current['title'],'مساحة '+identifier)
            self.assertEqual([tool['id'] for tool in current['tools']],bindings[identifier])
        self.assertFalse(self.store.rows('SELECT * FROM evidence'))
        self.assertFalse(self.store.rows('SELECT * FROM jobs'))
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_revision_exhaustion_cannot_commit_unreadable_identity(self):
        body=preferences(self.store,title='آخر مراجعة قابلة للقراءة')
        record={**body,'schema':'was.workspace/1','revision':2**31-1}
        with self.store.db:
            self.store.db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',(workspaces.PREFIX+'01',encode(record)))
            self.store.audit('workspace.updated',json.loads(workspaces._proof(record)))
        before=workspaces.describe(self.store,'01')['workspace']
        with self.assertRaises(Problem) as error:
            workspaces.save(self.store,preferences(self.store,title='تجاوز حد المراجعات'))
        self.assertEqual(error.exception.status,409)
        self.assertEqual(workspaces.describe(self.store,'01')['workspace'],before)

    def test_preferences_survive_reopen_without_changing_ids_or_tools(self):
        identifier = 'platform.01.01'
        before = workspaces.describe(self.store, identifier)['workspace']
        body = preferences(self.store, identifier, title='مصادري الخاصة', description='مراجعة مصادر المشروع', color='violet', icon='✧', landing='map')
        saved = workspaces.save(self.store, body)['workspace']
        self.assertEqual(saved['revision'], 1)
        self.assertEqual(saved['id'], identifier)
        self.assertEqual(saved['parent_id'], before['parent_id'])
        self.assertEqual(saved['tools'], before['tools'])
        reopened = Store(self.store.root)
        try:
            actual = workspaces.describe(reopened, identifier)['workspace']
            for field in ('title','description','color','icon','landing'):
                self.assertEqual(actual[field], body[field])
        finally:
            reopened.close()

    def test_child_title_and_identity_are_reflected_in_parent_map(self):
        workspaces.save(self.store, preferences(self.store,'platform.01.01',title='مصادر المالك',color='rose',icon='✓'))
        child = next(item for item in workspaces.describe(self.store,'01')['workspace']['children'] if item['id']=='platform.01.01')
        self.assertEqual(child['title'], 'مصادر المالك')
        self.assertEqual(child['color'], 'rose')
        self.assertEqual(child['icon'], '✓')
        self.assertEqual(workspaces.describe(self.store,'02')['workspace']['revision'],0)

    def test_two_owners_tabs_cannot_overwrite_stale_revision(self):
        original = preferences(self.store)
        workspaces.save(self.store,{**original,'title':'الإصدار الأول'})
        with self.assertRaises(Problem) as error:
            workspaces.save(self.store,{**original,'title':'تعديل متأخر'})
        self.assertEqual(error.exception.status,409)
        latest = workspaces.describe(self.store,'01')['workspace']
        self.assertEqual(latest['title'],'الإصدار الأول')
        self.assertEqual(latest['revision'],1)
        final = workspaces.save(self.store,preferences(self.store,title='الإصدار الثاني'))['workspace']
        self.assertEqual(final['revision'],2)

    def test_separate_connections_serialize_concurrent_revision_updates(self):
        from concurrent.futures import ThreadPoolExecutor
        other=Store(self.store.root)
        barrier=threading.Barrier(2)
        first=preferences(self.store,title='تعديل أول متزامن')
        second=preferences(other,title='تعديل ثان متزامن')
        def edit(store,body):
            barrier.wait(timeout=5)
            try:return workspaces.save(store,body)['workspace']['revision']
            except Problem as error:return error.status
        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                a=executor.submit(edit,self.store,first);b=executor.submit(edit,other,second)
                self.assertEqual(sorted([a.result(timeout=10),b.result(timeout=10)]),[1,409])
            current=workspaces.describe(self.store,'01')['workspace']
            self.assertEqual(current['revision'],1)
            self.assertIn(current['title'],(first['title'],second['title']))
            self.assertEqual(len(self.store.rows("SELECT seq FROM audit WHERE action='workspace.updated'")),1)
        finally:other.close()

    def test_one_workspace_setting_cannot_change_other_workspace(self):
        before = workspaces.describe(self.store,'platform.01.02')['workspace']
        workspaces.save(self.store,preferences(self.store,'platform.01.01',title='تغيير مستقل'))
        self.assertEqual(workspaces.describe(self.store,'platform.01.02')['workspace'],before)

    def test_invalid_ids_never_create_workspace_records(self):
        for identifier in ('../01','99','platform.99.01','eng.section.01','',None,True,{},'01\n'):
            with self.subTest(identifier=identifier):
                with self.assertRaises(Problem):workspaces.describe(self.store,identifier)
        self.assertFalse(self.store.rows("SELECT * FROM settings WHERE value LIKE '%was.workspace%'") )

    def test_save_requires_exact_fields_and_known_workspace(self):
        body = preferences(self.store)
        for candidate in ({}, {**body,'tools':['arbitrary']}, {k:v for k,v in body.items() if k!='description'}, {**body,'id':'platform.99.99'}):
            with self.assertRaises(Problem):workspaces.save(self.store,candidate)
        self.assertEqual(workspaces.describe(self.store,'01')['workspace']['revision'],0)

    def test_invalid_revision_and_palette_cannot_persist(self):
        body = preferences(self.store)
        for field, values in (('revision',(True,-1,1.0,'0')),('color',('red','url(https://invalid.test)',{})),('icon',('<script>','💣',None)),('landing',('settings','javascript:alert(1)',{}))):
            for value in values:
                with self.subTest(field=field,value=value):
                    with self.assertRaises(Problem):workspaces.save(self.store,{**body,field:value})
        self.assertEqual(workspaces.describe(self.store,'01')['workspace']['revision'],0)

    def test_text_limits_controls_and_surrogates_fail_cleanly(self):
        body=preferences(self.store)
        for field, values in (('title',('', ' '*5,'t'*121,'bad\nlabel','bad\x00label','\ud800')),('description',('', ' '*5,'d'*2001,'bad\x00text','\udfff'))):
            for value in values:
                with self.subTest(field=field,value=repr(value[:20])):
                    with self.assertRaises(Problem):workspaces.save(self.store,{**body,field:value})
        self.assertEqual(workspaces.describe(self.store,'01')['workspace']['revision'],0)

    def test_literal_markup_is_data_and_not_rewritten_or_executed(self):
        text='<img src=x onerror="alert(1)">'
        saved=workspaces.save(self.store,preferences(self.store,title=text,description='  وصف خاص  '))['workspace']
        self.assertEqual(saved['title'],text)
        self.assertEqual(saved['description'],'وصف خاص')
        self.assertEqual(saved['id'],'01')

    def test_audit_failure_rolls_back_preference_and_revision(self):
        workspaces.save(self.store,preferences(self.store,title='سابق'))
        before=workspaces.describe(self.store,'01')['workspace']
        with patch.object(self.store,'audit',side_effect=RuntimeError('synthetic audit failure')):
            with self.assertRaises(RuntimeError):workspaces.save(self.store,preferences(self.store,title='غير محفوظ'))
        self.assertEqual(workspaces.describe(self.store,'01')['workspace'],before)
        self.assertTrue(self.store.verify_audit()['valid'])

    def test_deleted_preference_cannot_silently_reset_audited_workspace(self):
        workspaces.save(self.store,preferences(self.store,title='إعداد محفوظ'))
        with self.store.db:self.store.db.execute('DELETE FROM settings WHERE key=?',(workspaces.PREFIX+'01',))
        with self.assertRaises(Problem) as error:workspaces.describe(self.store,'01')
        self.assertEqual(error.exception.status,409)

    def test_rollback_to_older_audited_preference_is_rejected(self):
        workspaces.save(self.store,preferences(self.store,title='مراجعة أولى'))
        old=self.store.rows('SELECT value FROM settings WHERE key=?',(workspaces.PREFIX+'01',))[0]['value']
        workspaces.save(self.store,preferences(self.store,title='مراجعة أحدث'))
        with self.store.db:
            self.store.db.execute('UPDATE settings SET value=? WHERE key=?',(old,workspaces.PREFIX+'01'))
        with self.assertRaises(Problem) as error:workspaces.describe(self.store,'01')
        self.assertEqual(error.exception.status,409)

    def test_direct_setting_tamper_is_rejected_by_creation_audit_binding(self):
        workspaces.save(self.store,preferences(self.store,title='عنوان موثق'))
        rows=self.store.rows('SELECT key,value FROM settings')
        setting=next(row for row in rows if 'عنوان موثق' in row['value'])
        value=json.loads(setting['value']);self.assertIsInstance(value,dict)
        value['title']='عنوان غير موثق'
        with self.store.db:self.store.db.execute('UPDATE settings SET value=? WHERE key=?',(encode(value),setting['key']))
        with self.assertRaises(Problem):workspaces.describe(self.store,'01')

    def test_encrypted_backup_restore_preserves_workspace_preferences(self):
        body=preferences(self.store,'platform.01.01',title='مساحة مستعادة',color='blue',icon='◎',landing='tools')
        workspaces.save(self.store,body)
        encrypted=backup.export(self.store,'synthetic-backup-password-123')
        target=Path(self.temp.name)/'workspace-restored'
        backup.restore(encrypted,'synthetic-backup-password-123',target)
        restored=Store(target)
        try:
            current=workspaces.describe(restored,'platform.01.01')['workspace']
            self.assertEqual(current['title'],body['title'])
            self.assertEqual(current['landing'],'tools')
            self.assertEqual(current['revision'],1)
            self.assertTrue(restored.verify_audit()['valid'])
        finally:restored.close()


class WorkspaceHTTPTests(StoreCase):
    request=core.HTTPTests.request
    login=core.HTTPTests.login

    def setUp(self):
        super().setUp();self.app=App(('127.0.0.1',0),self.store)
        self.thread=threading.Thread(target=self.app.serve_forever,daemon=True);self.thread.start()
        self.cookie,self.csrf='',''

    def tearDown(self):
        self.app.shutdown();self.app.server_close();self.thread.join();super().tearDown()

    def test_owner_auth_and_csrf_cover_reads_and_preferences(self):
        self.assertEqual(self.request('/api/workspaces?id=01')[0],401)
        body=preferences(self.store,title='عنوان خاص')
        self.assertEqual(self.request('/api/workspaces/settings',body)[0],401)
        self.login()
        self.assertEqual(self.request('/api/workspaces/settings',body,{'X-CSRF-Token':'bad'})[0],403)
        status,_,raw=self.request('/api/workspaces/settings',body)
        self.assertEqual(status,200)
        self.assertEqual(json.loads(raw)['workspace']['title'],body['title'])
        status,_,raw=self.request('/api/workspaces?id=01')
        self.assertEqual(status,200);self.assertEqual(json.loads(raw)['workspace']['revision'],1)

    def test_http_stale_revision_and_injected_fields_are_rejected(self):
        self.login();body=preferences(self.store,title='إعداد محفوظ')
        self.assertEqual(self.request('/api/workspaces/settings',{**body,'parent_id':'02'})[0],400)
        self.assertEqual(self.request('/api/workspaces/settings',body)[0],200)
        self.assertEqual(self.request('/api/workspaces/settings',{**body,'title':'كتابة قديمة'})[0],409)
        self.assertEqual(self.request('/api/workspaces?id=not-real')[0],404)

    def test_bootstrap_navigation_uses_saved_titles_with_original_ids_and_tool_bindings(self):
        self.login()
        section_name=workspaces.CATALOG[0]['name']
        platform=workspaces.CATALOG[0]['platforms'][0]
        original_tools=list(platform['tool_ids'])
        for body in (preferences(self.store,'01',title='قسم المالك'),preferences(self.store,platform['id'],title='منصة المالك',color='rose',icon='✓')):
            self.assertEqual(self.request('/api/workspaces/settings',body)[0],200)
        status,_,raw=self.request('/api/bootstrap')
        self.assertEqual(status,200)
        catalog=json.loads(raw)['catalog']
        section=next(item for item in catalog if item['id']=='01')
        child=next(item for item in section['platforms'] if item['id']==platform['id'])
        self.assertEqual(section['name'],'قسم المالك')
        self.assertEqual(child['name'],'منصة المالك')
        self.assertEqual(child['color'],'rose')
        self.assertEqual(child['icon'],'✓')
        self.assertEqual(child['tool_ids'],original_tools)
        self.assertEqual(workspaces.CATALOG[0]['name'],section_name)
        self.assertEqual(len(catalog),22)
        self.assertEqual(sum(len(item['platforms']) for item in catalog),109)

    def test_http_literal_markup_keeps_restrictive_content_security_policy(self):
        self.login();body=preferences(self.store,title='<script>alert(1)</script>')
        status,headers,raw=self.request('/api/workspaces/settings',body)
        self.assertEqual(status,200)
        self.assertEqual(json.loads(raw)['workspace']['title'],body['title'])
        self.assertIn("script-src 'self'",headers['Content-Security-Policy'])
        self.assertIn("frame-ancestors 'none'",headers['Content-Security-Policy'])
