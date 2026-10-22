"""Static workload review preserves scope, provenance and secret boundaries."""
import copy
import json
import unittest
from unittest.mock import patch
from cyber_platform import kubernetes_review as k


def raw(value):return json.dumps(value).encode()


class KubernetesReviewTests(unittest.TestCase):
    def pod(self):
        return {'apiVersion':'v1','kind':'Pod','metadata':{'name':'demo'},'spec':{'containers':[{'name':'app','image':'example.test/app:latest'}]}}
    def review(self,value=None):return k.analyze(raw(self.pod() if value is None else value))
    def codes(self,value):return {f['code'] for f in self.review(value)['findings']}
    def compare(self,a,b):return k.analyze_diff(raw({'left':a,'right':b}))

    def test_sample_has_independent_known_baseline_and_no_apply(self):
        r=self.review(k.sample())
        self.assertEqual(r['resource_count'],2);self.assertEqual(r['container_count'],1)
        self.assertEqual(r['summary'],{'findings':12,'baseline_gaps':8,'not_reviewed_resources':0,'high':2,'medium':10,'low':0})
        self.assertFalse(r['network']);self.assertFalse(r['applied']);self.assertTrue(r['complete'])

    def test_every_workload_kind_uses_its_actual_pod_path(self):
        for pair,path in k._PODS.items():
            value={'apiVersion':pair[0],'kind':pair[1],'metadata':{'name':'test'},'spec':{}}
            target=value['spec']
            for part in path:target[part]={};target=target[part]
            target.update(self.pod()['spec'])
            with self.subTest(pair=pair):
                result=self.review(value);self.assertEqual(result['container_count'],1)
                finding=next(f for f in result['findings'] if f['code']=='missing_cpu_limit')
                self.assertEqual(finding['field'],'.'.join(('spec',*path))+'.containers[0].resources.limits.cpu')

    def test_safe_inherited_context_eliminates_relevant_gaps(self):
        p=self.pod();p['spec']['securityContext']={'runAsNonRoot':True,'runAsUser':1000,'seccompProfile':{'type':'RuntimeDefault'}}
        p['spec']['automountServiceAccountToken']=False
        c=p['spec']['containers'][0];c['image']='example.test/app@sha256:'+'a'*64
        c['securityContext']={'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}}
        c['resources']={'limits':{'cpu':'100m','memory':'64Mi'}}
        self.assertEqual(self.review(p)['findings'],[])

    def test_container_override_of_inherited_identity_is_visible(self):
        p=self.pod();p['spec']['securityContext']={'runAsNonRoot':True,'runAsUser':1000}
        p['spec']['containers'][0]['securityContext']={'runAsNonRoot':False,'runAsUser':0}
        self.assertIn('root_uid',self.codes(p));self.assertIn('non_root_not_required',self.codes(p))

    def test_inherited_source_path_points_to_pod_security_context(self):
        p=self.pod();p['spec']['securityContext']={'runAsNonRoot':False,'runAsUser':0}
        f=next(f for f in self.review(p)['findings'] if f['code']=='root_uid')
        self.assertEqual(f['field'],'spec.securityContext.runAsUser')

    def test_invalid_pod_container_context_placement_is_not_inherited(self):
        p=self.pod();p['spec']['securityContext']={'allowPrivilegeEscalation':False}
        with self.assertRaises(ValueError):self.review(p)
        p=self.pod();p['spec']['containers'][0]['securityContext']={'fsGroup':1000}
        with self.assertRaises(ValueError):self.review(p)

    def test_host_flags_and_volume_are_independent_observations(self):
        p=self.pod();p['spec'].update(hostNetwork=True,hostPID=True,hostIPC=True,volumes=[{'name':'host','hostPath':{'path':'/sensitive/canary'}}])
        self.assertTrue({'hostNetwork','hostPID','hostIPC','host_path_volume'}<=self.codes(p))
        self.assertNotIn('/sensitive/canary',json.dumps(self.review(p)))

    def test_boolean_and_identity_types_reject_truthy_strings_and_bools(self):
        for context in ({'runAsUser':True},{'runAsUser':-1},{'privileged':'false'},{'runAsNonRoot':0}):
            p=self.pod();p['spec']['containers'][0]['securityContext']=context
            with self.subTest(context=context),self.assertRaises(ValueError):self.review(p)
        p=self.pod();p['spec']['hostNetwork']='false'
        with self.assertRaises(ValueError):self.review(p)

    def test_capability_and_seccomp_shapes_are_strict(self):
        for context in ({'capabilities':{'drop':['ALL','ALL']}},{'capabilities':{'add':['unsafe value']}},{'seccompProfile':{'type':'made-up'}},{'seccompProfile':{'type':'Localhost'}}):
            p=self.pod();p['spec']['containers'][0]['securityContext']=context
            with self.subTest(context=context),self.assertRaises(ValueError):self.review(p)

    def test_seccomp_local_profile_is_hashed_and_never_exported(self):
        p=self.pod();p['spec']['securityContext']={'seccompProfile':{'type':'Localhost','localhostProfile':'SECRET_PROFILE_PATH'}}
        r=self.review(p);self.assertNotIn('SECRET_PROFILE_PATH',json.dumps(r));self.assertNotIn('seccomp_not_confined',{f['code'] for f in r['findings']})

    def test_resource_quantities_supported_subset_is_validated(self):
        for resource,value in [('cpu','2'),('cpu','250m'),('memory','1Gi'),('memory','1024')]:
            p=self.pod();p['spec']['containers'][0]['resources']={'limits':{resource:value}}
            with self.subTest(resource=resource,value=value):self.review(p)
        for value in (True,3,'-1','10watts','1;exec'):
            p=self.pod();p['spec']['containers'][0]['resources']={'limits':{'cpu':value}}
            with self.subTest(value=value),self.assertRaises(ValueError):self.review(p)

    def test_init_and_ephemeral_containers_are_reviewed_without_name_collision(self):
        p=self.pod();p['spec']['initContainers']=[{'name':'init','image':'image'}];p['spec']['ephemeralContainers']=[{'name':'debug','image':'image'}]
        self.assertEqual(self.review(p)['container_count'],3)
        p['spec']['initContainers'][0]['name']='app'
        with self.assertRaises(ValueError):self.review(p)

    def test_declared_zero_limit_is_an_observation_not_resource_protection(self):
        p=self.pod();p['spec']['containers'][0]['resources']={'limits':{'cpu':'0m','memory':'0Gi'}}
        self.assertTrue({'zero_cpu_limit','zero_memory_limit'}<=self.codes(p))

    def test_missing_or_malformed_containers_prevent_partial_success(self):
        for values in ([],None,[{'name':'app'}],[True]):
            p=self.pod();p['spec']['containers']=values
            with self.subTest(values=values),self.assertRaises(ValueError):self.review(p)
        p=k.sample();p['items'].append({'apiVersion':'v1','kind':'Pod','metadata':{'name':'broken'},'spec':{}})
        with self.assertRaises(ValueError):self.review(p)

    def test_unknown_resources_are_not_reviewed_not_declared_safe(self):
        p={'apiVersion':'v1','kind':'Secret','metadata':{'name':'hidden'},'data':{'password':'SECRET_VALUE'}}
        r=self.review(p);self.assertEqual(r['summary']['not_reviewed_resources'],1)
        self.assertEqual(r['resources'][0]['review_status'],'not_reviewed');self.assertIsNone(r['resources'][0]['configuration_sha256'])
        self.assertNotIn('SECRET_VALUE',json.dumps(r))

    def test_known_kind_wrong_api_and_nested_list_refused(self):
        p=self.pod();p['apiVersion']='invalid/v1'
        with self.assertRaises(ValueError):self.review(p)
        with self.assertRaises(ValueError):self.review({'apiVersion':'v1','kind':'List','items':[{'apiVersion':'v1','kind':'List','items':[]}]})

    def test_duplicate_resource_identity_refused_but_namespaces_are_distinct(self):
        a,b=self.pod(),self.pod()
        with self.assertRaises(ValueError):self.review({'apiVersion':'v1','kind':'List','items':[a,b]})
        b['metadata']['namespace']='other';self.assertEqual(self.review({'apiVersion':'v1','kind':'List','items':[a,b]})['resource_count'],2)

    def test_service_exposure_baseline_and_unknown_type(self):
        p={'apiVersion':'v1','kind':'Service','metadata':{'name':'svc'},'spec':{'type':'NodePort'}}
        self.assertIn('exposed_service',self.codes(p));p['spec']['type']='ClusterIP';self.assertEqual(self.review(p)['findings'],[])
        p['spec']['type']='madeup'
        with self.assertRaises(ValueError):self.review(p)

    def test_rbac_wildcard_and_real_array_path(self):
        r={'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRole','metadata':{'name':'system:role'},'rules':[{'verbs':['*'],'apiGroups':[''],'resources':['pods']}]}
        result=self.review(r);self.assertEqual(result['findings'][0]['field'],'rules[0].verbs');self.assertIsNone(result['resources'][0]['namespace'])

    def binding(self,kind='RoleBinding'):
        return {'apiVersion':'rbac.authorization.k8s.io/v1','kind':kind,'metadata':{'name':'binding','namespace':'demo'},
                'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':'view'},'subjects':[{'kind':'ServiceAccount','name':'reader','namespace':'demo'}]}

    def test_cluster_role_binding_requires_cluster_role(self):
        p=self.binding('ClusterRoleBinding');self.review(p);p['roleRef']['kind']='Role'
        with self.assertRaises(ValueError):self.review(p)

    def test_serviceaccount_namespace_changes_are_not_falsely_equal(self):
        a,b=self.binding(),self.binding();b['subjects'][0]['namespace']='other'
        r=self.compare(a,b);self.assertFalse(r['normalized_review_equal']);self.assertEqual(len(r['changed_resources']),1)

    def test_rbac_subject_api_group_and_broad_binding(self):
        p=self.binding();p['subjects']=[{'kind':'Group','name':'system:unauthenticated'}]
        self.assertIn('broad_subject_binding',self.codes(p));p['subjects'][0]['apiGroup']='other'
        with self.assertRaises(ValueError):self.review(p)

    def test_env_command_image_and_unknown_secret_values_never_exported(self):
        p=self.pod();c=p['spec']['containers'][0];c.update(image='registry.test/SECRET_IMAGE:tag',command=['SECRET_COMMAND'],env=[{'name':'X','value':'SECRET_ENV'}])
        output=json.dumps(self.review(p))
        for secret in ('SECRET_IMAGE','SECRET_COMMAND','SECRET_ENV'):self.assertNotIn(secret,output)

    def test_email_style_rbac_user_identity_is_supported_without_exporting_subject(self):
        p=self.binding();p['subjects']=[{'kind':'User','name':'reader@example.test','apiGroup':'rbac.authorization.k8s.io'}]
        result=self.review(p);self.assertEqual(result['resource_count'],1)
        self.assertNotIn('reader@example.test',json.dumps(result))

    def test_input_size_json_duplicates_nonfinite_and_depth(self):
        for data in (b'{"apiVersion":"v1","apiVersion":"v2"}',b'{"x":NaN}',b'{"x":'+b'['*40+b'0'+b']'*40+b'}',b'\xff',b'[]'):
            with self.subTest(data=data[:40]),self.assertRaises(ValueError):k.analyze(data)
        with patch.dict(k.LIMITS,input_bytes=10),self.assertRaises(ValueError):self.review()

    def test_resource_container_finding_budgets_refuse_not_truncate(self):
        for key,value in [('resources',1),('containers',0),('findings',1)]:
            with self.subTest(key=key),patch.dict(k.LIMITS,{key:value}),self.assertRaises(ValueError):self.review(k.sample())

    def test_same_findings_but_changed_uid_and_image_are_detected(self):
        a,b=self.pod(),self.pod();a['spec']['securityContext']={'runAsUser':1000};b['spec']['securityContext']={'runAsUser':1001}
        self.assertEqual(self.review(a)['findings'],self.review(b)['findings']);self.assertFalse(self.compare(a,b)['normalized_review_equal'])
        b=copy.deepcopy(a);b['spec']['containers'][0]['image']='other/image:tag'
        self.assertFalse(self.compare(a,b)['normalized_review_equal'])

    def test_diff_equal_complete_and_canonical_document_binding(self):
        p=self.pod();r=self.compare(p,p)
        self.assertTrue(r['complete']);self.assertTrue(r['normalized_review_equal']);self.assertEqual(r['changed_resources'],[])
        self.assertEqual(r['left_sha256'],r['right_sha256']);self.assertEqual(r['embedded_document_encoding'],'canonical_json')

    def test_diff_added_removed_resources_and_findings(self):
        a,b=self.pod(),self.pod();b['metadata']['name']='new';r=self.compare(a,b)
        self.assertEqual(len(r['added_resources']),1);self.assertEqual(len(r['removed_resources']),1)
        self.assertTrue(r['added_findings']);self.assertTrue(r['removed_findings'])

    def test_diff_preserves_unknown_coverage_without_claiming_equality_of_secrets(self):
        a={'apiVersion':'v1','kind':'Secret','metadata':{'name':'secret'},'data':{'key':'A'}};b=copy.deepcopy(a);b['data']['key']='B'
        r=self.compare(a,b);self.assertTrue(r['unreviewed_resources_present']);self.assertTrue(r['normalized_review_equal'])
        self.assertIn('not_reviewed',r['notice'])

    def test_diff_has_exact_fields_and_refuses_malformed_later_document(self):
        p=self.pod()
        for value in ({'left':p},{'left':p,'right':p,'extra':1},{'left':p,'right':[]},{'left':p,'right':{'kind':'Pod'}}):
            with self.subTest(value=value),self.assertRaises(ValueError):k.analyze_diff(raw(value))

    def test_actual_worker_accepts_and_rejects_both_registered_tools(self):
        from cyber_platform import tools,worker
        for tool in ('kubernetes','kubernetes-diff'):
            self.assertIn(tool,tools.REGISTRY)
            sample=next(t['sample'] for t in tools.describe() if t['id']==tool)
            self.assertIn('schema',worker.analyze(tool,sample.encode(),timeout=3))
            with self.assertRaises(ValueError):worker.analyze(tool,b'not JSON',timeout=3)
