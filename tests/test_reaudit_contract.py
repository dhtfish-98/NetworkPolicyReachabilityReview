import unittest,json,sys,subprocess,copy,base64,hashlib,datetime
from network_policy_reachability_review import audit
from network_policy_reachability_review.common import ReviewError,load
import test_review as fixtures
def reject(test,d):
    with test.assertRaises(ReviewError):audit(d)
    p=subprocess.run([sys.executable,'-m','network_policy_reachability_review','-'],input=json.dumps(d).encode(),capture_output=True,timeout=10)
    out=json.loads(p.stdout);test.assertEqual(p.returncode,1);test.assertEqual(out['status'],'FAIL');test.assertFalse(out['complete']);test.assertFalse(out.get('verified',False))
class FiniteInputTests(unittest.TestCase):
    def test_exponent_overflow_rejected_api_and_cli(self):
        for raw in (b'{"x":1e999}',b'{"x":[-1e999]}'):
            with self.assertRaises(ReviewError):load(raw)
            p=subprocess.run([sys.executable,'-m','network_policy_reachability_review','-'],input=raw,capture_output=True,timeout=10);out=json.loads(p.stdout)
            self.assertEqual(p.returncode,1);self.assertFalse(out['complete']);self.assertEqual(out['status'],'FAIL')
        self.assertEqual(load(b'{"x":1.25}'),{'x':1.25})
    def test_unknown_fields_error_does_not_echo_canary(self):
        canary='SYNTHETIC-PRIVATE-CANARY-cc94e6f3'
        with self.assertRaises(ReviewError) as e:audit({canary:canary})
        self.assertNotIn(canary,str(e.exception))
        p=subprocess.run([sys.executable,'-m','network_policy_reachability_review','-'],input=json.dumps({canary:canary}).encode(),capture_output=True,timeout=10)
        self.assertEqual(p.returncode,1);self.assertNotIn(canary,p.stdout.decode()+p.stderr.decode())
class PeerAndPrivacyTests(unittest.TestCase):
    def test_null_peer_selectors_are_not_empty_selectors_api_cli(self):
        t=fixtures.NetworkTests();t.setUp()
        for peer in ({'namespaceSelector':None},{'podSelector':None},{'namespaceSelector':{},'podSelector':None}):
            d=copy.deepcopy(t.d);d['policies'][0]['spec']['ingress'][0]['from']=[peer];reject(self,d)
        d=copy.deepcopy(t.d);d['policies'][0]['spec']['ingress'][0]['from']=[{'namespaceSelector':{}}]
        self.assertTrue(audit(d)['answers'][0]['allowed_by_declared_policies'])
    def test_invalid_ip_api_cli_errors_do_not_echo_input(self):
        t=fixtures.NetworkTests();t.setUp();canary='SYNTHETIC-PRIVATE-CANARY-cc94e6f3'
        for field in ('pod','endpoint','cidr','exception'):
            d=copy.deepcopy(t.d)
            if field=='pod':d['pods'][0]['ip']=canary
            elif field=='endpoint':d['queries'][0]['source']={'external_ip':canary}
            else:d['policies'][0]['spec']['ingress'][0]['from']=[{'ipBlock':{'cidr':canary if field=='cidr' else '192.0.2.0/24','except':[canary] if field=='exception' else []}}]
            with self.assertRaises(ReviewError) as e:audit(d)
            self.assertNotIn(canary,str(e.exception));reject(self,d)
            p=subprocess.run([sys.executable,'-m','network_policy_reachability_review','-'],input=json.dumps(d).encode(),capture_output=True,timeout=10)
            self.assertNotIn(canary,p.stdout.decode()+p.stderr.decode())

class FilePlatformCapabilityTests(unittest.TestCase):
    def test_missing_or_unusable_file_flags_fail_closed(self):
        from unittest import mock
        from network_policy_reachability_review.common import read
        from network_policy_reachability_review import common
        for flag in ('O_NOFOLLOW','O_NONBLOCK'):
            for value in (None,0,'unusable'):
                with mock.patch.object(common.os,flag,value,create=True):
                    with self.assertRaisesRegex(ReviewError,'flags unavailable'):read('synthetic-nonexistent-file')
            with mock.patch.object(common.os,flag,1,create=True):
                delattr(common.os,flag)
                with self.assertRaisesRegex(ReviewError,'flags unavailable'):read('synthetic-nonexistent-file')

class KubernetesSyntaxTests(unittest.TestCase):
    def fixture(self):
        t=fixtures.NetworkTests();t.setUp();return t.d
    def test_invalid_label_keys_at_each_supported_location_api_cli(self):
        for key in ('','-key','key-','has space','é','a'*64,'/key','example.invalid/','Example.invalid/key','a/b/c','a'*254+'/key'):
            for location in ('namespace','pod','matchLabels','matchExpressions'):
                d=self.fixture()
                if location=='namespace':d['namespaces'][0]['labels']={key:'value'}
                elif location=='pod':d['pods'][0]['labels']={key:'value'}
                elif location=='matchLabels':d['policies'][0]['spec']['podSelector']={'matchLabels':{key:'value'}}
                else:d['policies'][0]['spec']['podSelector']={'matchExpressions':[{'key':key,'operator':'In','values':['value']}]}
                with self.subTest(key=key,location=location):reject(self,d)
    def test_invalid_label_values_at_each_supported_location_api_cli(self):
        for value in ('a'*64,'é','has space','/','-value','value-'):
            for location in ('namespace','pod','matchLabels','matchExpressions'):
                d=self.fixture()
                if location=='namespace':d['namespaces'][0]['labels']={'key':value}
                elif location=='pod':d['pods'][0]['labels']={'key':value}
                elif location=='matchLabels':d['policies'][0]['spec']['podSelector']={'matchLabels':{'key':value}}
                else:d['policies'][0]['spec']['podSelector']={'matchExpressions':[{'key':'key','operator':'In','values':[value]}]}
                with self.subTest(value=value,location=location):reject(self,d)
    def test_label_boundaries_and_case_and_empty_values_match(self):
        key='a'*253+'/'+'K'*63;value='V'*63
        d=self.fixture();d['pods'][0]['labels']={key:value,'Empty':''}
        peer=d['policies'][0]['spec']['ingress'][0]['from'][0]
        peer['podSelector']={'matchExpressions':[{'key':key,'operator':'In','values':[value]},{'key':'Empty','operator':'In','values':['']}]}
        self.assertTrue(audit(d)['answers'][0]['allowed_by_declared_policies'])
        d['pods'][0]['labels'][key]='Other';self.assertFalse(audit(d)['answers'][0]['allowed_by_declared_policies'])
        d=self.fixture();d['namespaces'][0]['labels']={'example.invalid/Key_Name.V1':''}
        d['policies'][0]['spec']['ingress'][0]['from'][0]['namespaceSelector']={'matchLabels':{'example.invalid/Key_Name.V1':''}}
        self.assertTrue(audit(d)['answers'][0]['allowed_by_declared_policies'])
    def test_invalid_namespace_names_and_references_api_cli(self):
        for name in ('','a.b','A','a'*64,'-a','a-','é','has space'):
            for location in ('object','pod','policy','query'):
                d=self.fixture()
                if location=='object':d['namespaces'][0]['name']=name
                elif location=='pod':d['pods'][0]['namespace']=name
                elif location=='policy':d['policies'][0]['metadata']['namespace']=name
                else:d['queries'][0]['source']['namespace']=name
                with self.subTest(name=name,location=location):reject(self,d)
    def test_invalid_pod_policy_names_and_query_references_api_cli(self):
        for name in ('','A','a'*254,'-a','a-','a..b','a.-b','a.b-','é','has space'):
            for location in ('pod','policy','query'):
                d=self.fixture()
                if location=='pod':d['pods'][0]['name']=name
                elif location=='policy':d['policies'][0]['metadata']['name']=name
                else:d['queries'][0]['source']['pod']=name
                with self.subTest(name=name,location=location):reject(self,d)
    def test_namespace_63_pod_policy_253_and_dotted_subdomain_boundaries(self):
        d=self.fixture();ns='n'*63;pod='p'*253
        d['namespaces'][0]['name']=ns;d['pods'][0].update(namespace=ns,name=pod)
        for q in d['queries']:q['source'].update(namespace=ns,pod=pod)
        d['policies'][0]['metadata']['name']='q'*253
        self.assertTrue(audit(d)['answers'][0]['allowed_by_declared_policies'])
        # Kubernetes NameIsDNSSubdomain imposes the whole 253-byte limit,
        # rather than a separate 63-byte limit on each segment.
        d=self.fixture();d['pods'][0]['name']='client.v1';d['policies'][0]['metadata']['name']='policy.v1'
        for q in d['queries']:q['source']['pod']='client.v1'
        self.assertTrue(audit(d)['answers'][0]['allowed_by_declared_policies'])
