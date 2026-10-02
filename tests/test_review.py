import unittest, json, base64, hashlib, tempfile, pathlib, datetime, copy, subprocess, sys, os, struct
from network_policy_reachability_review import audit
from network_policy_reachability_review.common import ReviewError,load,read
UTC=datetime.timezone.utc
def enc(b):return base64.b64encode(b).decode()
def url(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def save_example(d):
    if os.environ.get('GENERATE_REVIEW_EXAMPLES')!='1':return
    out=pathlib.Path(__file__).resolve().parents[1]/'examples';out.mkdir(exist_ok=True)
    (out/'valid.json').write_text(json.dumps(d,indent=2)+'\n')
class CommonTests(unittest.TestCase):
    def test_duplicate_and_nonfinite_input(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'[]'):
            with self.assertRaises(ReviewError):load(raw)
    def test_input_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as t:
            p=pathlib.Path(t);(p/'file').write_text('x');(p/'link').symlink_to(p/'file');os.mkfifo(p/'pipe')
            for q in (p/'link',p/'pipe'):
                with self.assertRaises((ReviewError,OSError)):read(str(q))
    def test_missing_fields_and_cli_exit(self):
        with self.assertRaises((ReviewError,KeyError)):audit({})
        proc=subprocess.run([sys.executable,'-m','network_policy_reachability_review','-'],input=b'{}',capture_output=True,timeout=10)
        self.assertEqual(proc.returncode,1);self.assertEqual(json.loads(proc.stdout)['status'],'FAIL');self.assertFalse(json.loads(proc.stdout)['complete'])

class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.d={'namespaces':[{'name':'a','labels':{'team':'client'}},{'name':'b','labels':{'team':'server'}}],'pods':[{'name':'client','namespace':'a','labels':{'app':'client'},'ip':'10.0.0.1','ports':[]},{'name':'server','namespace':'b','labels':{'app':'server'},'ip':'10.0.0.2','ports':[{'name':'https','port':443,'protocol':'TCP'}]}],'policies':[{'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'server-ingress','namespace':'b'},'spec':{'podSelector':{'matchLabels':{'app':'server'}},'policyTypes':['Ingress'],'ingress':[{'from':[{'namespaceSelector':{'matchLabels':{'team':'client'}},'podSelector':{'matchLabels':{'app':'client'}}}],'ports':[{'port':'https','protocol':'TCP'}]}]}}],'queries':[{'source':{'namespace':'a','pod':'client'},'destination':{'namespace':'b','pod':'server'},'protocol':'TCP','port':443},{'source':{'namespace':'a','pod':'client'},'destination':{'namespace':'b','pod':'server'},'protocol':'TCP','port':80}]}
    def test_named_ports_and_and_selector(self):
        result=audit(self.d);self.assertEqual([x['allowed_by_declared_policies'] for x in result['answers']],[True,False]);save_example(self.d)
        self.d['pods'][0]['labels']['app']='other';self.assertFalse(audit(self.d)['answers'][0]['allowed_by_declared_policies'])
    def test_union_egress_deny_and_ipblock_except(self):
        policy=copy.deepcopy(self.d['policies'][0]);policy['metadata']['name']='union';policy['spec']['ingress']=[{}];self.d['policies'].append(policy);self.assertTrue(audit(self.d)['answers'][1]['allowed_by_declared_policies'])
        self.d['policies'].append({'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'client-egress','namespace':'a'},'spec':{'podSelector':{},'policyTypes':['Egress'],'egress':[]}});self.assertFalse(audit(self.d)['answers'][0]['allowed_by_declared_policies'])
        self.d['policies'][-1]['spec']['egress']=[{'to':[{'ipBlock':{'cidr':'10.0.0.0/24','except':['10.0.0.2/32']}}]}];self.assertFalse(audit(self.d)['answers'][0]['allowed_by_declared_policies']);self.d['policies'][-1]['spec']['egress'][0]['to'][0]['ipBlock']['except']=[];self.assertTrue(audit(self.d)['answers'][0]['allowed_by_declared_policies'])
    def test_default_empty_egress_and_operation_budget(self):
        spec=self.d['policies'][0]['spec'];spec.pop('policyTypes');spec['egress']=[]
        # The empty egress field does not add Egress to the default policyTypes.
        result=audit(self.d);self.assertFalse(result['answers'][0]['source_egress_isolated'])
        reverse=copy.deepcopy(self.d['queries'][0]);reverse['source'],reverse['destination']=reverse['destination'],reverse['source'];self.d['queries']=[reverse]
        self.assertFalse(audit(self.d)['answers'][0]['source_egress_isolated'])
        self.d['policies']=[dict(copy.deepcopy(self.d['policies'][0]),metadata={'name':'p'+str(i),'namespace':'b'}) for i in range(128)];self.d['queries']=[reverse]*1024
        with self.assertRaises(ReviewError):audit(self.d)
    def test_named_port_api_validation(self):
        for value in ('123','Uppercase','a'*16,'-http','http-'):
            d=copy.deepcopy(self.d);d['pods'][0]['ports']=[{'name':value,'port':80,'protocol':'TCP'}]
            with self.assertRaises(ReviewError):audit(d)
    def test_invalid_schema_and_ranges(self):
        mutations=[lambda d:d['policies'][0]['spec']['ingress'][0]['ports'][0].update(endPort=444),lambda d:d['policies'][0]['spec']['podSelector'].update(matchExpressions=[{'key':'x','operator':'Invalid'}]),lambda d:d['queries'][0].update(protocol='ICMP')]
        for change in mutations:
            d=copy.deepcopy(self.d);change(d)
            with self.assertRaises(ReviewError):audit(d)

if __name__=="__main__":unittest.main()
