import unittest,json,subprocess,sys,copy,base64,hashlib,datetime,pathlib,re,struct
from network_policy_reachability_review import audit
from network_policy_reachability_review.common import ReviewError,load,string

class UnicodeContractTests(unittest.TestCase):
    def test_surrogate_rejected_api_and_cli(self):
        self.assertEqual(string('合法 Unicode'),'合法 Unicode')
        with self.assertRaises(ReviewError):string(chr(0xd800))
        for raw in (b'{"x":"\\ud800"}',b'{"\\udfff":1}'):
            with self.assertRaises(ReviewError):load(raw)
            p=subprocess.run([sys.executable,'-m','network_policy_reachability_review','-'],input=raw,capture_output=True,timeout=10);self.assertEqual(p.returncode,1);self.assertEqual(json.loads(p.stdout)['status'],'FAIL');self.assertFalse(json.loads(p.stdout)['complete'])
