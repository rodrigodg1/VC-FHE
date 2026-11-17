"""A transient IAM 404 never repeats account creation."""
from pathlib import Path
from types import SimpleNamespace
import sys,json,tempfile,subprocess,unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]));sys.path.insert(0,str(Path(__file__).resolve().parent))
from cloud_results import infra
from test_cloud_results import config

class ActorPropagationTests(unittest.TestCase):
    def test_not_found_read_is_retried_and_identity_is_fixed(self):
        c=config();created={'email':'actor@example.test','uniqueId':'123'}
        responses=[SimpleNamespace(returncode=1,stdout='',stderr='NOT_FOUND'),
                   SimpleNamespace(returncode=0,stdout=json.dumps(created),stderr='')]
        with patch.object(infra.subprocess,'run',side_effect=responses) as call,patch.object(infra.time,'sleep'):
            self.assertEqual(infra.wait_account(c,created['email'],created),created)
        self.assertEqual(call.call_count,2)
        self.assertTrue(all('describe' in c.args[0] for c in call.call_args_list))
    def test_permission_failure_is_not_treated_as_eventual_consistency(self):
        with patch.object(infra.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout='',stderr='PERMISSION_DENIED')) as call:
            with self.assertRaises(subprocess.CalledProcessError):infra.wait_account(config(),'actor@example.test',{'email':'actor@example.test','uniqueId':'123'})
        self.assertEqual(call.call_count,1)
    def test_replaced_account_is_rejected(self):
        with patch.object(infra.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps({'email':'actor@example.test','uniqueId':'999'}),stderr='')):
            with self.assertRaises(ValueError):infra.wait_account(config(),'actor@example.test',{'email':'actor@example.test','uniqueId':'123'})
    def test_creation_response_is_persisted_before_readiness_wait(self):
        c=config();expected=infra.actor_accounts(c);created=[]
        def cloud(*args):
            if args[2]=='list':return []
            self.assertEqual(args[2],'create');created.append(args[3])
            row=next(v for v in expected.values() if v['accountId']==args[3])
            return {'email':row['email'],'uniqueId':str(100+len(created)),'name':'synthetic/'+row['accountId']}
        with tempfile.TemporaryDirectory() as tmp,patch.object(infra,'gcloud',side_effect=cloud),patch.object(infra,'run'),patch.object(infra,'wait_account') as wait:
            value=infra.allocate_accounts(c,tmp)
            self.assertEqual(len(value['accounts']),4);self.assertEqual(len(set(created)),4)
            self.assertEqual(wait.call_count,4)
            self.assertEqual(json.loads((Path(tmp)/'actor-accounts.local.json').read_text()),value)

if __name__=='__main__':unittest.main()
