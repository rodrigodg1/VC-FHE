import copy
from datetime import datetime,timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import cloud_build
import cloud_tools
import gcp
import privacy
import topology

class CloudPreparationTests(unittest.TestCase):
    def setUp(self):
        self.config=json.loads((HERE/'config.example.json').read_text())
        self.config['project_id']='example-research-project'
    def test_cloud_build_binds_images_and_has_explicit_cost_timeout(self):
        resources={'region':'us-central1','builderServiceAccount':'projects/example/serviceAccounts/builder',
                   'bucket':'gs://synthetic-build-bucket'}
        spec,tag,besu=cloud_build.specification(self.config,{'fixture':'only'},resources,'hyperledger/besu@sha256:'+'a'*64)
        self.assertEqual(spec['timeout'],'7200s')
        self.assertEqual(spec['options']['machineType'],'E2_HIGHCPU_32')
        self.assertIn('--platform=linux/amd64',spec['steps'][1]['args'])
        self.assertIn('--target=build',spec['steps'][0]['args'][1])
        self.assertEqual(spec['images'],[tag,besu])
        self.assertEqual(spec['options']['logging'],'GCS_ONLY')
        self.assertNotIn('credentials',json.dumps(spec))
    def test_quote_refuses_paid_build_before_any_api_mutation(self):
        quote={'currency':'USD','campaign':self.config['campaign'],'layout':'four-hosts',
            'hourly':{'compute':20,'nat':1,'disks':1,'ipv4':1},'planned_hours':12,
            'build_registry':10,'retained_resources':1,'transfer_storage_upper_bound':5,
            'quoted_at':datetime.now(timezone.utc).isoformat(),'source_urls':['https://example.test/prices']}
        with patch('cloud_setup.inspect') as inspect:
            with self.assertRaises(ValueError):cloud_build.build(self.config,quote,'/uncreated-test-output')
            inspect.assert_not_called()
    def test_hash_mismatch_is_not_executed_as_a_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            file=Path(tmp)/'download';file.write_bytes(b'corrupted')
            with self.assertRaises(ValueError):cloud_tools.download('https://example.test',file,'0'*64)
    def test_iap_and_login_permissions_are_scoped_to_each_host(self):
        self.config['operator_principal']='user:operator@example.test'
        resources=gcp.terraform(self.config)['resource']
        for kind in ['google_compute_instance_iam_member','google_iap_tunnel_instance_iam_member','google_service_account_iam_member']:
            self.assertEqual(len(resources[kind]),4)
            self.assertTrue(all(r['member']==self.config['operator_principal'] for r in resources[kind].values()))
        self.assertNotIn('google_project_iam_member',resources)
    def test_no_personal_runtime_information_in_public_reproduction_files(self):
        self.assertEqual(privacy.audit()['status'],'passed')
    def test_account_reports_cannot_be_written_into_public_documentation(self):
        with self.assertRaises(ValueError):privacy.require_private(HERE.parent/'docs/account-setup.json')
        self.assertEqual(privacy.require_private(HERE/'generated/account-setup.local.json'),HERE/'generated/account-setup.local.json')

if __name__=='__main__':unittest.main()
