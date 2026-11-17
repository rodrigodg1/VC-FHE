"""Registry separation and staged provisioning. No cloud calls."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import cloud_build
import cloud_setup
import gcp
import launch
import topology

class PrimaryProvisionTests(unittest.TestCase):
    def config(self):
        cfg=json.loads((HERE/'config.example.json').read_text())
        cfg.update(project_id='example-research-project',operator_principal='user:researcher@example.test')
        cfg['regions'][0].update(name='us-east1',zone='us-east1-b')
        cfg['registry_region']='us-central1'
        prefix='us-central1-docker.pkg.dev/example-research-project/retained-images/'
        cfg['images']={'campaign':prefix+'campaign@sha256:'+'a'*64,'besu':prefix+'besu@sha256:'+'b'*64}
        return cfg
    def test_default_terraform_is_identical_to_a5(self):
        cfg=json.loads((HERE/'config.example.json').read_text())
        value=json.dumps(gcp.terraform(cfg),sort_keys=True,separators=(',',':')).encode()
        self.assertEqual(len(gcp.terraform(cfg)['resource']['google_compute_instance']), 4)
        self.assertEqual(value,json.dumps(gcp.terraform(cfg),sort_keys=True,separators=(',',':')).encode())
    def test_registry_stays_in_original_region_and_bound_project_repository(self):
        cfg=self.config();topology.validate(cfg)
        resources=gcp.terraform(cfg)['resource']
        self.assertEqual(gcp.image_repository(cfg),'retained-images')
        self.assertEqual(resources['google_artifact_registry_repository']['images']['location'],'us-central1')
        self.assertTrue(all(v['location']=='us-central1' for v in resources['google_artifact_registry_repository_iam_member'].values()))
        provision={'region':'us-central1','repository':'retained-images','project':cfg['project_id'],
            'builderServiceAccount':'projects/example/serviceAccounts/builder','bucket':'gs://example-build'}
        _,campaign,besu=cloud_build.specification(cfg,{},provision,'hyperledger/besu@sha256:'+'c'*64)
        self.assertTrue(campaign.startswith('us-central1-docker.pkg.dev/example-research-project/retained-images/'))
        self.assertTrue(besu.startswith('us-central1-docker.pkg.dev/example-research-project/retained-images/'))
        for image in ['us-east1-docker.pkg.dev/example-research-project/retained-images/besu@sha256:'+'b'*64,
                      'us-central1-docker.pkg.dev/foreign-project/retained-images/besu@sha256:'+'b'*64,
                      'us-central1-docker.pkg.dev/example-research-project/another-repo/besu@sha256:'+'b'*64]:
            cfg['images']['besu']=image
            with self.assertRaises(ValueError):gcp.image_repository(cfg)
    def test_builder_registry_grants_use_retained_location(self):
        cfg=self.config()
        def invoke(args,**kwargs):return subprocess.CompletedProcess(args,0,'{"projectNumber":"1"}','')
        with patch('cloud_setup.subprocess.run',side_effect=invoke) as run:
            result=cloud_setup.ensure_build_resources(cfg,{'operatorPrincipal':cfg['operator_principal'],'projectNumber':'1'})
        self.assertEqual(result['region'],'us-central1');self.assertEqual(result['repository'],'retained-images')
        calls=[call.args[0] for call in run.call_args_list if call.args[0][1:3]==['artifacts','repositories']]
        self.assertTrue(calls)
        self.assertTrue(all(args[args.index('--location')+1]=='us-central1' for args in calls))
    def test_primary_flag_adds_service_account_dependency_only_when_enabled(self):
        cfg=self.config()
        ordinary=gcp.terraform(cfg)['resource']['google_compute_instance']
        self.assertTrue(all(not any('service_account_iam' in ref for ref in vm['depends_on']) for vm in ordinary.values()))
        cfg['primary_first_provision']=True
        staged=gcp.terraform(cfg)['resource']['google_compute_instance']
        for key,vm in staged.items():self.assertIn('google_service_account_iam_member.'+key,vm['depends_on'])
        cfg.pop('operator_principal')
        with self.assertRaises(ValueError):gcp.terraform(cfg)
    def test_invalid_registry_or_primary_layout_is_rejected(self):
        for value in [None,'us-central1/foreign',True]:
            cfg=self.config();cfg['registry_region']=value
            with self.assertRaises(ValueError):topology.validate(cfg)
        for value in [None,'true',1]:
            cfg=self.config();cfg['primary_first_provision']=value
            with self.assertRaises(ValueError):topology.validate(cfg)
        cfg=self.config();cfg.update(primary_first_provision=True,layout='dedicated')
        with self.assertRaises(ValueError):topology.validate(cfg)
    def campaign(self,root,primary=True):
        value=launch.Campaign.__new__(launch.Campaign)
        value.config=self.config();value.config['primary_first_provision']=primary
        value.run=root;value.quote={};value.build=root/'prepared';value.started=0;value.provisioned=False
        return value
    def provision(self,campaign,commands,check,fail_primary=False):
        def invoke(args):
            commands.append(args)
            if fail_primary and args[-1]=='primary.tfplan' and 'apply' in args:
                raise subprocess.CalledProcessError(1,args)
        with patch('launch.shutil.which',return_value='/tool'),patch('launch.command',side_effect=invoke),patch('launch.check_launch',side_effect=check) as checked,patch('launch.subprocess.check_output',return_value='{}'),patch('launch.time.monotonic',return_value=3600):
            campaign.provision()
        return checked
    def test_primary_success_rechecks_before_full_apply_and_keeps_registry_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=self.campaign(Path(tmp));commands=[]
            checked=self.provision(c,commands,lambda *a,**kw:({},{}))
            applies=[args[-1] for args in commands if 'apply' in args]
            self.assertEqual(applies,['primary.tfplan','launch.tfplan'])
            self.assertEqual(checked.call_count,2)
            self.assertEqual(checked.call_args_list[1].kwargs,{'elapsed_hours':1})
            primary=next(args for args in commands if '-out=primary.tfplan' in args)
            self.assertIn('-target=google_compute_instance.host_1',primary)
            imported=next(args for args in commands if 'import' in args)
            self.assertIn('/locations/us-central1/repositories/retained-images',imported[-1])
    def test_capacity_failure_does_not_plan_or_apply_other_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=self.campaign(Path(tmp));commands=[]
            with self.assertRaises(subprocess.CalledProcessError):self.provision(c,commands,lambda *a,**kw:({},{}),True)
            self.assertFalse(any('launch.tfplan' in args or '-out=launch.tfplan' in args for args in commands))
            self.assertTrue(c.provisioned)
    def test_source_or_budget_recheck_failure_blocks_remaining_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=self.campaign(Path(tmp));commands=[]
            def check(*args,**kwargs):
                if kwargs:raise ValueError('source or budget changed')
                return {},{}
            with self.assertRaisesRegex(ValueError,'source or budget changed'):self.provision(c,commands,check)
            self.assertEqual([args[-1] for args in commands if 'apply' in args],['primary.tfplan'])
    def test_default_single_apply_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=self.campaign(Path(tmp),False);commands=[]
            checked=self.provision(c,commands,lambda *a,**kw:({},{}))
            self.assertEqual([args[-1] for args in commands if 'apply' in args],['launch.tfplan'])
            self.assertEqual(checked.call_count,1)

if __name__=='__main__':unittest.main()
