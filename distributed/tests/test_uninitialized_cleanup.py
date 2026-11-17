import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('cleanup_uninitialized',HERE/'maintenance/uninitialized.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)

class PartialCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.run=Path(self.temp.name).resolve()/'failed-smoke';self.run.mkdir(mode=0o700)
        self.config=json.loads((helper.HERE/'config.example.json').read_text())
        self.config.update(project_id='example-research-project',campaign='example-test-smoke',execution_mode='smoke')
        self.write('distributed-config.json',self.config)
        self.launch={'config':self.config,'status':'failed','createdAt':'2026-10-27T10:00:00+00:00',
            'stages':[{'name':'GCP provisioning','status':'failed'}]}
        self.write('launch-state.json',self.launch)
        self.write('terraform/main.tf.json',helper.gcp.terraform(self.config))
        self.write('terraform/terraform.tfvars.json',{'project_id':self.config['project_id']})
    def write(self,name,value):
        p=self.run/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(value))
    def test_provisioning_only_scope_accepted_without_cloud_actions(self):
        with patch.object(helper,'cloud') as cloud:
            self.assertEqual(helper.scope(self.config,self.run)[0],self.run)
            cloud.assert_not_called()
    def test_any_actor_stage_or_identity_directory_refuses_cleanup(self):
        self.launch['stages'].append({'name':'Local participant identities','status':'failed'})
        self.write('launch-state.json',self.launch)
        with self.assertRaises(ValueError):helper.scope(self.config,self.run)
        self.launch['stages'].pop();self.write('launch-state.json',self.launch)
        (self.run/'enrollment').mkdir()
        with self.assertRaises(ValueError):helper.scope(self.config,self.run)
    def test_terraform_plan_cannot_delete_shared_repo_or_create_update_resources(self):
        rows={'google_compute_instance.host_2':{'attributes':{'id':'owned-instance','instance_id':'1234'}}}
        change={'mode':'managed','address':'google_compute_instance.host_2',
                'change':{'actions':['delete'],'before':{'id':'owned-instance','instance_id':'1234'}}}
        self.assertEqual(helper.validate_plan({'resource_changes':[change]},rows),['google_compute_instance.host_2'])
        for address,actions in [(helper.REPOSITORY,['delete']),('google_storage_bucket.foreign',['delete']),
                                ('google_compute_instance.host_2',['create']),('google_compute_instance.host_2',['update'])]:
            bad=copy.deepcopy(change);bad['address']=address;bad['change']['actions']=actions
            with self.assertRaises(ValueError):helper.validate_plan({'resource_changes':[bad]},rows)
    def test_destroy_plan_replaced_identity_is_rejected(self):
        rows={'google_compute_instance.host_2':{'attributes':{'id':'owned','instance_id':'1234'}}}
        change={'mode':'managed','address':'google_compute_instance.host_2',
                'change':{'actions':['delete'],'before':{'id':'owned','instance_id':'9999'}}}
        with self.assertRaises(ValueError):helper.validate_plan({'resource_changes':[change]},rows)
    def test_shared_repository_must_be_in_original_state_and_unknown_types_refused(self):
        with self.assertRaises(ValueError):helper.state_rows(self.config,{'resources':[]})
        with self.assertRaises(ValueError):helper.state_rows(self.config,{'resources':[{
            'mode':'managed','type':'google_storage_bucket','name':'foreign','instances':[{'attributes':{}}]}]})
    def test_date_comparison_respects_timezone_and_rejects_old_state(self):
        self.assertTrue(helper.fresh('2026-10-27T03:01:00-07:00','2026-10-27T10:00:00+00:00'))
        self.assertFalse(helper.fresh('2026-10-27T02:59:00-07:00','2026-10-27T10:00:00+00:00'))
    def test_service_account_absence_requires_successful_project_inventory(self):
        email='owned@'+self.config['project_id']+'.iam.gserviceaccount.com'
        args=['iam','service-accounts','describe',email]
        with patch.object(helper.safe,'_cloud',return_value=[]) as query:
            self.assertIsNone(helper.cloud(self.config,args,missing=True))
            self.assertEqual(query.call_args.args[0][:3],['iam','service-accounts','list'])
        with patch.object(helper.safe,'_cloud',side_effect=ValueError('Permission denied')):
            with self.assertRaises(ValueError):helper.cloud(self.config,args,missing=True)
        with patch.object(helper.safe,'_cloud',return_value={}):
            with self.assertRaises(ValueError):helper.cloud(self.config,args,missing=True)
    def test_service_account_inventory_retains_exact_live_identity(self):
        email='owned@'+self.config['project_id']+'.iam.gserviceaccount.com'
        owned={'email':email,'name':'projects/example/serviceAccounts/'+email,'uniqueId':'12345'}
        another={'email':'other@'+self.config['project_id']+'.iam.gserviceaccount.com','uniqueId':'99999'}
        with patch.object(helper.safe,'_cloud',return_value=[another,owned]):
            self.assertEqual(helper.cloud(self.config,['iam','service-accounts','describe',email],missing=True),owned)
        with patch.object(helper.safe,'_cloud') as query:
            with self.assertRaises(ValueError):helper.cloud(self.config,['iam','service-accounts','describe','foreign@other-project.iam.gserviceaccount.com'],missing=True)
            query.assert_not_called()
    def test_prepare_preserves_originals_and_detaches_repository_only_in_copy(self):
        self._assert_prepare_preserves_originals()
    def test_prepare_uses_explicit_registry_region_after_first_host_moves(self):
        self.config['registry_region']='us-central1'
        self.config['regions'][0].update(name='us-east1',zone='us-east1-b')
        self.write('distributed-config.json',self.config)
        self.write('launch-state.json',self.launch)
        self.write('terraform/main.tf.json',helper.gcp.terraform(self.config))
        self._assert_prepare_preserves_originals()
    def _assert_prepare_preserves_originals(self):
        host=helper.topology.hosts(self.config)[0]
        repository={'project':self.config['project_id'],'id':'repository-owned',
            'name':'repository-owned','repository_id':helper.gcp.image_repository(self.config),
            'location':helper.topology.registry_region(self.config)}
        disk={'project':self.config['project_id'],'id':'state-disk-owned','disk_id':'12345',
            'name':host['name']+'-state','zone':host['zone']}
        original={'serial':7,'lineage':'synthetic-only','resources':[
            {'type':'google_artifact_registry_repository','name':'images','mode':'managed',
             'instances':[{'attributes':repository}]},
            {'type':'google_compute_disk','name':'host_1','mode':'managed',
             'instances':[{'attributes':disk}]}]}
        self.write('terraform/terraform.tfstate',original)
        original_bytes=(self.run/'terraform/terraform.tfstate').read_bytes()
        def terraform(work,args,log):
            if args[0]=='plan':(work/'cleanup.tfplan').write_bytes(b'synthetic-plan')
        def show(work,planfile,destination):
            value={'resource_changes':[{'address':'google_compute_disk.host_1','mode':'managed',
                'change':{'actions':['delete'],'before':disk}}]}
            helper.write(destination,value);return value
        with patch.object(helper,'inspect_live',return_value=[]),\
             patch.object(helper,'cloud',return_value={'name':'repository-owned','createTime':'2026-10-27T10:00:00Z'}) as cloud,\
             patch.object(helper,'terraform',side_effect=terraform),patch.object(helper,'show_plan',side_effect=show):
            result=helper.prepare(self.config,self.run)
        destination=self.run/'uninitialized-cleanup-private'
        self.assertEqual(result['destroyActions'],1)
        self.assertEqual((self.run/'terraform/terraform.tfstate').read_bytes(),original_bytes)
        copied=helper.read(destination/'terraform-work/terraform.tfstate')
        self.assertFalse(any(r['type']=='google_artifact_registry_repository' for r in copied['resources']))
        copied_config=helper.read(destination/'terraform-work/main.tf.json')
        self.assertNotIn('prevent_destroy',copied_config['resource']['google_compute_disk']['host_1']['lifecycle'])
        self.assertTrue(helper.read(self.run/'terraform/main.tf.json')['resource']['google_compute_disk']['host_1']['lifecycle']['prevent_destroy'])
        with tarfile.open(destination/'original-failed-run.tar') as archive:
            self.assertEqual(archive.extractfile('terraform/terraform.tfstate').read(),original_bytes)
        self.assertEqual(destination.stat().st_mode&0o777,0o700)
        self.assertEqual(cloud.call_count,1)
        self.assertIn('describe',cloud.call_args.args[1])
        args=cloud.call_args.args[1]
        self.assertEqual(args[args.index('--location')+1],helper.topology.registry_region(self.config))
    def test_cross_region_registry_iam_guard_rejects_first_host_location(self):
        self.config['registry_region']='us-central1'
        self.config['regions'][0].update(name='us-east1',zone='us-east1-b')
        account_id=helper.gcp.terraform(self.config)['resource']['google_service_account']['host_1']['account_id']
        email=account_id+'@'+self.config['project_id']+'.iam.gserviceaccount.com'
        account={'account_id':account_id,'name':'projects/'+self.config['project_id']+'/serviceAccounts/'+email,
                 'id':'projects/'+self.config['project_id']+'/serviceAccounts/'+email,'email':email,'project':self.config['project_id']}
        repository={'name':'repository-owned','id':'repository-owned','project':self.config['project_id']}
        grant={'member':'serviceAccount:'+email,'role':'roles/artifactregistry.reader','location':'us-central1',
               'repository':'repository-owned','project':self.config['project_id']}
        state={'resources':[{'mode':'managed','type':kind,'name':name,'instances':[{'attributes':attrs}]}
            for kind,name,attrs in [('google_artifact_registry_repository','images',repository),
                                    ('google_service_account','host_1',account),
                                    ('google_artifact_registry_repository_iam_member','host_1',grant)]]}
        self.assertEqual(len(helper.state_rows(self.config,state)),3)
        grant['location']='us-east1'
        with self.assertRaises(ValueError):helper.state_rows(self.config,state)

if __name__=='__main__':unittest.main()
