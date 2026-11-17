import json
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import gce_image
import cloud_setup
import topology

class TemporaryBuilderTests(unittest.TestCase):
    def setUp(self):
        self.config=json.loads((HERE/'config.example.json').read_text())
        self.config['project_id']='example-research-project'
        self.resources={'builderServiceAccount':'projects/example/serviceAccounts/builder@example.test'}
    def test_builder_is_single_disposable_machine_without_protocol_state(self):
        tf=gce_image.terraform(self.config,{'operatorPrincipal':'user:researcher@example.test'},self.resources)
        resources=tf['resource']
        self.assertEqual(len(resources['google_compute_instance']),1)
        vm=resources['google_compute_instance']['builder']
        self.assertEqual(vm['machine_type'],'n2-standard-8')
        self.assertEqual(vm['scheduling']['instance_termination_action'],'STOP')
        self.assertEqual(vm['scheduling']['max_run_duration']['seconds'],14400)
        self.assertNotIn('attached_disk',vm)
        self.assertNotIn('google_compute_disk',resources)
        self.assertEqual(resources['google_compute_firewall']['builder']['source_ranges'],['35.235.240.0/20'])
        self.assertNotIn('kms',vm['metadata_startup_script'])
    def test_highmem_builder_keeps_protocol_hosts_and_build_limits(self):
        hosts=topology.hosts(self.config)
        self.config['builder_machine_type']='n2-highmem-4'
        topology.validate(self.config)
        tf=gce_image.terraform(self.config,{'operatorPrincipal':'user:researcher@example.test'},self.resources)
        vm=tf['resource']['google_compute_instance']['builder']
        self.assertEqual(vm['machine_type'],'n2-highmem-4')
        self.assertEqual(vm['min_cpu_platform'],'Intel Ice Lake')
        self.assertEqual(vm['boot_disk']['initialize_params']['size'],100)
        self.assertEqual(vm['scheduling']['max_run_duration']['seconds'],14400)
        self.assertEqual(topology.hosts(self.config),hosts)
    def test_n2d_profile_keeps_four_homogeneous_hosts_and_an_intel_builder(self):
        self.config.update(host_machine_type='n2d-standard-4',min_cpu_platform='AMD Milan')
        self.config['builder_machine_type']='n2-highmem-4'
        hosts=topology.hosts(self.config)
        self.assertEqual(len(hosts),4)
        self.assertTrue(all(h['machine_type']=='n2d-standard-4' for h in hosts))
        self.assertEqual(topology.plan(self.config)['capacity_request']['ram_gib'],64)
        vm=gce_image.terraform(self.config,{'operatorPrincipal':'user:researcher@example.test'},self.resources)['resource']['google_compute_instance']['builder']
        self.assertEqual(vm['machine_type'],'n2-highmem-4')
        self.assertEqual(vm['min_cpu_platform'],'Intel Ice Lake')
        self.config['min_cpu_platform']='Intel Ice Lake'
        with self.assertRaises(ValueError):topology.validate(self.config)
        self.config.update(min_cpu_platform='AMD Milan',layout='dedicated')
        with self.assertRaises(ValueError):topology.validate(self.config)
        self.config.update(layout='four-hosts',builder_min_cpu_platform='AMD Milan')
        with self.assertRaises(ValueError):topology.validate(self.config)
    def test_unsupported_builder_shapes_are_rejected(self):
        for value in ['n2-standard-4','n2-highmem-8','e2-standard-8',None,True]:
            with self.subTest(value=value):
                self.config['builder_machine_type']=value
                with self.assertRaises(ValueError):topology.validate(self.config)
                with self.assertRaises(ValueError):gce_image.terraform(self.config,{'operatorPrincipal':'user:researcher@example.test'},self.resources)
    def test_builder_zone_changes_only_disposable_resource_locations(self):
        hosts=topology.hosts(self.config)
        selected=self.config['regions'][1]
        self.config['builder_zone']=selected['zone']
        topology.validate(self.config)
        resources=gce_image.terraform(self.config,{'operatorPrincipal':'user:researcher@example.test'},self.resources)['resource']
        self.assertEqual(resources['google_compute_instance']['builder']['zone'],selected['zone'])
        self.assertEqual(resources['google_compute_subnetwork']['builder']['region'],selected['name'])
        self.assertEqual(resources['google_compute_instance_iam_member']['builder']['zone'],selected['zone'])
        self.assertEqual(resources['google_iap_tunnel_instance_iam_member']['builder']['zone'],selected['zone'])
        self.assertEqual(topology.hosts(self.config),hosts)
    def test_builder_zone_must_be_one_of_the_four_configured_zones(self):
        self.assertEqual(topology.builder_location(self.config),self.config['regions'][0])
        for value in ['unconfigured-zone','us-central1-z',None,True]:
            with self.subTest(value=value):
                self.config['builder_zone']=value
                with self.assertRaises(ValueError):topology.validate(self.config)
                with self.assertRaises(ValueError):gce_image.terraform(self.config,{'operatorPrincipal':'user:researcher@example.test'},self.resources)
    def test_quota_preflight_uses_selected_builder_without_summing_protocol_hosts(self):
        def inspect(*args):
            if args[:2]==('projects','describe'):
                return {'lifecycleState':'ACTIVE','projectId':self.config['project_id'],'projectNumber':'1'}
            if args[:3]==('billing','projects','describe'):return {'billingEnabled':True}
            if args[:2]==('services','list'):return [{'config':{'name':api}} for api in cloud_setup.APIS]
            if args[:3]==('compute','project-info','describe'):
                return {'quotas':[{'metric':'CPUS_ALL_REGIONS','limit':16,'usage':0}]}
            if args[:3]==('compute','regions','describe'):
                return {'quotas':[{'metric':metric,'limit':limit,'usage':0}
                                  for metric,limit in [('N2_CPUS',8),('N2D_CPUS',16),('SSD_TOTAL_GB',200),('IN_USE_ADDRESSES',1)]]}
            if args[:3]==('compute','zones','describe'):
                return {'status':'UP','availableCpuPlatforms':['Intel Ice Lake','AMD Milan']}
            raise AssertionError('unexpected preflight request')
        for machine,needed in [('n2-standard-8',8),('n2-highmem-4',4)]:
            self.config['builder_machine_type']=machine
            for index in [0,1]:
                self.config['builder_zone']=self.config['regions'][index]['zone']
                with self.subTest(machine=machine,region=index),patch('cloud_setup.ensure'),patch('cloud_setup.subprocess.check_output',return_value='researcher@example.test\n'),patch('cloud_setup.gcloud',side_effect=inspect):
                    report=cloud_setup.inspect(self.config)
                for row in [r for r in report['quota'] if r['metric']=='N2_CPUS']:
                    self.assertEqual(row['required'],needed if row['region']==self.config['regions'][index]['name'] else 4)
        self.config.update(host_machine_type='n2d-standard-4',min_cpu_platform='AMD Milan',builder_machine_type='n2-highmem-4')
        with patch('cloud_setup.ensure'),patch('cloud_setup.subprocess.check_output',return_value='researcher@example.test\n'),patch('cloud_setup.gcloud',side_effect=inspect):
            report=cloud_setup.inspect(self.config)
        n2d=[row for row in report['quota'] if row['metric']=='N2D_CPUS']
        n2=[row for row in report['quota'] if row['metric']=='N2_CPUS']
        self.assertEqual(len(n2d),4);self.assertTrue(all(row['required']==4 for row in n2d))
        self.assertEqual(len(n2),1);self.assertEqual(n2[0]['region'],self.config['regions'][1]['name'])
        self.assertEqual(n2[0]['required'],4)
    def test_repeated_attempts_share_the_allowance(self):
        with tempfile.TemporaryDirectory() as folder:
            ledger=Path(folder)/'ledger.local.json';quote={'build_registry':'8.00'}
            for _ in range(3):gce_image.reserve(self.config,quote,ledger,[])
            with self.assertRaises(ValueError):gce_image.reserve(self.config,quote,ledger,[])
            self.assertEqual(len(json.loads(ledger.read_text())['reservations']),3)
    def test_an_active_remote_build_blocks_another_attempt(self):
        with tempfile.TemporaryDirectory() as folder:
            ledger=Path(folder)/'ledger.local.json'
            with self.assertRaises(ValueError):gce_image.reserve(self.config,{'build_registry':'8.00'},ledger,[{'status':'WORKING'}])
            self.assertFalse(ledger.exists())
    def test_read_probe_retries_transport_without_restarting_a_job(self):
        args=['sudo','cat','/srv/vcfhe-build/status.json']
        remote=Mock();remote.run.side_effect=[subprocess.CalledProcessError(1,args),
            subprocess.TimeoutExpired(args,40),subprocess.CompletedProcess(args,0,'{"exitCode":0}','')]
        with patch('gce_image.time.sleep') as sleep:
            self.assertEqual(gce_image.read_probe(remote,args,json_result=True),{'exitCode':0})
        self.assertEqual(remote.run.call_count,3)
        self.assertEqual([call.args[0] for call in remote.run.call_args_list],[args,args,args])
        self.assertTrue(all(call.kwargs['timeout']==40 for call in remote.run.call_args_list))
        self.assertEqual([call.args[0] for call in sleep.call_args_list],[2,4])
        remote.upload.assert_not_called();remote.shell.assert_not_called()
    def test_read_probe_stops_after_three_failures(self):
        args=['sudo','tail','-n','8','/srv/vcfhe-build/build.log']
        remote=Mock();remote.run.side_effect=subprocess.CalledProcessError(1,args)
        with patch('gce_image.time.sleep'),self.assertRaises(subprocess.CalledProcessError):
            gce_image.read_probe(remote,args)
        self.assertEqual(remote.run.call_count,3)
        remote.upload.assert_not_called();remote.shell.assert_not_called()
    def test_read_probe_retries_incomplete_status_json(self):
        remote=Mock();remote.run.side_effect=[subprocess.CompletedProcess([],0,'{"exitCode":',''),
            subprocess.CompletedProcess([],0,'{"exitCode":0}','')]
        with patch('gce_image.time.sleep'):
            self.assertEqual(gce_image.read_probe(remote,['sudo','cat','status.json'],json_result=True),{'exitCode':0})
        self.assertEqual(remote.run.call_count,2)
    def test_absent_status_is_pending_without_a_transport_retry(self):
        remote=Mock();remote.run.return_value=subprocess.CompletedProcess([],0,'null\n','')
        with patch('gce_image.time.sleep') as sleep:
            self.assertIsNone(gce_image.read_probe(remote,['sudo','python3','-c','read-status-only'],json_result=True))
        self.assertEqual(remote.run.call_count,1);sleep.assert_not_called()

if __name__=='__main__':unittest.main()
