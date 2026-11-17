import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock,patch
import docker_read
import recover


class DockerReadTests(unittest.TestCase):
    def test_transient_socket_read_recovers_with_bounds(self):
        run=Mock(side_effect=[subprocess.CompletedProcess([],1,'','Cannot connect to the Docker daemon'),subprocess.CompletedProcess([],0,'ok','')])
        sleep=Mock()
        self.assertEqual(docker_read.docker_read(['docker','inspect','id'],run=run,sleep=sleep),'ok')
        self.assertEqual(run.call_count,2);sleep.assert_called_once_with(1)
        self.assertEqual(run.call_args.kwargs['timeout'],5)
    def test_missing_container_is_not_retried(self):
        run=Mock(return_value=subprocess.CompletedProcess([],1,'','No such object'))
        with self.assertRaises(subprocess.CalledProcessError):docker_read.docker_read(['docker','inspect','gone'],run=run)
        self.assertEqual(run.call_count,1)
    def test_socket_retry_is_finite(self):
        run=Mock(return_value=subprocess.CompletedProcess([],1,'','Cannot connect to the Docker daemon'))
        with self.assertRaisesRegex(RuntimeError,'bounded'):docker_read.docker_read(['docker','ps'],run=run,sleep=Mock())
        self.assertEqual(run.call_count,3)
    def test_timeout_is_finite(self):
        run=Mock(side_effect=subprocess.TimeoutExpired(['docker'],5))
        with self.assertRaises(subprocess.TimeoutExpired):docker_read.docker_read(['docker','ps'],run=run,sleep=Mock())
        self.assertEqual(run.call_count,3)
    def test_actions_are_never_retried(self):
        for args in [['docker','start','x'],['docker','compose','-f','x','up'],['docker','exec','x'],['node','rpc.mjs']]:
            with self.assertRaisesRegex(ValueError,'only Docker'):docker_read.docker_read(args)
    def test_oom_and_stopped_roles_fail_closed(self):
        for state in [{'Running':False,'ExitCode':137,'OOMKilled':True},{'Running':False,'ExitCode':143,'OOMKilled':False}]:
            with patch.object(docker_read,'docker_read',side_effect=['id',json.dumps(state)]),self.assertRaises(RuntimeError):
                docker_read.require_running(['docker','compose','-f','x'],['kms1'])
    def test_recipient_exit_only_after_explicit_completion(self):
        state=json.dumps({'Running':False,'ExitCode':0,'OOMKilled':False})
        with patch.object(docker_read,'docker_read',side_effect=['id',state]),self.assertRaises(RuntimeError):
            docker_read.require_running(['docker','compose','-f','x'],['recipient'])
        with patch.object(docker_read,'docker_read',side_effect=['id',state]):
            docker_read.require_running(['docker','compose','-f','x'],['recipient'],True)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.jobs=[{'name':'a','fullCase':True,'half':'nonlinear','faultPosition':'early'},
                   {'name':'b','fullCase':True,'half':'nonlinear','faultPosition':'middle'}]
        self.case={**self.jobs[0],'finalOutputKmsCalls':1,'metrics':{'leaves':8,'disputeCosts':{'transactionCount':1},
            'disputes':[{'faultIndex':0,'settlement':{'state':[3,2,True],'index':0,'certificates':[{'plaintextOpenings':0}]*2}}]}}
        self.cfg={'pocPlan':{'jobs':self.jobs}}
        self.app={'kmsCalls':1,'cases':[self.case]}
        self.prepared={'cases':self.jobs}
    def test_exact_remaining_suffix(self):
        self.assertEqual(recover.prefix_cases(self.cfg,self.app,self.prepared),[self.jobs[1]])
    def test_release_without_settlement_cannot_be_replayed(self):
        self.case['metrics']['disputes']=[]
        with self.assertRaisesRegex(ValueError,'complete dispute'):recover.prefix_cases(self.cfg,self.app,self.prepared)
    def test_uncertain_mpc_counter_blocks(self):
        self.app['kmsCalls']=2
        with self.assertRaisesRegex(ValueError,'in-flight'):recover.prefix_cases(self.cfg,self.app,self.prepared)
    def test_reordered_prefix_blocks(self):
        self.case['name']='b'
        with self.assertRaisesRegex(ValueError,'prefix'):recover.prefix_cases(self.cfg,self.app,self.prepared)
    def test_capacity_preserves_counters(self):
        remaining=[{'recordIds':['r'],'owners':['OWNER'],'n':1}]*4
        ledger={'slots':{},'records':{'r':{'owner':'owner','spent':13,'limit':18}}};before=copy.deepcopy(ledger)
        self.assertEqual(recover.capacity(remaining,ledger,18)['minimumProjectedRemaining'],1)
        self.assertEqual(ledger,before)
        with self.assertRaisesRegex(ValueError,'exhausted'):recover.capacity(remaining*2,ledger,18)
    def test_reserved_slot_blocks_even_for_other_case(self):
        with self.assertRaisesRegex(ValueError,'reserved'):recover.capacity([],{'slots':{'x':{'state':'reserved'}}},18)
    def test_overlay_changes_only_single_exact_anchor(self):
        self.assertEqual(recover.overlay('a\nawait prepare();\nz','await prepare();','RESTORE'),'a\nRESTORE\nz')
        for text in ['absent','x x']:
            with self.assertRaisesRegex(ValueError,'anchor'):recover.overlay(text,'x','y')
    def test_preservation_detects_mutation(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);(p/'data').write_text('original');manifest=recover.inventory(p)
            recover.verify_inventory(p,manifest);(p/'data').write_text('changed')
            with self.assertRaisesRegex(ValueError,'changed original'):recover.verify_inventory(p,manifest)
    def test_external_and_dangling_links_are_recorded_not_followed(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);(p/'link').symlink_to('/absent/unmounted/build-path')
            manifest=recover.inventory(p)
            self.assertEqual(manifest,{'link':{'symlink':'/absent/unmounted/build-path'}})
            recover.verify_inventory(p,manifest)

if __name__=='__main__':unittest.main()
