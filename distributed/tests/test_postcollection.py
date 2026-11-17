"""A collector repair cannot turn a failed protocol into successful evidence."""
import copy
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cloud_results.common import read, write, sha
from cloud_results.postcollection import eligible, verify_attestation, SCHEMA
import deployment


class PostcollectionEligibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name);self.original=root/'original';self.view=root/'view';self.addendum=root/'addendum'
        import json
        outer=json.loads((Path(__file__).resolve().parents[1]/'config.example.json').read_text())
        outer.update(execution_mode='smoke',diagnostic_profile='regional-output-release-v1',maximum_vm_runtime_seconds=14400)
        self.cfg=deployment.campaign_config(outer,'synthetic-regional')
        self.app={'status':'passed','cases':[{'name':'regional_qoe_compliance-0','half':'nonlinear','n':50,'regional':True,'metrics':{'disputes':[{}]}}]}
        for run in (self.original,self.view):
            write(run/'config/campaign.json',self.cfg)
            write(run/'state.json',{'status':'validating','config':self.cfg,'source':{}})
            write(run/'distributed/source.json',{'localSource':{}})
            write(run/'distributed/public-identities.json',{})
            write(run/'distributed/task-inventory.json',[])
            write(run/'reports/application.json',self.app)
        write(self.original/'launch-state.json',{'status':'failed','error':'experiment_plan.py failed',
            'stages':[{'name':'Full evaluation','status':'passed'},{'name':'Collect and validate evidence','status':'failed'}]})
        self.witness='owner/regional_qoe_compliance-0/approved-context.json'
        write(self.addendum/self.witness,{'synthetic':'context'});write(self.view/self.witness,{'synthetic':'context'})
        write(self.addendum/'acquisition.local.json',{'schema':'missing-owner-public-context-acquisition-v1',
            'status':'copied-existing-evidence','role':'owner-1','host':'host-1','file':self.witness,
            'sha256':sha(self.addendum/self.witness),'protocolRequestsRepeated':0,'nativeRunUntouched':True})
        self.module=SimpleNamespace(SEALED_ARTIFACT_FOLDERS=('reports','owner','config'),source_manifest=lambda:{})
    def check(self):
        with patch('deployment.campaign_module',return_value=self.module):return eligible(self.original,self.view,self.addendum)
    def test_only_public_witness_omission_is_eligible(self):self.assertEqual(self.check()[1]['fullCases'],1)
    def test_original_failure_is_preserved(self):
        before=sha(self.original/'state.json');self.check();self.assertEqual(sha(self.original/'state.json'),before)
        self.assertFalse((self.original/'seal.json').exists())
    def test_protocol_failure_is_refused(self):
        launch=read(self.original/'launch-state.json');launch['stages'][0]['status']='failed';write(self.original/'launch-state.json',launch)
        with self.assertRaises(ValueError):self.check()
    def test_original_passed_status_is_ineligible(self):
        state=read(self.original/'state.json');state['status']='passed';write(self.original/'state.json',state)
        with self.assertRaises(ValueError):self.check()
    def test_original_or_view_ordinary_seal_is_refused(self):
        for root in (self.original,self.view):
            write(root/'seal.json',{})
            with self.assertRaises(ValueError):self.check()
            (root/'seal.json').unlink()
    def test_changed_recipient_result_is_refused(self):
        write(self.original/'recipient/result-0.json',{'value':1});write(self.view/'recipient/result-0.json',{'value':2})
        with self.assertRaisesRegex(ValueError,'changed'):self.check()
    def test_failed_application_is_refused(self):
        app=copy.deepcopy(self.app);app['status']='failed';write(self.original/'reports/application.json',app)
        with self.assertRaises(ValueError):self.check()
    def test_changed_recovered_context_is_refused(self):
        write(self.view/self.witness,{'synthetic':'other'})
        with self.assertRaisesRegex(ValueError,'changed'):self.check()
    def test_repeated_protocol_requests_are_ineligible(self):
        write(self.addendum/'acquisition.local.json',{'protocolRequestsRepeated':1,'nativeRunUntouched':True})
        with self.assertRaises(ValueError):self.check()
    def test_existing_original_context_is_ineligible(self):
        write(self.original/self.witness,{'synthetic':'context'})
        with self.assertRaisesRegex(ValueError,'inapplicable'):self.check()
    def test_active_cleanup_is_ineligible(self):
        launch=read(self.original/'launch-state.json');launch['stages'].append({'name':'cleanup','status':'running'});write(self.original/'launch-state.json',launch)
        with self.assertRaises(ValueError):self.check()
    def test_same_directory_is_refused(self):
        with self.assertRaises(ValueError):eligible(self.original,self.original,self.addendum)


class PostcollectionInventoryTests(unittest.TestCase):
    def test_changed_derived_evidence_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            view=Path(tmp);write(view/'state.json',{'status':'validating'});write(view/'reports/synthetic.json',{})
            proof={'schema':SCHEMA,'status':'passed','evaluationPublishable':False,'originalSealVerified':False,
                'originalRunnerStatus':'failed','originalStateStatus':'validating','protocolRequestsRepeated':0,
                'validatedFiles':{'reports/synthetic.json':sha(view/'reports/synthetic.json')}}
            write(view/'postcollection-attestation.local.json',proof)
            self.assertEqual(verify_attestation(view)['status'],'passed')
            write(view/'reports/synthetic.json',{'changed':True})
            with self.assertRaises(ValueError):verify_attestation(view)

if __name__=='__main__':unittest.main()
