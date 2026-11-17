import copy
import importlib.util
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('workflow_continuation_transforms',HERE/'transforms.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class ContinuationGates(unittest.TestCase):
    def setUp(self):
        self.pairs={'status':'passed','rows':[{'warmup':False} for _ in range(480)]+[{'warmup':True} for _ in range(18)]}
        self.app={'cases':[],'kmsCalls':0}
        self.probe={'allDenied':True,'transactionsSubmitted':0,
            'views':[{'blockHash':'same','requestExists':False,'slotUnused':True,'totalReservations':0} for _ in range(4)],
            'results':[{'grpcStatus':7} for _ in range(4)]}
    def test_complete_untouched_prefix(self):
        m.verify_prefix(self.pairs,self.app,self.probe)
    def test_refuse_any_release_or_completed_case(self):
        for field,value in [('kmsCalls',1),('cases',[{'name':'done'}])]:
            app={**self.app,field:value}
            with self.assertRaises(ValueError):m.verify_prefix(self.pairs,app,self.probe)
    def test_refuse_missing_pairs_or_changed_warmups(self):
        for value in [self.pairs['rows'][:-1],self.pairs['rows']+[{'warmup':False}],
                      [{'warmup':False} for _ in range(498)]]:
            with self.assertRaises(ValueError):m.verify_prefix({**self.pairs,'rows':value},self.app,self.probe)
    def test_refuse_unavailable_core_or_actual_acceptance(self):
        for code in [0,14,3,None]:
            p=copy.deepcopy(self.probe);p['results'][0]['grpcStatus']=code
            with self.assertRaises(ValueError):m.verify_prefix(self.pairs,self.app,p)
    def test_refuse_reserved_or_inconsistent_chain(self):
        for field,value in [('requestExists',True),('slotUnused',False),('blockHash','other'),('totalReservations',1)]:
            p=copy.deepcopy(self.probe);p['views'][0][field]=value
            with self.assertRaises(ValueError):m.verify_prefix(self.pairs,self.app,p)
    def test_configuration_may_only_change_continuation_identity(self):
        p={'executionProfile':'gcp-four-hosts-role-local-v1','runId':'original','windowSeconds':120,'threshold':3}
        c={**p,'runId':'new','workflowContinuation':{'profile':m.PROFILE,'fullCases':['one']}}
        m.verify_configuration(p,c,['one'])
        for field,value in [('windowSeconds',2),('threshold',2),('runId','original')]:
            with self.assertRaises(ValueError):m.verify_configuration(p,{**c,field:value},['one'])
    def test_anchors_refuse_added_or_missing_calls(self):
        with self.assertRaises(ValueError):m.evaluator_overlay('if(cfg.pocPlan)await runPairs(cfg,prepared);')
        anchor="await (await import('/app/distributed/admission.mjs')).verifyBytes(cfg,prepared);\n if(cfg.pocPlan)await runPairs(cfg,prepared);"
        result=m.evaluator_overlay(anchor+'\nALL_ORIGINAL_WORKFLOWS;')
        self.assertIn('ALL_ORIGINAL_WORKFLOWS;',result)
        self.assertNotIn('await runPairs',result)
        with self.assertRaises(ValueError):m.evaluator_overlay(anchor+anchor)
    def test_original_owner_guards_are_kept_in_restore_overlay(self):
        restore=(HERE.parents[2]/'threshold-kms/recovery/owner-restore-v3.mjs').read_text()
        original='GUARDS_BEFORE;\nawait prepare();\nGUARDS_AFTER;'
        value=m.owner_overlay(original,restore)
        self.assertIn('GUARDS_BEFORE;',value)
        self.assertIn('GUARDS_AFTER;',value)
        self.assertIn('ownerChain.withView',value)
        self.assertIn('remaining continuation releases exceed',value)
        self.assertIn('cfg.workflowContinuation.fullCases',value)
        self.assertNotIn('await prepare();',value)
    def test_continuation_has_no_setup_or_provisioning_invocation(self):
        import ast
        tree=ast.parse((HERE/'continue.py').read_text())
        forbidden={'run_all','initialize','provision','bootstrap','enrollment','validators','policy','kms','roles','restore_cache'}
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):
                self.assertNotIn(node.func.attr,forbidden)
    def test_storage_increase_preserves_every_archive_check(self):
        source=(HERE.parents[1]/'cloud_results/preservation.py').read_text()
        result=m.retention_overlay(source)
        self.assertEqual(result.replace('256*1024**3','100*1024**3'),source)
        for phrase in ['store.download','archive member changed','Insufficient cloud boot-disk',
                       'Foreign state mount','Original full','original']:
            if phrase in source:self.assertIn(phrase,result)
        with self.assertRaises(ValueError):m.retention_overlay(source,1024)
    def test_scratch_overlay_has_exact_checked_anchors(self):
        source=(HERE.parents[1]/'cloud_results/preservation.py').read_text()
        value=m.retention_overlay(source,scratch=True)
        compile(value,'retention.py','exec')
        self.assertIn('validate_archive_attachment(campaign,host,actual,expected,attached)',value)
        self.assertIn('archive_scratch_path(campaign,host)',value)
        for phrase in ['store.download','archive member changed','Foreign state mount',
                       'ownership.local.json','Actor remains active']:
            if phrase in source:self.assertIn(phrase,value)
        with self.assertRaises(ValueError):m.retention_overlay(source.replace('Unexpected disk attachment','changed'),scratch=True)
    def test_finish_authority_keeps_time_storage_and_cost_accounting(self):
        source=(HERE.parents[1]/'admission.mjs').read_text()
        value=m.admission_overlay(source)
        for phrase in ['elapsed+envelope.caseAllowanceHours<=envelope.plannedHours',
                       "fs.statfs('/fixtures')",'disk.bavail*disk.bsize>=envelope.minimumFreeBytes',
                       'elapsed*envelope.hourlyUsd+envelope.fixedUpperUsd','projectedUsd:projected',
                       'maximumVmRuntimeSeconds===86400','stopOnBillingThreshold===false']:
            self.assertIn(phrase,value)
        self.assertIn('forecastCeilingExceeded:!withinForecast',value)
        self.assertIn('explicitUserRequest===true',value)
        with self.assertRaises(ValueError):m.admission_overlay(source.replace('projectedUsd:projected','changed'))

class ScratchOwnership(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('continuation_storage',HERE/'continuation_storage.py')
        self.storage=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.storage)
        self.scratch={'name':'archive','source':'projects/p/zones/z/disks/archive','vmId':'123'}
        self.expected={'boot','state'}
        self.actual={'id':'123','disks':[{'source':'boot'},{'source':'state'},
            {'source':self.scratch['source'],'autoDelete':True,'deviceName':'vcfhe-archive-c1'}]}
    def test_only_original_two_disks_without_scratch(self):
        self.storage.check_layout({'disks':[{},{}]},self.expected,self.expected,None)
        with self.assertRaises(ValueError):self.storage.check_layout(self.actual,self.expected,self.expected|{'archive'},None)
    def test_exact_owned_scratch(self):
        self.storage.check_layout(self.actual,self.expected,self.expected|{'archive'},self.scratch)
    def test_refuse_foreign_changed_or_unretired_scratch(self):
        for kind in ['vm','autoDelete','device','source','extra']:
            value=copy.deepcopy(self.actual)
            if kind=='vm':value['id']='other'
            elif kind=='extra':value['disks'].append({'source':'foreign'})
            else:value['disks'][-1][{'device':'deviceName','source':'source'}.get(kind,kind)]='other'
            with self.assertRaises(ValueError):self.storage.check_layout(value,self.expected,self.expected|{'archive'},self.scratch)

if __name__=='__main__':unittest.main()
