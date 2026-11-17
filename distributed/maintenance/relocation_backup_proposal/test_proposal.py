"""Synthetic infrastructure with original scope, seal and TAR validators."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import recovery

SOURCE = recovery.SOURCE
sys.path.insert(0,str(SOURCE))
import deployment
import topology
from smoke import validate_cases

spec = importlib.util.spec_from_file_location('original_cleanup_fixtures',SOURCE/'tests/test_smoke_cleanup.py')
fixture_module = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture_module)


class RelocationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.SmokeCleanupTests()
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.run = self.fixture.run
        self.config = self.fixture.config
        self.parent = self.run.parent
        self.logical = self.parent/'original-logical-location'
        self.logical.symlink_to(self.run,target_is_directory=True)
        self.destination = self.run/'relocation-private-backup'
        self.provenance = self.run/'relocation-recovery.local.json'
        self.build = self.parent/'original-frozen-build'; self.build.mkdir()
        self.record = {'distributedSource':{p.name:recovery.sha(p) for p in SOURCE.iterdir()
                       if p.is_file() and p.suffix in ('.py','.mjs','.sh')},
                       'localSource':deployment.campaign_module().source_manifest()}
        (self.build/'distributed-source.json').write_text(json.dumps(self.record))
        self.fixture.put('launch-state.json',{'config':self.config,'status':'smoke-complete-cleanup-failed',
            'stages':[{'name':'Full evaluation','status':'passed'},
                      {'name':'Collect and validate evidence','status':'passed'},
                      {'name':'Preserve private smoke state before resource removal','status':'failed'}]})
        cfg={'smoke':True,'readinessOnly':True,'half':'both','parameters':'Test',
             'classification':'test-insecure-distributed-smoke-not-evaluation'}
        self.fixture.put('config/campaign.json',cfg)
        self.fixture.put('state.json',{'status':'passed','config':cfg,'source':self.record['localSource'],'datasets':{}})
        cases=[{'name':'linear-acr-27-0','half':'linear','n':27,'metrics':{}},
               {'name':'regulatory_qoe_compliance-0','half':'nonlinear','n':50,'metrics':{'disputes':[{}]}},
               {'name':'regional_qoe_compliance-0','half':'nonlinear','n':50,'metrics':{'disputes':[{}]}}]
        self.fixture.put('reports/application.json',{'status':'passed','cases':cases})
        self.fixture.put('distributed/source.json',self.record)
        self.fixture.put('distributed/execution.json',{'status':'completed','fullCases':3,'measuredPairs':0,'warmups':0})
        self.fixture.put('distributed/smoke-result.json',dict(status='passed',**validate_cases(cases)))
        self.seal()

    def seal(self):
        names=['state.json','config/campaign.json','reports/application.json','distributed/source.json','distributed/execution.json']
        self.fixture.put('seal.json',{'version':deployment.campaign_module().VERSION,
            'source':self.record['localSource'],'files':{n:recovery.sha(self.run/n) for n in names},
            'parameters':'Test','classification':'test-insecure-distributed-smoke-not-evaluation',
            'halves':['linear','nonlinear']})

    def module(self):
        return recovery.isolated_cleanup(SOURCE,self.record)[0]

    def prepare(self):
        with patch.object(recovery,'RUN_PARENT',self.parent):
            return recovery.prepare(self.logical,self.run,self.destination,self.build,self.provenance)

    def test_only_inspect_scope_call_changes_original_functions_identical(self):
        original=(SOURCE/'smoke_cleanup.py').read_text()
        changed=original.replace(recovery.ANCHOR,recovery.REPLACEMENT)
        left={n.name:ast.dump(n,include_attributes=False) for n in ast.parse(original).body if isinstance(n,ast.FunctionDef)}
        right={n.name:ast.dump(n,include_attributes=False) for n in ast.parse(changed).body if isinstance(n,ast.FunctionDef)}
        self.assertEqual([n for n in left if left[n]!=right[n]],['inspect_plan'])
        self.assertEqual(left['_scope'],right['_scope'])
        for name in ['backup','verify_backup','apply','_state','_check_identity']:
            self.assertEqual(left[name],right[name])

    def test_terminal_cleanup_failure_can_be_inspected_without_status_rewrite(self):
        before=(self.run/'launch-state.json').read_bytes()
        module=self.module()
        with patch.object(module,'_cloud',side_effect=self.fixture.cloud):
            plan=module.inspect_plan(self.config,self.run)
        self.assertEqual(len([r for r in plan['resources'] if r['type']=='google_compute_instance']),4)
        self.assertEqual((self.run/'launch-state.json').read_bytes(),before)
        self.assertEqual(self.fixture.mutations,[])

    def test_original_scope_still_rejects_retry_without_explicit_flag(self):
        module=self.module()
        with self.assertRaises(ValueError):module._scope(self.config,self.run)
        self.assertEqual(module._scope(self.config,self.run,allow_cleanup_retry=True),self.run)

    def test_prepare_uses_original_seal_verifier_and_no_cloud_operations(self):
        before=(self.run/'launch-state.json').read_bytes()
        with patch('subprocess.run',side_effect=AssertionError('No command expected')):
            result=self.prepare()
        self.assertEqual(result['status'],'prepared-local-only')
        self.assertEqual(result['logicalRunIdentity'],str(self.logical))
        self.assertEqual(result['physicalRun'],str(self.run))
        self.assertFalse(result['backupOnlyVmRestartPlan']['automaticallyExecuted'])
        self.assertFalse(self.destination.exists())
        self.assertEqual((self.run/'launch-state.json').read_bytes(),before)

    def test_missing_collect_or_failed_protocol_refused(self):
        original=json.loads((self.run/'launch-state.json').read_text())
        for value in ['failed','running','completed']:
            with self.subTest(value=value):
                item=copy.deepcopy(original);item['status']=value
                self.fixture.put('launch-state.json',item)
                with self.assertRaises(ValueError):self.prepare()
        for value in ['running','failed']:
            item=copy.deepcopy(original);item['stages'][1]['status']=value
            self.fixture.put('launch-state.json',item)
            with self.assertRaises(ValueError):self.prepare()
        self.fixture.put('launch-state.json',original)
        state=json.loads((self.run/'state.json').read_text());state['status']='failed'
        self.fixture.put('state.json',state);self.seal()
        with self.assertRaises(ValueError):self.prepare()

    def test_incomplete_cases_and_false_smoke_marker_refused(self):
        result=json.loads((self.run/'distributed/smoke-result.json').read_text())
        result['status']='failed';self.fixture.put('distributed/smoke-result.json',result)
        with self.assertRaises(ValueError):self.prepare()
        result['status']='passed';self.fixture.put('distributed/smoke-result.json',result)
        app=json.loads((self.run/'reports/application.json').read_text());app['cases'].pop()
        self.fixture.put('reports/application.json',app);self.seal()
        with self.assertRaises(ValueError):self.prepare()

    def test_changed_sealed_bytes_config_and_source_refused(self):
        original=(self.run/'reports/application.json').read_bytes()
        (self.run/'reports/application.json').write_bytes(original+b' ')
        with self.assertRaisesRegex(ValueError,'changed/missing artifact'):self.prepare()
        (self.run/'reports/application.json').write_bytes(original)
        changed=copy.deepcopy(self.config);changed['window_seconds']=121
        self.fixture.put('distributed-config.json',changed)
        with self.assertRaises(ValueError):self.prepare()
        self.fixture.put('distributed-config.json',self.config)
        record=copy.deepcopy(self.record);record['distributedSource']['smoke_cleanup.py']='0'*64
        with self.assertRaisesRegex(ValueError,'frozen A11'):recovery.isolated_cleanup(SOURCE,record)

    def test_foreign_or_replaced_vm_identity_rejected_by_original_inspector(self):
        module=self.module()
        key=next(k for k in self.fixture.live if k[:3]==('compute','instances','describe'))
        self.fixture.live[key]['id']='replacement-instance-id'
        with patch.object(module,'_cloud',side_effect=self.fixture.cloud):
            with self.assertRaisesRegex(ValueError,'replaced'):
                module.inspect_plan(self.config,self.run)
        self.assertEqual(self.fixture.mutations,[])

    def test_symlink_physical_path_or_destination_refused(self):
        with patch.object(recovery,'RUN_PARENT',self.parent):
            with self.assertRaisesRegex(ValueError,'physical path'):
                recovery.prepare(self.logical,self.logical,self.destination,self.build,self.provenance)
        link=self.parent/'destination-link';link.symlink_to(self.run,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'physical path'):
            recovery.physical(link/'new-backup')

    def test_explicit_reviewed_backup_still_requires_four_actual_original_tars(self):
        self.prepare()
        original_loader=recovery.isolated_cleanup
        def synthetic_loader(source,record):
            module,change=original_loader(source,record)
            module._cloud=self.fixture.cloud
            module.Remote=self.fixture.remote_factory
            return module,change
        before=(self.run/'launch-state.json').read_bytes()
        with patch.object(recovery,'isolated_cleanup',side_effect=synthetic_loader):
            result=recovery.backup_after_review(self.provenance)
        self.assertEqual(result['status'],'original-backup-actually-verified')
        self.assertFalse(result['resourceRemovalPerformed'])
        manifest=self.module().verify_backup(self.destination)
        self.assertEqual(set(manifest['archives']),{f'host-{i}' for i in range(1,5)})
        self.assertTrue(all((self.destination/f'host-{i}-private-state.tar').is_file() for i in range(1,5)))
        self.assertEqual((self.run/'launch-state.json').read_bytes(),before)
        self.assertEqual(self.fixture.mutations,[])


if __name__=='__main__':unittest.main(verbosity=2)
