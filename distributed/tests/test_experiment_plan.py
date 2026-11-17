import collections
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
import deployment
import experiment_plan
import postprocess_adapter
import smoke
import status

class DistributedDesignTests(unittest.TestCase):
    def setUp(self):self.config=json.loads((HERE/'config.example.json').read_text())
    def test_only_full_repetitions_change_and_fault_positions_remain_covered(self):
        module=deployment.campaign_module();local=module.poc_plan('both');wan=experiment_plan.plan()
        self.assertEqual(local['fullCases'],45)
        self.assertEqual((wan['measuredPairs'],wan['fullCases']), (480,27))
        self.assertNotEqual(local['designSha256'],wan['designSha256'])
        self.assertEqual(sum(j['warmup'] for j in wan['jobs']),18)
        counts=collections.Counter();faults=collections.defaultdict(set)
        for old,new in zip(local['jobs'],wan['jobs'],strict=True):
            self.assertEqual({k:v for k,v in old.items() if k not in ('fullCase','faultPosition')},
                             {k:v for k,v in new.items() if k not in ('fullCase','faultPosition')})
            if new['fullCase']:
                counts[new['group']]+=1
                if new['half']=='nonlinear':faults[new['group']].add(new['faultPosition'])
        self.assertEqual(set(counts.values()),{3});self.assertEqual(len(counts),9)
        self.assertTrue(all(v=={'early','middle','terminal'} for v in faults.values()))
        self.assertEqual(wan['windowSeconds'],local['windowSeconds'])
    def test_smoke_is_original_readiness_not_a_publishable_grid(self):
        self.config['execution_mode']='smoke'
        cfg=deployment.campaign_config(self.config,'smoke-fixture-only')
        self.assertTrue(cfg['smoke']);self.assertTrue(cfg['readinessOnly'])
        self.assertNotIn('pocPlan',cfg)
        self.assertEqual((cfg['linearSizes'],cfg['records'],cfg['windowSeconds']),([27],50,120))
        with self.assertRaises(ValueError):smoke.validate_cases([])
    def test_three_case_validator_cannot_be_used_for_the_local_profile(self):
        with self.assertRaises(ValueError):experiment_plan.evidence_module({'half':'both'})
        cfg=deployment.campaign_config(self.config,'fixture-only')
        method=experiment_plan.evidence_module(cfg)
        cfg=copy.deepcopy(cfg);cfg['pocPlan']['fullCases']=26
        with self.assertRaisesRegex(ValueError,'design'):method.validate_pairs(cfg,{})
    def test_generator_copies_leave_every_original_file_unchanged(self):
        source=HERE.parent/'threshold-kms/postprocess'
        before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in source.iterdir() if p.is_file()}
        with tempfile.TemporaryDirectory() as tmp:
            out=postprocess_adapter.prepare(Path(tmp)/'generators');postprocess_adapter.verify(out)
            for file in out.glob('*.py'):compile(file.read_text(),str(file),'exec')
            self.assertIn('else 3',(out/'workflow.py').read_text())
            self.assertEqual((out/'workflow_figures.py').read_bytes(),(source/'workflow_figures.py').read_bytes())
            (out/'workflow.py').write_text('changed')
            with self.assertRaises(ValueError):postprocess_adapter.verify(out)
        self.assertEqual(before,{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in source.iterdir() if p.is_file()})
    def test_status_reads_progress_without_exposing_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=Path(tmp)
            (run/'launch-state.json').write_text(json.dumps({'status':'prepared','stages':[],
                'config':{'private':'never print account configuration'}}))
            (run/'live-progress.local.json').write_text(json.dumps({'phase':'auditor-recomputation','current':1,'total':27}))
            result=status.snapshot(run)
            self.assertEqual(result['progress']['total'],27)
            self.assertNotIn('config',result)

if __name__=='__main__':unittest.main()
