import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import availability_evidence as evidence
import run as campaign


class AvailabilityEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.run=Path(self.tmp.name);(self.run/'config').mkdir()
        (self.run/Path(evidence.REPORT).parent).mkdir(parents=True)
        self.cfg=dict(half='nonlinear',nonlinearProtocol='bounty-v2',availabilityControlsVersion=evidence.VERSION)
        self.source={k:'a'*64 for k in ['contracts/src/Test.sol','scripts/evaluate-committee-availability.mjs',
            'scripts/canonical-bounty-client.mjs','scripts/canonical-chain.mjs','scripts/evm-lib.mjs','contracts/test/chain-harness.mjs']}
        self.report=dict(schema=evidence.VERSION,status='passed',classification='local-EVM-control-flow-only',
            realFheExecutions=0,kmsReleases=0,externalChain=False,sourceUnchanged=True,sourceHashes=self.source,
            checks=[dict(name=k,status='passed',detail=copy.deepcopy(v)) for k,v in evidence.EXPECTED.items()])
        self.write()

    def write(self):
        (self.run/'config/campaign.json').write_text(json.dumps(self.cfg))
        (self.run/'state.json').write_text(json.dumps(dict(source={'fhe-pod/'+k:v for k,v in self.source.items()})))
        (self.run/evidence.REPORT).write_text(json.dumps(self.report))

    def test_all_controls_bound_to_source_and_seal(self):
        self.assertEqual(len(evidence.validate(self.run,{evidence.REPORT})['checks']),9)

    def test_missing_sealed_control_rejected(self):
        with self.assertRaisesRegex(ValueError,'unsealed'):evidence.validate(self.run,set())

    def test_missing_control_cannot_be_passed(self):
        self.report['checks'].pop();self.write()
        with self.assertRaises(ValueError):evidence.validate(self.run)

    def test_false_acceptance_and_misclassified_fhe_rejected(self):
        self.report['checks'][1]['detail']['accepted']=True;self.write()
        with self.assertRaises(ValueError):evidence.validate(self.run)
        self.report['checks'][1]['detail']['accepted']=False;self.report['realFheExecutions']=1;self.write()
        with self.assertRaises(ValueError):evidence.validate(self.run)

    def test_changed_source_rejected(self):
        self.write();self.report['sourceHashes']['contracts/src/Test.sol']='b'*64
        (self.run/evidence.REPORT).write_text(json.dumps(self.report))
        with self.assertRaises(ValueError):evidence.validate(self.run)

    def test_legacy_run_does_not_acquire_controls(self):
        del self.cfg['availabilityControlsVersion'];self.write()
        self.assertIsNone(evidence.validate(self.run))

    def test_linear_scope_does_not_run_nonlinear_controls(self):
        self.assertEqual(campaign.comparison_control_stages({'half':'linear'},self.run),[])
        self.cfg['half']='linear'
        with self.assertRaises(ValueError):campaign.comparison_control_stages(self.cfg,self.run)

    def test_main_route_runs_isolated_control_without_dependencies(self):
        for half in ['nonlinear','both']:
            cfg=self.cfg|dict(half=half)
            stages=campaign.comparison_control_stages(cfg,self.run)
            self.assertEqual(stages[0][1][-4:],['run','--rm','--no-deps','availability-controls'])
            self.assertEqual(stages[0][1][3],str(self.run/'config/availability-compose.json'))

    def test_image_contains_harness_and_service_has_no_private_mounts_or_network(self):
        self.assertIn(campaign.ROOT/'fhe-pod/contracts/test/chain-harness.mjs',campaign.source_files())
        module=self.run/'module';module.mkdir();target=self.run/'new';target.mkdir()
        args=campaign.parser().parse_args(['--half','nonlinear','--nonlinear-protocol','bounty-v2'])
        with patch.object(campaign,'MODULE',module):campaign.configuration(target,args,'immutable-image')
        compose=json.loads((target/'config/availability-compose.json').read_text())
        self.assertNotIn('networks',compose)
        self.assertEqual(set(compose['services']),{'availability-controls'})
        service=compose['services']['availability-controls']
        self.assertEqual(service['network_mode'],'none');self.assertNotIn('networks',service)
        self.assertEqual(service['entrypoint'],['node'])
        self.assertEqual([m['target'] for m in service['volumes']],['/reports'])
        self.assertTrue(service['read_only'])
