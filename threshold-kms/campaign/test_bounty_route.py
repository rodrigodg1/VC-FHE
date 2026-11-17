import copy
import tempfile
import unittest
from pathlib import Path
from run import parser, selection
from bounty_evidence import validate_bounty_evidence, test_economics
from onchain_evidence import _keccak256, EvidenceError


def fixture():
    addresses = ['0x'+format(i,'040x') for i in range(1,8)]
    op, challenger, relay, other1, other2, game, availability = addresses
    task = '0x'+'a'*64
    topic = lambda a: '0x'+a[2:].zfill(64)
    economics, penalty, reward = test_economics()
    fee = int(economics['disclosureBaseWei']) + 8 * int(economics['disclosurePerLeafWei'])
    labels = ['requestBountyTraceDisclosure','publishAuthenticatedTraceBatch','submitSealedAudit',
              'revealSealedAudit','admitCanonicalLeaf','settleCanonicalLeaf','claimUnusedAuditBond',
              'withdrawChallengeBounty','honestSubmitSealedAudit','honestRevealSealedAudit',
              'honestClaimAuditBond','relayOperatorBisection','relayChallengerBisection']
    receipts = [dict(label=l,txHash='0x'+format(i+1,'064x'),status=1,to=game,
                     **{'from':challenger if l in {'withdrawChallengeBounty','requestBountyTraceDisclosure'} else relay},
                     gasUsed='21000',effectiveGasPriceWei='2',transactionFeeWei='42000',
                     valueWei=str(fee) if l=='requestBountyTraceDisclosure' else '0',logs=[])
                for i,l in enumerate(labels)]
    settlement=next(r for r in receipts if r['label']=='settleCanonicalLeaf')
    settlement['logs']=[dict(address=game,
        topics=[_keccak256(b'BountySettlement(bytes32,address,address,uint256,uint256,uint256)'),
                task,topic(op),topic(challenger)],
        data='0x'+''.join(format(v,'064x') for v in [penalty,reward,penalty-reward]))]
    withdrawal=next(r for r in receipts if r['label']=='withdrawChallengeBounty')
    withdrawal['logs']=[dict(address=game,
        topics=[_keccak256(b'StakeWithdrawn(address,address,uint256)'),topic(challenger),topic(relay)],
        data='0x'+format(reward,'064x'))]
    b=dict(protocol='bounty-v2',taskId=task,operator=op,challenger=challenger,relayer=relay,
        game=game,availability=availability,parties=[op,challenger,other1,other2],
        stakesBefore=[str(2*penalty)]*4,
        stakesAfter=list(map(str,[penalty,2*penalty+reward,2*penalty,2*penalty])),
        penaltyWei=str(penalty),rewardWei=str(reward),burnedWei=str(penalty-reward),withdrawalWei=str(reward),
        settlementTx=settlement['txHash'],withdrawalTx=withdrawal['txHash'],
        disclosure=dict(requester=challenger,recipient=op,requestBondWei=str(fee),splits=7,commitDeadline='1120',disclosureDeadline='1000',receipts=[receipts[0]['txHash'],receipts[1]['txHash']]))
    receipts[1]['logs']=[dict(address=availability,topics=[_keccak256(b'DisclosureRequestBondSettled(bytes32,address,uint256,bool)'),task,topic(op)],data='0x'+format(fee,'064x')+format(1,'064x'))]
    profile=dict(revision=economics['revision'],maxTraceLeaves=512,maxDisclosureFeeWei='1044000000000000000',challengeCostBudgetWei=economics['challengeCostBudgetWei'],challengerMarginWei=economics['challengerMarginWei'],operatorLossFloorWei=economics['operatorLossFloorWei'],bountyWei=str(reward),operatorPenaltyWei=str(penalty),extraConstructorArgs=[str(penalty),str(reward),512,economics['challengeCostBudgetWei']])
    case=dict(half='nonlinear',workflowManifest=dict(kind='canonical-bounty-nonlinear-v2',game=game,availability=availability),
        metrics=dict(economics=profile,nonlinearProtocol='bounty-v2',leaves=8,disputes=[dict(settlement=dict(state=[3,2,True,op,challenger],bounty=b))]))
    return dict(bountyEconomics=economics,half='nonlinear',nonlinearProtocol='bounty-v2',windowSeconds=120),dict(cases=[case],receipts=receipts)


class BountyRouteTests(unittest.TestCase):
    def test_economic_inputs_are_in_the_sealed_build_source(self):
        from run import source_manifest
        manifest = source_manifest()
        for name in ['fhe-pod/scripts/bounty-economics.json', 'fhe-pod/scripts/bounty-economics.mjs']:
            self.assertIn(name, manifest)

    def test_profile_is_explicit_and_cannot_downgrade_or_reset_lineage(self):
        argv=['--half','nonlinear','--nonlinear-protocol','bounty-v2','--poc','--fhe-params','Test',
              '--allow-insecure-test','--kms-threads','1']
        selected=selection(parser().parse_args(argv))
        self.assertEqual(selected['nonlinearProtocol'],'bounty-v2')
        self.assertEqual(selected['pocPlan']['measuredPairs'],180)
        self.assertEqual(selected['pocPlan']['fullCases'],30)
        combined=selection(parser().parse_args(argv+['--half','both']))
        self.assertEqual(combined['pocPlan']['measuredPairs'],480)
        self.assertEqual(combined['pocPlan']['fullCases'],45)
        for extra in [['--half','linear'],['--fhe-params','Default'],['--kms-threads','2'],['--new-policy-lineage']]:
            with self.assertRaises(ValueError):selection(parser().parse_args(argv+extra))
        pilot=[a for a in argv if a!='--poc']+['--poc-readiness','--smoke']
        self.assertTrue(selection(parser().parse_args(pilot))['readinessOnly'])
        self.assertNotIn('nonlinearProtocol',selection(parser().parse_args(['--half','linear'])))

    def test_check_cannot_relabel_a_legacy_run(self):
        import json
        from unittest.mock import patch
        import run
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);(directory/'config').mkdir()
            (directory/'config/campaign.json').write_text(json.dumps({'half':'nonlinear'}))
            argv=['run.py','--half','nonlinear','--nonlinear-protocol','bounty-v2','--poc',
                  '--fhe-params','Test','--allow-insecure-test','--kms-threads','1',
                  '--check','--run-dir',str(directory)]
            with patch('sys.argv',argv),patch.object(run,'verify',side_effect=AssertionError('legacy verification invoked')):
                with self.assertRaisesRegex(ValueError,'not a nonlinear bounty-v2'):run.main()

    def test_raw_settlement_withdrawal_and_abandonment_evidence(self):
        cfg, app=fixture();validate_bounty_evidence(cfg,app)
        for change in ['reward','other-auditor','withdrawal','event','operator-response','deadline','protocol','disclosure','receipts','oversized','gas-fee','disclosure-fee','economic-profile']:
            broken=copy.deepcopy(app);b=broken['cases'][0]['metrics']['disputes'][0]['settlement']['bounty']
            if change=='reward':b['rewardWei']='1'
            elif change=='other-auditor':b['stakesAfter'][2]=str(int(b['stakesAfter'][2])+1)
            elif change=='withdrawal':b['withdrawalWei']='0'
            elif change=='event':next(r for r in broken['receipts'] if r['label']=='settleCanonicalLeaf')['logs'][0]['topics'][3]='0x'+'f'*64
            elif change=='operator-response':broken['receipts'][1]['from']=b['operator']
            elif change=='deadline':b['disclosure']['commitDeadline']='1119'
            elif change=='protocol':broken['cases'][0]['workflowManifest']['kind']='canonical-nonlinear'
            elif change=='disclosure':b['disclosure']['splits']=6
            elif change=='receipts':broken['receipts'].append(broken['receipts'][0])
            elif change=='gas-fee':broken['receipts'][0]['transactionFeeWei']='1'
            elif change=='disclosure-fee':b['disclosure']['requestBondWei']='0'
            elif change=='economic-profile':broken['cases'][0]['metrics']['economics']['maxTraceLeaves']=1024
            elif change=='oversized':broken['cases'][0]['metrics']['leaves']=1024
            with self.subTest(change=change),self.assertRaises(EvidenceError):validate_bounty_evidence(cfg,broken)
        with self.assertRaises(EvidenceError):validate_bounty_evidence(dict(half='nonlinear'),app)

    def test_full_contract_status_binds_final_decision_and_both_roles(self):
        cfg, app = fixture()
        actual = app['cases'][0]['metrics']['disputes'][0]['settlement']['state']
        for wrong in [actual[:3], actual+[0], [2,*actual[1:]], [3,1,*actual[2:]],
                      [3,2,False,*actual[3:]], [3,2,1,*actual[3:]],
                      [3,2,True,actual[4],actual[3]], [3,2,True,0,actual[4]]]:
            broken=copy.deepcopy(app)
            broken['cases'][0]['metrics']['disputes'][0]['settlement']['state']=wrong
            with self.subTest(state=wrong), self.assertRaises(EvidenceError):
                validate_bounty_evidence(cfg,broken)

    def test_runtime_contains_bounty_client_and_preserves_build_patch_anchors(self):
        import importlib.util
        source=Path(__file__).resolve().parents[1]/'scripts/kms-profile-build.py'
        spec=importlib.util.spec_from_file_location('bounty_runtime_test',source)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            dest=module.build_runtime(Path(temporary)/'runtime')
            self.assertTrue((dest/'scripts/canonical-bounty-client.mjs').is_file())
            self.assertTrue((dest/'scripts/bounty-economics.mjs').is_file())
            self.assertTrue((dest/'scripts/bounty-economics.json').is_file())
            driver=(dest/'scripts/canonical-game-driver.mjs').read_text()
            self.assertEqual(driver.count('  const identityFiles = [];'),1)
            self.assertEqual(driver.count('const f = path.join(workDir, `attester-${i}.key`);'),1)

class BountyMetricTests(unittest.TestCase):
    def observation(self):
        from bounty_evidence import economic_observation
        cfg,app=fixture();case=app['cases'][0]
        rows=[r for r in app['receipts'] if not r['label'].startswith('honest')]
        case['metrics']['disputeCosts']={'receiptScopes':{'dispute':{'transactions':[r['txHash'] for r in rows]}}}
        validate_bounty_evidence(cfg,app)
        return case,app,economic_observation(case,app['receipts'])

    def test_all_senders_counted_once_and_principal_is_not_gas(self):
        case,app,out=self.observation()
        fee=int(case['metrics']['disputes'][0]['settlement']['bounty']['disclosure']['requestBondWei'])
        self.assertEqual(int(out['disputeGasFeeWei']),10*42000)
        self.assertEqual(int(out['rewardAfterDisclosureAndGasWei']),int(out['rewardWei'])-fee-10*42000)
        self.assertEqual(sum(map(int,out['gasFeesBySender'].values())),10*42000)
        self.assertFalse(out['gasExceedsDeclaredBudget'])
        self.assertIn('not observed profit',out['scope'])

    def test_combined_route_validates_bounty_and_keeps_linear_separate(self):
        cfg,app=fixture();cfg['half']='both'
        app['cases'].insert(0,{'half':'linear','metrics':{}})
        validate_bounty_evidence(cfg,app)
        app['cases'][0]['metrics']['nonlinearProtocol']='bounty-v2'
        with self.assertRaises(EvidenceError):validate_bounty_evidence(cfg,app)

    def test_negative_economic_outcome_is_reported_not_discarded(self):
        from bounty_evidence import economic_observation
        case,app,_=self.observation()
        for r in app['receipts']:
            r['effectiveGasPriceWei']=str(10**18)
            r['transactionFeeWei']=str(int(r['gasUsed'])*10**18)
        out=economic_observation(case,app['receipts'])
        self.assertTrue(out['gasExceedsDeclaredBudget'])
        self.assertLess(int(out['rewardAfterDisclosureAndGasWei']),0)

    def test_duplicate_cost_hash_rejected(self):
        from bounty_evidence import economic_observation
        case,app,_=self.observation()
        hashes=case['metrics']['disputeCosts']['receiptScopes']['dispute']['transactions']
        hashes.append(hashes[0])
        with self.assertRaises(EvidenceError):economic_observation(case,app['receipts'])
