import unittest
from nonlinear_readiness_prefix import validate_material
from readiness_prefix import RESULT_CHECKS, ZERO


class NonlinearPrefixTests(unittest.TestCase):
    def material(self):
        name='regulatory_qoe_compliance-0';cfg=dict(half='nonlinear',readinessOnly=True,smoke=True,
             parameters='Test',records=50,repeats=1,nonlinearProtocol='bounty-v2',runId='pilot')
        keys=dict(status='passed',parameters='Test',fullPreprocessing=True,preloadedFheKey=False)
        ids=[str(i) for i in range(50)];before={i:dict(owner='owner',recordReference=i,releaseLimit=18,spent=0) for i in ids}
        case=dict(name=name,half='nonlinear',n=50,workflowKind=2,finalOutputKmsCalls=1,
                  metrics=dict(disputes=[]),outputDigest='output',releaseSlot='slot',releaseRequestId='request',
                  recordIds=ids,workflowManifest=dict(kind='canonical-bounty-nonlinear-v2',availability='availability'))
        app=dict(status='failed',config=cfg,keys=keys,cases=[case],kmsCalls=1,
                 onChainPolicy=dict(address='policy'),protectedRecordBaselines=before)
        prepared=dict(keys=keys,cases=[dict(name=name),dict(name='regional_qoe_compliance-0')])
        result=dict(name=name,index=0,actual=1,outputDigest='output',**RESULT_CHECKS)
        snapshot=dict(policy='policy',blockNumber=20,blockHash='block',
             records={i:{**r,'spent':1} for i,r in before.items()},
             slots={f'pilot:{name}:final:onchain-v3':dict(slot='slot',requestId='request'),
                    'pilot:regional_qoe_compliance-0:final:onchain-v3':dict(slot='other',requestId=ZERO)},
             failedTransaction=dict(to='availability',method='publishAuthenticatedTraceBatch',rows=64,
                                    status=0,gasLimit='20000000',gasUsed='20000000'))
        return [dict(status='failed',config=cfg),app,prepared,result,{name:1},keys,snapshot]

    def test_honest_result_is_not_relabelled_a_complete_case(self):
        summary=validate_material(*self.material())
        self.assertEqual(summary['predecessorStatus'],'failed');self.assertFalse(summary['analysisComplete'])
        self.assertIn('regulatory-dispute-only',summary['pending'])

    def test_counter_replay_and_pending_slot_consumption_reject(self):
        for change in ('spent','slot'):
            data=self.material()
            if change=='spent':data[-1]['records']['0']['spent']=2
            else:data[-1]['slots']['pilot:regional_qoe_compliance-0:final:onchain-v3']['requestId']='consumed'
            with self.assertRaises(ValueError):validate_material(*data)

    def test_wrong_gas_failure_or_output_rejects(self):
        for change in ('gas','output','status'):
            data=self.material()
            if change=='gas':data[-1]['failedTransaction']['gasUsed']='1000000'
            elif change=='output':data[3]['actual']=0
            else:data[0]['status']='passed'
            with self.assertRaises(ValueError):validate_material(*data)


if __name__=='__main__':unittest.main()
