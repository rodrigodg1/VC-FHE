import copy
import datetime
import unittest
from poc_plan import plan
from poc_evidence import validate_pairs, validate_full_cases, paired_summary
from run import parser, selection


def fixture(half='both'):
    design=plan(half)
    cfg={'pocPlan':design,'half':half,'parameters':'Test','smoke':False,'readinessOnly':False,
         'classification':design['classification'],'windowSeconds':120,'disclosureBatchSize':64,
         'selectionProfile':design['selectionProfile']}
    rows=[];cases=[]
    for job in design['jobs']:
        row=copy.deepcopy(job)
        start=datetime.datetime(2026,1,1,tzinfo=datetime.timezone.utc)+datetime.timedelta(seconds=job['ordinal']*10)
        stamp=lambda seconds:(start+datetime.timedelta(seconds=seconds)).isoformat()
        row.update(fixtureDigest='0x'+format(job['ordinal'],'064x'),wallStarted=stamp(0),wallFinished=stamp(9),
                   scope='admission-and-aggregate-verification-v1' if job['half']=='linear' else 'one-vs-two-public-replays-component-v1',observations={})
        for i,v in enumerate(job['order']):
            evidence={'accepted':True,'verifiedSignatures':job['n'],'plaintextOpenings':0}
            if job['half']=='nonlinear':
                evidence={'index':None,'plaintextOpenings':0,'operatorRoot':'root','replayRoot':'root','contextDigest':row['fixtureDigest']}
                if v=='baseline':evidence=[copy.deepcopy(evidence),copy.deepcopy(evidence)]
            row['observations'][v]={'ms':10 if v=='proposed' else 20,'startedAt':stamp(1+i*3),'finishedAt':stamp(2+i*3),'evidence':evidence}
        rows.append(row)
        if job['fullCase']:
            c=copy.deepcopy(job);c.update(finalOutputKmsCalls=1,receiptScopes={'proposed':{'transactionCount':1,'gasUsed':'5','calldataBytes':4}},
               transactionCount=1,gasUsed='5',calldataBytes=4,metrics={'baselineProfile':'ordinary-bls-canonical-vector-v1'})
            if job['half']=='nonlinear':
                leaves=({16:128,32:256,50:512} if job['workload']=='regional_qoe_compliance' else {16:64,32:128,50:128})[job['n']]
                fault={'early':0,'middle':(leaves-1)//2,'terminal':leaves-1}[job['faultPosition']]
                c['metrics']={'leaves':leaves,'disputes':[{'faultIndex':fault,'settlement':{'index':fault,'state':[3,2,True],
                    'certificates':[{'plaintextOpenings':0},{'plaintextOpenings':0}]}}]}
            cases.append(c)
    return cfg,{'status':'passed','profile':design['profile'],'designSha256':design['designSha256'],'rows':rows},{'cases':cases,'kmsCalls':len(cases)}


class PocEvidenceTests(unittest.TestCase):
    def test_complete_and_independent_grids(self):
        for half,n in [('both',45),('linear',15),('nonlinear',30)]:
            cfg,paired,app=fixture(half)
            self.assertEqual(validate_full_cases(cfg,app,paired)['fullCases'],n)

    def test_partial_wrong_order_reused_fixture_and_plaintext_are_rejected(self):
        cfg,p,_=fixture('nonlinear')
        variants=[]
        b=copy.deepcopy(p);b['rows'].pop();variants.append(b)
        b=copy.deepcopy(p);b['rows'][0]['order'].reverse();variants.append(b)
        b=copy.deepcopy(p);b['rows'][1]['fixtureDigest']=b['rows'][0]['fixtureDigest'];variants.append(b)
        b=copy.deepcopy(p);b['rows'][0]['observations']['proposed']['evidence']['plaintextOpenings']=1;variants.append(b)
        b=copy.deepcopy(p);b['rows'][0]['observations']['baseline']['evidence'][0]['operatorRoot']='changed';variants.append(b)
        b=copy.deepcopy(p);b['rows'][0]['observations']['proposed']['ms']=float('nan');variants.append(b)
        b=copy.deepcopy(p);b['rows'][1]['wallStarted']=b['rows'][0]['wallStarted'];variants.append(b)
        for b in variants:
            with self.assertRaises(ValueError):validate_pairs(cfg,b)

    def test_full_case_grid_releases_costs_and_faults_cannot_be_dropped(self):
        cfg,p,a=fixture('nonlinear');variants=[]
        b=copy.deepcopy(a);b['cases'].pop();variants.append(b)
        b=copy.deepcopy(a);b['kmsCalls']-=1;variants.append(b)
        b=copy.deepcopy(a);b['cases'][0]['metrics']['disputes'][0]['faultIndex']=2;variants.append(b)
        b=copy.deepcopy(a);b['cases'][0]['gasUsed']='6';variants.append(b)
        b=copy.deepcopy(a);b['cases'][0]['metrics']['leaves']=8;variants.append(b)
        for b in variants:
            with self.assertRaises(ValueError):validate_full_cases(cfg,b,p)

    def test_smoke_and_default_cannot_enter_explicit_poc_gate(self):
        cfg,p,_=fixture()
        for patch in [{'smoke':True},{'parameters':'Default'},{'classification':'test-insecure-readiness-not-evaluation'},{'windowSeconds':240}]:
            with self.assertRaises(ValueError):validate_pairs(cfg|patch,p)

    def test_cli_requires_explicit_test_and_exact_full_scope(self):
        for extra in [[],['--smoke'],['--poc-readiness'],['--readiness-workload','regional']]:
            args=['--poc']+extra
            if extra:args+=['--fhe-params','Test','--allow-insecure-test']
            with self.assertRaises(ValueError):selection(parser().parse_args(args))
        cfg=selection(parser().parse_args(['--poc','--half','linear','--fhe-params','Test','--allow-insecure-test']))
        self.assertEqual(cfg['pocPlan']['measuredPairs'],300);self.assertEqual(cfg['pocPlan']['fullCases'],15)

    def test_conditional_interval_has_exact_degenerate_case_and_fixed_seed(self):
        _,p,_=fixture('linear');rows=[r for r in p['rows'] if r['group']=='linear-acr-10' and not r['warmup']]
        a=paired_summary(rows)
        self.assertEqual(a,paired_summary(rows));self.assertEqual(a['pairedDifferenceMs'],10)
        self.assertEqual(a['conditional95IntervalMs'],[10,10]);self.assertEqual(a['pairs'],100)
        self.assertTrue(a['requiresVisualDiagnosticReview']);self.assertFalse(a['temporalReviewFlag'])


if __name__=='__main__':unittest.main()
