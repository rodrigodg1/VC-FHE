"""Regression checks for the V3 continuation planner (no Docker, chain or KMS)."""
import copy
from pathlib import Path
import subprocess
import tempfile
import unittest
import recover_v3 as r

CFG={'readinessOnly':False}
EXPECTED={'linear-acr-10-0':30,'regulatory_qoe_compliance-0':1,'regional_qoe_compliance-0':0}
NAMES=list(EXPECTED)

def result(name,**changes):
    row={'name':name,'actual':EXPECTED[name],'outputDigest':'0x'+name.encode().hex(),**r.RESULT_CHECKS}
    row.update(changes);return row

def linear(name):
    return {'name':name,'half':'linear','finalOutputKmsCalls':1,'outputDigest':'0x'+name.encode().hex()}

def nonlinear(name,position='terminal',settled=True):
    leaves=128;terminal=leaves-1;index={'early':0,'middle':terminal//2,'terminal':terminal}[position]
    certs=[{'plaintextOpenings':0},{'plaintextOpenings':0}]
    case={'name':name,'half':'nonlinear','faultPosition':position,'finalOutputKmsCalls':1,
          'outputDigest':'0x'+name.encode().hex(),'metrics':{'leaves':leaves,'disputes':[]}}
    if settled:
        case['metrics']['disputes']=[{'faultIndex':index,'settlement':{'index':index,'state':[3,2,True],'certificates':certs}}]
        case['metrics']['disputeCosts']={'gasUsed':'1'}
    return case

class Planner(unittest.TestCase):
    def test_settled_prefix_is_kept(self):
        cases=[linear(NAMES[0]),nonlinear(NAMES[1])]
        kept,redo=r.split_prefix(cases,NAMES,CFG,{0:result(NAMES[0]),1:result(NAMES[1])},EXPECTED)
        self.assertEqual([c['name'] for _,c in kept],NAMES[:2]);self.assertEqual(redo,[])

    def test_released_but_unsettled_last_case_is_rerun(self):
        cases=[linear(NAMES[0]),nonlinear(NAMES[1],settled=False)]
        kept,redo=r.split_prefix(cases,NAMES,CFG,{0:result(NAMES[0]),1:result(NAMES[1])},EXPECTED)
        self.assertEqual(len(kept),1);self.assertEqual(redo,[NAMES[1]])

    def test_unsettled_case_before_the_last_is_rejected(self):
        cases=[nonlinear(NAMES[1],settled=False),nonlinear(NAMES[2])]
        with self.assertRaisesRegex(ValueError,'preselected order'):
            r.split_prefix(cases,NAMES,CFG,{0:result(NAMES[1]),1:result(NAMES[2])},EXPECTED)
        order=[NAMES[1],NAMES[2]]
        with self.assertRaisesRegex(ValueError,'unsettled case before'):
            r.split_prefix(cases,order,CFG,{0:result(NAMES[1]),1:result(NAMES[2])},EXPECTED)

    def test_wrong_decryption_or_missing_denials_is_rejected(self):
        cases=[linear(NAMES[0])]
        with self.assertRaisesRegex(ValueError,'correctness'):
            r.split_prefix(cases,NAMES,CFG,{0:result(NAMES[0],actual=31)},EXPECTED)
        with self.assertRaisesRegex(ValueError,'threshold/ingress'):
            r.split_prefix(cases,NAMES,CFG,{0:result(NAMES[0],directAdministrativeDenied=27)},EXPECTED)
        with self.assertRaisesRegex(ValueError,'without recipient result'):
            r.split_prefix(cases,NAMES,CFG,{},EXPECTED)

    def test_wrong_fault_position_is_not_settled(self):
        case=nonlinear(NAMES[1],'middle');case['faultPosition']='early'
        self.assertFalse(r.settled(case,CFG))
        readiness=nonlinear(NAMES[1],'terminal');readiness.pop('faultPosition')
        self.assertTrue(r.settled(readiness,{'readinessOnly':True}))
        opened=nonlinear(NAMES[1]);opened['metrics']['disputes'][0]['settlement']['certificates'][0]['plaintextOpenings']=1
        self.assertFalse(r.settled(opened,CFG))

    def test_budget_gate_never_exceeds_cumulative_limit(self):
        info={'remaining':[{'recordIds':['a','b'],'releaseLimits':[18,18]},{'recordIds':['a'],'releaseLimits':[18]}]}
        snap={'records':{'a':{'spent':16},'b':{'spent':0}}}
        self.assertEqual(r.budget_gate(info,snap)['minimumProjectedRemaining'],0)
        snap['records']['a']['spent']=17
        with self.assertRaisesRegex(ValueError,'budget exhausted'):r.budget_gate(info,snap)

    def test_overlay_anchors_exist_once_and_parse(self):
        campaign=r.MODULE/'campaign'
        owner=r.overlay((campaign/'owner.mjs').read_text(),'await prepare();',(r.HERE/'owner-restore-v3.mjs').read_text())
        evaluate=r.overlay((campaign/'evaluate.mjs').read_text(),'if(cfg.pocPlan)await runPairs(cfg,prepared);','await 0;')
        with tempfile.TemporaryDirectory() as d:
            for name,text in [('owner.mjs',owner),('evaluate.mjs',evaluate)]:
                (Path(d)/name).write_text(text)
                subprocess.run(['node','--check',str(Path(d)/name)],check=True)
        with self.assertRaisesRegex(ValueError,'anchor'):r.overlay('x','y','z')

    def test_compose_rejects_private_leak_and_setup_roles(self):
        base=Path('/runs/base');seg=Path('/runs/seg')
        vol=lambda s,t,ro=True:{'source':s,'target':t,'read_only':ro}
        svc=lambda **k:{'image':'img','read_only':True,'cap_drop':['ALL'],'volumes':[],**k}
        compose={'services':{**{f'kms{i}':svc(volumes=[vol(str(seg/f'private-{i}'),'/private',False)]) for i in range(1,5)},
                 'public-store':svc(),'owner':svc(networks=['besu']),'evaluate':svc(networks=['besu']),
                 'worker':svc(network_mode='none'),'recipient':svc(networks=['kms'])},'networks':{'kms':{'internal':True}}}
        info={'state':{'imageId':'img'},'base':base,'original':base}
        r.validate_compose(copy.deepcopy(compose),info,seg)
        bad=copy.deepcopy(compose);bad['services']['evaluate']['volumes'].append(vol('/x','/owner-identity'))
        with self.assertRaisesRegex(ValueError,'leakage'):r.validate_compose(bad,info,seg)
        bad=copy.deepcopy(compose);bad['services']['setup']=svc()
        with self.assertRaisesRegex(ValueError,'role/setup'):r.validate_compose(bad,info,seg)
        bad=copy.deepcopy(compose);bad['services']['kms1']['volumes'].append(vol(str(base/'reports'),'/r',False))
        with self.assertRaisesRegex(ValueError,'writable'):r.validate_compose(bad,info,seg)

class OnlyInterruptions(unittest.TestCase):
    def cause(self,status,error='',log='',app_error=''):
        with tempfile.TemporaryDirectory() as d:
            if log:(Path(d)/'evaluation.log').write_text(log)
            return r.interruption_cause(Path(d),{'status':status,'error':error},{'error':app_error})

    def test_interruptions_are_eligible(self):
        self.assertEqual(self.cause('interrupted',app_error='Error: campaign interrupted: SIGINT'),'operator interrupt')
        self.assertEqual(self.cause('running'),'runner or host terminated abruptly')
        self.assertEqual(self.cause('failed','kms2 exited (code 137, OOM=True); no release will be retried'),'service killed')
        self.assertEqual(self.cause('failed','Cannot connect to the Docker daemon at unix:///x'),'infrastructure interruption')
        self.assertEqual(self.cause('failed','evaluation exceeded configured timeout'),'infrastructure interruption')

    def test_defects_are_refused(self):
        for kwargs in [dict(status='failed',error='evaluation failed (1)',log='TypeError: Do not know how to serialize a BigInt'),
                       dict(status='running',log='AssertionError [ERR_ASSERTION]: local and on-chain consent IDs differ'),
                       dict(status='failed',error='recipient exited (code 1, OOM=False); no release will be retried'),
                       dict(status='failed',error='evaluation failed (1)',log='Error: something unexpected')]:
            with self.assertRaises(ValueError):self.cause(**kwargs)

if __name__=='__main__':unittest.main()
