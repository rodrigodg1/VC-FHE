"""Synthetic smoke evidence only. No FHE, cloud operations or publication."""
import csv
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT=Path(__file__).resolve().parents[1]/'smoke_audit.py'
spec=importlib.util.spec_from_file_location('derived_smoke_audit',SCRIPT)
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
sys.path.insert(0,str(audit.DISTRIBUTED))
import topology

class SmokeAuditTests(unittest.TestCase):
    def put(self,run,name,value):
        p=run/name;p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text(json.dumps(value));return p
    def csv(self,run,name,rows,fields):
        p=run/name;p.parent.mkdir(parents=True,exist_ok=True)
        with p.open('w',newline='') as stream:
            w=csv.DictWriter(stream,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(rows)
    def measurement(self):
        return {'exitCode':0,'signal':None,'elapsedMs':10,'resources':{
            'scope':'command-and-waited-descendants','userCpuMs':2,'systemCpuMs':1,
            'totalCpuMs':3,'maxRssBytes':1024,'unavailableReason':None}}
    def fixture(self,run):
        cfg=json.loads((audit.DISTRIBUTED/'config.example.json').read_text());plan=topology.plan(cfg)
        roles={r['id']:r for r in plan['nodes']};image='example.test/project/image@sha256:'+'a'*64
        config={'smoke':True,'readinessOnly':True,'half':'both','executionProfile':audit.PROFILE,'classification':audit.CLASSIFICATION}
        cases=[{'name':name,'half':half,'n':n,'metrics':{'disputes':[{}] if half=='nonlinear' else [],
                'scheduling':{'commitTimestamp':10,'commitDeadline':30,'openTimestamp':40,'openDeadline':60}}}
               for name,half,n in [('linear-acr-27-0','linear',27),('regulatory_qoe_compliance-0','nonlinear',50),('regional_qoe_compliance-0','nonlinear',50)]]
        ready={'status':'passed','parties':4,'corruptionThreshold':1,'fullPreprocessing':True,
            'preloadedFheKey':False,'parameters':'Test','preprocessingSeconds':1,'dkgSeconds':1}
        self.put(run,'keyset/ready.json',ready);self.put(run,'keyset/prss.json',{'livePRSS':True,'seconds':1})
        self.put(run,'owner/expected.json',{c['name']:42 for c in cases})
        for i,c in enumerate(cases):
            c['outputDigest']='0x'+str(i+1)*64
            self.put(run,f'recipient/result-{i}.json',{'name':c['name'],'actual':42,'outputDigest':c['outputDigest'],
                'responses':3,'directUserAndPublicDenied':4,'negativeResponseChecks':4,
                'directAdministrativeDenied':28,'changedReservedWireDenied':4})
        self.put(run,'reports/onchain-release-evidence.json',{})
        self.put(run,'config/campaign.json',config);self.put(run,'reports/application.json',{'cases':cases,'status':'passed','kmsCalls':3,'keys':ready})
        source={'fixture':'synthetic-unit-data-not-cloud-evidence'};self.put(run,'distributed/source.json',source)
        self.put(run,'state.json',{'status':'passed','config':config,'imageId':image,'distributedSourceSha256':audit.digest(source)})
        self.put(run,'distributed/smoke-result.json',{'status':'passed',**audit.validate_cases(cases)})
        binary=run/'bin/kms-campaign';binary.parent.mkdir();binary.write_bytes(b'synthetic nonexecutable test fixture')
        execution={'executionProfile':audit.PROFILE,'status':'completed','hosts':plan['hosts'],'roles':plan['nodes'],
            'administration':'same-gcp-project','pairTiming':'coordinator-request-response-including-public-transfer',
            'imageDigest':image,'binarySha256':audit.sha(binary),'sourceSha256':audit.digest(source),
            'fullCases':3,'measuredPairs':0,'warmups':0}
        self.put(run,'distributed/execution.json',execution)
        for host in plan['hosts']:
            self.put(run,f'distributed/hosts/{host["id"]}.json',{'host':host['id'],'region':host['region'],
                'imageDigest':image,'binarySha256':audit.sha(binary),'cpuModel':'synthetic CPU','kernelRelease':'fixture-kernel','architecture':'x86_64'})
        tasks=[];inventory=[]
        names={'operator-1':'canonical-execute',**{f'auditor-{i}':'canonical-audit' for i in range(1,4)},
            'adjudicator-1':'canonical-attest',**{f'owner-{i}':'owner-request' for i in range(1,5)},
            **{f'kms-{i}':'kms-evidence' for i in range(1,5)},'recipient-1':'recipient-exchange'}
        for node,task in names.items():
            row={'node':node,'host':roles[node]['host'],'role':roles[node]['role'],'id':node+'-fixture-id',
                'task':task,'status':'completed','elapsedMs':12,'publicWorkerResources':[],
                'measurement':self.measurement() if task in audit.COMPUTED else None}
            name=f'distributed/tasks/{node}/{node}.task.json';p=self.put(run,name,row)
            inventory.append({'path':name,'sha256':audit.sha(p)});tasks.append(row)
        self.put(run,'distributed/task-inventory.json',inventory)
        root='0x'+'1'*64
        self.put(run,'reports/distributed/byte-repeatability.json',{'status':'passed','plaintextOpenings':0,
            'includedInMeasurements':False,'operatorEventId':'operator-1-fixture-id',
            'audits':[{'node':f'auditor-{i}','eventId':f'auditor-{i}-fixture-id',
                'evidence':{'index':None,'plaintextOpenings':0,'operatorRoot':root,'replayRoot':root}} for i in range(1,4)]})
        owners=[]
        for case in cases:
            for i in range(4):
                node=f'owner-{i+1}'
                self.put(run,f'fixtures/{case["name"]}/owner-fragments/{i}/fragment.json',{
                    'owner':i,'node':node,'host':roles[node]['host'],'indices':list(range(i,case['n'],4)),
                    'scopeSha256':'synthetic-shared-encryption-context','encryptionElapsedMs':10,'resources':self.measurement()})
                owners.append({'case_id':case['name'],'node':node,'host':roles[node]['host']})
        network=[]
        for host in plan['hosts']:
            rows=[{'kind':'host_sample','host':host['id']}]
            for target in plan['hosts']:
                row={'kind':'network_probe','host':host['id'],'target_host':target['id'],'port':8545,'status':'connected','elapsed_seconds':.01}
                rows.append(row);network.append(row)
            p=run/f'distributed/samples/{host["id"]}/host-observations.jsonl';p.parent.mkdir(parents=True)
            p.write_text(''.join(json.dumps(row)+'\n' for row in rows))
        raw=[{'kind':'role_transport','node':'coordinator-1','host':roles['coordinator-1']['host'],
            'target':'auditor-1','id':'fixture-rpc','requestJsonBytes':10,'responseJsonBytes':20,'elapsedSeconds':.5}]
        p=run/'reports/distributed/transport.jsonl';p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(raw[0])+'\n')
        transport=audit.summarize_transport(raw,roles);base='distributed/supplement/'
        self.csv(run,base+'network-connections.csv',network,['host','target_host','port','status','elapsed_seconds'])
        self.csv(run,base+'role-communication.csv',transport,['node','host','target'])
        self.csv(run,base+'participant-work.csv',tasks,['node','host','role','task'])
        self.csv(run,base+'owner-encryption.csv',owners,['case_id','node','host'])
        callers={r['role'] for r in roles.values()}-{'validator'}
        communication=[{'role':role,'rpc_count':1 if role=='coordinator' else 0,
            'request_json_bytes':10 if role=='coordinator' else 0,'response_json_bytes':20 if role=='coordinator' else 0} for role in callers]
        self.csv(run,base+'communication-summary.csv',communication,['role','rpc_count','request_json_bytes','response_json_bytes'])
        self.csv(run,base+'application-delay-summary.csv',[{'role':r,'observations':1 if r=='coordinator' else 0} for r in callers],['role','observations'])
        self.csv(run,base+'network-delay-summary.csv',network,['host','target_host','port'])
        self.csv(run,base+'deadline-margins.csv',[{'case_id':c['name'],'audit_commit_margin_seconds':20,'audit_open_margin_seconds':20} for c in cases if c['half']=='nonlinear'],['case_id','audit_commit_margin_seconds','audit_open_margin_seconds'])
        self.put(run,base+'summary.json',{'full_cases':3,'delays':{'tcpObservations':16,'applicationRpcObservations':1}})
        self.seal(run)
    def seal(self,run):
        files={p.relative_to(run).as_posix():audit.sha(p) for p in run.rglob('*')
               if p.is_file() and p.name!='seal.json' and p.relative_to(run).as_posix()!='distributed/smoke-result.json'}
        self.put(run,'seal.json',{'files':files})
    def perform(self,run):
        with patch.object(audit,'verify_original',return_value={}) as verify:
            result=audit.audit(run)
        verify.assert_called_once_with(run.resolve(),sources=None);return result
    def test_complete_audit_preserves_every_original_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=Path(tmp);self.fixture(run)
            before={p.relative_to(run):p.read_bytes() for p in run.rglob('*') if p.is_file()}
            result=self.perform(run)
            self.assertEqual(result['status'],'passed');self.assertFalse(result['evaluationPublishable'])
            self.assertEqual(result['crossHostTcpDirections'],12);self.assertEqual(result['ownerEncryptionFragments'],12)
            self.assertEqual(before,{p.relative_to(run):p.read_bytes() for p in run.rglob('*') if p.is_file()})
    def test_missing_or_different_actual_environment_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=Path(tmp);self.fixture(run)
            p=run/'distributed/hosts/host-4.json';v=json.loads(p.read_text());v['cpuModel']='different CPU';p.write_text(json.dumps(v));self.seal(run)
            with self.assertRaisesRegex(ValueError,'environments differ'):self.perform(run)
    def test_wrong_host_and_omitted_role_are_rejected(self):
        for omission in [False,True]:
            with self.subTest(omission=omission),tempfile.TemporaryDirectory() as tmp:
                run=Path(tmp);self.fixture(run)
                p=run/'distributed/task-inventory.json';rows=json.loads(p.read_text())
                if omission:p.write_text(json.dumps([r for r in rows if 'adjudicator-1' not in r['path']]))
                else:
                    row=next(r for r in rows if 'adjudicator-1' in r['path']);f=run/row['path'];v=json.loads(f.read_text());v['host']='host-1';f.write_text(json.dumps(v));row['sha256']=audit.sha(f);p.write_text(json.dumps(rows))
                self.seal(run)
                with self.assertRaises(ValueError):self.perform(run)
    def test_missing_network_direction_and_host_samples_are_rejected(self):
        for empty in [False,True]:
            with self.subTest(empty=empty),tempfile.TemporaryDirectory() as tmp:
                run=Path(tmp);self.fixture(run)
                p=run/'distributed/samples/host-4/host-observations.jsonl'
                if empty:p.write_text('')
                else:
                    rows=[json.loads(s) for s in p.read_text().splitlines()];p.write_text(''.join(json.dumps(r)+'\n' for r in rows if r.get('target_host')!='host-1'))
                self.seal(run)
                with self.assertRaises(ValueError):self.perform(run)
    def test_divergent_byte_probe_and_wrong_owner_host_are_rejected(self):
        for byte in [False,True]:
            with self.subTest(byte=byte),tempfile.TemporaryDirectory() as tmp:
                run=Path(tmp);self.fixture(run)
                if byte:
                    p=run/'reports/distributed/byte-repeatability.json';v=json.loads(p.read_text());v['audits'][1]['evidence'].update(operatorRoot='0xother',replayRoot='0xother')
                else:
                    p=run/'fixtures/linear-acr-27-0/owner-fragments/2/fragment.json';v=json.loads(p.read_text());v['host']='host-1'
                p.write_text(json.dumps(v));self.seal(run)
                with self.assertRaises(ValueError):self.perform(run)
    def test_original_verifier_failure_cannot_produce_passed_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            run=Path(tmp);self.fixture(run)
            with patch.object(audit,'verify_original',side_effect=ValueError('original validation failed')):
                with self.assertRaisesRegex(ValueError,'original validation failed'):audit.audit(run)
    def test_missing_real_setup_or_wrong_recipient_output_is_rejected(self):
        for keyset in [False,True]:
            with self.subTest(keyset=keyset),tempfile.TemporaryDirectory() as tmp:
                run=Path(tmp);self.fixture(run)
                if keyset:
                    p=run/'keyset/ready.json';v=json.loads(p.read_text());v['preloadedFheKey']=True
                else:
                    p=run/'recipient/result-1.json';v=json.loads(p.read_text());v['actual']=43
                p.write_text(json.dumps(v));self.seal(run)
                with self.assertRaises(ValueError):self.perform(run)
    def test_cli_writes_separate_failed_report_without_touching_original_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);run=root/'run';run.mkdir();self.fixture(run);output=root/'audit.local.json'
            original=(run/'state.json').read_bytes();seal=(run/'seal.json').read_bytes()
            with patch.object(sys,'argv',['smoke_audit.py','--run',str(run),'--output',str(output)]),patch.object(audit,'verify_original',side_effect=ValueError('real audit failure')):
                self.assertEqual(audit.main(),1)
            self.assertEqual(json.loads(output.read_text())['status'],'failed')
            self.assertEqual((run/'state.json').read_bytes(),original);self.assertEqual((run/'seal.json').read_bytes(),seal)
            self.assertEqual(output.stat().st_mode&0o777,0o600)
    def test_preserved_source_context_does_not_consult_current_project_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);sources=root/'preserved';sources.mkdir()
            files={'app/threshold-kms/campaign/run.py':'frozen original validator',
                   'app/distributed/launch.py':'frozen A7 adapter','upstream/lib.rs':'frozen native source'}
            for name,text in files.items():
                p=sources/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
            (sources/'Dockerfile').write_text('FROM synthetic-test-only\n')
            record={'dockerfileSha256':audit.sha(sources/'Dockerfile'),
                'localSource':{'threshold-kms/campaign/run.py':audit.sha(sources/'app/threshold-kms/campaign/run.py')},
                'distributedSource':{'launch.py':audit.sha(sources/'app/distributed/launch.py')},
                'buildInputs':{name:{'sha256':audit.sha(sources/name)} for name in files},
                'buildCommand':['not-executed',str(sources)]}
            self.put(sources,'distributed-source.json',record)
            with patch.object(audit,'DISTRIBUTED',root/'nonexistent-current-project'):
                self.assertEqual(audit.source_context(record,None),sources.resolve())
            (sources/'app/distributed/launch.py').write_text('changed archive')
            with self.assertRaises(ValueError):audit.source_context(record,sources)
    def test_original_validators_execute_only_from_the_verified_temporary_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);context=root/'context';app=context/'app';run=root/'run';run.mkdir()
            files={'threshold-kms/campaign/run.py':'def verify(run):\n return "synthetic frozen validator"\n',
                'threshold-kms/campaign/onchain_evidence.py':'def validate_run(run):\n return {"fixture": "preserved-source-validator"}\n',
                'distributed/launch.py':'# synthetic frozen adapter\n'}
            lock={'packages':{'node_modules/ethers':{'version':'6.0.0'},'node_modules/solc':{'version':'0.8.20'}}}
            for component in ['fhe-pod','BN254-Signatures']:
                files[component+'/package-lock.json']=json.dumps(lock)
                for package,version in [('ethers','6.0.0'),('solc','0.8.20')]:
                    self.put(root/'current',f'{component}/node_modules/{package}/package.json',{'version':version})
            for name,text in files.items():
                p=app/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
            (context/'upstream').mkdir();(context/'Dockerfile').write_text('FROM synthetic-test-only\n')
            record={'dockerfileSha256':audit.sha(context/'Dockerfile'),
                'localSource':{name:audit.sha(app/name) for name in files if not name.startswith('distributed/')},
                'distributedSource':{'launch.py':audit.sha(app/'distributed/launch.py')},
                'buildInputs':{'app/'+name:{'sha256':audit.sha(app/name)} for name in files},
                'buildCommand':['not-executed',str(context)]}
            self.put(context,'distributed-source.json',record)
            self.put(run,'distributed/source.json',record);self.put(run,'state.json',{'datasets':{}});self.seal(run)
            current=root/'current/threshold-kms/campaign/run.py';current.parent.mkdir(parents=True)
            current.write_text('raise RuntimeError("current source must not execute")\n')
            with patch.object(audit,'DISTRIBUTED',root/'current/distributed'):
                result=audit.verify_original(run,context)
            self.assertEqual(result,{'fixture':'preserved-source-validator'})

if __name__=='__main__':unittest.main()
