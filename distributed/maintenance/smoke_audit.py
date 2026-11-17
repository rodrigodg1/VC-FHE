"""Derived, cloud-offline smoke audit. Never changes original experiment files."""
import argparse
from collections import Counter
from datetime import datetime,timezone
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode=True
DISTRIBUTED=Path(__file__).resolve().parents[1]
PROFILE='gcp-four-hosts-role-local-v1'
CLASSIFICATION='test-insecure-distributed-smoke-not-evaluation'

COMPUTED={'canonical-execute','canonical-audit','canonical-attest','linear-aggregate','linear-proposed','linear-baseline'}
REQUIRED_ROLES={'owner','operator','auditor','adjudicator','recipient','kms'}

def require(value,message):
    if not value:raise ValueError(message)

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_text())
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def number(value,label):
    require(type(value) in (int,float) and math.isfinite(value) and value>=0,'invalid '+label)
    return value

# These metadata rules mirror distributed_evidence/distributed_profile and the
# smoke/transport validators reviewed for A7. Keep them controller-only so a
# later edit to current project files cannot change validation of an old run.
def validate_cases(cases):
    expected={'linear-acr-27-0':('linear',27),'regulatory_qoe_compliance-0':('nonlinear',50),
              'regional_qoe_compliance-0':('nonlinear',50)}
    require(len(cases)==3 and {c['name']:(c['half'],c['n']) for c in cases}==expected,'wrong three-case smoke coverage')
    require(all(len(c['metrics']['disputes'])==1 for c in cases if c['half']=='nonlinear'),'missing faulty-execution dispute')
    return {'fullCases':3,'nonlinearDisputes':2,'evaluationPublishable':False,'pairedComparisonsExecuted':False,
        'scope':'One existing largest-size readiness workflow per computation. Not a repeated performance campaign.'}

def descriptor(value):
    require(value.get('executionProfile')==PROFILE,'unknown distributed execution profile')
    hosts=value.get('hosts',[]);roles=value.get('roles',[])
    require(len(hosts)==4 and len({h['id'] for h in hosts})==4 and len({h['region'] for h in hosts})==4,'four distinct measured hosts/regions required')
    required={'validator':4,'kms':4,'owner':4,'operator':1,'auditor':3,'adjudicator':3,'recipient':1,'coordinator':1}
    require(len(roles)==sum(required.values()) and len({r['id'] for r in roles})==len(roles),'incomplete role inventory')
    for role,count in required.items():
        rows=[r for r in roles if r['role']==role]
        require(len(rows)==count and all(r['host'] in {h['id'] for h in hosts} for r in rows),'incorrect role placement')
        if role in ('validator','kms'):require(len({r['host'] for r in rows})==4,'validator/KMS roles must occupy four hosts')
    require(value.get('administration')=='same-gcp-project' and value.get('pairTiming')=='coordinator-request-response-including-public-transfer','missing administration or timing scope')
    return value

def validate_byte_probe(probe,records):
    require(probe.get('status')=='passed' and probe.get('plaintextOpenings')==0 and probe.get('includedInMeasurements') is False,'byte admission did not pass without decryption outside measurements')
    audits=probe.get('audits',[])
    require(len(audits)==3 and {a.get('node') for a in audits}=={'auditor-1','auditor-2','auditor-3'},'byte probe omits an auditor host')
    require(records.get(('operator-1',probe.get('operatorEventId')),{}).get('task')=='canonical-execute','byte probe lacks its operator task')
    roots=set()
    for audit in audits:
        require(records.get((audit['node'],audit.get('eventId')),{}).get('task')=='canonical-audit','byte probe lacks an independent auditor task')
        e=audit.get('evidence',{})
        require('index' in e and e['index'] is None and e.get('plaintextOpenings')==0,'byte probe reports divergence or decryption')
        require(e.get('operatorRoot') and e['operatorRoot']==e.get('replayRoot'),'byte-probe trace roots differ')
        roots.add(e['operatorRoot'])
    require(len(roots)==1,'auditors did not compare the same operator trace')

def summarize_transport(rows,roles):
    out=[];seen=set()
    for row in rows:
        require(row.get('kind')=='role_transport','not a role transport record')
        key=(row['node'],row['id']);require(key not in seen,'duplicate RPC record');seen.add(key)
        require(row['node'] in roles and row['target'] in roles and row['host']==roles[row['node']]['host'],'transport record on wrong participant host')
        for field in ['requestJsonBytes','responseJsonBytes','elapsedSeconds']:number(row[field],'transport '+field)
        out.append({**row,'roundTripSeconds':row['elapsedSeconds'],'target_host':roles[row['target']]['host'],
                    'cross_host':row['host']!=roles[row['target']]['host']})
    return out

def source_context(record,sources):
    """Validate preserved inputs directly, without consulting current adapters."""
    if sources is None:
        command=record.get('buildCommand',[])
        require(command and isinstance(command[-1],str),'provide the preserved --sources image context')
        sources=command[-1]
    sources=Path(sources).resolve()
    require(read(sources/'distributed-source.json')==record,'preserved source context belongs to another image')
    require(sha(sources/'Dockerfile')==record['dockerfileSha256'],'preserved Dockerfile changed')
    actual={}
    for top in ('app','upstream'):
        for path in sorted((sources/top).rglob('*')):
            name=path.relative_to(sources).as_posix()
            if path.is_symlink():
                require(path.resolve().is_relative_to(sources),'preserved source symlink escapes context')
                actual[name]={'symlink':str(path.readlink())}
            elif path.is_file():actual[name]={'sha256':sha(path)}
    require(actual==record.get('buildInputs'),'preserved build input closure changed')
    for name,digest in record['localSource'].items():
        require(sha(sources/'app'/name)==digest,'preserved protocol source changed: '+name)
    for name,digest in record['distributedSource'].items():
        require(sha(sources/'app/distributed'/name)==digest,'preserved adapter source changed: '+name)
    return sources

def verify_original(run,sources=None):
    run=Path(run).resolve()
    seal=read(run/'seal.json');load=reader(run,seal)
    record=load('distributed/source.json');sources=source_context(record,sources)
    state=load('state.json')
    # The retained image context has source files but no plaintext dataset or
    # installed Node modules. Construct a private temporary validation view.
    # Its validators come exclusively from that verified source context.
    with tempfile.TemporaryDirectory(prefix='vcfhe-smoke-audit-') as temporary:
        app=Path(temporary)/'app';shutil.copytree(sources/'app',app,symlinks=True)
        for name,evidence in state['datasets'].items():
            preserved=run/'dataset-transfer'/('stav.csv' if 'Raw_Ratings' in name else 'qoe/'+Path(name).name)
            require(sha(preserved)==evidence['sha256'],'retained dataset differs from original run')
            target=app/name;require(target.resolve().is_relative_to(app),'invalid dataset source path')
            target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(preserved,target)
        for component in ['fhe-pod','BN254-Signatures']:
            lock=read(app/component/'package-lock.json')
            installed=DISTRIBUTED.parent/component/'node_modules'
            for package in ['ethers','solc']:
                require(read(installed/package/'package.json')['version']==lock['packages']['node_modules/'+package]['version'],
                        'controller dependency version differs from frozen lock: '+component+'/'+package)
            (app/component/'node_modules').symlink_to(installed.resolve(),target_is_directory=True)
        program=("import json,sys\nfrom pathlib import Path\n"
            "sys.dont_write_bytecode=True\nsys.path.insert(0,sys.argv[1])\n"
            "import run as original\noriginal.verify(Path(sys.argv[2]))\n"
            "from onchain_evidence import validate_run\nprint(json.dumps(validate_run(Path(sys.argv[2]))))\n")
        result=subprocess.run([sys.executable,'-c',program,str(app/'threshold-kms/campaign'),str(run)],
            cwd=app,capture_output=True,text=True,timeout=600,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        require(result.returncode==0,'preserved original validators failed: '+(result.stderr or '')[-1500:])
        return json.loads(result.stdout)

def reader(run,seal):
    def load(name,json_value=True):
        p=Path(name)
        require(not p.is_absolute() and '..' not in p.parts,'unsafe sealed path')
        path=run/p
        require(path.resolve().is_relative_to(run),'sealed path escapes run')
        require(name in seal['files'] and sha(path)==seal['files'][name],'changed or unsealed audit input: '+name)
        return read(path) if json_value else path
    return load

def resources(row,label):
    require(isinstance(row,dict) and row.get('exitCode')==0 and row.get('signal') is None,'failed or missing process: '+label)
    number(row.get('elapsedMs'),label+' elapsed time')
    r=row.get('resources')
    require(isinstance(r,dict) and r.get('scope')=='command-and-waited-descendants','wrong process scope: '+label)
    cpu=r.get('totalCpuMs')
    if cpu is None:
        require(bool(r.get('unavailableReason')) and r.get('userCpuMs') is None and r.get('systemCpuMs') is None,
                'CPU missing without an explicit reason: '+label)
    else:
        number(cpu,label+' CPU')
        require(math.isclose(cpu,number(r.get('userCpuMs'),label+' user CPU')+number(r.get('systemCpuMs'),label+' system CPU'),
                             rel_tol=1e-12,abs_tol=1e-9),'CPU sum mismatch: '+label)
    if r.get('maxRssBytes') is not None:number(r['maxRssBytes'],label+' RSS')
    return cpu is not None

def csv_rows(load,name):
    with load(name,False).open(newline='') as stream:return list(csv.DictReader(stream))

def audit(run,sources=None):
    run=Path(run).resolve()
    release_evidence=verify_original(run,sources=sources)
    initial_seal=sha(run/'seal.json');seal=read(run/'seal.json');load=reader(run,seal)
    cfg,state,app=load('config/campaign.json'),load('state.json'),load('reports/application.json')
    require(cfg.get('smoke') is True and cfg.get('readinessOnly') is True
            and cfg.get('executionProfile')==PROFILE and cfg.get('classification')==CLASSIFICATION,
            'not the exact nonpublishing distributed smoke profile')
    require(state.get('status')=='passed' and state.get('config')==cfg,'original run did not pass')
    require(release_evidence==load('reports/onchain-release-evidence.json'),'V3 authorization summary differs from raw evidence')
    ready,prss=load('keyset/ready.json'),load('keyset/prss.json')
    require(ready.get('status')=='passed' and ready.get('parties')==4 and ready.get('corruptionThreshold')==1
            and ready.get('fullPreprocessing') is True and ready.get('preloadedFheKey') is False
            and ready.get('parameters')=='Test' and prss.get('livePRSS') is True,'incomplete four-core PRSS/preprocessing/DKG evidence')
    for field in ['preprocessingSeconds','dkgSeconds']:number(ready.get(field),'KMS '+field)
    number(prss.get('seconds'),'PRSS elapsed time')
    require(app.get('status')=='passed' and app.get('kmsCalls')==3 and app.get('keys')==ready,'application/keyset scope mismatch')
    expected=load('owner/expected.json')
    for i,case in enumerate(app['cases']):
        result=load(f'recipient/result-{i}.json')
        require(result.get('name')==case['name'] and result.get('actual')==expected[case['name']]
                and result.get('outputDigest')==case['outputDigest'],'recipient output/reference binding failure')
        require(all(result.get(field)==count for field,count in [('responses',3),('directUserAndPublicDenied',4),
            ('negativeResponseChecks',4),('directAdministrativeDenied',28),('changedReservedWireDenied',4)]),
            'threshold or unauthorized-ingress checks are incomplete')
    expected_result={'status':'passed',**validate_cases(app['cases'])}
    require(read(run/'distributed/smoke-result.json')==expected_result,'smoke result differs from its original cases')
    d=descriptor(load('distributed/execution.json'))
    require(d.get('status')=='completed' and d.get('fullCases')==3 and d.get('measuredPairs')==0 and d.get('warmups')==0,
            'wrong completed smoke execution scope')
    require(d.get('imageDigest')==state.get('imageId') and '@sha256:' in d['imageDigest'],'image identity mismatch')
    require(d.get('sourceSha256')==state.get('distributedSourceSha256')==digest(load('distributed/source.json')),
            'distributed source identity mismatch')
    require(d.get('binarySha256')==sha(load('bin/kms-campaign',False)),'native binary identity mismatch')
    roles={r['id']:r for r in d['roles']};hosts={h['id'] for h in d['hosts']};environments=[]
    for host in d['hosts']:
        report=load('distributed/hosts/'+host['id']+'.json')
        require(report.get('host')==host['id'] and report.get('region')==host['region'],'host evidence misassigned')
        require(report.get('imageDigest')==d['imageDigest'] and report.get('binarySha256')==d['binarySha256'],
                'different image or binary across hosts')
        env=tuple(report.get(k) for k in ['cpuModel','kernelRelease','architecture'])
        require(all(isinstance(v,str) and v for v in env),'incomplete actual host environment')
        environments.append(env)
    require(len(set(environments))==1,'canonical execution environments differ across four hosts')
    records={};role_counts=Counter();node_counts=Counter();cpu_available=0;processes=0
    inventory=load('distributed/task-inventory.json')
    for item in inventory:
        p=Path(item['path'])
        require(p.parts[:2]==('distributed','tasks') and len(p.parts)==4,'invalid task inventory path')
        record=load(item['path']);role=roles.get(record.get('node'))
        require(sha(run/p)==item['sha256'],'task inventory hash mismatch')
        require(role and p.parts[2]==record['node'] and record.get('host')==role['host'] and record.get('role')==role['role'],
                'task node, host or role mismatch')
        identity=(record['node'],record['id'])
        require(identity not in records and record.get('status')=='completed','duplicate or incomplete task')
        records[identity]=record;role_counts[role['role']]+=1;node_counts[record['node']]+=1
        number(record.get('elapsedMs'),'task elapsed time')
        if record['task'] in COMPUTED:
            cpu_available+=resources(record.get('measurement'),record['node']+'/'+record['task']);processes+=1
            for child in record.get('publicWorkerResources',[]):
                cpu_available+=resources(child,'native FHE child');processes+=1
    require(all(role_counts[r]>0 for r in REQUIRED_ROLES),'some protocol roles have no task evidence')
    validate_byte_probe(load('reports/distributed/byte-repeatability.json'),records)
    owners=[]
    for case in app['cases']:
        fragments=[]
        for index in range(4):
            f=load(f'fixtures/{case["name"]}/owner-fragments/{index}/fragment.json');node=f'owner-{index+1}'
            require(f.get('owner')==index and f.get('node')==node and f.get('host')==roles[node]['host'],
                    'owner encryption fragment on wrong participant')
            number(f.get('encryptionElapsedMs'),'owner encryption elapsed time')
            require(isinstance(f.get('indices'),list) and all(type(i) is int and i>=0 for i in f['indices']),
                    'invalid owner fragment indices')
            if f['indices']:
                cpu_available+=resources(f.get('resources'),'owner encryption');processes+=1
            fragments.append(f);owners.append((case['name'],node,roles[node]['host']))
        require(len({f.get('scopeSha256') for f in fragments})==1 and fragments[0].get('scopeSha256'),
                'owner fragments disagree on encryption context')
        indices=[i for f in fragments for i in f['indices']]
        require(indices and sorted(indices)==list(range(len(indices))),'owner encryption fragments overlap or omit input indices')
    network=[];sample_counts={}
    for host in hosts:
        file=load(f'distributed/samples/{host}/host-observations.jsonl',False)
        rows=[json.loads(line) for line in file.read_text().splitlines() if line.strip()]
        require(rows and all(row.get('host')==host for row in rows),'missing or misassigned host telemetry')
        sample_counts[host]=sum(row.get('kind')=='host_sample' for row in rows)
        require(sample_counts[host]>0,'host has no resource samples')
        for row in rows:
            if row.get('kind')!='network_probe':continue
            require(row.get('target_host') in hosts and row.get('port')==8545 and row.get('status') in ('connected','unavailable'),
                    'invalid network telemetry binding')
            number(row.get('elapsed_seconds'),'TCP connection duration');network.append(row)
    connected={(r['host'],r['target_host']) for r in network if r['status']=='connected'}
    require({(a,b) for a in hosts for b in hosts if a!=b}<=connected,'missing successful TCP observations for a cross-host direction')
    raw_transport=[]
    for name in seal['files']:
        if name=='reports/distributed/transport.jsonl' or (name.startswith('collected/') and name.endswith('/reports/distributed/transport.jsonl')):
            file=load(name,False);raw_transport.extend(json.loads(line) for line in file.read_text().splitlines() if line.strip())
    transport=summarize_transport(raw_transport,roles)
    require(any(r['cross_host'] for r in transport),'cross-host application RPC telemetry missing')
    base='distributed/supplement/'
    require(len(csv_rows(load,base+'network-connections.csv'))==len(network),'TCP export does not cover raw samples')
    require(len(csv_rows(load,base+'role-communication.csv'))==len(transport),'RPC export does not cover raw calls')
    work=csv_rows(load,base+'participant-work.csv')
    require(Counter((r['node'],r['host'],r['role'],r['task']) for r in work)==
            Counter((r['node'],r['host'],r['role'],r['task']) for r in records.values()),'participant-work CSV coverage mismatch')
    require(Counter((r['case_id'],r['node'],r['host']) for r in csv_rows(load,base+'owner-encryption.csv'))==Counter(owners),
            'owner encryption CSV coverage mismatch')
    callers={r['role'] for r in roles.values()}-{'validator'}
    communication=csv_rows(load,base+'communication-summary.csv')
    require(len(communication)==len(callers) and {r['role'] for r in communication}==callers,'communication summary role coverage mismatch')
    for row in communication:
        calls=[r for r in transport if roles[r['node']]['role']==row['role']]
        require(int(row['rpc_count'])==len(calls)
                and int(row['request_json_bytes'])==sum(r['requestJsonBytes'] for r in calls)
                and int(row['response_json_bytes'])==sum(r['responseJsonBytes'] for r in calls),'communication totals mismatch')
    delays=csv_rows(load,base+'application-delay-summary.csv')
    require(len(delays)==len(callers) and {r['role'] for r in delays}==callers,'application delay role coverage mismatch')
    for row in delays:
        require(int(row['observations'])==sum(r['cross_host'] and roles[r['node']]['role']==row['role'] for r in transport),
                'application delay count mismatch')
    groups={(r['host'],r['target_host'],r['port']) for r in network}
    network_summary=csv_rows(load,base+'network-delay-summary.csv')
    require(len(network_summary)==len(groups) and {(r['host'],r['target_host'],int(r['port'])) for r in network_summary}==groups,
            'network delay group coverage mismatch')
    margins=csv_rows(load,base+'deadline-margins.csv');nonlinear={c['name']:c for c in app['cases'] if c['half']=='nonlinear'}
    require(len(margins)==2 and {r['case_id'] for r in margins}==set(nonlinear),'deadline export coverage mismatch')
    for row in margins:
        s=nonlinear[row['case_id']]['metrics']['scheduling']
        for field,start,end in [('audit_commit_margin_seconds','commitTimestamp','commitDeadline'),('audit_open_margin_seconds','openTimestamp','openDeadline')]:
            value=number(float(row[field]),'mined deadline margin')
            require(value==s[end]-s[start],'deadline margin differs from mined receipt evidence')
    summary=load(base+'summary.json')
    require(summary.get('full_cases')==3 and summary['delays']['tcpObservations']==len(network)
            and summary['delays']['applicationRpcObservations']==sum(r['cross_host'] for r in transport),
            'supplement summary scope mismatch')
    require(sha(run/'seal.json')==initial_seal,'original seal changed during audit')
    return {'schema':'vcfhe-derived-smoke-audit-v1','status':'passed','evaluationPublishable':False,
        'originalSealSha256':initial_seal,'originalStateSha256':sha(run/'state.json'),
        'originalSmokeResultSha256':sha(run/'distributed/smoke-result.json'),
        'validatorSources':'verified preserved image context, not current project source files',
        'realThresholdSetupParties':4,'authorizedResults':3,'rejectedFaultyNonlinearExecutions':2,
        'hosts':len(hosts),'homogeneousEnvironment':list(environments[0]),'tasks':len(records),
        'tasksByRole':dict(role_counts),'tasksByNode':dict(node_counts),'ownerEncryptionFragments':len(owners),
        'hostResourceSamples':sample_counts,'tcpObservations':len(network),'crossHostTcpDirections':12,
        'roleRpcObservations':len(transport),'crossHostRoleRpcs':sum(r['cross_host'] for r in transport),
        'measuredProcesses':processes,'processCpuAvailable':cpu_available,'processCpuUnavailable':processes-cpu_available,
        'scope':'Additional audit of sealed three-case smoke evidence. Original run and seal are unchanged.',
        'limitations':['Common cloud administration. Host/task reports are experimental evidence, not remote attestation.',
            'Three functional cases and no paired repetitions do not establish campaign performance or tail probabilities.',
            'TCP probes use port 8545. Role RPC JSON excludes KMS gRPC, Besu P2P and TLS/IP wire overhead.',
            'CPU can be explicitly unavailable. Only the reported availability counts establish which process costs were recorded.',
            'Unused quorum members need not execute a measured task. Role coverage is not a claim that every committee member signed.']}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--sources',type=Path,help='preserved image-build context if its recorded location moved')
    args=parser.parse_args();run=args.run.resolve();output=args.output.resolve()
    require(output.name.endswith('.local.json') and not output.is_relative_to(run),'use a separate private .local.json report outside the run')
    require(not output.exists(),'retain existing audit reports')
    try:report=audit(run,sources=args.sources);code=0
    except Exception as error:
        report={'schema':'vcfhe-derived-smoke-audit-v1','status':'failed','evaluationPublishable':False,
            'errorType':type(error).__name__,'error':str(error),
            'originalSealSha256':sha(run/'seal.json') if (run/'seal.json').is_file() else None,
            'scope':'Derived audit failed. No original run status or seal was changed.'};code=1
    report.update(auditedAt=datetime.now(timezone.utc).isoformat(),auditScriptSha256=sha(__file__))
    output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with output.open('x') as stream:
        os.fchmod(stream.fileno(),0o600);json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps({'status':report['status'],'report':str(output),'originalRunChanged':False}))
    return code

if __name__=='__main__':raise SystemExit(main())
