#!/usr/bin/env python3
"""Dataset-backed real-FHE/Besu/Zama-threshold campaigns, independently selectable."""
import argparse
import contextlib
import csv
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import uuid
import threading
from progress import ProgressMonitor, stage_message
from datasets import ensure as ensure_datasets
from poc_plan import (TEST_POC_DISCLOSURE_BATCH_SIZE, TEST_POC_WINDOW_SECONDS,
                      plan as poc_plan, validate_timing_window)
from policy_refresh import (CLASSIFICATION as POLICY_REFRESH_CLASSIFICATION,
                            RECOVERY_MESSAGE as POLICY_REFRESH_RECOVERY_MESSAGE,
                            assert_attempt_available as assert_policy_refresh_attempt_available,
                            plan as policy_refresh_plan,
                            reserve_attempt as reserve_policy_refresh_attempt,
                            validate_prepared_preflight as validate_policy_refresh_preflight,
                            validate_run_directory as validate_policy_refresh_run)
from comparative_evidence import VERSION as COMPARATIVE_METRICS_VERSION, validate_report as validate_comparative_report
from availability_evidence import VERSION as AVAILABILITY_VERSION, validate as validate_availability
from scheduling_evidence import VERSION as SCHEDULING_VERSION, validate_run as validate_scheduling
from host_environment import capture as capture_host_environment
from policy_bootstrap import (bootstrap_lock, inspect_docker_state, classify_bootstrap,
                              prepare_bootstrap, mark_identities_ready,
                              mark_policy_starting, mark_deployed)

MODULE=Path(__file__).resolve().parents[1]
ROOT=MODULE.parent
PIN='986537258d8c0348f497b1860ccf63252bc238f3'
VERSION='dataset-threshold-campaign-v3'
OWNER_RPC_URLS=[f'http://node{i}:8545' for i in range(1,5)]
STAGES=['dependencies','pinned-build','nonlinear:committee-availability-controls','besu-qbft','adminless-on-chain-release-policy',
        'four-kms-cores-with-independent-chain-reads','live-prss','full-preprocessing-and-dkg',
        'owner-dataset-encryption','linear:verification-and-recipient-release',
        'nonlinear:execution-replay-disputes-and-recipient-release','verify-and-export','results-analysis']
SEALED_ARTIFACT_FOLDERS=('reports','fixtures','release-evidence','owner','keyset','config',
                         'bin','build-evidence')

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def seal_payload_sha256(seal):
    """Bind seal metadata without trying to include the digest in itself."""
    payload={key:value for key,value in seal.items() if key!='sealPayloadSha256'}
    return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def collect_seal_files(run):
    run=Path(run)
    files={path.relative_to(run).as_posix():sha(path)
           for folder in SEALED_ARTIFACT_FOLDERS for path in (run/folder).rglob('*')
           if path.is_file() and not path.name.endswith('.key')}
    files.update({path.relative_to(run).as_posix():sha(path)
                  for path in (run/'recipient').glob('result-*.json')})
    files.update({name:sha(run/name)
                  for name in ['state.json','compose.json','setup-compose.json','besu.json']})
    return files

def write(path,value):
    path=Path(path);temp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    with temp.open('x') as f:
        json.dump(value,f,indent=2);f.flush();os.fsync(f.fileno())
    temp.replace(path)
    fd=os.open(path.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)

def command(args,**kwargs):
    return subprocess.run([str(x) for x in args],check=True,**kwargs)

def output(args):return subprocess.check_output([str(x) for x in args],text=True).strip()

@contextlib.contextmanager
def resource_samples(run,compose,stage):
    stop=threading.Event()
    def sample():
        with (run/'reports/resources.jsonl').open('a') as log:
            while not stop.is_set():
                try:
                    ids=output(compose+['ps','-q']).splitlines()
                    ids+=output(['docker','ps','-q','--filter','label=com.docker.compose.project=vcfhe-besu']).splitlines()
                    ids=list(dict.fromkeys(ids))
                    if ids:
                        raw=subprocess.check_output(['docker','stats','--no-stream','--format','{{json .}}',*ids],text=True,timeout=15)
                        for line in raw.splitlines():
                            log.write(json.dumps({'stage':stage,'unixTime':time.time(),'docker':json.loads(line)})+'\n')
                        log.flush()
                except (OSError,ValueError,subprocess.SubprocessError) as error:
                    log.write(json.dumps({'stage':stage,'sampleError':str(error)})+'\n');log.flush()
                stop.wait(15)
    thread=threading.Thread(target=sample,daemon=True);thread.start()
    try:yield
    finally:stop.set();thread.join(timeout=20)

def retry(args,attempts=3):
    for attempt in range(attempts):
        try:return command(args)
        except subprocess.CalledProcessError:
            if attempt==attempts-1:raise
            print('Transient command failure; retrying without changing security parameters.',flush=True)
            time.sleep(2**attempt)

def stop_oneshots(compose_file):
    """Stop only this run's detached one-shot containers; retain all volumes."""
    project=json.loads(Path(compose_file).read_text())['name']
    ids=output(['docker','ps','-q','--filter','label=com.docker.compose.project='+project,
                '--filter','label=com.docker.compose.oneoff=True']).splitlines()
    if ids:command(['docker','stop','--time','15',*ids],stdout=subprocess.DEVNULL)

def stop_campaign_services(compose):
    # Stop processes, never remove private vaults, chain data or raw evidence.
    # Otherwise consecutive independent halves accumulate four live cores each.
    command(compose+['stop','--timeout','15','owner','recipient','worker',
                     'kms1','kms2','kms3','kms4','public-store'],stdout=subprocess.DEVNULL)

def require_running(compose,roles,allow_recipient_exit=False):
    for role in roles:
        ids=output(compose+['ps','--all','--quiet',role]).splitlines()
        if len(ids)!=1:raise RuntimeError('missing/ambiguous campaign service: '+role)
        state=json.loads(output(['docker','inspect','--format','{{json .State}}',ids[0]]))
        if not state['Running'] and not (role=='recipient' and allow_recipient_exit and state['ExitCode']==0):
            raise RuntimeError(f'{role} exited (code {state["ExitCode"]}, OOM={state["OOMKilled"]}); no release will be retried')


POLICY_REFRESH_PASSIVE_ROLES=('kms1','kms2','kms3','kms4','public-store',
                              'owner','worker','recipient')


def validate_policy_refresh_preclaim_files(run,cfg):
    """Fail closed on passive preparation before consuming a refresh attempt."""
    run=Path(run)
    paths={
        'prepared':run/'fixtures/prepared.json',
        'keyset':run/'keyset/ready.json',
        'preflight':run/'reports/release-capacity-preflight.json',
    }
    try:
        values={name:json.loads(path.read_text(encoding='utf-8'))
                for name,path in paths.items()}
    except (OSError,json.JSONDecodeError) as error:
        raise ValueError('V3 policy-refresh passive preparation is incomplete or unreadable') from error
    design=validate_policy_refresh_preflight(
        cfg,values['prepared'],values['keyset'],values['preflight'])
    return {'design':design,'prepared':values['prepared'],'keyset':values['keyset'],
            'preflight':values['preflight']}


def wait_policy_refresh_preclaim(run,compose,cfg,timeout_seconds):
    """Wait for atomic owner preparation while all passive services stay live."""
    run=Path(run);deadline=time.monotonic()+timeout_seconds;next_check=0
    prepared=run/'fixtures/prepared.json'
    preflight=run/'reports/release-capacity-preflight.json'
    while True:
        now=time.monotonic()
        if now>=next_check:
            require_running(compose,list(POLICY_REFRESH_PASSIVE_ROLES))
            next_check=now+5
        if prepared.is_file() and preflight.is_file():
            result=validate_policy_refresh_preclaim_files(run,cfg)
            require_running(compose,list(POLICY_REFRESH_PASSIVE_ROLES))
            return result
        if now>=deadline:
            raise TimeoutError('V3 policy-refresh owner preparation and capacity preflight timed out')
        time.sleep(min(.2,max(0,deadline-now)))


def activate_policy_refresh_attempt(run,compose,cfg,state,timeout_seconds):
    """Reserve the permanent attempt only after the passive pre-release gate."""
    validated=wait_policy_refresh_preclaim(run,compose,cfg,timeout_seconds)
    report=validated['preflight']
    print('POLICY_REFRESH_PREFLIGHT '+json.dumps({
        'blockNumber':report['view']['blockNumber'],'blockHash':report['view']['blockHash'],
        'recordCount':report['recordCount'],'maxCurrentSpent':report['maxCurrentSpent'],
        'maxPlannedCharges':report['maxPlannedCharges'],
        'minRemainingAfterPlan':report['minRemainingAfterPlan']}),flush=True)
    attempt=reserve_policy_refresh_attempt(
        MODULE/'.policy-state',cfg['half'],cfg['runId'],run,cfg['policyRefreshPlan'])
    cfg['policyRefreshAttempt']=attempt
    write(Path(run)/'config/campaign.json',cfg)
    state['config']=cfg
    write(Path(run)/'state.json',state)
    return attempt

def source_files():
    # Build image intentionally excludes plaintext fixtures, raw datasets,
    # historical binaries and any private runtime state.
    selected=[]
    for directory in ['threshold-kms/campaign','threshold-kms/src','threshold-kms/scripts',
                      'threshold-kms/contracts','fhe-pod/scripts','fhe-pod/contracts/src',
                      'fhe-pod/crates/tfhe-pod-demo/src','BN254-Signatures/scripts','BN254-Signatures/contract']:
        selected.extend(p for p in (ROOT/directory).rglob('*') if p.is_file() and p.suffix in {'.py','.sh','.rs','.mjs','.cjs','.js','.sol'})
    for d in ['fhe-pod','BN254-Signatures']:
        selected.extend([ROOT/d/'package.json',ROOT/d/'package-lock.json'])
    selected.append(MODULE/'campaign/Dockerfile')
    selected.append(ROOT/'fhe-pod/scripts/bounty-economics.json')
    selected.append(ROOT/'fhe-pod/contracts/test/chain-harness.mjs')
    selected.extend(ROOT/p for p in ['run-poc.sh','run-linear.sh','run-nonlinear.sh','non-linear.sh','run-nonlinear-bounty.sh',
        'BN254-Signatures/run-experiment-output-binding.sh',
        'network/run-all.mjs','network/validators-besu/docker-compose.besu.yml','network/validators-besu/qbftConfig.json'])
    return sorted(set(selected))

def source_manifest():return {str(p.relative_to(ROOT)):sha(p) for p in source_files()}

def rust_source(cache,manifest):
    names={n:h for n,h in manifest.items() if n.endswith('.rs') or n in
           ['threshold-kms/campaign/build-profile.py','threshold-kms/scripts/kms-profile-build.py']}
    digest=hashlib.sha256(json.dumps({'pin':PIN,'source':names},sort_keys=True).encode()).hexdigest()
    base=cache/('rust-'+digest)
    if (base/'complete.json').exists():
        saved=json.loads((base/'complete.json').read_text())
        if saved['source']!=names:raise ValueError('wrong Rust source cache')
        for name,h in saved['files'].items():
            if sha(base/'upstream'/name)!=h:raise ValueError('changed Rust source cache: '+name)
        return base/'upstream'
    if base.exists():base=cache/('rust-'+digest+'-'+uuid.uuid4().hex[:8])
    base.mkdir();upstream=base/'upstream';seed=None
    # Reuse only a verified identical adapter source closure. Preserving its
    # mtimes lets Cargo reuse unchanged code; changed sources always get a new
    # content-addressed checkout, never a stale executable or evidence seal.
    for candidate in cache.iterdir():
        marker=candidate/'complete.json'
        if candidate.name.startswith('rust-') or not marker.is_file():continue
        saved=json.loads(marker.read_text())
        if all(saved.get('source',{}).get(n)==h for n,h in names.items()) and saved.get('upstream')==PIN and saved.get('buildFiles'):
            for name,h in saved['buildFiles'].items():
                if sha(candidate/name)!=h:raise ValueError('changed candidate build cache: '+name)
            seed=candidate/'upstream';break
    if seed:shutil.copytree(seed,upstream)
    else:
        command(['git','init',upstream]);command(['git','-C',upstream,'remote','add','origin','https://github.com/zama-ai/kms.git'])
        retry(['git','-C',upstream,'fetch','--depth','1','origin',PIN])
        command(['git','-C',upstream,'checkout','--detach','FETCH_HEAD'])
        command([sys.executable,MODULE/'campaign/build-profile.py','--source',upstream])
    if output(['git','-C',upstream,'rev-parse','HEAD'])!=PIN:raise ValueError('wrong upstream source revision')
    files={n:sha(upstream/n) for n in output(['git','-C',upstream,'ls-files']).splitlines() if (upstream/n).is_file()}
    files['vcfhe-adapter.json']=sha(upstream/'vcfhe-adapter.json')
    write(base/'complete.json',{'source':names,'files':files})
    return upstream

def build_context(cache,manifest):
    digest=hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()
    context=cache/digest
    if (context/'complete.json').exists():
        saved=json.loads((context/'complete.json').read_text())
        if saved.get('source')!=manifest or saved.get('upstream')!=PIN:raise ValueError('changed cached source identity')
        for name,h in saved['buildFiles'].items():
            if sha(context/name)!=h:raise ValueError('changed cached build input: '+name)
        return context,digest
    if context.exists():
        context=cache/(digest+'-retry-'+uuid.uuid4().hex[:8])
    context.mkdir(parents=True)
    upstream=context/'upstream'
    shutil.copytree(rust_source(cache,manifest),upstream)
    for name in manifest:
        target=context/'app'/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,target)
    shutil.copy2(MODULE/'campaign/Dockerfile',context/'Dockerfile')
    files=[context/'Dockerfile',*[context/'app'/n for n in manifest],upstream/'vcfhe-adapter.json']
    files.extend(upstream/n for n in output(['git','-C',upstream,'ls-files']).splitlines())
    write(context/'complete.json',{'source':manifest,'upstream':PIN,'buildFiles':{str(p.relative_to(context)):sha(p) for p in files if p.is_file()}})
    return context,digest

def core_config(i, rayon_threads=2, tokio_threads=1):
    if rayon_threads < 1 or tokio_threads < 1:
        raise ValueError('KMS thread counts must be positive')
    value=f'''mock_enclave = true
[internal_config]
num_rayon_threads = {rayon_threads}
num_tokio_threads = {tokio_threads}
[service]
listen_address = "0.0.0.0"
listen_port = 50100
timeout_secs = 360
grpc_max_message_size = 104857600
[public_vault.storage.file]
path = "/public"
prefix = "PUB-p{i}"
[private_vault.storage.file]
path = "/private"
prefix = "PRIV-p{i}"
[threshold]
listen_address = "0.0.0.0"
listen_port = 50001
my_id = {i}
threshold = 1
dec_capacity = 100
min_dec_cache = 10
num_sessions_preproc = 2
decryption_mode = "NoiseFloodSmall"
[threshold.tls.manual]
cert.path = "/public/PUB-p{i}/tls.pem"
key.path = "/private/tls-key.pem"
'''
    for j in range(1,5):value+=f'''\n[[threshold.peers]]
party_id = {j}
address = "kms{j}"
mpc_identity = "kms{j}"
port = 50001
tls_cert.path = "/public/PUB-p{j}/tls.pem"
'''
    return value

def configuration(run,args,image):
    config=run/'config'
    policy=MODULE/'.policy-state'
    policy.mkdir(exist_ok=True,mode=0o700)
    for role in ['owner','recipient','setup','onchain']:(policy/role).mkdir(exist_ok=True,mode=0o700)
    for d in ['config','owner','recipient','exchange','release-evidence','owner-rpc','worker-rpc','keyset','fixtures','reports','public']:
        (run/d).mkdir(exist_ok=True,mode=0o700)
    for i in range(1,5):
        (run/f'private-{i}').mkdir(exist_ok=True,mode=0o700)
        (run/'public'/f'PUB-p{i}').mkdir(exist_ok=True,mode=0o700)
        (config/f'core-{i}.toml').write_text(core_config(i,args.kms_threads,args.kms_tokio_threads))
    client=f'kms_type = "threshold"\nnum_majority = 2\nnum_reconstruct = 3\ndecryption_mode = "NoiseFloodSmall"\nfhe_params = "{args.fhe_params}"\n'
    for i in range(1,5):client+=f'\n[[cores]]\nparty_id = {i}\naddress = "kms{i}:50100"\ns3_endpoint = "http://public-store:8080"\nobject_folder = "PUB-p{i}"\n'
    (config/'client.toml').write_text(client)
    env={'VCFHE_FHE_PARAMS':args.fhe_params,'VCFHE_KMS_MAX_POLLS':str(args.timeout*10),
         'VCFHE_ALLOW_INSECURE':'1' if args.allow_insecure_test else '0','RAYON_NUM_THREADS':str(args.kms_threads),
         'RUST_LOG':'warn','AWS_EC2_METADATA_DISABLED':'true'}
    mount=lambda src,dst,ro=False:{'type':'bind','source':str(run/src),'target':dst,'read_only':ro}
    base={'image':image,'user':f'{os.getuid()}:{os.getgid()}',
          'security_opt':['no-new-privileges:true'],'cap_drop':['ALL'],
          'environment':env,'networks':['kms'],'init':True,'read_only':True,
          'tmpfs':['/tmp:rw,nosuid,nodev,size=512m'], 'working_dir':'/tmp'}
    public=[mount(f'public/PUB-p{i}',f'/public/PUB-p{i}',True) for i in range(1,5)]
    services={}
    for i in range(1,5):
        services[f'kms{i}']={**base,'command':['core'],'networks':['kms','besu'],
          'environment':{**env,'VCFHE_PARTY':str(i),'VCFHE_POLICY_RPC_URLS':','.join(OWNER_RPC_URLS),
                         'VCFHE_RELEASE_POLICY_CONFIG':'/config/release-policy.json'},
          'volumes':[mount('config','/config',True),mount(f'private-{i}','/private'),
                     mount('release-evidence','/release-evidence',True),mount('keyset','/release-keyset',True),
                     *[mount(f'public/PUB-p{j}',f'/public/PUB-p{j}',j!=i) for j in range(1,5)]],
          'healthcheck':{'test':['CMD','python3','-c',"import socket;socket.create_connection(('127.0.0.1',50100),2).close()"],
                         'interval':'5s','timeout':'3s','retries':120},'pids_limit':256}
    services['public-store']={**base,'command':['public-store'],'volumes':public}
    shared=[mount('config','/config',True),mount('keyset','/keyset'),mount(str(policy/'setup'),'/setup-identity',True)]
    services['init']={**base,'command':['init'],'volumes':shared}
    services['setup']={**base,'command':['setup'],'volumes':shared}
    allow_initial_setup=args.new_policy_lineage or getattr(args,'verified_initial_policy_setup',False)
    services['identities']={**base,'command':['identities'],'network_mode':'none',
        'environment':{**env,'VCFHE_ALLOW_NEW_POLICY_LINEAGE':'1' if allow_initial_setup else '0'},'volumes':[
        mount('config','/provision/config'),*[mount(str(policy/role),'/provision/'+role) for role in ['owner','recipient','setup']]]}
    del services['identities']['networks']
    services['policy-init']={**base,'command':['policy-init'],'networks':['besu'],
        'environment':{**env,'VCFHE_POLICY_RPC_URL':'http://node1:8545',
                       'VCFHE_EXPECTED_CHAIN_ID':'46853','VCFHE_POLICY_VERSION':'3',
                       'VCFHE_ALLOW_NEW_POLICY_LINEAGE':'1' if allow_initial_setup else '0',
                       'VCFHE_REQUIRE_EXISTING_POLICY':'1' if args.policy_refresh_v3 else '0'},
        'volumes':[mount('config','/config'),mount(str(policy/'onchain'),'/policy-state')]}
    legacy=policy/'gateway'/'ledger.json'
    if legacy.exists() and not args.policy_refresh_v3:
        services['policy-init']['volumes'].append({'type':'bind','source':str(legacy),
                                                  'target':'/migration/ledger.json','read_only':True})
    services['owner']={**base,'command':['owner'],'environment':{**env,'RAYON_NUM_THREADS':'1'},
        'networks':['besu'],
        'volumes':[mount('config','/config',True),mount('owner','/owner'),mount('owner-rpc','/owner-rpc'),
                    mount('exchange','/exchange',True),
                    mount(str(policy/'owner'),'/owner-identity',True),
                    mount('keyset','/keyset',True),mount('fixtures','/fixtures'),mount('reports','/reports')]}
    if args.half!='linear':services['owner']['volumes'].append({'type':'bind','source':str(ROOT/'data'),'target':'/datasets/qoe','read_only':True})
    if args.half!='nonlinear':
        for source,target in [('datasets/raw/stav360/Raw_Ratings.csv','/datasets/stav.csv'),('datasets/outputs/linear-inputs.json','/datasets/linear.json')]:
            services['owner']['volumes'].append({'type':'bind','source':str(ROOT/source),'target':target,'read_only':True})
    services['evaluate']={**base,'command':['evaluate'],'environment':{**env,'RAYON_NUM_THREADS':'1'},
        'networks':['besu'],'volumes':[mount('config','/config',True),mount('keyset','/keyset',True),
            mount('fixtures','/fixtures'),mount('owner-rpc','/owner-rpc'),
            mount('exchange','/exchange'),mount('release-evidence','/release-evidence'),
            mount('worker-rpc','/worker-rpc'),mount('reports','/reports')]}
    services['worker']={**base,'command':['worker'],'network_mode':'none','environment':{**env,'RAYON_NUM_THREADS':'1'},
        'volumes':[mount('keyset','/keyset',True),mount('fixtures','/fixtures'),mount('worker-rpc','/worker-rpc')]}
    del services['worker']['networks']
    if args.half!='linear' and getattr(args,'nonlinear_protocol','canonical')=='bounty-v2':
        services['availability-controls']={**base,'entrypoint':['node'],
            'command':['/app/fhe-pod/scripts/evaluate-committee-availability.mjs',
                       '--output-dir','/reports/committee-availability'],
            'network_mode':'none','environment':{'VCFHE_TEST_RPC_URL':''},
            'volumes':[mount('reports','/reports')]}
        del services['availability-controls']['networks']
        write(config/'availability-compose.json',{'name':'vcfhe-controls-'+run.name[-12:].lower(),
              'services':{'availability-controls':services.pop('availability-controls')}})
    services['recipient']={**base,'command':['recipient'],'volumes':[mount('config','/config',True),
        mount('keyset','/keyset',True),mount('recipient','/recipient'),mount(str(policy/'recipient'),'/recipient-identity',True),mount('exchange','/exchange')]}
    compose={'name':'vcfhe-kms-'+run.name[-12:].lower(),'services':services,
             'networks':{'kms':{'internal':True},'besu':{'external':True,'name':args.besu_network}}}
    write(run/'compose.json',compose)
    # Every KMS core independently quorum-reads the four validator RPCs.
    # Besu and the registry therefore exist before this setup view starts them.
    setup_roles=['kms1','kms2','kms3','kms4','public-store','identities','init','setup']
    write(run/'setup-compose.json',{'name':compose['name'],
        'services':{role:services[role] for role in setup_roles},
        'networks':compose['networks']})
    if getattr(args,'verified_initial_policy_setup',False):
        # Provision and bind identities before any new blockchain state exists.
        # This isolated Compose view has no external-network prerequisite.
        write(config/'identities-compose.json',{'name':compose['name'],
              'services':{'identities':services['identities']}})
    return ['docker','compose','-f',str(run/'compose.json')]

def infrastructure_stages(run,compose,keyset_reuse=False):
    setup=['docker','compose','-f',str(run/'setup-compose.json')]
    stages=[
        ('besu',['docker','compose','-p','vcfhe-besu','-f',run/'besu.json',
                 'up','-d','--wait','--wait-timeout','180','node1','node2','node3','node4']),
        ('identities',setup+['run','--rm','identities']),
        ('release-policy',compose+['run','--rm','policy-init']),
        ('kms-cores',setup+['up','-d','--wait','kms1','kms2','kms3','kms4','public-store']),
        ('owner-start',compose+['up','-d','owner']),
        ('worker-start',compose+['up','-d','worker']),
        ('recipient-start',compose+['up','-d','recipient']),
    ]
    if not keyset_reuse:
        stages[4:4]=[('prss',setup+['run','--rm','init']),('dkg',setup+['run','--rm','setup'])]
    return stages

def comparison_control_stages(cfg, run):
    if not cfg.get('availabilityControlsVersion'): return []
    if (cfg['availabilityControlsVersion']!=AVAILABILITY_VERSION or cfg.get('half') not in {'nonlinear','both'}
            or cfg.get('nonlinearProtocol')!='bounty-v2'):
        raise ValueError('invalid availability-control selection')
    return [('committee-availability-controls',['docker','compose','-f',str(Path(run)/'config/availability-compose.json'),
            'run','--rm','--no-deps','availability-controls'])]

def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--half',choices=['linear','nonlinear','both'],default='both')
    p.add_argument('--nonlinear-protocol', choices=['canonical','bounty-v2'], default='canonical',
                   help='versioned nonlinear settlement; bounty-v2 supports nonlinear or combined Test PoC/readiness')
    p.add_argument('--fhe-params',choices=['Default','Test'],default='Default')
    p.add_argument('--allow-insecure-test',action='store_true')
    p.add_argument('--poc',action='store_true',help='complete approved 100/30-pair Test campaign; requires --fhe-params Test --allow-insecure-test; not smoke')
    p.add_argument('--policy-refresh-v3',action='store_true',
                   help='standalone V3 refresh of 15 linear, 30 nonlinear, or all 45 preselected full cases; never reruns/imports paired measurements')
    p.add_argument('--poc-readiness',action='store_true',help='explicit Test/smoke admission pilot: n=27 linear and n=50 nonlinear, never evaluation evidence')
    p.add_argument('--readiness-workload',choices=['both','regulatory','regional'],default='both',help='select a nonlinear admission check only; requires --poc-readiness, never limits a full evaluation campaign')
    p.add_argument('--readiness-disputes-only',action='store_true',help='separate Test readiness dispute checks without output requests or decryption; never evaluation evidence')
    p.add_argument('--smoke',action='store_true');p.add_argument('--fresh',action='store_true')
    p.add_argument('--resume',action='store_true');p.add_argument('--keep-chain',action='store_true')
    p.add_argument('--list',action='store_true');p.add_argument('--check',action='store_true')
    p.add_argument('--preflight',action='store_true',help='read-only host-tool and retained-policy checks, without Docker startup or experiments')
    p.add_argument('--explain-threshold-scaling',action='store_true',help='report the measured threshold scope without running a simulated sweep')
    p.add_argument('--build-only',action='store_true')
    p.add_argument('--postprocess-only',action='store_true',help='derive/review/publish a completed run without transactions or KMS calls')
    p.add_argument('--derived-dir',type=Path,help='new derived directory directly under threshold-kms/composites, with --postprocess-only')
    p.add_argument('--diagnostic-review',type=Path,help='existing hash-bound diagnostic review for postprocessing')
    p.add_argument('--manual-review',action='store_true',help='generate preliminary diagnostics for explicit review')
    p.add_argument('--new-policy-lineage',action='store_true',
                   help='explicitly create a new cumulative-policy lineage; never represents continuity with prior releases')
    p.add_argument('--auto-policy-setup',action='store_true',
                   help='initialize an empty installation only after checking for retained policy and blockchain state')
    p.add_argument('--keyset-base',type=Path,
                   help='sealed local Default keyset base to clone into this fresh run; skips only PRSS/preprocessing/DKG')
    p.add_argument('--run-dir',type=Path);p.add_argument('--cache-dir',type=Path,default=MODULE/'.cache')
    p.add_argument('--chain',choices=['qbft'],default='qbft',help='evaluation path requires real Besu; no Ganache fallback')
    p.add_argument('--timeout',type=int,default=86400,help='per-stage seconds, default 24 h accommodates the full QBFT windows; no insecure fallback')
    p.add_argument('--target-cell',type=int,default=474859250,help='public regional query cell, fixed before reading records (default Rome: 41.90 N, 12.50 E)')
    p.add_argument('--kms-threads',type=int,default=2,help='Rayon MPC workers per core, explicitly configured in upstream internal_config')
    p.add_argument('--kms-tokio-threads',type=int,default=1,help='Tokio runtime workers per core, not the corruption threshold')
    p.add_argument('--besu-network',default='vcfhe-besu_default')
    return p

def selection(args):
    disputes_only = getattr(args, 'readiness_disputes_only', False)
    if disputes_only and not (args.poc_readiness and args.smoke and args.half == 'nonlinear'
                             and args.fhe_params == 'Test' and args.allow_insecure_test
                             and args.nonlinear_protocol == 'bounty-v2' and not args.poc
                             and not args.policy_refresh_v3):
        raise ValueError('--readiness-disputes-only requires nonlinear bounty-v2 Test readiness, never a full campaign')
    protocol = getattr(args, 'nonlinear_protocol', 'canonical')
    if protocol == 'bounty-v2':
        if (args.half not in {'nonlinear','both'} or not (args.poc or args.poc_readiness)
                or args.policy_refresh_v3 or args.fhe_params != 'Test' or not args.allow_insecure_test
                or args.kms_threads != 1 or args.kms_tokio_threads != 1 or args.new_policy_lineage):
            raise ValueError('bounty-v2 requires nonlinear or combined Test PoC/readiness, explicit insecure consent, one worker per core, and retained policy state or verified initial setup')
    selected = _selection(args)
    if disputes_only:
        selected.update(classification='test-insecure-dispute-readiness-not-evaluation',
                        readinessDisputesOnly='bounty-v2-dispute-readiness-v1')
    if protocol != 'canonical':
        selected['nonlinearProtocol'] = protocol
        selected['bountyEconomics'] = json.loads((ROOT/'fhe-pod/scripts/bounty-economics.json').read_text())
    return selected


def _selection(args):
    if args.policy_refresh_v3:
        if args.new_policy_lineage:
            raise ValueError('--policy-refresh-v3 reuses the existing on-chain policy and live counters; --new-policy-lineage is forbidden')
        if args.poc or args.smoke or args.poc_readiness or args.readiness_workload!='both':
            raise ValueError('--policy-refresh-v3 is a separate complete full-case profile; cannot combine with PoC, smoke or readiness options')
        if args.fhe_params!='Test' or not args.allow_insecure_test:
            raise ValueError('--policy-refresh-v3 requires --fhe-params Test --allow-insecure-test')
        design=policy_refresh_plan(args.half)
        return {'repeats':None,'records':50,'linearSizes':[10,16,27],
                'nonlinearSizes':[16,32,50],
                'nonlinearWorkloads':['regulatory','regional'],
                'windowSeconds':design['windowSeconds'],
                'disclosureBatchSize':design['disclosureBatchSize'],
                'selectionProfile':design['selectionProfile'],'readinessOnly':False,
                'classification':POLICY_REFRESH_CLASSIFICATION,
                'policyRefreshPlan':design,
                'auditorFunding':'deployed-challenge-bond-v1'}
    if args.poc:
        if args.smoke or args.poc_readiness or args.readiness_workload!='both':
            raise ValueError('--poc is the complete fixed grid; cannot combine with smoke/readiness/filter')
        if args.fhe_params!='Test' or not args.allow_insecure_test:
            raise ValueError('--poc requires --fhe-params Test --allow-insecure-test')
        design=poc_plan(args.half)
        validate_timing_window(design['windowSeconds'],design['disclosureBatchSize'])
        return {'repeats':None,'records':50,'linearSizes':[10,16,27],'nonlinearSizes':[16,32,50],
                'nonlinearWorkloads':['regulatory','regional'],'windowSeconds':design['windowSeconds'],
                'disclosureBatchSize':design['disclosureBatchSize'],
                'selectionProfile':'poc-disjoint-panels-v1','readinessOnly':False,
                'classification':'test-insecure-functional-poc','pocPlan':design,
                'auditorFunding':'deployed-challenge-bond-v1'}
    if args.readiness_workload!='both' and (not args.poc_readiness or args.half=='linear'):
        raise ValueError('--readiness-workload requires a nonlinear --poc-readiness run')
    if args.poc_readiness:
        if not (args.smoke and args.allow_insecure_test and args.fhe_params=='Test'):
            raise ValueError('--poc-readiness requires --smoke --fhe-params Test --allow-insecure-test')
        validate_timing_window(TEST_POC_WINDOW_SECONDS,TEST_POC_DISCLOSURE_BATCH_SIZE)
        return {'repeats':1,'records':50,'linearSizes':[27],
                'windowSeconds':TEST_POC_WINDOW_SECONDS,
                'disclosureBatchSize':TEST_POC_DISCLOSURE_BATCH_SIZE,
                'selectionProfile':'poc-disjoint-panels-v1','readinessOnly':True,
                'classification':'test-insecure-readiness-not-evaluation',
                'auditorFunding':'deployed-challenge-bond-v1',
                'nonlinearWorkloads':['regulatory','regional'] if args.readiness_workload=='both' else [args.readiness_workload]}
    return {'repeats':1 if args.smoke else 3,'records':2 if args.smoke else 16,
            'linearSizes':[2] if args.smoke else [2,10,16],
            'windowSeconds':240 if args.smoke else 1800}


def validate_execution_profile(args):
    """Reject runtime choices that would invalidate the fixed refresh evidence profile."""
    if args.policy_refresh_v3 and args.kms_threads != 1:
        raise ValueError('--policy-refresh-v3 requires --kms-threads 1 for the pinned canonical execution profile')
    if args.auto_policy_setup and args.new_policy_lineage:
        raise ValueError('automatic initial setup cannot be combined with --new-policy-lineage')
    if args.auto_policy_setup and args.besu_network!='vcfhe-besu_default':
        raise ValueError('automatic initial setup requires the standard retained Besu network')
    if args.keyset_base:
        if args.fhe_params!='Default':
            raise ValueError('--keyset-base accepts only a sealed Default base')
        if args.poc or args.policy_refresh_v3 or args.poc_readiness or args.smoke or args.allow_insecure_test:
            raise ValueError('--keyset-base cannot be combined with Test, PoC, refresh, or smoke profiles')

def policy_lineage(args):
    root=MODULE/'.policy-state';deployment=root/'onchain'/'deployment.json'
    ledger=root/'gateway'/'ledger.json';owners=root/'owner'/'identities.json'
    if args.policy_refresh_v3:
        if not deployment.exists() or not owners.exists():
            raise ValueError('--policy-refresh-v3 requires the existing V3 on-chain lineage; migration or replacement is forbidden')
        try:state=json.loads(deployment.read_text())
        except (OSError,json.JSONDecodeError) as error:
            raise ValueError('existing V3 on-chain deployment state is unreadable') from error
        descriptor=state.get('legacyMigrationInput')
        if (state.get('schema')!='vcfhe-release-policy-deployment-v3'
                or state.get('status')!='deployed'
                or str(state.get('chainId'))!='46853'
                or str(state.get('policyVersion'))!='3'
                or not isinstance(descriptor,dict)
                or not isinstance(descriptor.get('ownersSha256'),str)
                or len(descriptor['ownersSha256'])!=64
                or any(character not in '0123456789abcdef'
                       for character in descriptor['ownersSha256'].lower())):
            raise ValueError('--policy-refresh-v3 requires a completed V3 deployment bound to the retained owner identities')
        return 'existing-on-chain-lineage'
    if args.new_policy_lineage:
        if deployment.exists() or ledger.exists():
            raise ValueError('--new-policy-lineage cannot replace or bypass deployed or legacy policy state')
        # A failed first attempt may already have created the owner identities
        # before policy-init durably records its pending deployment. Reuse those
        # identities only under the same explicit new-lineage flag. The
        # identities stage validates their exact format and uniqueness.
        return 'explicit-new-lineage'
    if deployment.exists():
        if not owners.exists():raise ValueError('on-chain policy exists but owner identities are missing')
        return 'existing-on-chain-lineage'
    if ledger.exists() and owners.exists():return 'owner-attested-legacy-migration'
    raise ValueError('cumulative policy lineage is unavailable: restore the retained .policy-state and matching blockchain state before an evaluation rerun')

def verify(run,cache_dir=None):
    run=Path(run).resolve()
    seal=json.loads((run/'seal.json').read_text())
    version=seal.get('version') if isinstance(seal,dict) else None
    if version=='dataset-threshold-campaign-v1':
        # V1 used a different source closure and seal inventory.  Its isolated
        # verifier proves only the historical integrity claim; it cannot be
        # treated as V3 on-chain authorization evidence.
        from legacy_v1_seal import verify as verify_legacy_v1
        return verify_legacy_v1(run,cache_dir=cache_dir or MODULE/'.cache',repo_root=ROOT)
    if version!=VERSION:raise ValueError('unsupported campaign seal version')
    if seal.get('source')!=source_manifest():raise ValueError('stale source seal')
    files=seal.get('files')
    if not isinstance(files,dict):
        raise ValueError('seal omits the campaign configuration or state')
    normalized=set();resolved_paths=set()
    for name,digest in files.items():
        if not isinstance(name,str) or not isinstance(digest,str):raise ValueError('invalid seal file entry')
        canonical=name.replace('\\','/')
        parts=canonical.split('/')
        if (name!=canonical or not canonical or canonical.startswith('/')
                or any(part in ('','.','..') for part in parts) or ':' in parts[0]):
            raise ValueError('noncanonical seal file path: '+name)
        if canonical in normalized:raise ValueError('duplicate normalized seal file entry: '+canonical)
        normalized.add(canonical)
        path=(run/Path(*parts)).resolve()
        try:path.relative_to(run)
        except ValueError as error:raise ValueError('seal file escapes the run directory: '+name) from error
        if path in resolved_paths:raise ValueError('seal contains aliased file paths: '+name)
        resolved_paths.add(path)
        if sha(path)!=digest:raise ValueError('changed/missing artifact: '+name)
    if 'config/campaign.json' not in normalized or 'state.json' not in normalized:
        raise ValueError('seal omits the campaign configuration or state')
    state=json.loads((run/'state.json').read_text())
    if state['status']!='passed' or state['source']!=seal['source']:raise ValueError('inconsistent run status/source')
    cfg=json.loads((run/'config/campaign.json').read_text())
    if state.get('config')!=cfg:raise ValueError('run state is not bound to the sealed campaign configuration')
    if cfg.get('readinessDisputesOnly'):
        from dispute_readiness import validate, CLASSIFICATION
        validate_availability(run, normalized)
        if not {'reports/dispute-readiness.json','reports/bounty-economics.json'}.issubset(normalized):
            raise ValueError('dispute readiness seal omits its validated reports')
        if seal.get('classification')!=CLASSIFICATION or seal.get('parameters')!='Test' or seal.get('halves')!=['nonlinear']:
            raise ValueError('invalid dispute-only seal scope')
        for name,record in state['datasets'].items():
            if sha(ROOT/name)!=record['sha256']:raise ValueError('changed dispute-pilot dataset')
        summary=validate(run)
        if json.loads((run/'reports/dispute-readiness.json').read_text())!=summary:
            raise ValueError('dispute readiness summary changed')
        return summary
    validate_comparative_report(run, normalized)
    validate_availability(run, normalized)
    validate_scheduling(run, normalized)
    if cfg.get('nonlinearProtocol')=='bounty-v2':
        if cfg.get('bountyEconomics') != json.loads((ROOT/'fhe-pod/scripts/bounty-economics.json').read_text()):
            raise ValueError('economic configuration differs from the sealed source profile')
        if 'reports/bounty-economics.json' not in normalized:
            raise ValueError('missing sealed economic observations')
    for name,record in state['datasets'].items():
        if sha(ROOT/name)!=record['sha256']:raise ValueError('changed/missing source dataset: '+name)
    expected_classification=cfg.get('classification','smoke-not-evaluation' if cfg.get('smoke') else 'dataset-real-threshold-besu')
    expected_halves=[cfg['half']] if cfg.get('half')!='both' else ['linear','nonlinear']
    if (seal.get('classification')!=expected_classification
            or seal.get('parameters')!=cfg.get('parameters')
            or seal.get('halves')!=expected_halves):
        raise ValueError('seal parameters, classification, or halves differ from the campaign configuration')
    refresh=cfg.get('policyRefreshPlan') is not None
    refresh_fields={'evidenceProfile','designSha256','policyLineage','policyRefreshAttemptId',
                    'legacyEvidenceImported','pairedMeasurementsExecuted','sealPayloadSha256'}
    if refresh:
        required_reports={'reports/application.json','reports/results.json',
                          'reports/onchain-release-evidence.json',
                          'reports/release-capacity-preflight.json',
                          'reports/policy-refresh-v3-evidence.json'}
        if not required_reports.issubset(normalized):
            raise ValueError('V3 policy-refresh seal omits a validated report')
        required_critical={'fixtures/prepared.json','config/owners.json',
                           'config/release-policy.json','keyset/ready.json',
                           'keyset/encryption-key.bin','keyset/evaluation-key.bin',
                           'bin/kms-campaign','bin/kms-server','bin/kms-gen-keys','bin/kms-init',
                           'build-evidence/vcfhe-adapter.json',
                           'build-evidence/installed-files.json.gz',
                           'build-evidence/fhe-pod-package-lock.json',
                           'build-evidence/fhe-pod-installed-lock.json',
                           'build-evidence/BN254-Signatures-package-lock.json',
                           'build-evidence/BN254-Signatures-installed-lock.json'}
        if not required_critical.issubset(normalized):
            raise ValueError('V3 policy-refresh seal omits critical keyset, binary, fixture, or build evidence')
        try:
            with gzip.open(run/'build-evidence/installed-files.json.gz','rt',encoding='utf-8') as stream:
                installed=json.load(stream)
        except (OSError,json.JSONDecodeError) as error:
            raise ValueError('V3 policy-refresh installed-source inventory is unreadable') from error
        if not isinstance(installed,dict):
            raise ValueError('V3 policy-refresh installed-source inventory has the wrong format')
        original_locks={
            'fhe-pod/package-lock.json':'build-evidence/fhe-pod-package-lock.json',
            'BN254-Signatures/package-lock.json':'build-evidence/BN254-Signatures-package-lock.json'}
        for name,digest in seal['source'].items():
            if name in original_locks:
                if sha(run/original_locks[name])!=digest:
                    raise ValueError('V3 build evidence changed original dependency lock: '+name)
            elif not isinstance(installed.get(name),dict) or installed[name].get('sha256')!=digest:
                raise ValueError('V3 installed source differs from the sealed source closure: '+name)
        if seal.get('sealPayloadSha256')!=seal_payload_sha256(seal):
            raise ValueError('V3 policy-refresh seal metadata digest is invalid')
        summary=validate_policy_refresh_run(run)
        expected={'classification':summary['classification'],'parameters':cfg['parameters'],
                  'halves':expected_halves,'evidenceProfile':summary['profile'],
                  'designSha256':summary['designSha256'],'policyLineage':summary['policyLineage'],
                  'policyRefreshAttemptId':summary['policyRefreshAttemptId'],
                  'legacyEvidenceImported':summary['legacyEvidenceImported'],
                  'pairedMeasurementsExecuted':summary['pairedMeasurementsExecuted']}
        if any(seal.get(field)!=value for field,value in expected.items()):
            raise ValueError('V3 policy-refresh seal claims differ from validated evidence')
    elif (seal.get('classification')==POLICY_REFRESH_CLASSIFICATION
          or any(field in seal for field in refresh_fields)):
        raise ValueError('non-refresh configuration carries V3 policy-refresh seal claims')
    return seal

def main():
    a=parser().parse_args()
    if a.postprocess_only:
        if not a.run_dir: raise ValueError('--postprocess-only requires --run-dir')
        postprocess(a.run_dir.resolve(), a)
        return
    if a.diagnostic_review or a.derived_dir:
        raise ValueError('review files apply only with --postprocess-only to an existing completed run')
    if a.explain_threshold_scaling:
        raise ValueError('This real-KMS profile is n=4, t=1, reconstruction=3. Latency/bytes are exported per output. The old 4/8/16 approval sweep is not a KMS threshold benchmark. A new n/t sweep requires separately provisioned and validated MPC contexts.')
    if a.resume:
        if not a.run_dir:raise ValueError('--resume requires --run-dir; automatic release replay is forbidden')
        if (a.run_dir/'seal.json').exists():print(json.dumps(verify(a.run_dir.resolve(),a.cache_dir),indent=2));return
        if a.policy_refresh_v3:
            raise ValueError('Incomplete V3 policy-refresh run preserved. ' +
                             POLICY_REFRESH_RECOVERY_MESSAGE)
        raise ValueError('Incomplete run preserved. Automatic replay of MPC/release requests is unsafe: use a fresh run; the on-chain release-policy state is retained.')
    if a.timeout<60 or a.kms_threads<1 or a.kms_tokio_threads<1:raise ValueError('invalid resource limits')
    if not 0<=a.target_cell<=647999999:raise ValueError('public query cell is outside the admitted grid')
    if a.fhe_params=='Test' and not (a.allow_insecure_test and (a.smoke or a.poc or a.policy_refresh_v3)):
        raise ValueError('Test requires --smoke, --poc or --policy-refresh-v3, and --allow-insecure-test')
    selected=selection(a)
    if a.preflight:
        report=startup_preflight(a)
        print(json.dumps(report,indent=2))
        if not report['startupPrerequisitesPresent']:
            raise ValueError('startup checks incomplete or blocked, inspect the reported prerequisites and policy state')
        return
    if a.list:
        print('FHE_PARAMETERS '+a.fhe_params)
        print('NONLINEAR_PROTOCOL '+('not-used' if a.half=='linear' else a.nonlinear_protocol))
        if a.auto_policy_setup:print('POLICY_SETUP automatic only for an empty installation, retained counters are never reset')
        if a.half!='linear' and a.nonlinear_protocol=='bounty-v2':
            print('NONLINEAR_SCHEDULING '+SCHEDULING_VERSION+' (protocol windows unchanged)')
        if a.half!='nonlinear':print('LINEAR_COMPILATION source-and-compiler-keyed in-process cache')
        if selected.get('bountyEconomics'):print('ECONOMICS_REVISION '+selected['bountyEconomics']['revision'])
        if selected.get('readinessDisputesOnly'):
            print('READINESS_SCOPE dispute-only, zero output requests/releases, never evaluation evidence')
        print('\n'.join(('nonlinear:dispute-only-without-output-release'
                        if selected.get('readinessDisputesOnly') and s=='nonlinear:execution-replay-disputes-and-recipient-release' else s)
                        for s in STAGES if (':' not in s or a.half=='both' or s.startswith(a.half+':'))
                        and (s!='nonlinear:committee-availability-controls' or a.nonlinear_protocol=='bounty-v2')
                        and (s!='results-analysis' or not a.smoke)))
        if a.poc:print(json.dumps({k:v for k,v in selected['pocPlan'].items() if k!='jobs'},indent=2))
        if a.policy_refresh_v3:print(json.dumps({k:v for k,v in selected['policyRefreshPlan'].items() if k!='jobs'},indent=2))
        return
    if a.check:
        if not a.run_dir:raise ValueError('--check requires --run-dir')
        if a.nonlinear_protocol == 'bounty-v2':
            checked = json.loads((a.run_dir/'config/campaign.json').read_text())
            if checked.get('nonlinearProtocol') != 'bounty-v2' or checked.get('half') != a.half:
                raise ValueError('the supplied run is not a nonlinear bounty-v2 campaign of the selected scope')
        print(json.dumps(verify(a.run_dir.resolve(),a.cache_dir),indent=2));return
    validate_execution_profile(a)
    fixed_plan=selected.get('pocPlan') or selected.get('policyRefreshPlan')
    nonlinear_cases=(sum(j['fullCase'] and j['half']=='nonlinear' for j in fixed_plan['jobs'])
                     if fixed_plan else len(selected.get('nonlinearWorkloads',['regulatory','regional']))*selected['repeats'])
    minimum_wait=nonlinear_cases*((6 if a.nonlinear_protocol == 'bounty-v2' else 5)*selected['windowSeconds']+3) if a.half!='linear' else 0
    if not a.build_only and a.timeout<=minimum_wait:
        raise ValueError(f'--timeout must exceed the {minimum_wait} s cumulative nonlinear phase-clock allowance; also allow computation time')
    automatic_setup=a.auto_policy_setup and not a.policy_refresh_v3 and not a.build_only
    lineage=None if a.build_only or automatic_setup else policy_lineage(a)
    if a.policy_refresh_v3 and not a.build_only:
        # This is a read-only fast failure. The later reservation repeats the
        # decision while holding the persistent policy-state lock.
        assert_policy_refresh_attempt_available(MODULE/'.policy-state',a.half)
    if subprocess.run(['docker','info'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
        if platform.system()=='Darwin':command(['open','-a','Docker'])
        elif shutil.which('systemctl'):command(['sudo','-n','systemctl','start','docker'])
        deadline=time.monotonic()+120
        while subprocess.run(['docker','info'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
            if time.monotonic()>deadline:raise RuntimeError('Docker daemon unavailable; start it and retry')
            time.sleep(2)
    resources=json.loads(output(['docker','info','--format','{{json .}}']))
    print(f'Docker: {resources["NCPU"]} CPUs, {resources["MemTotal"]/2**30:.1f} GiB RAM; '+
          f'free disk {shutil.disk_usage(ROOT).free/2**30:.1f} GiB',flush=True)
    if shutil.disk_usage(ROOT).free<20*2**30:raise RuntimeError('less than 20 GiB disk reserve; no files will be deleted')
    cache=a.cache_dir.resolve();cache.mkdir(parents=True,exist_ok=True)
    # One build and one active campaign per workspace; locks are released on crash.
    with bootstrap_lock(MODULE/'.policy-state'), (cache/'campaign.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('another threshold campaign is running')
        bootstrap=None
        if automatic_setup:
            bootstrap=prepare_bootstrap(MODULE/'.policy-state',inspect_docker_state(network=a.besu_network))
            a.verified_initial_policy_setup=bootstrap['allowNewLineage']
            lineage=('automatic-first-setup' if bootstrap['allowNewLineage'] else policy_lineage(a))
            print('POLICY_SETUP '+json.dumps(bootstrap),flush=True)
        elif not a.build_only:
            lineage=policy_lineage(a)
        print('Preparing the pinned source and container build. First-time builds may take longer than cached builds.',flush=True)
        manifest=source_manifest();context,digest=build_context(cache,manifest)
        image='vcfhe-kms:'+digest[:16]
        # BuildKit retains completed layers. A compiler error is deterministic,
        # so do not relaunch a long build automatically with the same sources.
        # A fresh invocation safely reuses the verified cache after correction.
        command(['docker','build','--tag',image,context])
        if source_manifest()!=manifest:raise ValueError('sources changed during build; use a fresh invocation with the cached layers')
        if a.build_only:return
        data=ensure_datasets(a.half)
        runs=MODULE/'runs';runs.mkdir(exist_ok=True)
        run=a.run_dir.resolve() if a.run_dir else runs/(time.strftime('run-%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8])
        if run.exists():raise ValueError('existing run preserved; completed runs support --check; use a fresh run directory')
        reuse=None
        if a.keyset_base:
            # The base validator checks every copied private/public/keyset file
            # before this run exists. It is never mounted writable into a new
            # evaluation, and a new run never claims to have performed DKG.
            from default_keyset_base import restore as restore_keyset_base
            reuse=restore_keyset_base(a.keyset_base.resolve(),run)
        else:
            run.mkdir(mode=0o700)
        besu=json.loads(output(['docker','compose','-p','vcfhe-besu','-f',ROOT/'network/validators-besu/docker-compose.besu.yml','config','--format','json']))
        # Campaign roles use the isolated Docker network. Removing host port
        # publication avoids collision with a separately preserved Besu chain.
        for service in besu['services'].values():service.pop('ports',None)
        write(run/'besu.json',besu)
        cfg={'version':VERSION,'half':a.half,'parameters':a.fhe_params,'smoke':a.smoke,
             'comparativeMetricsVersion':COMPARATIVE_METRICS_VERSION,
             **({'availabilityControlsVersion':AVAILABILITY_VERSION,
                 'nonlinearSchedulingVersion':SCHEDULING_VERSION} if a.half!='linear' and a.nonlinear_protocol=='bounty-v2' else {}),
             **selected,
              'rpcUrl':'http://node1:8545',
              'ownerRpcUrls':OWNER_RPC_URLS,'chainId':'46853',
             'timeoutSeconds':a.timeout,
             'kmsRayonThreads':a.kms_threads,'kmsTokioThreads':a.kms_tokio_threads,
              'infrastructureOrder':'besu-policy-before-kms-v3',
              'targetCell':a.target_cell,
              'runId':run.name,'policyDomain':VERSION,'ownerReleaseLimit':18,'policyLineage':lineage}
        if bootstrap and bootstrap.get('bootstrapId'):
            cfg['initialPolicySetup']={key:bootstrap[key] for key in ['kind','bootstrapId','phase']}
            if bootstrap['identitiesMustRunFirst']:
                cfg['infrastructureOrder']='identities-besu-policy-before-kms-v3'
        if reuse:
            cfg['keysetReuse']={'format':reuse['format'],'baseManifestSha256':reuse['baseManifestSha256'],
                                'baseFiles':reuse['baseFiles'],'restoredFrom':reuse['restoredFrom']}
        compose=configuration(run,a,image);write(run/'config/campaign.json',cfg)
        if reuse:write(run/'config/keyset-reuse.json',cfg['keysetReuse'])
        print('RUN_DIRECTORY '+str(run),flush=True)
        print('PROFILE '+json.dumps({'parameters':cfg['parameters'],'half':cfg['half'],
            'classification':cfg.get('classification','smoke-not-evaluation' if a.smoke else 'dataset-real-threshold-besu'),
            'linearSizes':cfg['linearSizes'] if a.half!='nonlinear' else [],
            'nonlinearRecords':cfg['records'] if a.half!='linear' else None,
            'nonlinearWorkloads':cfg.get('nonlinearWorkloads',['regulatory','regional']) if a.half!='linear' else [],
            'repeats':cfg['repeats'],'windowSeconds':cfg['windowSeconds'],
            'nonlinearProtocol':cfg.get('nonlinearProtocol','canonical'),
            'pairedGrid':{k:cfg['pocPlan'][k] for k in ['measuredPairs','fullCases','designSha256']} if a.poc else None,
            'policyRefreshGrid':{k:cfg['policyRefreshPlan'][k] for k in ['fullCases','designSha256']} if a.policy_refresh_v3 else None,
            'disclosureBatchSize':cfg.get('disclosureBatchSize',8)}),flush=True)
        if a.fhe_params=='Test':print('WARNING: insecure Test functional PoC; no confidentiality or secure-performance claim. Raw decryption timings are diagnostics, not evaluation metrics.',flush=True)
        (run/'bin').mkdir()
        holder=output(['docker','create',image])
        try:
            for binary in ['kms-campaign','kms-server','kms-gen-keys','kms-init']:
                command(['docker','cp',holder+':/usr/local/bin/'+binary,run/'bin'/binary])
            command(['docker','cp',holder+':/app/threshold-kms/campaign/build-evidence',run/'build-evidence'])
        finally:command(['docker','rm',holder],stdout=subprocess.DEVNULL)
        state={'version':VERSION,'status':'running','config':cfg,'source':manifest,'upstream':PIN,
               'datasets':data,
               'imageId':output(['docker','image','inspect',image,'--format','{{.Id}}']),
               'hostEnvironment':capture_host_environment(),
               'resources':{k:resources[k] for k in ['NCPU','MemTotal','Architecture','OperatingSystem']},'stages':[]}
        write(run/'state.json',state)
        print('Progress counts show completed items within each phase, not an estimate of remaining time.',flush=True)
        progress=ProgressMonitor(run,emit=lambda message:print(message,flush=True))
        def stage(name,args):
            print('STAGE '+name+': '+stage_message(name),flush=True);item={'name':name,'status':'running'};state['stages'].append(item);write(run/'state.json',state)
            start=time.monotonic();next_check=start;next_progress=start+60
            try:
                with resource_samples(run,compose,name),(run/(name+'.log')).open('x') as log:
                    proc=subprocess.Popen([str(x) for x in args],stdout=log,stderr=subprocess.STDOUT)
                    try:
                        while proc.poll() is None:
                            progress.poll()
                            if time.monotonic()>=next_progress:
                                print(f'Still running: {stage_message(name)}. Elapsed {int(time.monotonic()-start)} s.',flush=True)
                                next_progress=time.monotonic()+60
                            if time.monotonic()-start>a.timeout:raise TimeoutError(name+' exceeded configured timeout')
                            if shutil.disk_usage(run).free<5*2**30:raise RuntimeError('disk reserve reached; evidence preserved')
                            if time.monotonic()>=next_check and name in ['prss','dkg','evaluation']:
                                roles=['kms1','kms2','kms3','kms4']+((['owner','worker']+
                                       ([] if cfg.get('readinessDisputesOnly') else ['recipient'])) if name=='evaluation' else [])
                                require_running(compose,roles,(run/'exchange/complete.json').exists());next_check=time.monotonic()+15
                            time.sleep(1)
                        if proc.returncode:raise RuntimeError(f'{name} failed ({proc.returncode}); see {run/(name+".log")}')
                    finally:
                        if proc.poll() is None:
                            proc.terminate()
                            try:proc.wait(timeout=15)
                            except subprocess.TimeoutExpired:proc.kill();proc.wait()
                        progress.poll()
                item['status']='passed'
                print(f'Completed stage {name} in {time.monotonic()-start:.1f} s. Log: {run/(name+".log")}',flush=True)
            except BaseException:
                item['status']='failed';raise
            finally:item['seconds']=time.monotonic()-start;write(run/'state.json',state)
        try:
            for name,args in comparison_control_stages(cfg,run):
                stage(name,args)
                validate_availability(run)
            identities_first=bool(bootstrap and bootstrap['identitiesMustRunFirst'])
            if identities_first:
                stage('identities',['docker','compose','-f',str(run/'config/identities-compose.json'),
                                    'run','--rm','identities'])
                bootstrap=mark_identities_ready(MODULE/'.policy-state',inspect_docker_state(network=a.besu_network))
            for name,args in infrastructure_stages(run,compose,bool(reuse)):
                if name=='recipient-start' and cfg.get('readinessDisputesOnly'):continue
                if name=='identities' and identities_first:continue
                if name=='release-policy' and bootstrap and bootstrap.get('phase')=='identities-ready':
                    bootstrap=mark_policy_starting(MODULE/'.policy-state',inspect_docker_state(network=a.besu_network))
                stage(name,args)
                if name=='release-policy' and bootstrap and bootstrap.get('phase')=='policy-started':
                    bootstrap=mark_deployed(MODULE/'.policy-state',inspect_docker_state(network=a.besu_network))
                if name=='besu':
                    ids=output(['docker','ps','-q','--filter','label=com.docker.compose.project=vcfhe-besu']).splitlines()
                    images=sorted(set(output(['docker','inspect','--format','{{.Image}}',i]) for i in ids))
                    write(run/'reports/besu-images.json',json.loads(output(['docker','image','inspect',*images])))
            if a.policy_refresh_v3:
                activate_policy_refresh_attempt(run,compose,cfg,state,a.timeout)
            stage('evaluation',compose+['run','--rm','evaluate'])
            print('Validating workflow observations and exporting measured results.',flush=True)
            command([sys.executable,MODULE/'campaign/export.py',run])
            if source_manifest()!=manifest:raise ValueError('sources changed during measurement; no seal')
            if ensure_datasets(a.half)!=data:raise ValueError('datasets changed during measurement; no seal')
            state['status']='passed';write(run/'state.json',state)
            files=collect_seal_files(run)
            seal={'version':VERSION,'source':manifest,'files':files,'parameters':a.fhe_params,
                  'classification':cfg.get('classification','smoke-not-evaluation' if a.smoke else 'dataset-real-threshold-besu'),
                  'halves':[a.half] if a.half!='both' else ['linear','nonlinear']}
            if a.policy_refresh_v3:
                seal.update({'evidenceProfile':cfg['policyRefreshPlan']['profile'],
                             'designSha256':cfg['policyRefreshPlan']['designSha256'],
                             'policyLineage':cfg['policyLineage'],
                             'policyRefreshAttemptId':cfg['policyRefreshAttempt']['attemptId'],
                             'legacyEvidenceImported':False,'pairedMeasurementsExecuted':0})
                seal['sealPayloadSha256']=seal_payload_sha256(seal)
            write(run/'seal.json',seal)
            if a.policy_refresh_v3:verify(run)
            print('Completed and verified: '+str(run),flush=True)
            if not a.smoke:
                pointer=runs/('latest-policy-refresh-v3-evidence.json' if a.policy_refresh_v3 else
                             ('latest-poc-evidence.json' if a.poc else 'latest-evidence.json'))
                pointers=json.loads(pointer.read_text()) if pointer.exists() else {}
                for half in (['linear','nonlinear'] if a.half=='both' else [a.half]):pointers[half]=str(run)
                write(pointer,pointers)
        except BaseException as e:
            state['status']='interrupted' if isinstance(e,KeyboardInterrupt) else 'failed';state['error']=str(e);write(run/'state.json',state)
            try:
                with (run/'container-diagnostics.log').open('x') as log:
                    subprocess.run(compose+['logs','--no-color','--tail','100'],stdout=log,stderr=subprocess.STDOUT,timeout=20,check=False)
            except (OSError,subprocess.SubprocessError):pass
            raise
        finally:
            # Retain Besu, private vaults, fixtures, logs and on-chain policy state.
            try:stop_campaign_services(compose)
            except (OSError,subprocess.SubprocessError) as error:
                print('Could not stop this run\'s services: '+str(error),file=sys.stderr)
            try:stop_oneshots(run/'compose.json')
            except (OSError,ValueError,subprocess.SubprocessError) as error:
                print('Could not stop this run\'s one-shot containers: '+str(error),file=sys.stderr)
    # Derivation is outside the sealed measurement lifecycle. A missing plotting
    # dependency or pending review must not relabel a completed experiment as failed.
    if a.poc and not a.build_only:
        postprocess(run, a)

def postprocess(run, args):
    print('Generating validated results, tables and figures from the sealed run.',flush=True)
    command_args=[sys.executable,MODULE/'postprocess/refresh.py','--run',run]
    if args.derived_dir:command_args+=['--output',args.derived_dir]
    if args.manual_review:command_args+=['--manual-review']
    if args.diagnostic_review:command_args+=['--diagnostic-review',args.diagnostic_review.resolve()]
    command(command_args)

def startup_preflight(args):
    tools={name:bool(shutil.which(name)) for name in ['python3','git','docker']}
    bootstrap=None
    try:
        if args.auto_policy_setup and not args.policy_refresh_v3:
            validate_execution_profile(args)
            bootstrap=classify_bootstrap(MODULE/'.policy-state',inspect_docker_state(network=args.besu_network))
            lineage=('automatic-first-setup-planned' if bootstrap['allowNewLineage'] else policy_lineage(args))
        else:lineage=policy_lineage(args)
        policy_error=None
    except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as error:
        lineage=None
        policy_error=str(error)
    return {'profile':'read-only-startup-preflight-v1','half':args.half,'parameters':args.fhe_params,
            'nonlinearProtocol':args.nonlinear_protocol if args.half!='linear' else None,
            'hostTools':tools,'policyLineage':lineage,'policyError':policy_error,'initialPolicySetup':bootstrap,
            'startupPrerequisitesPresent':all(tools.values()) and lineage is not None,
            'notChecked':['Docker execution capacity','live policy counters and chain state','largest-case deadlines'],
            'experimentsExecuted':False,'policyStateChanged':False}



if __name__=='__main__':
    try:main()
    except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as error:raise SystemExit(str(error))
