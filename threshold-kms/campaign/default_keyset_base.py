#!/usr/bin/env python3
"""Create, seal, verify, and restore a local Default threshold-KMS keyset base."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

HERE=Path(__file__).resolve().parent
MODULE=HERE.parent
sys.path.insert(0,str(HERE))
import run as campaign

FORMAT='vcfhe-default-keyset-base-v1'
FOLDERS=('config','keyset','public','private-1','private-2','private-3','private-4','provision','build-evidence')

def write(path,value): campaign.write(path,value)

def files(root):
    root=Path(root)
    return {path.relative_to(root).as_posix():campaign.sha(path) for folder in FOLDERS for path in (root/folder).rglob('*') if path.is_file()}

def payload_digest(value):
    value={key:item for key,item in value.items() if key!='manifestSha256'}
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def validate(base):
    base=Path(base).resolve()
    try: manifest=json.loads((base/'base.json').read_text())
    except (OSError,json.JSONDecodeError) as error: raise ValueError('Default keyset base manifest is unreadable') from error
    if manifest.get('format')!=FORMAT or manifest.get('status')!='passed': raise ValueError('Default keyset base is not a completed sealed base')
    if manifest.get('manifestSha256')!=payload_digest(manifest): raise ValueError('Default keyset base manifest digest is invalid')
    if manifest.get('parameters')!='Default' or manifest.get('upstreamCommit')!=campaign.PIN: raise ValueError('Default keyset base parameters or upstream pin differ')
    if manifest.get('parties')!=4 or manifest.get('corruptionThreshold')!=1 or manifest.get('network')!='isolated-docker-kms': raise ValueError('Default keyset base topology differs')
    if manifest.get('files')!=files(base): raise ValueError('Default keyset base changed or is incomplete')
    try: ready=json.loads((base/'keyset/ready.json').read_text())
    except (OSError,json.JSONDecodeError) as error: raise ValueError('Default keyset ready record is unreadable') from error
    if (ready.get('status')!='passed' or ready.get('parameters')!='Default' or ready.get('parties')!=4 or ready.get('corruptionThreshold')!=1 or ready.get('preloadedFheKey') is not False or ready.get('fullPreprocessing') is not True or ready.get('upstreamCommit')!=campaign.PIN): raise ValueError('Default keyset ready record does not prove a fresh full setup')
    for name in ['encryption-key.bin','evaluation-key.bin','prss.json']:
        if not (base/'keyset'/name).is_file(): raise ValueError('Default keyset omits '+name)
    return manifest

def restore(base,target):
    manifest=validate(base);base=Path(base).resolve();target=Path(target).resolve()
    if target.exists(): raise ValueError('restore target already exists; preserving it')
    target.mkdir(mode=0o700,parents=True)
    for name in FOLDERS: shutil.copytree(base/name,target/name,copy_function=shutil.copy2)
    record={'format':FORMAT,'restoredFrom':str(base),'baseManifestSha256':manifest['manifestSha256'],'baseFiles':manifest['files'],'restoredAtUnix':time.time()}
    write(target/'restored-from-default-keyset-base.json',record)
    if files(target)!=manifest['files']: raise ValueError('restored keyset copy differs from sealed base')
    return record

def client_config():
    value='kms_type = "threshold"\nnum_majority = 2\nnum_reconstruct = 3\ndecryption_mode = "NoiseFloodSmall"\nfhe_params = "Default"\n'
    for i in range(1,5): value+=f'\n[[cores]]\nparty_id = {i}\naddress = "kms{i}:50100"\ns3_endpoint = "http://public-store:8080"\nobject_folder = "PUB-p{i}"\n'
    return value

def compose_for(base,args,image):
    config=base/'config'
    for name in FOLDERS: (base/name).mkdir(mode=0o700)
    # The shared sampler writes reports/resources.jsonl while each setup stage
    # is running.  A keyset base does not otherwise need reports, but create it
    # before the first stage so monitoring cannot fail at startup.
    (base/'reports').mkdir(mode=0o700)
    for role in ['owner','recipient','setup']:(base/'provision'/role).mkdir(mode=0o700)
    for i in range(1,5):
        (base/'public'/f'PUB-p{i}').mkdir(mode=0o700)
        (config/f'core-{i}.toml').write_text(campaign.core_config(i,args.kms_threads,args.kms_tokio_threads))
    (config/'client.toml').write_text(client_config())
    write(config/'release-policy.json',{'format':'keyset-base-no-release-v1','releaseEnabled':False})
    env={'VCFHE_FHE_PARAMS':'Default','VCFHE_KMS_MAX_POLLS':str(args.timeout*10),'VCFHE_ALLOW_INSECURE':'0','RAYON_NUM_THREADS':str(args.kms_threads),'RUST_LOG':'warn','AWS_EC2_METADATA_DISABLED':'true'}
    mount=lambda source,target,readonly=False:{'type':'bind','source':str(base/source),'target':target,'read_only':readonly}
    common={'image':image,'user':f'{os.getuid()}:{os.getgid()}','security_opt':['no-new-privileges:true'],'cap_drop':['ALL'],'environment':env,'networks':['kms'],'init':True,'read_only':True,'tmpfs':['/tmp:rw,nosuid,nodev,size=512m'],'working_dir':'/tmp'}
    services={}
    for i in range(1,5): services[f'kms{i}']={**common,'command':['core'],'environment':{**env,'VCFHE_PARTY':str(i)},'volumes':[mount('config','/config',True),mount(f'private-{i}','/private'),mount('keyset','/release-keyset',True),*[mount(f'public/PUB-p{j}',f'/public/PUB-p{j}',j!=i) for j in range(1,5)]],'healthcheck':{'test':['CMD','python3','-c',"import socket;socket.create_connection(('127.0.0.1',50100),2).close()"],'interval':'5s','timeout':'3s','retries':120},'pids_limit':256}
    services['public-store']={**common,'command':['public-store'],'volumes':[mount(f'public/PUB-p{i}',f'/public/PUB-p{i}',True) for i in range(1,5)]}
    services['identities']={**common,'command':['identities'],'network_mode':'none','environment':{**env,'VCFHE_ALLOW_NEW_POLICY_LINEAGE':'1'},'volumes':[mount('config','/provision/config'),*[mount(f'provision/{role}',f'/provision/{role}') for role in ['owner','recipient','setup']]]}
    services['identities'].pop('networks')
    shared=[mount('config','/config',True),mount('keyset','/keyset'),mount('provision/setup','/setup-identity',True)]
    services['init']={**common,'command':['init'],'volumes':shared};services['setup']={**common,'command':['setup'],'volumes':shared}
    write(base/'compose.json',{'name':'vcfhe-default-base-'+base.name[-12:].lower(),'services':services,'networks':{'kms':{'internal':True}}})
    return ['docker','compose','-f',str(base/'compose.json')]

def stage(base,compose,name,args,timeout):
    print('STAGE '+name,flush=True);started=time.monotonic()
    with (base/(name+'.log')).open('x') as log, campaign.resource_samples(base,compose,name):
        process=subprocess.Popen([str(item) for item in args],stdout=log,stderr=subprocess.STDOUT)
        try:
            while process.poll() is None:
                if time.monotonic()-started>timeout: raise TimeoutError(name+' exceeded configured timeout')
                if shutil.disk_usage(base).free<5*2**30: raise RuntimeError('disk reserve reached; keyset state preserved')
                if name in ['prss','dkg']: campaign.require_running(compose,['kms1','kms2','kms3','kms4'])
                time.sleep(5)
            if process.returncode: raise RuntimeError(f'{name} failed ({process.returncode}); see {base/(name+".log")}')
        finally:
            if process.poll() is None: process.terminate();process.wait(timeout=20)
    return time.monotonic()-started

def create(args):
    if args.timeout<60 or args.kms_threads<1 or args.kms_tokio_threads<1: raise ValueError('invalid resource limits')
    if subprocess.run(['docker','info'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode: raise RuntimeError('Docker daemon unavailable')
    if shutil.disk_usage(MODULE).free<20*2**30: raise RuntimeError('less than 20 GiB disk reserve; no files will be deleted')
    root=(MODULE/'keyset-bases').resolve();root.mkdir(mode=0o700,exist_ok=True);name=args.name or ('default-'+time.strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8])
    if '/' in name or name in {'.','..'}: raise ValueError('invalid base name')
    base=root/name
    if base.exists(): raise ValueError('existing keyset base preserved; choose a new name')
    cache=args.cache_dir.resolve();cache.mkdir(parents=True,exist_ok=True)
    with (cache/'campaign.lock').open('a') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('another threshold campaign is running')
        manifest=campaign.source_manifest();context,digest=campaign.build_context(cache,manifest);image='vcfhe-kms:'+digest[:16];campaign.command(['docker','build','--tag',image,context])
        if campaign.source_manifest()!=manifest: raise ValueError('sources changed during build; no keyset base created')
        base.mkdir(mode=0o700);compose=compose_for(base,args,image)
        holder=campaign.output(['docker','create',image])
        try:
            for binary in ['kms-campaign','kms-server','kms-gen-keys','kms-init']: campaign.command(['docker','cp',holder+':/usr/local/bin/'+binary,base/'build-evidence'/binary])
            campaign.command(['docker','cp',holder+':/app/threshold-kms/campaign/build-evidence',base/'build-evidence'/'source'])
        finally: campaign.command(['docker','rm',holder],stdout=subprocess.DEVNULL)
        state={'format':FORMAT,'status':'running','parameters':'Default','upstreamCommit':campaign.PIN,'parties':4,'corruptionThreshold':1,'network':'isolated-docker-kms','source':manifest,'imageId':campaign.output(['docker','image','inspect',image,'--format','{{.Id}}']),'stages':[]};write(base/'state.json',state);print('DEFAULT_KEYSET_BASE '+str(base),flush=True)
        try:
            for label,command in [('identities',compose+['run','--rm','identities']),('kms-cores',compose+['up','-d','--wait','kms1','kms2','kms3','kms4','public-store']),('prss',compose+['run','--rm','init']),('dkg',compose+['run','--rm','setup'])]:
                seconds=stage(base,compose,label,command,args.timeout);state['stages'].append({'name':label,'status':'passed','seconds':seconds});write(base/'state.json',state)
            ready=json.loads((base/'keyset/ready.json').read_text())
            if ready.get('parameters')!='Default' or not ready.get('fullPreprocessing') or ready.get('preloadedFheKey'): raise ValueError('setup did not produce a fresh Default full-preprocessing keyset')
            state['status']='passed';write(base/'state.json',state)
            sealed={'format':FORMAT,'status':'passed','parameters':'Default','upstreamCommit':campaign.PIN,'parties':4,'corruptionThreshold':1,'network':'isolated-docker-kms','source':manifest,'imageId':state['imageId'],'files':files(base),'createdAtUnix':time.time()};sealed['manifestSha256']=payload_digest(sealed);write(base/'base.json',sealed);validate(base);print('DEFAULT_KEYSET_BASE_SEALED '+str(base),flush=True)
        except BaseException as error: state['status']='failed';state['error']=str(error);write(base/'state.json',state);raise
        finally:
            try: campaign.command(compose+['stop','--timeout','15','kms1','kms2','kms3','kms4','public-store'],stdout=subprocess.DEVNULL)
            except (OSError,subprocess.SubprocessError): pass
            try: campaign.stop_oneshots(base/'compose.json')
            except (OSError,ValueError,subprocess.SubprocessError): pass

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--name');parser.add_argument('--timeout',type=int,default=86400);parser.add_argument('--kms-threads',type=int,default=2);parser.add_argument('--kms-tokio-threads',type=int,default=1);parser.add_argument('--cache-dir',type=Path,default=MODULE/'.cache');parser.add_argument('--verify',type=Path);parser.add_argument('--restore',type=Path);parser.add_argument('--into',type=Path);args=parser.parse_args()
    if args.verify: print(json.dumps(validate(args.verify),indent=2));return
    if args.restore:
        if not args.into: raise ValueError('--restore requires --into')
        print(json.dumps(restore(args.restore,args.into),indent=2));return
    if args.into: raise ValueError('--into requires --restore')
    create(args)

if __name__=='__main__':
    try: main()
    except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as error: raise SystemExit(str(error))
