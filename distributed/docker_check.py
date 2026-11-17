"""Short local transport check. Never substitutes for real FHE/KMS workflows."""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import uuid
import topology

HERE=Path(__file__).resolve().parent
NODE_IMAGE='node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5'
SOURCES=['agent.mjs','adapter-policy.mjs','client.mjs','public-files.mjs','role-transport.mjs',
         'docker-transport-check.mjs','docker_restart_check.mjs']

def write(path,value):
    Path(path).write_text(json.dumps(value,indent=2)+'\n')

def check(config,output):
    output=Path(output).resolve()
    if output.exists():raise ValueError('use a new Docker check directory')
    output.mkdir(parents=True,mode=0o700)
    report={'schema':'vcfhe-docker-local-check-v1','createdAt':datetime.now(timezone.utc).isoformat(),
            'cloudActions':[],'evaluationPublishable':False,'nativeWorkflows':{'status':'not-executed'},'status':'running'}
    def execute(args,**kwargs):
        print('DOCKER CHECK '+str(args[0]),flush=True)
        return subprocess.run(list(map(str,args)),check=True,timeout=120,**kwargs)
    info=json.loads(subprocess.check_output(['docker','info','--format','{{json .}}'],timeout=20))
    report['resources']={'dockerMemoryBytes':info['MemTotal'],'dockerCpus':info['NCPU'],
                         'architecture':info['Architecture'],'hostFreeBytes':shutil.disk_usage(output).free}
    campaign_image=config['images']['campaign']
    found=False
    if campaign_image:
        found=subprocess.run(['docker','image','inspect',campaign_image],capture_output=True,timeout=20).returncode==0
    report['nativeWorkflows']={'status':'blocked','campaignImage':campaign_image,'imageAvailable':found,
        'reason':'No prepared campaign image is available locally' if not found else 'This command checks transport only',
        'required':'Real compiled FHE/KMS image, fresh isolated policy and four real cores. No simulated fallback.'}
    if subprocess.run(['docker','image','inspect',NODE_IMAGE],capture_output=True,timeout=20).returncode:
        execute(['docker','pull',NODE_IMAGE])
    source=output/'source';source.mkdir()
    for name in SOURCES:shutil.copy2(HERE/name,source/name)
    report['sources']={n:hashlib.sha256((source/n).read_bytes()).hexdigest() for n in SOURCES}
    nodes=[n for n in topology.inventory(config) if n['role']!='validator']
    identities={}
    for node in nodes:
        folder=output/node['id'];folder.mkdir()
        command=['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes',
            '-keyout',str(folder/'tls.key'),'-out',str(folder/'tls.crt'),'-days','1','-subj','/CN='+node['id'],
            '-addext','subjectAltName=DNS:'+node['id'],'-addext','extendedKeyUsage=serverAuth,clientAuth']
        subprocess.run(command,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        fingerprint=subprocess.check_output(['openssl','x509','-in',str(folder/'tls.crt'),'-noout','-fingerprint','-sha256'],text=True).strip().split('=')[-1]
        identities[node['id']]={'key':folder/'tls.key','cert':folder/'tls.crt','fingerprint256':fingerprint}
        # Keys are test-only and remain behind the mode-0700 output directory.
        (folder/'tls.key').chmod(0o644)
    ca=output/'ca.pem';ca.write_text('\n'.join(v['cert'].read_text() for v in identities.values()))
    services={};volumes={}
    for node in nodes:
        name=node['id'];folder=output/name
        peers=[{'node':other['id'],'fingerprint256':identities[other['id']]['fingerprint256'],
                'url':'https://'+other['id']+':9449/v1/role',
                'operations':['public-manifest','missing-chunks','put-chunk','get-chunk']+
                             (['task','bind-contract','transaction'] if other['id']=='coordinator-1' else [])} for other in nodes]
        role={'campaign':'local-docker-check','node':name,'role':node['role'],'host':'local-docker',
              'port':9449,'timeoutSeconds':30,'tls':{'key':'/identity/tls.key','cert':'/identity/tls.crt','ca':'/config/ca.pem'},'peers':peers}
        write(folder/'role.json',role)
        binds=[f'{source}:/app/distributed:ro',f'{folder}/role.json:/config/role.json:ro',
               f'{folder}/tls.key:/identity/tls.key:ro',f'{folder}/tls.crt:/identity/tls.crt:ro',f'{ca}:/config/ca.pem:ro']
        for directory in ('fixtures','reports','transport','release-evidence'):
            volume=name+'-'+directory;volumes[volume]={};binds.append(volume+':/'+directory)
        if name=='coordinator-1':
            write(folder/'unprivileged.json',{'key':'/test-owner/tls.key','cert':'/test-owner/tls.crt'})
            binds.extend([f'{folder}/unprivileged.json:/config/unprivileged.json:ro',
                f'{identities["owner-1"]["key"]}:/test-owner/tls.key:ro',
                f'{identities["owner-1"]["cert"]}:/test-owner/tls.crt:ro'])
        services[name]={'image':NODE_IMAGE,'user':'10001:10001','read_only':True,'cap_drop':['ALL'],
            'security_opt':['no-new-privileges:true'],'tmpfs':['/tmp:size=16m'],
            'environment':{'NODE_ENV':'production'},'volumes':binds,'mem_limit':'128m','pids_limit':64,
            'entrypoint':['node','/app/distributed/agent.mjs']}
    project='vcfhe-check-'+uuid.uuid4().hex[:10]
    compose=output/'compose.json'
    write(compose,{'name':project,'services':services,'volumes':volumes,'networks':{'default':{'internal':True}}})
    base=['docker','compose','-p',project,'-f',str(compose)]
    try:
        # Initialize only the newly created check volumes, never existing data.
        for name in services:
            execute(base+['run','--rm','--no-deps','--user','0:0','--cap-add','CHOWN','--cap-add','FOWNER','--entrypoint','node',name,'-e',
                "const fs=require('fs');for(const d of ['/fixtures','/reports','/transport','/release-evidence']){fs.chownSync(d,10001,10001);fs.chmodSync(d,0o700)}"],stdout=subprocess.DEVNULL)
        execute(base+['up','-d'])
        # A bounded health gate handles container boot without assuming a sleep.
        script="const fs=require('fs'),https=require('https');const c=JSON.parse(fs.readFileSync('/config/role.json'));Promise.all(c.peers.map(p=>new Promise((ok,no)=>{const q=https.request(p.url,{method:'POST',key:fs.readFileSync(c.tls.key),cert:fs.readFileSync(c.tls.cert),ca:fs.readFileSync(c.tls.ca)},r=>{r.resume();r.on('end',ok)});q.on('error',no);q.end()}))).catch(()=>process.exit(1));"
        import time
        deadline=time.monotonic()+30
        while subprocess.run(base+['exec','-T','coordinator-1','node','-e',script],capture_output=True).returncode:
            if time.monotonic()>deadline:raise ValueError('Docker role endpoints did not become available')
            time.sleep(1)
        execute(base+['exec','-T','coordinator-1','node','/app/distributed/docker-transport-check.mjs'])
        execute(base+['restart','kms-1'])
        # Restart readiness uses the same bounded health gate.
        deadline=time.monotonic()+30
        while subprocess.run(base+['exec','-T','coordinator-1','node','-e',script],capture_output=True).returncode:
            if time.monotonic()>deadline:raise ValueError('restarted endpoint did not become available')
            time.sleep(1)
        execute(base+['exec','-T','coordinator-1','node','/app/distributed/docker_restart_check.mjs'])
        execute(base+['cp','coordinator-1:/reports/transport-check.json',str(output/'transport-check.json')])
        execute(base+['cp','coordinator-1:/reports/restart-check.json',str(output/'restart-check.json')])
        execute(base+['cp','coordinator-1:/reports/distributed/transport.jsonl',str(output/'transport.jsonl')])
        report['transport']=json.loads((output/'transport-check.json').read_text())
        report['restart']=json.loads((output/'restart-check.json').read_text())
        report['status']='transport-passed-native-workflows-blocked'
    except BaseException as error:
        report['status']='failed';report['error']=str(error);raise
    finally:
        with (output/'docker.log').open('w') as log:
            subprocess.run(base+['logs','--no-color'],stdout=log,stderr=subprocess.STDOUT,timeout=30)
        # These resources were created solely for this check. Keep its reports.
        subprocess.run(base+['down','--volumes','--remove-orphans'],timeout=90,check=True)
        report['finishedAt']=datetime.now(timezone.utc).isoformat()
        write(output/'report.json',report)
    return report
