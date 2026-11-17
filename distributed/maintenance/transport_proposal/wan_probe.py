#!/usr/bin/env python3
"""Explicit isolated WAN infrastructure probe on two already-running hosts.

No VM creation, image build/pull, protocol task, FHE, KMS or on-chain action.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

import prepare_patch

HERE = Path(__file__).resolve().parent
DISTRIBUTED = HERE.parents[1]
sys.path.insert(0, str(DISTRIBUTED))
from remote import Remote
import topology
from privacy import require_private

def sha(data): return hashlib.sha256(data).hexdigest()
def quiet(remote, args, **kwargs):
    return remote.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,**kwargs)

def permitted(ports, port):
    for value in ports:
        parts = value.split('-')
        if int(parts[0]) <= port <= int(parts[-1]): return True
    return False

def remove_empty_probe_parent(remote, remote_dir):
    """Remove only this probe's now-empty shared parent, never recursively."""
    parent = '/srv/vcfhe/maintenance-probes'
    if not re.fullmatch(re.escape(parent) + r'/transport-probe-[a-f0-9]{12}', remote_dir):
        raise ValueError('unexpected probe directory')
    # A nonempty or symlink parent makes rmdir fail. Propagate that failure
    # rather than deleting another probe or claiming successful cleanup.
    quiet(remote, ['sudo', 'test', '!', '-e', remote_dir], timeout=30)
    quiet(remote, ['sudo', 'rmdir', '--', parent], timeout=30)
    quiet(remote, ['sudo', 'test', '!', '-e', parent], timeout=30)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run=args.run.resolve(); output=require_private(args.output.resolve())
    if output.exists() or output.is_relative_to(run): raise ValueError('use a new private report outside the live run')
    cfg=json.loads((run/'distributed-config.json').read_text())
    plan=topology.plan(cfg); hosts={h['id']:h for h in plan['hosts']}; nodes={n['id']:n for n in plan['nodes']}
    client_role=json.loads((run/'participant-config/coordinator-1/role.json').read_text())
    server_role=json.loads((run/'participant-config/auditor-1/role.json').read_text())
    assert nodes['coordinator-1']['host']=='host-1' and nodes['auditor-1']['host']=='host-2'
    peers={p['node']:p for p in client_role['peers']}
    client_peer=next(p for p in server_role['peers'] if p['node']=='coordinator-1')
    image=cfg['images']['campaign']; assert '@sha256:' in image
    sdk=DISTRIBUTED.parents[1]/'tmp/gcp-preparation-tools/google-cloud-sdk/bin/gcloud'
    if not sdk.is_file(): raise ValueError('existing verified Google Cloud SDK required')
    os.environ['PATH']=str(sdk.parent)+os.pathsep+os.environ['PATH']
    os.environ.setdefault('CLOUDSDK_PYTHON',sys.executable)
    remotes={'client':Remote(cfg,hosts['host-1']),'server':Remote(cfg,hosts['host-2'])}
    probe='transport-probe-'+uuid.uuid4().hex[:12]
    remote_dir='/srv/vcfhe/maintenance-probes/'+probe
    names={side:'vcfhe-'+probe+'-'+side for side in remotes}
    created=set();started=set();cleaned={};report={'schema':'vcfhe-private-wan-proposal-check-v1',
        'classification':'infrastructure-only-not-evaluation-evidence','status':'failed',
        'startedAt':datetime.now(timezone.utc).isoformat(),'evaluationInfrastructureCreated':False,
        'liveRunEdited':False,'protocolTasks':0,'fheCalls':0,'kmsCalls':0,'onChainCalls':0,
        'performanceClaim':False,'hosts':['host-1','host-2'],
        'probeRpcTimeoutSeconds':10,'originalRpcTimeoutChanged':False}
    failure=None;stage='existing-firewall-and-free-port'
    try:
        # Confirm a free port inside an existing permission. Never change a rule.
        firewall=json.loads(subprocess.check_output([str(sdk),'compute','firewall-rules','describe',
            cfg['campaign']+'-role-rpc-0-0','--project',cfg['project_id'],'--format=json'],
            stderr=subprocess.PIPE,text=True,timeout=30))
        ports=[p for a in firewall['allowed'] if a['IPProtocol']=='tcp' for p in a.get('ports',[])]
        listeners=quiet(remotes['server'],['sudo','ss','-H','-ltn'],timeout=30).stdout
        used={int(line.split()[3].rsplit(':',1)[1]) for line in listeners.splitlines() if line.split()}
        port=next((p for p in [9450,9448,9447,9444] if p not in used and permitted(ports,p)),None)
        if port is None: raise ValueError('no existing permitted free temporary port')
        report['temporaryPort']=port
        original,candidate,patch=prepare_patch.render()
        binding=json.loads((HERE/'proposal.json').read_text())
        assert prepare_patch.hashes(original)==binding['source'] and prepare_patch.hashes(candidate)==binding['candidate']
        report['proposalSha256']=sha(patch.encode());report['sourceSha256']=binding['source'];report['candidateSha256']=binding['candidate']
        with tempfile.TemporaryDirectory(prefix='vcfhe-wan-probe-sources-') as directory:
            source=Path(directory)
            for name,value in candidate.items(): (source/name).write_text(value)
            core=(DISTRIBUTED/'role-transport.mjs').read_bytes()
            (source/'role-transport-core.mjs').write_bytes(core)
            report['roleTransportSha256']=sha(core)
            wrapper='''import {callRole as core} from './role-transport-core.mjs';
export async function callRole(options){
  const state=globalThis.vcfheProbe,operation=options.request.operation;
  if(!['probe-ping','missing-chunks','put-chunk','get-chunk'].includes(operation))throw Error('infrastructure operation required');
  const chunk=operation==='put-chunk'||operation==='get-chunk';
  if(chunk){state.active++;state.maximum=Math.max(state.maximum,state.active);state[operation==='put-chunk'?'put':'get']++;}
  try{return await core({...options,timeoutMs:10000});}
  catch(error){state.errors++;console.error(JSON.stringify({probeRpcFailure:operation,errorCode:error.code??null,errorType:error.name,message:error.message}));throw error;}
  finally{if(chunk)state.active--;}
}
'''
            (source/'role-transport.mjs').write_text(wrapper)
            for name in ['wan-client.mjs','wan-server.mjs']:(source/name).write_bytes((HERE/name).read_bytes())
            report['probeSourceSha256']={p.name:sha(p.read_bytes()) for p in source.iterdir() if p.suffix=='.mjs'}
            operations=['probe-ping','missing-chunks','put-chunk','get-chunk']
            (source/'server-config.json').write_text(json.dumps({'campaign':probe,'node':'auditor-1','port':port,
                'peers':[{'node':'coordinator-1','fingerprint256':client_peer['fingerprint256'],'operations':operations}]}))
            (source/'client-config.json').write_text(json.dumps({'campaign':probe,'node':'coordinator-1','host':'host-1',
                'tls':{'key':'/probe-tls/key','cert':'/probe-tls/cert','ca':'/probe-tls/ca'},
                'peers':[{'node':'auditor-1','url':f'https://{nodes["auditor-1"]["private_ip"]}:{port}/v1/role',
                    'fingerprint256':peers['auditor-1']['fingerprint256']}]}))
            def base(side,detach=False):
                node=nodes['coordinator-1' if side=='client' else 'auditor-1'];root=node['state_directory']
                args=['sudo','docker','run','--rm','--name',names[side]]
                if detach:args+=['-d']
                args+=['--network','host','--user','10001:10001','--read-only','--cap-drop','ALL',
                    '--security-opt','no-new-privileges:true','--entrypoint','node',
                    '--mount',f'type=bind,src={remote_dir},dst=/probe,readonly',
                    '--mount',f'type=bind,src={root}/identity/tls.key,dst=/probe-tls/key,readonly',
                    '--mount',f'type=bind,src={root}/identity/tls.crt,dst=/probe-tls/cert,readonly',
                    '--mount',f'type=bind,src={root}/config/ca.pem,dst=/probe-tls/ca,readonly']
                for target in ['/fixtures','/transport','/reports']:
                    args+=['--tmpfs',target+':rw,nosuid,nodev,noexec,uid=10001,gid=10001,mode=0700,size=64m']
                args+=['--env','VCFHE_ROLE_CONFIG=/probe/client-config.json',image,
                    '/probe/wan-'+side+'.mjs']
                return args
            for side,remote in remotes.items():
                stage=side+'-source-upload'
                quiet(remote,['sudo','test','!','-e',remote_dir],timeout=30)
                quiet(remote,['sudo','docker','image','inspect',image],timeout=30)
                created.add(side);remote.upload(source,remote_dir)
            stage='server-start'
            quiet(remotes['server'],base('server',True),timeout=40);started.add('server')
            for attempt in range(10):
                logs=quiet(remotes['server'],['sudo','docker','logs',names['server']],timeout=20).stdout
                if '"ready":true' in logs:break
                time.sleep(0.5)
            else:raise ValueError('isolated TLS server did not become ready')
            stage='server-listener-check'
            listener=quiet(remotes['server'],['sudo','ss','-H','-ltn',f'sport = :{port}'],timeout=30).stdout.strip()
            if not listener: raise ValueError('temporary server did not bind the permitted private port')
            report['listenerVerified']=True
            stage='client-private-tcp-check'
            tcp='import socket,sys,json\ns=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=3);s.close();print(json.dumps(dict(connected=True)))'
            tcp_result=quiet(remotes['client'],['python3','-c',tcp,nodes['auditor-1']['private_ip'],str(port)],timeout=30)
            if json.loads(tcp_result.stdout).get('connected') is not True: raise ValueError('private probe TCP connection failed')
            report['privateTcpVerified']=True
            stage='client-run'
            started.add('client')
            result=quiet(remotes['client'],base('client'),timeout=100)
            observation=json.loads(result.stdout.strip())
            assert observation['status']=='passed' and observation['maximumChunkConcurrency']==8
            report['observation']=observation;report['status']='passed';report['clientDiagnostics']=result.stderr
    except BaseException as error:
        failure=error;report['errorType']=type(error).__name__;report['errorStage']=stage
        for name in ['stdout','stderr']:
            value=getattr(error,name,None)
            if value:report['failure'+name.title()]=(value.decode(errors='replace') if isinstance(value,bytes) else str(value))[-12000:]
    finally:
        for side,remote in remotes.items():
            checks={'containerAbsent':False,'temporarySourcesRemoved':False,
                    'emptyProbeParentRemoved':False,'parentRemovalRequired':side in created}
            try:
                if failure is not None and side in started:
                    try:
                        logs=quiet(remote,['sudo','docker','logs',names[side]],timeout=20)
                        report[side+'ContainerDiagnostics']={'stdout':logs.stdout[-12000:],'stderr':logs.stderr[-12000:]}
                    except BaseException:pass
                # Remove only the exact temporary container name, whether or not
                # docker --rm already removed it after a successful client exit.
                try:quiet(remote,['sudo','docker','rm','-f',names[side]],timeout=30)
                except subprocess.CalledProcessError:pass
                remaining=quiet(remote,['sudo','docker','ps','-a','--filter','name=^/'+names[side]+'$','--format','{{.Names}}'],timeout=30).stdout.strip()
                checks['containerAbsent']=not remaining
                if side in created:
                    # This unique directory was required absent before upload.
                    quiet(remote,['sudo','find',remote_dir,'-mindepth','1','-maxdepth','1','-type','f','-delete'],timeout=30)
                    quiet(remote,['sudo','rmdir','--',remote_dir],timeout=30)
                    quiet(remote,['sudo','test','!','-e',remote_dir],timeout=30)
                    remove_empty_probe_parent(remote, remote_dir)
                    checks['emptyProbeParentRemoved']=True
                checks['temporarySourcesRemoved']=True
            except BaseException as error:checks['cleanupErrorType']=type(error).__name__
            cleaned[side]=checks
        report['cleanup']=cleaned;report['finishedAt']=datetime.now(timezone.utc).isoformat()
        report['sourcesUnchanged']=prepare_patch.hashes(prepare_patch.render()[0])==json.loads((HERE/'proposal.json').read_text())['source']
        if not all(all(c.get(k) for k in ['containerAbsent','temporarySourcesRemoved'])
                   and (not c['parentRemovalRequired'] or c['emptyProbeParentRemoved']) for c in cleaned.values()):
            report['status']='cleanup-failed'
        output.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps({'status':report['status'],'report':str(output),'cleanup':cleaned,'liveRunEdited':False}))
    if report['status']!='passed':return 1
    return 0

if __name__=='__main__':sys.exit(main())
