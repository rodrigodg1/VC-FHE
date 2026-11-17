#!/usr/bin/env python3
"""Bounded cloud preparation and single dispatch of a versioned continuation."""
from pathlib import Path
import argparse,os,sys,json,subprocess,traceback

def main(input_root,preflight,output):
    input_root=Path(input_root).resolve();preflight=Path(preflight).resolve();out=Path(output).resolve()
    root=input_root/'repository/VC-FHE';driver=Path(__file__).resolve().parent
    sys.path.insert(0,str(root/'distributed'));os.environ['CLOUDSDK_PYTHON']=sys.executable;os.environ['CLOUDSDK_PYTHON_SITEPACKAGES']='1'
    from cloud_tools import ensure
    ensure()
    from cloud_results.common import read,write,sha,require,now
    from cloud_results.cli import stop_compute_local
    from remote import Remote
    import topology
    cfg=read(input_root/'job/config.local.json');source=read(input_root/'source-manifest.json')
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    write(out/'intent.json',{'requestedAt':now(),'setupRepeated':False,'completedPrefix':10,'pending':17},new=True)
    original_run=Remote.run
    def bounded(self,args,**kw):kw.setdefault('timeout',900);return original_run(self,args,**kw)
    Remote.run=bounded
    def phase(name):write(out/'progress.json',{'phase':name,'observedAt':now()});print(name,flush=True)
    try:
        require(read(preflight/'prefix-validation.json')['status']=='validated-completed-prefix-only','Prefix not validated')
        phase('restart-only-same-validators')
        from concurrent.futures import ThreadPoolExecutor
        def validators(host):
            r=Remote(cfg,host);running=r.text(['sudo','docker','ps','--format','{{.Names}}'])
            require(not running,'A participant is already active')
            r.run(['sudo','docker','compose','-f','/srv/vcfhe/'+cfg['campaign']+'/'+host['id']+'/compose.json',
                'start','validator-'+host['id'].split('-')[1]],stdout=subprocess.DEVNULL)
        list(ThreadPoolExecutor(max_workers=4).map(validators,topology.hosts(cfg)))
        phase('prepare-seventeen-pending-cases-with-empty-recipient-exchange')
        from prepare import main as prepare
        prepare(input_root,preflight)
        segment=root/'threshold-kms/runs'/(source['runName']+'-workflows-c4');c=segment/'distributed/workflow-continuation'
        p=read(c/'prepared.json');m=read(c/'manifest.json')
        require(sha(c/'manifest.json')==p['manifestSha256'],'Manifest changed')
        require(all(sha(driver/n)==h for n,h in m['maintenanceSources'].items()),'Maintenance source changed')
        # Validate actual mounted JavaScript and own writable public keysets.
        for host in topology.hosts(cfg):
            r=Remote(cfg,host);compose=read(segment/'compose'/host['id']/'compose.json')
            for name,service in compose['services'].items():
                if name in ('init','setup','policy-init'):
                    require(service.get('profiles')==['never-in-continuation'],'Setup service enabled');continue
                for mount in service.get('volumes',[]):
                    if mount['target']=='/keyset':require(mount['read_only'] is False and mount['source']==p['newBase']+'/'+name+'/keyset','Wrong public-key mount')
            folder=p['newBase']+'/'+host['id']+'/continuation'
            r.run(['sudo','docker','run','--rm','--network','none','--entrypoint','/bin/sh',
                '--mount','type=bind,src='+folder+',dst=/check,readonly',cfg['images']['campaign'],
                '-c','node --check /check/owner.mjs && node --check /check/evaluate.mjs && node --check /check/guard.mjs && node --check /check/admission.mjs'],stdout=subprocess.DEVNULL)
        phase('freeze-and-request-remaining-workflows-once')
        write(out/'freeze.json',{'frozenAt':now(),'manifestSha256':p['manifestSha256'],'prepared':p,'manifest':m},new=True)
        unit='vcfhe-workflows-c4'
        state=subprocess.run(['systemctl','show',unit,'--property=LoadState','--value'],capture_output=True,text=True)
        require(state.stdout.strip()=='not-found','Existing continuation unit. Inspect instead of dispatching again')
        py=str(root/'threshold-kms/.cache/postprocess-python/bin/python')
        command=['systemd-run','--unit='+unit,'--property=WorkingDirectory='+str(root),'--property=UMask=0077',
            '--property=RuntimeMaxSec=82800','--property=TimeoutStopSec=600',
            '--property=StandardOutput=append:'+str(c/'controller.log'),'--property=StandardError=append:'+str(c/'controller.log'),
            '--property=ExecStopPost='+py+' '+str(driver/'cleanup.py')+' --input '+str(input_root)+' --output '+str(out/'workflow-stop'),
            py,str(driver/'runner.py'),'--input',str(input_root),'--segment',str(segment),'--execute']
        write(out/'workflow-start-intent.json',{'requestedAt':now(),'manifestSha256':p['manifestSha256']},new=True)
        subprocess.run(command,check=True,stdout=subprocess.DEVNULL)
        write(out/'launched.json',{'status':'continuation-service-requested-once','requestedAt':now(),'unit':unit,
            'segment':str(segment),'newBase':p['newBase'],'manifestSha256':p['manifestSha256'],
            'completedPreserved':10,'pendingWorkflows':17,'comparisonsRepeated':False,'warmupsRepeated':False,
            'windowHours':22},new=True)
        phase('continuation-service-requested-await-owner-restoration')
    except BaseException as e:
        write(out/'failure.json',{'observedAt':now(),'errorType':type(e).__name__,'message':str(e),'traceback':traceback.format_exc()})
        stop_compute_local(cfg,out);raise

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--preflight',required=True);p.add_argument('--output',required=True)
    a=p.parse_args();os.umask(0o077);main(a.input,a.preflight,a.output)
