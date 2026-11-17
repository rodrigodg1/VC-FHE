"""Systemd stop hook. Stop owned compute, never delete data or replay a stage."""
import json
from pathlib import Path
import sys
import urllib.request
import urllib.error
import time


def stop(root):
    root=Path(root)
    config=json.loads((root/'job/config.local.json').read_text())
    manifest=json.loads((root/'source-manifest.json').read_text())
    def token():
        request=urllib.request.Request('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',headers={'Metadata-Flavor':'Google'})
        with urllib.request.urlopen(request,timeout=15) as response:return json.load(response)['access_token']
    def api(path,method='GET'):
        request=urllib.request.Request('https://compute.googleapis.com/compute/v1/projects/'+config['project_id']+'/'+path,
            data=b'' if method=='POST' else None,method=method,headers={'Authorization':'Bearer '+token()})
        with urllib.request.urlopen(request,timeout=45) as response:return json.load(response)
    # A small failure report remains observable even after the controller stops.
    # No logs, credentials or participant state enter this report.
    if not (root/'terminal-object.local.json').exists():
        try:
            sys.path.insert(0,str(root/'repository/VC-FHE/distributed'))
            from cloud_results.storage import Store
            class MetadataStore(Store):
                def token(self):return token()
            failed=root/'failure.local.json'
            value=json.loads(failed.read_text()) if failed.exists() else {}
            report=root/'failure-summary.local.json'
            report.write_text(json.dumps({'status':'failed-preserved','errorType':value.get('errorType','ControllerServiceFailure'),
                'dataDeleted':False,'protocolReplayed':False,'inspectionRequired':True}))
            MetadataStore(manifest['names']['bucket'],config['project_id']).upload(report,'runs/'+manifest['jobId']+'/failure.json')
        except Exception:
            # Failure to publish a summary must never prevent stopping compute.
            pass
    hosts=[(config['campaign']+'-host-'+str(i),region['zone']) for i,region in enumerate(config['regions'],1)]
    hosts.append((manifest['names']['controller'],config['regions'][0]['zone']))
    outcomes=[]
    for name,zone in hosts:
        try:
            path='zones/'+zone+'/instances/'+name
            try:live=api(path)
            except urllib.error.HTTPError as error:
                if error.code==404:outcomes.append({'name':name,'absent':True});continue
                raise
            if live.get('labels',{}).get('experiment')!=config['campaign']:raise ValueError('Foreign VM')
            if live.get('status')!='TERMINATED':api(path+'/stop','POST')
            outcomes.append({'name':name,'stopRequested':True})
        except Exception as error:outcomes.append({'name':name,'errorType':type(error).__name__})
    (root/'stop-hook.local.json').write_text(json.dumps({'hosts':outcomes,'dataDeleted':False}))
    if any('errorType' in row for row in outcomes):raise RuntimeError('Compute stop hook needs inspection')

if __name__=='__main__':stop(sys.argv[1])
