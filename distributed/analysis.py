"""Generate validated WAN results without repeating protocol operations."""
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


def write_result(path,value):
    path=Path(path);pending=path.with_name('.'+path.name+'-'+uuid.uuid4().hex+'.pending')
    with pending.open('x') as f:json.dump(value,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    pending.replace(path)


def generate(run,post):
    run=Path(run);cfg=json.loads((run/'config/campaign.json').read_text())
    if cfg.get('smoke') or cfg.get('readinessOnly'):raise ValueError('Readiness evidence is not a complete campaign')
    root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(post))
    from single_run import validate
    from refresh import refresh
    provenance=validate(run)
    if 'distributedExecution' not in provenance:raise ValueError('Missing distributed execution evidence')
    base=root/'threshold-kms/composites'/(run.name+'-distributed')
    refresh(run,base)
    from result_package import package_index
    package_index(run,base)
    result={'status':'results-ready','source':'cloud','composite':str(base),
            'artifacts':str(base/'analysis-package.json'),'index':str(base/'CLOUD-RESULTS.md')}
    write_result(base/'distributed-results.json',result)
    launch=run/'launch-state.json'
    if launch.exists():
        state=json.loads(launch.read_text());state.update(resultsStatus='results-ready')
        if state.get('status')=='evaluation-complete-postprocessing-failed':state['status']='completed'
        write_result(launch,state)
    return result


def derive(run):
    run=Path(run)
    from postprocess_adapter import prepare,verify
    post=run/'distributed/generators';post=verify(post) if post.exists() else prepare(post)
    result=run/'distributed/results-result.json'
    subprocess.run([sys.executable,__file__,'--run',str(run),'--processor',str(post),'--output',str(result)],check=True)
    return json.loads(result.read_text())

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('run','processor','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();write_result(a.output,generate(a.run,a.processor))
