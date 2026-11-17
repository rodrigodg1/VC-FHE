#!/usr/bin/env python3
"""Validate a completed run and derive CSV/JSON summaries and plots."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
from verify_composite import HERE, MODULE, read, require, sha, verify_files
from single_run import validate as validate_run
from review import template, validate as validate_diagnostics, ensure_automated
import setup_evidence


def invoke(name,*args,python=None):
    subprocess.run([str(python or sys.executable),str(HERE/name),*map(str,args)],check=True)


def plotting_python():
    python=MODULE/'.cache/postprocess-python/bin/python'
    requirements=HERE/'requirements.txt';marker=python.parent.parent/'requirements.sha256'
    if not python.exists():subprocess.run([sys.executable,'-m','venv',str(python.parent.parent)],check=True)
    if not marker.exists() or marker.read_text().strip()!=sha(requirements):
        subprocess.run([str(python),'-m','pip','install','--disable-pip-version-check','-r',str(requirements)],check=True)
        marker.write_text(sha(requirements)+'\n')
    return python


def validate_derived(base):
    base=Path(base)
    provenance=read(base/'provenance.json')
    require(validate_run(Path(provenance['run']))==provenance,'Changed original run provenance')
    setup_evidence.validate(base)
    validate_diagnostics(base)
    verify_files(base/'diagnostics',read(base/'diagnostics/diagnostic-hashes.json'))
    verify_files(base/'workflow',read(base/'workflow/hashes.json'))
    report=read(base/'workflow/summary.json')
    require(report.get('preliminary') is False and report['provenanceSha256']==sha(base/'provenance.json')
            and report['scriptSha256']==sha(HERE/'workflow.py'),'Incomplete or stale workflow derivation')
    manifest=read(base/'analysis-package.json')
    cfg=read(Path(provenance['run'])/'config/campaign.json')
    require(manifest.get('schema')=='poc-analysis-package-v1' and manifest['half']==cfg['half']
            and manifest['preliminary'] is False and manifest['provenanceSha256']==sha(base/'provenance.json'),
            'Incomplete analysis package')
    require(manifest['rendererSha256']==sha(HERE/'render.py'),'Result renderer changed')
    verify_files(base,manifest['files'])
    expected={'linear-cost'} if cfg['half']=='linear' else {'nonlinear-work','workflow-gas'}
    if cfg['half']=='both':expected.add('linear-cost')
    require(all('figures/'+name+suffix in manifest['files'] for name in expected
                for suffix in ('.pdf','.png','.svg','.csv','.json')),'Missing plots or source data')
    require({'metrics.csv','METRICS.md','workflow/observations.csv','workflow/summary.json'}<=manifest['files'].keys(),
            'Missing metric tables')
    return manifest


def refresh(run,base,diagnostic_review=None,manual_review=False):
    provenance=validate_run(run);cfg=read(run/'config/campaign.json')
    require(base.parent==MODULE/'composites','derived directory must be a direct composites child')
    if not base.exists():
        base.parent.mkdir(parents=True,exist_ok=True)
        invoke('single_run.py','--run',run,'--output',base)
    require(read(base/'provenance.json')==provenance,'Derivation belongs to different evidence')
    setup_evidence.ensure(base)
    if not (base/'diagnostics').exists():invoke('diagnostics.py','--composite',base,python=plotting_python())
    verify_files(base/'diagnostics',read(base/'diagnostics/diagnostic-hashes.json'))
    if diagnostic_review:
        target=base/'diagnostic-review.json'
        require(not target.exists() or sha(target)==sha(diagnostic_review),'Existing review differs')
        if not target.exists():shutil.copy2(diagnostic_review,target)
    if manual_review and not (base/'diagnostic-review.json').exists():
        target=base/'diagnostic-review-template.json'
        if not target.exists():target.write_text(json.dumps(template(base),indent=2)+'\n')
        return save_status(base,'diagnostic-review-required',template=target.name)
    if not (base/'diagnostic-review.json').exists():ensure_automated(base)
    validate_diagnostics(base)
    if not (base/'workflow').exists():invoke('workflow.py','--composite',base)
    if not (base/'analysis-package.json').exists():
        invoke('render.py','--composite',base,'--half',cfg['half'],python=plotting_python())
    validate_derived(base)
    return save_status(base,'results-ready',index='METRICS.md',manifest='analysis-package.json')


def save_status(base,status,**fields):
    value=dict(status=status,**fields)
    (base/'postprocess-status.json').write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps(value,indent=2));return value


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',type=Path,required=True);p.add_argument('--output',type=Path)
    p.add_argument('--diagnostic-review',type=Path);p.add_argument('--manual-review',action='store_true')
    a=p.parse_args();run=a.run.resolve();base=a.output.resolve() if a.output else MODULE/'composites'/(run.name+'-workflow')
    refresh(run,base,a.diagnostic_review,a.manual_review)

if __name__=='__main__':main()
