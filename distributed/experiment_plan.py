"""Separate WAN measurement design. The local campaign remains frozen."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

VERSION='distributed-three-full-v1'
EXECUTION='gcp-four-hosts-role-local-v1'
CAMPAIGN=Path(__file__).resolve().parents[1]/'threshold-kms/campaign'

def load(name,path):
    sys.path.insert(0,str(Path(path).parent))
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def plan(half='both'):
    value=load('wan_original_poc_plan',CAMPAIGN/'poc_plan.py').plan(half)
    indices={'linear':(0,49,99),'nonlinear':(0,14,29)}
    for job in value['jobs']:
        job['fullCase']=job['repeat'] in indices[job['half']]
        job['faultPosition']=(('early','middle','terminal')[indices['nonlinear'].index(job['repeat'])]
            if job['fullCase'] and job['half']=='nonlinear' else None)
    value.update(profile=VERSION,fullCases=sum(j['fullCase'] for j in value['jobs']))
    value.pop('designSha256')
    value['designSha256']=hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()
    return value

def evidence_module(cfg,source=None):
    if cfg.get('executionProfile')!=EXECUTION or cfg.get('distributedPlan')!=VERSION:
        raise ValueError('three full cases are restricted to the explicit distributed design')
    module=load('wan_poc_evidence',source or CAMPAIGN/'poc_evidence.py')
    module.plan=plan
    return module

def validate_export(run):
    run=Path(run)
    cfg=json.loads((run/'config/campaign.json').read_text())
    exporter=load('wan_export',CAMPAIGN/'export.py')
    if not cfg.get('smoke'):
        module=evidence_module(cfg)
        exporter.validate_full_cases=module.validate_full_cases
        exporter.export_poc=module.export_poc
    exporter.export(run)

if __name__=='__main__':
    validate_export(sys.argv[1])
