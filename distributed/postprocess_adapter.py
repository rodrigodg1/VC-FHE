"""Guarded generator copies for WAN evidence. Never edit local campaign scripts."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent

def prepare(output):
    output=Path(output).resolve()
    if output.exists():raise ValueError('preserve prior distributed generator copies')
    output.mkdir(parents=True)
    original=ROOT/'threshold-kms/postprocess'
    inventory={}
    for file in sorted(original.iterdir()):
        if file.is_file() and file.suffix in ('.py','.txt'):
            shutil.copy2(file,output/file.name)
            inventory[file.name]={'originalSha256':hashlib.sha256(file.read_bytes()).hexdigest()}
    def edit(name,old,new,count=1):
        file=output/name;text=file.read_text()
        if text.count(old)!=count:raise ValueError('distributed generator source drift: '+name+' '+old[:70])
        file.write_text(text.replace(old,new))
    edit('verify_composite.py','MODULE = HERE.parent',
         'MODULE = Path('+repr(str(ROOT/'threshold-kms'))+')\nsys.path.insert(0, '+repr(str(HERE))+')')
    edit('single_run.py','design = validate_pairs(cfg, paired)',
         "from experiment_plan import evidence_module\n    method=evidence_module(cfg)\n    validate_pairs,validate_full_cases=method.validate_pairs,method.validate_full_cases\n    design = validate_pairs(cfg, paired)")
    edit('diagnostics.py',"poc_evidence.validate_pairs(read(original / 'config/campaign.json'), paired)",
         "from experiment_plan import evidence_module\n    poc_evidence=evidence_module(read(original/'config/campaign.json'),cache/'threshold-kms/campaign/poc_evidence.py')\n    poc_evidence.validate_pairs(read(original/'config/campaign.json'),paired)")
    edit('distributed_evidence.py',"summary.get('fullCases')==45","summary.get('fullCases')==27")
    edit('distributed_evidence.py',"require(not cfg.get('smoke') and not cfg.get('readinessOnly'),'pilot cannot become evaluation evidence')",
         "require(not cfg.get('smoke') and not cfg.get('readinessOnly'),'pilot cannot become evaluation evidence')\n    from experiment_plan import VERSION,plan\n    require(cfg.get('distributedPlan')==VERSION and cfg.get('pocPlan')==plan('both'),'wrong distributed measurement design')")
    edit('distributed_evidence.py',"hashes=sealed('distributed/source.json')",
         "hashes=sealed('distributed/source.json')\n    import experiment_plan\n    require(hashes['distributedSource'].get('experiment_plan.py')==sha(Path(experiment_plan.__file__)),'distributed design adapter changed')")
    edit('workflow.py',"if item['cohort'] == 'paired' else 5","if item['cohort'] == 'paired' else 3")
    for name,item in inventory.items():
        item['adaptedSha256']=hashlib.sha256((output/name).read_bytes()).hexdigest()
        if hashlib.sha256((original/name).read_bytes()).hexdigest()!=item['originalSha256']:
            raise ValueError('local generator changed while preparing WAN copy')
    (output/'distributed-generator-adapter.json').write_text(json.dumps({
        'schema':'distributed-three-case-generators-v1','files':inventory,
        'localSourcesEdited':False,'protocolRulesChanged':False},indent=2)+'\n')
    return output

def verify(output):
    output=Path(output)
    record=json.loads((output/'distributed-generator-adapter.json').read_text())
    for name,item in record['files'].items():
        if hashlib.sha256((output/name).read_bytes()).hexdigest()!=item['adaptedSha256']:
            raise ValueError('adapted WAN generator changed: '+name)
        if hashlib.sha256((ROOT/'threshold-kms/postprocess'/name).read_bytes()).hexdigest()!=item['originalSha256']:
            raise ValueError('original generator changed after WAN preparation: '+name)
    return output

def validate(run):
    output=prepare(Path(run)/'distributed/generators')
    subprocess.run([sys.executable,str(output/'single_run.py'),'--run',str(run)],check=True)
    return output
