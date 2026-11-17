#!/usr/bin/env python3
"""Verify retained numerical observations and optionally render plots. No infrastructure."""
import argparse
from collections import defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

ROOT=Path(__file__).resolve().parent

def read(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def csv_rows(path):
    with path.open(newline='') as stream:return list(csv.DictReader(stream))
def require(ok,message):
    if not ok:raise ValueError(message)

def verify(base):
    manifest=read(base/'collection.json')
    require(manifest['schema']=='poc-numeric-collection-v1','Unknown numerical collection')
    for name,expected in manifest['files'].items():
        p=Path(name);require(not p.is_absolute() and '..' not in p.parts,'Unsafe collection path')
        path=base/p;require(not path.is_symlink() and path.is_file(),'Missing or linked collection file')
        require(sha(path)==expected,'Changed collection file: '+name)
    obs=csv_rows(base/'workflow/observations.csv');report=read(base/'workflow/summary.json')
    columns=['group','half','n','cohort','step','metric','unit'];grouped=defaultdict(list)
    for row in obs:
        value=json.loads(row['value']);require(isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value),'Nonfinite observation')
        grouped[tuple(str(row[k]) for k in columns)].append(value)
    require(len(grouped)==len(report['metrics']),'Summary metric inventory differs')
    seen=set()
    for row in report['metrics']:
        key=tuple(str(row[k]) for k in columns);require(key not in seen,'Repeated summary metric');seen.add(key)
        values=grouped[key];require(len(values)==row['observations'],'Observation count differs')
        expected=dict(mean=statistics.mean(values),minimum=min(values),maximum=max(values),
                      sampleSd=statistics.stdev(values) if len(values)>1 else None)
        for k,v in expected.items():
            actual=row[k];require(actual is None if v is None else actual is not None and math.isclose(v,actual,rel_tol=1e-10,abs_tol=1e-6),'Statistic differs: '+str(key)+' '+k)
    pairs=csv_rows(base/'diagnostics/paired-observations.csv')
    require(sum(r['warmup']=='False' for r in pairs)==manifest['measuredPairs'],'Incomplete paired collection')
    require(sum(r['warmup']=='True' for r in pairs)==manifest['warmups'],'Incomplete warm-up collection')
    full={r['case'] for r in obs if r['cohort']=='full'}
    require(len(full)==manifest['fullCases'],'Incomplete full-case collection')
    sys.path.insert(0,str(ROOT.parent/'threshold-kms/postprocess'))
    timing=verification=None
    if base.name=='distributed':
        from decision_timing import load
        from verification_budget import load_retained,derive
        timing=load(base/'workflow',report)
        workflows,_=load_retained(base/'cpu-inputs')
        verification=derive(workflows,obs,pairs)
    return report,obs,timing,verification

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--collection',choices=['local-archive','distributed','all'],default='all')
    p.add_argument('--output',type=Path,help='New directory for tables and plots')
    a=p.parse_args();names=['local-archive','distributed'] if a.collection=='all' else [a.collection]
    validated=[(name,*verify(ROOT/name)) for name in names]
    if a.output:
        require(not a.output.exists(),'Preserve previous outputs; choose a new directory')
        from workflow_figures import generate_selected
        a.output.mkdir(parents=True)
        for name,report,obs,timing,verification in validated:
            out=a.output/name;out.mkdir()
            metrics=report['metrics']
            with (out/'metrics.csv').open('w',newline='') as stream:
                writer=csv.DictWriter(stream,fieldnames=list(dict.fromkeys(k for r in metrics for k in r)));writer.writeheader();writer.writerows(metrics)
            lines=['# Workflow metrics','','Mean and sample SD with the actual count per row. See docs/METRICS.md for scope.','',
                   '| Group | Cohort | Step | Metric | Unit | Count | Mean | Sample SD |',
                   '| --- | --- | --- | --- | --- | ---: | ---: | ---: |']
            for r in metrics:lines.append('| '+' | '.join(str(r[k]) for k in ['group','cohort','step','metric','unit','observations','mean','sampleSd'])+' |')
            (out/'METRICS.md').write_text('\n'.join(lines)+'\n')
            generate_selected(report,obs,out,'both',timing,verification)
            for label,data in [('decision-timing',timing),('verification-budget',verification)]:
                if data is not None:(out/(label+'.json')).write_text(json.dumps(data,indent=2)+'\n')
            (out/'output-hashes.json').write_text(json.dumps({q.name:sha(q) for q in sorted(out.iterdir()) if q.is_file()},indent=2)+'\n')
    print(json.dumps({'status':'passed','collections':[{ 'name':name,'metrics':len(report['metrics']),'observations':len(obs)} for name,report,obs,_,_ in validated],
                      'scope':'Numerical hashes, counts and summary reconciliation. No raw protocol revalidation.',
                      'output':str(a.output) if a.output else None},indent=2))

if __name__=='__main__':main()
