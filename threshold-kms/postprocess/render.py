#!/usr/bin/env python3
"""Export every workflow metric as CSV/Markdown and render validated comparisons."""
import argparse
import csv
import json
from pathlib import Path
from verify_composite import read, require, sha, verify_files


def render(base,half='both'):
    base=Path(base)
    require(not (base/'analysis-package.json').exists(),'Preserve existing analysis; use a new directory')
    folder=base/'workflow';report=read(folder/'summary.json')
    verify_files(folder,read(folder/'hashes.json'))
    require(report.get('preliminary') is not True,'Preliminary values need diagnostic review')
    with (folder/'observations.csv').open(newline='') as f:observations=list(csv.DictReader(f))
    selected=[row for row in report['metrics'] if half=='both' or row['half']==half]
    require(selected,'Empty metric selection')
    fields=list(dict.fromkeys(k for row in selected for k in row))
    with (base/'metrics.csv').open('x',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader();writer.writerows(selected)
    lines=['# Measured workflow costs','',
           'Means and sample standard deviations retain the observation counts of each row.',
           'Shared, baseline, correct-task and disputed-task costs have separate labels. Do not add overlapping timers.',
           'A final decision precedes bond release and reward withdrawal. Process CPU is not elapsed time.',
           '', '| Group | Cohort | Step | Metric | Unit | Count | Mean | Sample SD |',
           '| --- | --- | --- | --- | --- | ---: | ---: | ---: |']
    for row in selected:
        values=[row[k] for k in ['group','cohort','step','metric','unit','observations','mean','sampleSd']]
        lines.append('| '+' | '.join(str(v) for v in values)+' |')
    (base/'METRICS.md').write_text('\n'.join(lines)+'\n')
    from workflow_figures import generate_selected
    from decision_timing import load
    figures=base/'figures';figures.mkdir()
    timing=load(folder,report) if half!='linear' and (folder/'receipt-partition.csv').exists() else None
    verification=None
    if report.get('distributedExecution') and half!='linear':
        from verification_budget import derive
        provenance=read(base/'provenance.json')
        cases=read(Path(provenance['run'])/'reports/application.json')['cases']
        with (base/'diagnostics/paired-observations.csv').open(newline='') as stream:
            pairs=list(csv.DictReader(stream))
        verification=derive(cases,observations,pairs)
        (figures/'verification-budget.json').write_text(json.dumps(verification,indent=2)+'\n')
    generate_selected(report,observations,figures,half,timing,verification)
    files={}
    for directory in ['workflow','diagnostics','figures']:
        for path in sorted((base/directory).rglob('*')):
            if path.is_file():files[str(path.relative_to(base))]=sha(path)
    for name in ['metrics.csv','METRICS.md']:
        files[name]=sha(base/name)
    manifest=dict(schema='poc-analysis-package-v1',half=half,preliminary=False,
                  provenanceSha256=sha(base/'provenance.json'),rendererSha256=sha(Path(__file__)),files=files)
    (base/'analysis-package.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--composite',type=Path,required=True)
    p.add_argument('--half',choices=['both','linear','nonlinear'],default='both')
    a=p.parse_args();render(a.composite,a.half)
