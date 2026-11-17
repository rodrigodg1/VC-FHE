"""Export observed TCP and application durations without conflating their scopes."""
import csv
import json
import math
from pathlib import Path
import statistics

def distribution(values):
    if any(type(v) not in (float,int) or not math.isfinite(v) or v<0 for v in values):
        raise ValueError('invalid delay observation')
    ordered=sorted(values)
    def percentile(p):
        position=(len(ordered)-1)*p;lo=int(position)
        return ordered[lo]+(ordered[min(lo+1,len(ordered)-1)]-ordered[lo])*(position-lo)
    return {'observations':len(values),'median_seconds':statistics.median(values) if values else None,
            'observed_p95_seconds':percentile(.95) if len(values)>=20 else None,
            'maximum_seconds':max(values) if values else None}

def network_rows(samples,hosts):
    rows=[]
    for sample in samples:
        if sample.get('kind')!='network_probe':continue
        if sample['host'] not in hosts or sample['target_host'] not in hosts:
            raise ValueError('network probe on an unknown host')
        if sample['status'] not in ('connected','unavailable'):raise ValueError('unknown TCP probe status')
        distribution([sample['elapsed_seconds']])
        rows.append({key:sample.get(key) for key in ['host','target_host','port','status','elapsed_seconds','error','utc']})
    return rows

def write_csv(path,rows,fields):
    with Path(path).open('x',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows(rows)

def export(run,roles,transport):
    run=Path(run);output=run/'distributed/supplement'
    samples=[]
    for file in sorted((run/'distributed/samples').glob('*/host-observations.jsonl')):
        samples.extend(json.loads(line) for line in file.read_text().splitlines() if line.strip())
    hosts={r['host'] for r in roles.values()}
    network=network_rows(samples,hosts)
    if not network:raise ValueError('distributed network delay observations are missing')
    write_csv(output/'network-connections.csv',network,['host','target_host','port','status','elapsed_seconds','error','utc'])
    groups={}
    for row in network:groups.setdefault((row['host'],row['target_host'],row['port']),[]).append(row)
    summary=[]
    for (host,target,port),rows in sorted(groups.items()):
        connected=[r['elapsed_seconds'] for r in rows if r['status']=='connected']
        summary.append(dict(host=host,target_host=target,port=port,attempts=len(rows),
            failures=sum(r['status']=='unavailable' for r in rows),**distribution(connected)))
    write_csv(output/'network-delay-summary.csv',summary,['host','target_host','port','attempts','failures','observations','median_seconds','observed_p95_seconds','maximum_seconds'])
    latency=[]
    for role in sorted({r['role'] for r in roles.values()}-{'validator'}):
        calls=[r for r in transport if roles[r['node']]['role']==role and r['cross_host']]
        latency.append(dict(role=role,**distribution([r['roundTripSeconds'] for r in calls])))
    write_csv(output/'application-delay-summary.csv',latency,['role','observations','median_seconds','observed_p95_seconds','maximum_seconds'])
    return {'tcpObservations':len(network),'applicationRpcObservations':sum(r['observations'] for r in latency),
        'tcpScope':'Local monotonic TCP connection duration. Failures include startup observations.',
        'applicationScope':'Cross-host request-to-response duration including TLS, transfer and handler processing.',
        'p95Scope':'Observed sample percentile, exported only with at least 20 observations. No tail-latency guarantee.'}
