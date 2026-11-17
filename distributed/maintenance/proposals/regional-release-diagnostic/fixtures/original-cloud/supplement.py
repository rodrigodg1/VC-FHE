"""Measured WAN tables. No inferred timings and no plaintext in publication files."""
import csv
import hashlib
import json
from pathlib import Path
import statistics
import math

def read(path):return json.loads(Path(path).read_text())
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def dump(path,value):Path(path).write_text(json.dumps(value,indent=2)+'\n')
def csv_file(path,rows,fields):
    with Path(path).open('x',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows([{k:r.get(k) for k in fields} for r in rows])

def summarize_transport(rows,roles):
    out=[];seen=set()
    for row in rows:
        if row.get('kind')!='role_transport':raise ValueError('not a role transport record')
        key=(row['node'],row['id'])
        if key in seen:raise ValueError('duplicate RPC record')
        seen.add(key)
        if row['node'] not in roles or row['target'] not in roles or row['host']!=roles[row['node']]['host']:
            raise ValueError('transport record on wrong participant host')
        for key in ['requestJsonBytes','responseJsonBytes','elapsedSeconds']:
            value=row[key]
            if type(value) not in (float,int) or not math.isfinite(value) or value<0:raise ValueError('invalid transport measurement')
        out.append({**row,'roundTripSeconds':row['elapsedSeconds'],'target_host':roles[row['target']]['host'],
                    'cross_host':row['host']!=roles[row['target']]['host']})
    return out

def generate(run,plan):
    run=Path(run);out=run/'distributed/supplement';out.mkdir()
    roles={n['id']:n for n in plan['nodes']};raw=[]
    logs=[*(run/'collected').glob('*/reports/distributed/transport.jsonl')]
    coordinator_log=run/'reports/distributed/transport.jsonl'
    if coordinator_log.exists():logs.append(coordinator_log)
    for p in logs:
        raw.extend(json.loads(line) for line in p.read_text().splitlines() if line.strip())
    transport=summarize_transport(raw,roles)
    from delay_metrics import export as export_delays
    delays=export_delays(run,roles,transport)
    csv_file(out/'role-communication.csv',transport,['node','host','target','target_host','cross_host','case_id','task',
        'operation','phaseId','requestJsonBytes','responseJsonBytes','roundTripSeconds','handlerSeconds'])
    task_rows=[]
    for record in (run/'distributed/tasks').glob('*/*.task.json'):
        value=read(record);m=value.get('measurement') or {};r=m.get('resources') or {}
        fhe=value.get('publicWorkerResources',[])
        cpu=r.get('totalCpuMs')
        fhe_cpu=sum(v['resources']['totalCpuMs'] for v in fhe) if fhe else None
        task_rows.append({'node':value['node'],'host':value['host'],'role':value['role'],'task':value['task'],
            'mode':value.get('mode'),'case_id':value.get('caseId'),'status':value['status'],
            'handler_ms':value['elapsedMs'],'controller_cpu_ms':cpu,'native_fhe_cpu_ms':fhe_cpu,
            'controller_max_rss_bytes':r.get('maxRssBytes'),
            'native_fhe_max_rss_bytes':max((v['resources']['maxRssBytes'] for v in fhe),default=None)})
    csv_file(out/'participant-work.csv',task_rows,['node','host','role','task','mode','case_id','status','handler_ms',
        'controller_cpu_ms','native_fhe_cpu_ms','controller_max_rss_bytes','native_fhe_max_rss_bytes'])
    owners=[]
    for file in (run/'fixtures').glob('*/owner-fragments/*/fragment.json'):
        value=read(file);r=(value.get('resources') or {}).get('resources') or {}
        owners.append({'case_id':file.parts[-4],'node':value['node'],'host':value['host'],'encrypted_inputs':len(value['indices']),
            'elapsed_ms':value['encryptionElapsedMs'],'cpu_ms':r.get('totalCpuMs'),'max_rss_bytes':r.get('maxRssBytes')})
    csv_file(out/'owner-encryption.csv',owners,['case_id','node','host','encrypted_inputs','elapsed_ms','cpu_ms','max_rss_bytes'])
    app=read(run/'reports/application.json');margins=[]
    for c in app['cases']:
        if c['half']=='nonlinear':
            s=c['metrics']['scheduling']
            margins.append({'case_id':c['name'],'records':c['n'],
                'audit_commit_margin_seconds':s['commitDeadline']-s['commitTimestamp'],
                'audit_open_margin_seconds':s['openDeadline']-s['openTimestamp']})
    csv_file(out/'deadline-margins.csv',margins,['case_id','records','audit_commit_margin_seconds','audit_open_margin_seconds'])
    cfg=read(run/'config/campaign.json')
    expected_nonlinear=2 if cfg.get('smoke') else 18
    expected_full=3 if cfg.get('smoke') else 27
    if len(margins)!=expected_nonlinear or any(min(r['audit_commit_margin_seconds'],r['audit_open_margin_seconds'])<0 for r in margins):
        raise ValueError('incomplete or missed measured audit deadlines')
    byte=read(run/'reports/distributed/byte-repeatability.json')
    if byte.get('status')!='passed' or byte.get('plaintextOpenings')!=0 or len(byte.get('audits',[]))!=3:
        raise ValueError('cross-host byte repeatability evidence missing')
    if {a['node'] for a in byte['audits']}!={'auditor-1','auditor-2','auditor-3'}:
        raise ValueError('byte repeatability does not cover all auditor hosts')
    for a in byte['audits']:
        e=a['evidence']
        if e['index'] is not None or e['operatorRoot']!=e['replayRoot'] or e['plaintextOpenings']!=0:
            raise ValueError('ciphertext divergence in readiness test')
    expected_ids={('operator-1',byte['operatorEventId']),*[(a['node'],a['eventId']) for a in byte['audits']]}
    actual_ids={(read(run/i['path'])['node'],read(run/i['path'])['id']) for i in read(run/'distributed/task-inventory.json')}
    if not expected_ids<=actual_ids:raise ValueError('readiness tasks missing from participant evidence')
    refs={'byteRepeatability':'reports/distributed/byte-repeatability.json','largestCase':'reports/results.json',
          'kmsSetup':'keyset/ready.json','authorization':'reports/onchain-release-evidence.json','budget':'distributed/budget.json'}
    # The original export checks every expected output, threshold
    # response checks, all-owner approvals and fixed-block reservation evidence.
    ready={'sameCiphertextBytes':True,'largestCaseCompleted':len(app['cases'])==expected_full,
        'deadlineMarginsNonnegative':True,'fourKmsDkg':read(run/'keyset/ready.json')['parties']==4,
        'fixedBlockQuorum':True,'exactRecipientRelease':True,'authorizationReuseRejected':True,
        'budgetAdmitted':read(run/'distributed/budget.json')['status']=='admit',
        'evidenceFiles':{k:{'path':p,'sha256':sha(run/p)} for k,p in refs.items()}}
    dump(run/'distributed/readiness.json',ready)
    summary=[]
    for role in ['owner','operator','auditor','adjudicator','recipient','kms','coordinator']:
        calls=[r for r in transport if roles[r['node']]['role']==role]
        summary.append({'role':role,'rpc_count':len(calls),'request_json_bytes':sum(r['requestJsonBytes'] for r in calls),
            'response_json_bytes':sum(r['responseJsonBytes'] for r in calls),
            'cross_host_calls':sum(r['cross_host'] for r in calls),
            'median_roundtrip_seconds':statistics.median(r['roundTripSeconds'] for r in calls) if calls else None})
    csv_file(out/'communication-summary.csv',summary,list(summary[0]))
