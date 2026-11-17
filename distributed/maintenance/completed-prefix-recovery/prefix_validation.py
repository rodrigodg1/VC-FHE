"""Validate a failed administrative segment's completed cases, never relabel it.

Only the complete-run status assertion is replaced by an exact failed-prefix
gate. Missing terminal counter observations come from a separately stored,
four-validator read at the preserved frontier. All per-case checks are retained.
"""
import hashlib
import types
import sys
from pathlib import Path
from frontier import inspect_frontier

def validator(source, app, events, plan, reconciliation, source_path=None):
    frontier=inspect_frontier(plan,events,app)
    if app.get('status')!='failed' or 'budget duration leaves insufficient allowance for another complete case' not in app.get('error',''):
        raise ValueError('Only the diagnosed pre-case administrative refusal is eligible')
    starts=[e['caseName'] for e in events if e.get('phase')=='full-case' and e.get('state')=='start']
    if starts and starts!=frontier['completedCases']:
        raise ValueError('An unfinished workflow started')
    if reconciliation.get('status')!='reconciled' or reconciliation.get('transactionsSubmitted')!=0:
        raise ValueError('Missing read-only chain reconciliation')
    views=reconciliation.get('views',[])
    if len(views)!=4 or any(v!=views[0] for v in views[1:]):
        raise ValueError('Missing four-validator fixed-block agreement')
    if reconciliation['completed']!=frontier['completedCases'] or reconciliation['remaining']!=frontier['remainingCases']:
        raise ValueError('Different reconciled frontier')
    ids=set(r for c in app['cases'] for r in c['recordIds'])
    records={r:{k:v for k,v in views[0]['records'][r].items() if k in ('owner','recordReference','releaseLimit','spent')} for r in ids}
    old='require(app.get("status") == "passed", "application report did not pass")'
    counter='final_records = _normalized_record_map(app.get("protectedRecords"), "protectedRecords")'
    status='"status": "passed",'
    if source.count(old)!=1 or source.count(counter)!=1 or source.count(status)!=1:
        raise ValueError('Native evidence validator anchors changed')
    changed=source.replace(old,'require(app == EXPECTED_FAILED_APPLICATION, "completed-prefix bytes changed")')
    changed=changed.replace(counter,'final_records = _normalized_record_map(RECONCILED_FINAL_RECORDS, "reconciled protectedRecords")')
    changed=changed.replace(status,'"status": "completed-prefix-validated",')
    module=types.ModuleType('completed_prefix_onchain_evidence')
    module.__dict__.update(EXPECTED_FAILED_APPLICATION=app,RECONCILED_FINAL_RECORDS=records)
    if source_path is not None:
        module.__file__=str(Path(source_path).resolve())
    exec(compile(changed,'<versioned-completed-prefix-validator>','exec'),module.__dict__)
    return module,{'originalValidatorSha256':hashlib.sha256(source.encode()).hexdigest(),
        'derivedValidatorSha256':hashlib.sha256(changed.encode()).hexdigest(),
        'scope':'completed-prefix-only-not-successful-campaign','analysisComplete':False}
