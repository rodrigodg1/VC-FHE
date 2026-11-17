"""Compose validated case rows without rewriting either execution's raw report."""
import collections

def combine(prefix, continuation, planned, *, prefix_verdict, continuation_verdict):
    if prefix_verdict.get('status')!='completed-prefix-validated' or prefix_verdict.get('caseCount')!=10:
        raise ValueError('Missing completed-prefix validation')
    if continuation_verdict.get('status')!='passed' or continuation_verdict.get('caseCount')!=17:
        raise ValueError('Missing continuation release validation')
    a,b=prefix['cases'],continuation['cases']
    if [r['name'] for r in a+b]!=planned or len(set(planned))!=27:
        raise ValueError('Missing, reordered or duplicated full workflows')
    if prefix['kmsCalls']!=10 or continuation['kmsCalls']!=17:
        raise ValueError('Unexpected release count')
    if prefix['keys']!=continuation['keys'] or prefix['onChainPolicy']!=continuation['onChainPolicy']:
        raise ValueError('Keyset or cumulative policy lineage changed')
    for field in ('releaseSlot','releaseRequestId','requestKey','reservationTransaction','consentId'):
        values=[r[field] for r in a+b]
        if len(set(values))!=27:raise ValueError('Repeated '+field)
    charges=collections.Counter(r for c in a for r in c['recordIds'])
    for rid,before in continuation['protectedRecordBaselines'].items():
        if rid in prefix['protectedRecordBaselines']:
            prior=prefix['protectedRecordBaselines'][rid]
            if any(before[k]!=prior[k] for k in ('owner','recordReference','releaseLimit')):
                raise ValueError('Protected record identity changed')
            if before['spent']!=prior['spent']+charges[rid]:
                raise ValueError('Cumulative counters reset or changed between segments')
    return {'schema':'distributed-completed-prefix-composite-v1',
        'status':'case-grid-and-release-continuity-validated',
        'cases':a+b,'kmsCalls':27,'segments':[{'runId':prefix['config']['runId'],'count':10},
        {'runId':continuation['config']['runId'],'count':17}],
        'analysisComplete':False,'requiresFullRawAndMetricValidation':True}
