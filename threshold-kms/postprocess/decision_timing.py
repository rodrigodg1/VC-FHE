"""Derive decision intervals from completed cases and inclusion-block receipts.

Wall-clock intervals and block differences remain separate. Neither published
workflow timer ends at the decision transaction: both include later withdrawals.
"""
import csv
import json
import math
import statistics
from pathlib import Path
from verify_composite import require
from distributed_profile import is_distributed

GROUPS = [f'{w}-{n}' for w in ['regulatory_qoe_compliance', 'regional_qoe_compliance'] for n in [16,32,50]]


def derive(report, observations, receipts):
    count = 3 if is_distributed(report) else 5
    records = []
    names = ['disputeWorkflowMs', 'discovery_and_dispute', 'auditMs', 'finalizationMs']
    for group in GROUPS:
        cases = {}
        for row in observations:
            if row['group'] == group and row['cohort'] == 'full' and row['metric'] in names:
                bucket = cases.setdefault(row['case'], {})
                require(row['metric'] not in bucket, 'duplicate timing observation')
                bucket[row['metric']] = float(row['value'])
        require(len(cases) == count and all(set(c) == set(names) for c in cases.values()),
                'incomplete timing cases: '+group)
        for name in names:
            values = [c[name] for c in cases.values()]
            summary = [r for r in report['metrics'] if (r['group'],r['cohort'],r['metric']) == (group,'full',name)]
            require(len(summary) == 1 and summary[0]['observations'] == count, 'ambiguous timing summary')
            require(all(math.isfinite(v) and v >= 0 for v in values), 'invalid timing value')
            require(abs(statistics.mean(values)-summary[0]['mean']) < 1e-6 and
                    abs(statistics.stdev(values)-summary[0]['sampleSd']) < 1e-6, 'timing summary mismatch')
        for case, values in sorted(cases.items()):
            def block(cohort, label):
                selected = [int(r['block']) for r in receipts if
                            (r['case'],r['cohort'],r['label']) == (case,cohort,label)]
                require(len(selected) == 1, 'missing or duplicate timing endpoint: '+case+' '+label)
                return selected[0]
            request = block('challenged','requestBountyTraceDisclosure')
            challenge = block('challenged','openChallenge')
            decision = block('challenged','settleCanonicalLeaf')
            withdrawal = block('challenged','withdrawChallengeBounty')
            require(request < challenge < decision < withdrawal, 'unordered decision endpoints')
            later = [r for r in receipts if r['case']==case and r['cohort']=='challenged'
                     and decision < int(r['block']) <= withdrawal]
            require(sorted(r['label'] for r in later)==['claimUnusedAuditBond','claimUnusedAuditBond','withdrawChallengeBounty'],
                    'unexpected post-decision operations')
            require(all(int(r['block']) < withdrawal for r in later if r['label']=='claimUnusedAuditBond'),
                    'bond return endpoint no longer precedes withdrawal')

            outer, inner = values['disputeWorkflowMs']/1000, values['discovery_and_dispute']/1000
            require(outer >= inner > 0, 'inconsistent nested dispute timers')
            records.append(dict(case=case, group=group, contested_s=outer, detection_dispute_s=inner,
                outside_s=outer-inner, audit_plus_finalization_s=(values['auditMs']+values['finalizationMs'])/1000,
                before_challenge_blocks=challenge-request, challenge_decision_blocks=decision-challenge,
                request_decision_blocks=decision-request,
                after_decision_blocks=withdrawal-decision,
                honest_decision_blocks=block('honest','finalizeUnchallenged')-block('honest','sampleParticipants')))
    return records


def load(folder, report):
    # This analysis is enabled only for the measured geographic campaign.
    if not is_distributed(report) or report.get('half') == 'linear':
        return None
    with (Path(folder)/'observations.csv').open(newline='') as stream:
        observations = list(csv.DictReader(stream))
    if not any(r['group'] in GROUPS for r in observations):
        return None
    with (Path(folder)/'receipt-partition.csv').open(newline='') as stream:
        receipts = list(csv.DictReader(stream))
    return derive(report, observations, receipts)


def summary(records, group, metric):
    values = [r[metric] for r in records if r['group'] == group]
    return statistics.mean(values), statistics.stdev(values), len(values)









