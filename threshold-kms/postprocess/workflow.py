#!/usr/bin/env python3
"""Traceable workflow-step observations, without KMS performance or run writes."""
import argparse
import collections
import csv
import json
import math
from pathlib import Path
import statistics as st
import sys
sys.dont_write_bytecode = True
from verify_composite import MODULE, read, require, sha
from review import evidence_path

# Exhaustive partition of the measured receipt labels. A stage is descriptive,
# not a new transaction or a claim that two cost-bearing operations are equal.
BOUNDARIES = {
    'harness': ['fund-owner'],
    'shared_deployment': ['linear-deploy', 'deploy:ObjectiveMicroVerifier', 'deploy:VerifiableFHEDisputeGame', 'deploy:CanonicalFHEDisputeGame',
                          'deploy:AuthenticatedTraceAvailability', 'deploy:CanonicalLeafVerifier', 'deploy:CanonicalBountyFHEDisputeGame', 'deploy:BountyTraceAvailability',
                          'setAvailabilityModule', 'setCanonicalLeafVerifier'],
    'collateral_setup': ['registerOperator', 'registerAuditor', 'registerOpeningParticipant', 'operator-stake'],
    'step1_owner_admission': ['owner-key', 'owner-admission', 'protected-record-binding', 'registerInputOrigins'],
    # V3 adminless release policy: record registration and consent before
    # execution; exact-request approval and reservation after finality.
    'release_setup': ['protected-record-registration', 'create-release-consent', 'approve-release-consent'],
    'release_authorization': ['propose-exact-release', 'approve-exact-release', 'reserve-exact-release'],
    'step1_task_context': ['authorizeTaskStatement', 'createTask', 'registerCanonicalContext', 'register-task'],
    'step2_result': ['bound-result'],
    'step2_sampling': ['sampleParticipants'],
    'step2_finality': ['finalizeUnchallenged','honestSubmitSealedAudit','honestRevealSealedAudit','honestClaimAuditBond'],
    'baseline_deployment': ['deploy:CanonicalExecutionBaseline'],
    'step2_baseline_certificate': ['acceptFullExecution'],
    'step2_dispute_audit': ['submitAudit','submitSealedAudit','revealSealedAudit', 'openVerdict', 'sealDiligenceRandomness', 'proveAuditDiligence'],
    'step3_challenge_disclosure': ['openChallenge', 'publishDisputedTraceBatch','requestBountyTraceDisclosure','publishAuthenticatedTraceBatch'],
    'step3_bisection': ['operatorBisection','relayOperatorBisection','relayChallengerBisection', 'challengerBisection', 'advanceDispute'],
    'step4_admission_settlement': ['admitCanonicalLeaf', 'settleCanonicalLeaf','claimUnusedAuditBond','withdrawChallengeBounty'],
}
LABEL_BOUNDARY = {label: boundary for boundary, labels in BOUNDARIES.items() for label in labels}
LEGACY_BOUNDARIES = [b for b in BOUNDARIES if not b.startswith('release_')]
SCOPE_LABELS = {
    'harness': BOUNDARIES['harness'], 'deployment': BOUNDARIES['shared_deployment'],
    'collateral': BOUNDARIES['collateral_setup'], 'ownerAdmission': BOUNDARIES['step1_owner_admission'],
    'releaseSetup': BOUNDARIES['release_setup'], 'releaseAuthorization': BOUNDARIES['release_authorization'],
    'proposed': sum([BOUNDARIES[k] for k in ['step1_task_context', 'step2_result', 'step2_sampling', 'step2_finality']], []),
    'baseline': BOUNDARIES['baseline_deployment'] + BOUNDARIES['step2_baseline_certificate'],
    'dispute': sum([BOUNDARIES[k] for k in ['step2_dispute_audit', 'step3_challenge_disclosure',
                                        'step3_bisection', 'step4_admission_settlement']], []),
}
LABEL_SCOPE = {label: scope for scope, labels in SCOPE_LABELS.items() for label in labels}


def txid(receipt):
    return receipt.get('hash', receipt.get('txHash'))


def receipt_index(receipts):
    index = {}
    for r in receipts:
        key = txid(r)
        require(key and key not in index, 'missing/duplicate receipt hash')
        index[key] = r
    return index


def totals(receipts):
    return {'transactionCount': len(receipts), 'gasUsed': sum(int(r['gasUsed']) for r in receipts),
            'calldataBytes': sum(r['calldataBytes'] for r in receipts)}


def select_receipts(scopes, reported, index, used):
    selected = []
    for scope, summary in scopes.items():
        require(scope in SCOPE_LABELS, 'unknown measured scope')
        subset = []
        for key in summary['transactions']:
            require(key in index and key not in used, 'missing/duplicate scoped transaction')
            r = index[key]
            require(r['label'] in LABEL_SCOPE and LABEL_SCOPE[r['label']] == scope, 'misclassified transaction')
            require(type(r['calldataBytes']) is int and r['calldataBytes'] >= 0
                    and int(r['gasUsed']) >= 0 and r.get('status', 1) == 1, 'invalid measured receipt')
            subset.append(r)
            used.add(key)
        require(totals(subset) == {k: int(summary[k]) for k in totals(subset)}, 'scope cost mismatch')
        selected.extend(subset)
    require(totals(selected) == {k: int(reported[k]) for k in totals(selected)}, 'case cost mismatch')
    return selected


def describe(values):
    require(values and all(isinstance(v, (int, float)) and math.isfinite(v) for v in values), 'invalid observations')
    return {'observations': len(values), 'mean': st.mean(values),
            'sampleSd': st.stdev(values) if len(values) > 1 else None, 'minimum': min(values), 'maximum': max(values)}




def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--composite', type=Path, required=True)
    parser.add_argument('--preview', action='store_true', help='derive preliminary values without recording diagnostic approval')
    args = parser.parse_args()
    base = args.composite.resolve()
    require(base.parent == MODULE / 'composites', 'invalid composite directory')
    provenance = read(base / 'provenance.json')
    require(provenance['validation'] == 'passed' and provenance['analysisComplete'] is False, 'unvalidated composite')
    single = provenance.get('kind') == 'single-complete-run'
    if single:
        from single_run import load
        from review import validate as validate_review
        if not args.preview: validate_review(base)
        _, original, run_sealed = load(base)
        segment = None
        sealed = lambda run, rel: run_sealed(rel)
        runs = [original]
    else:
        original, segment = Path(provenance['originalRun']), Path(provenance['continuationRun'])
        require(sha(segment / 'original-preservation.json') == provenance['originalPreservationSha256']
                and sha(segment / 'segment-seal.json') == provenance['segmentSealSha256'], 'changed evidence anchors')
        inventories = {original: read(segment / 'original-preservation.json')['files'],
                       segment: read(segment / 'segment-seal.json')['files']}
        def sealed(run, rel):
            require(sha(run / rel) == inventories[run][rel], 'changed measured report: ' + rel)
            return read(run / rel)
        runs = [original, segment]
    paired = sealed(original, 'reports/paired.json')
    reports = {run: sealed(run, 'reports/application.json') for run in runs}
    sys.path.insert(0, str(MODULE/'campaign'))
    from comparative_evidence import validate_report as validate_comparative_report, numeric_rows as comparative_numeric_rows, REPORT as COMPARATIVE_REPORT
    comparisons = {}
    availability = {}
    from availability_evidence import validate as validate_availability, REPORT as AVAILABILITY_REPORT
    from scheduling_evidence import validate as validate_scheduling
    scheduling = set()
    for run in runs:
        cfg = sealed(run, 'config/campaign.json')
        schedule = validate_scheduling(cfg, reports[run])
        if any(c['half'] == 'nonlinear' for c in reports[run]['cases']):
            scheduling.add(schedule)
        comparison = validate_comparative_report(run)
        if comparison is not None:
            require(sealed(run, COMPARATIVE_REPORT) == comparison, 'comparison evidence differs from its seal')
            comparisons[run] = comparison
        control = validate_availability(run)
        if control is not None:
            require(sealed(run, AVAILABILITY_REPORT)==control, 'availability controls differ from their seal')
            availability[run] = control
    protocols = {r.get('config', {}).get('nonlinearProtocol','canonical') for r in reports.values()}
    require(len(protocols) == 1, 'cannot combine different nonlinear settlement protocols')
    require(len(scheduling) <= 1, 'cannot combine different nonlinear scheduling profiles')
    schedule_version = next(iter(scheduling), None)
    if not args.preview:
        review = read(evidence_path(base))
        require(review['provenanceSha256'] == sha(base / 'provenance.json')
                and review['summarySha256'] == sha(base / 'diagnostics/summary.json')
                and review['excludedMeasuredObservations'] == 0, 'diagnostic review binding failed')
    output = base / ('workflow-preview' if args.preview else 'workflow')
    require(not output.exists(), 'retain existing derived workflow artifacts')
    rows, receipt_rows, orphans, economic_rows = [], [], [], []
    def add(case, cohort, step, metric, unit, value, source):
        require(isinstance(value, (int, float)) and math.isfinite(value), 'invalid timer/value: ' + metric)
        rows.append({'case': case['name'], 'group': case['group'], 'half': case['half'], 'n': case['n'],
                     'cohort': cohort, 'step': step, 'metric': metric, 'unit': unit, 'value': value, 'source': source})
    for i, row in enumerate(paired['rows']):
        source = str(original / 'reports/paired.json') + f'#/rows/{i}'
        if row['warmup']:
            # Only the initial uncached basis construction is a setup observation.
            if row['name'] == 'linear-acr-10-warmup0':
                add(row, 'setup-once', 'setup', 'uncached_public_basis', 'ms', row['preparation']['generatorsMs'], source)
            continue
        add(row, 'paired', 'step1', 'owner_encrypt_prepare', 'ms', row['preparation']['ownerEncryptionMs'], source)
        add(row, 'paired', 'step2', 'operator_execution', 'ms', row['operatorMs'], source)
        add(row, 'paired', 'step1', 'shared_instrumented_preparation', 'ms', row['sharedPreparationMs'], source)
        for variant in ['proposed', 'baseline']:
            add(row, 'paired', 'step2', variant + '_verification', 'ms', row['observations'][variant]['ms'], source)
        add(row, 'paired', 'step2', 'baseline_minus_proposed', 'ms',
            row['observations']['baseline']['ms'] - row['observations']['proposed']['ms'], source)
        if row['half'] == 'linear':
            signatures = row['preparation']['ownerSignatures']
            require(len(signatures) == row['n'], 'missing owner preparation')
            for key, name in [('keygenMs', 'owner_signing_keys'), ('commitmentMs', 'owner_commitments'),
                              ('proposalSignMs', 'proposal_signatures'), ('baselineSignMs', 'baseline_signatures')]:
                add(row, 'paired', 'step1', name, 'ms', sum(s[key] for s in signatures), source)
    for run, app in reports.items():
        if run in comparisons:
            comparison_indices = {c['case']: i for i, c in enumerate(comparisons[run]['cases'])}
            for measured in comparative_numeric_rows(comparisons[run]):
                case = {**measured, 'name': measured['case']}
                add(case, 'full', 'comparison', measured['metric'], measured['unit'], measured['value'],
                    str(run / COMPARATIVE_REPORT) + '#/cases/' + str(comparison_indices[measured['case']]))
        index, used = receipt_index(app['receipts']), set()
        for i, case in enumerate(app['cases']):
            source = str(run / 'reports/application.json') + f'#/cases/{i}'
            cohorts = [('honest', case)]
            if case['half'] == 'nonlinear':
                cohorts.append(('challenged', case['metrics']['disputeCosts']))
            for cohort, costs in cohorts:
                selected = select_receipts(costs['receiptScopes'], costs, index, used)
                boundaries = collections.defaultdict(list)
                for r in selected:
                    boundary = LABEL_BOUNDARY[r['label']]
                    boundaries[boundary].append(r)
                    receipt_rows.append({'case': case['name'], 'group': case['group'], 'cohort': cohort,
                                         'boundary': boundary, 'label': r['label'], 'txHash': txid(r),
                                         'gasUsed': int(r['gasUsed']), 'calldataBytes': r['calldataBytes'],
                                         'effectiveGasPriceWei':r.get('effectiveGasPriceWei'),
                                         'transactionFeeWei':r.get('transactionFeeWei'), 'valueWei':r.get('valueWei'),
                                         'sender':r.get('from'), 'recipient':r.get('to'),
                                         'block': r.get('block', r.get('blockNumber')), 'source': source})
                for boundary in (BOUNDARIES if single else LEGACY_BOUNDARIES):
                    for metric, unit in [('transactionCount', 'tx'), ('gasUsed', 'gas'), ('calldataBytes', 'bytes')]:
                        # Zero here means exactly no receipt in this exhaustive
                        # transaction partition, never an unmeasured timer.
                        add(case, 'full-' + cohort, boundary, metric, unit, totals(boundaries[boundary])[metric], source)
                    if app.get('receiptMetricsVersion')=='mined-fee-v1':
                        fee=0
                        for r in boundaries[boundary]:
                            require(int(r['transactionFeeWei']) == int(r['gasUsed'])*int(r['effectiveGasPriceWei'])
                                    and int(r['effectiveGasPriceWei'])>=0, 'receipt gas fee mismatch')
                            fee+=int(r['transactionFeeWei'])
                        add(case,'full-'+cohort,boundary,'transactionFeeWei','wei',fee,source)
            m = case['metrics']
            add(case, 'full', 'step1', 'owner_encrypt_prepare', 'ms', case['ownerPreparationMs'], source)
            if case['half'] == 'linear':
                # V3 has no gateway: the untrusted relayer independently repeats
                # the public conversion before any release request.
                independent = 'relayerVerificationMs' if single else 'gatewayConversionMs'
                for step, key in [('step1', 'ownerAdmissionMs'), ('step2', 'aggregateMs'),
                                  ('step2', 'fullReaggregationMs'), ('step3', 'publicConversionMs'),
                                  ('step3', independent)]:
                    add(case, 'full', step, key, 'ms', m[key], source)
                add(case, 'full', 'step3', 'delivered_field_vector', 'bytes', m['aggregateBytes'], source)
            else:
                for step, key in [('step1', 'operatorMs'), ('step2', 'auditMs'), ('step2', 'finalizationMs'),
                                  ('step3-4', 'disputeWorkflowMs')]:
                    add(case, 'full', step, key, 'ms', m[key], source)
                add(case, 'full', 'step1', 'padded_leaves', 'leaves', m['leaves'], source)
                add(case, 'full', 'step2', 'certified_baseline_wall', 'ms', m['baseline']['fullReplayWallMs'], source)
                if schedule_version:
                    observed = m['scheduling']
                    add(case, 'full', 'scheduling', 'baseline_during_finalization', 'ms', observed['elapsedMs'], source)
                    for phase in ('commit', 'open'):
                        add(case, 'full', 'scheduling', 'audit_'+phase+'_margin', 's',
                            observed[phase+'Deadline']-observed[phase+'Timestamp'], source)
                certs = m['baseline']['certificates']
                require(len(certs) == 2 and all(c['plaintextOpenings'] == 0 for c in certs), 'invalid baseline evidence')
                add(case, 'full', 'step2', 'baseline_inner_replay_sum', 'ms', sum(c['evidence']['replayMs'] for c in certs), source)
                dispute = m['disputes'][0]
                add(case, 'full', 'step3-4', 'discovery_and_dispute', 'ms', dispute['seconds'] * 1000, source)
                certs = dispute['settlement']['certificates']
                require(len(certs) == 2 and all(c['plaintextOpenings'] == 0 for c in certs), 'invalid leaf evidence')
                add(case, 'full', 'step4', 'leaf_inner_evaluation_sum', 'ms', sum(c['evidence']['elapsedMs'] for c in certs), source)
                if m.get('nonlinearProtocol') == 'bounty-v2':
                    sys.path.insert(0, str(MODULE/'campaign'))
                    from bounty_evidence import economic_observation
                    economic = economic_observation(case,app['receipts'])
                    measured = sealed(run,'reports/bounty-economics.json')
                    expected = {'case':case['name'], 'group':case.get('group'), **economic}
                    require([r for r in measured['cases'] if r['case']==case['name']] == [expected],
                            'sealed economic observations differ from receipts')
                    economic_rows.append(expected)
                    for key in ['disclosureFeeWei','rewardWei','penaltyWei','burnedWei','withdrawalWei',
                                'disputeGasFeeWei','rewardAfterDisclosureAndGasWei',
                                'coalitionLossAfterDisclosureWei','declaredOtherCostBudgetWei']:
                        add(case,'full-challenged','economics',key,'wei',int(economic[key]),source)
        for key, receipt in index.items():
            if key not in used:
                orphans.append({'run': str(run), 'txHash': key, 'label': receipt['label'],
                                'classification': 'uncompleted-attempt-diagnostic-only'})
        if run == segment or single:
            require(not [r for r in orphans if r['run'] == str(run)], 'unaccounted receipt in a completed run')
    groups = collections.defaultdict(list)
    for row in rows:
        groups[tuple(row[k] for k in ['group', 'half', 'n', 'cohort', 'step', 'metric', 'unit'])].append(row['value'])
    summary = []
    for key, values in groups.items():
        item = dict(zip(['group', 'half', 'n', 'cohort', 'step', 'metric', 'unit'], key)) | describe(values)
        count = 1 if item['cohort'] == 'setup-once' else (100 if item['half'] == 'linear' else 30) if item['cohort'] == 'paired' else 5
        require(item['observations'] == count, 'wrong per-row observation count')
        summary.append(item)
    require(len({r['txHash'] for r in receipt_rows}) == len(receipt_rows), 'cross-case receipt reuse')
    output.mkdir()
    if availability:
        require(len(availability)==1, 'availability controls require one source run')
        control = next(iter(availability.values()))
        (output/'committee-availability.json').write_text(json.dumps(control,indent=2)+'\n')
    if economic_rows:
        (output/'economics.json').write_text(json.dumps(economic_rows,indent=2)+'\n')
    for name, data in [('observations.csv', rows), ('receipt-partition.csv', receipt_rows)]:
        with (output / name).open('x') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(data[0]))
            writer.writeheader()
            writer.writerows(data)
    report = {'profile': 'test-poc-workflow-stages-v1', 'analysisComplete': False,
              **({'distributedExecution':provenance['distributedExecution']} if provenance.get('distributedExecution') is not None else {}),
              'preliminary': args.preview,
              'committeeAvailabilityReports':len(availability),
              'comparativeMetricsVersion': 'comparative-metrics-v1' if comparisons else None,
              'comparativeScope': 'Serialized-byte accounting and role process measurements. Hypothetical SUM encoding is not deployed transport. CPU and summed worker elapsed time are not workflow wall time.' if comparisons else None,
              'nonlinearProtocol': next(iter(protocols)),
              'nonlinearSchedulingVersion': schedule_version,
              'provenanceSha256': sha(base / 'provenance.json'),
              'diagnosticReviewSha256': None if args.preview else sha(evidence_path(base)),
              'analysisValidationFile': None if args.preview else evidence_path(base).name,
              'diagnosticSummarySha256': sha(base / 'diagnostics/summary.json'),
              'scriptSha256': sha(Path(__file__)), 'metrics': summary, 'receiptCount': len(receipt_rows),
              'uncompletedAttemptReceipts': orphans,
              'overlapWarnings': ['Do not sum shared preparation with its owner-signature components.',
                                  'Full ownerAdmissionMs includes cryptography/RPC/chain waiting.',
                                  'Paired operator is vector aggregation; full aggregateMs includes commitment/digest.',
                                  'FinalizationMs includes protocol windows; not compute latency.',
                                  'discovery_and_dispute is nested in disputeWorkflowMs; neither separates discovery.',
                                  'Inner replay/leaf certificate timings exclude outer process/context/chain work.',
                                  ('All full-case values are descriptive, across the measured four hosts with one keyset'
                                   if provenance.get('distributedExecution') else 'All full-case values are descriptive, on one host/keyset') +
                                  ('.' if single else ' and across the interruption.')],
              'notSeparatelyMeasured': ['Consumer digest/commitment check', 'Isolated constant-cost linear result equality',
                                       'Nonlinear owner-policy/context construction', 'Discovery versus remaining dispute time'],
              'excludedFromEvaluation': ['KMS/decryption performance', 'endToEndMs', 'releaseMs',
                                      'Aborted-attempt costs', 'Full workflow total containing baseline/diagnostics'],
              'pending': ['CSV and Markdown formatting', 'diagnostic review', 'analysis validation']}
    if schedule_version:
        report['overlapWarnings'].append(
            'FinalizationMs includes the separately measured baseline after audit opening. '
            'Do not add these overlapping intervals or treat the finality interval as isolated proposed latency.')
    (output / 'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    (output / 'hashes.json').write_text(json.dumps({p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file()}, indent=2)+'\n')
    print(json.dumps({'metrics': len(summary), 'observations': len(rows), 'classifiedReceipts': len(receipt_rows),
                      'uncompletedAttemptReceipts': len(orphans), 'output': str(output)}, indent=2))


if __name__ == '__main__':
    main()
