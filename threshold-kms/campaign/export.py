#!/usr/bin/env python3
"""Validate recipient results against the isolated owner oracle, then export."""
import csv
import json
from pathlib import Path
import statistics
import sys
from onchain_evidence import CAMPAIGN_VERSION, validate_run
from poc_evidence import validate_full_cases, export_poc
from policy_refresh import (validate_application as validate_policy_refresh,
                            write_evidence as write_policy_refresh_evidence)
from comparative_evidence import build_report as comparative_report, REPORT as COMPARATIVE_REPORT
from availability_evidence import validate as validate_availability
from scheduling_evidence import validate as validate_scheduling

def export(run):
    validate_availability(run)
    cfg=json.loads((run/'config/campaign.json').read_text())
    if cfg.get('readinessDisputesOnly'):
        from dispute_readiness import validate
        validate(run, write=True)
        print('Dispute-only Test readiness verified with zero output releases. No evaluation results were generated.')
        return
    app=json.loads((run/'reports/application.json').read_text())
    scheduling_version=validate_scheduling(cfg,app)
    expected=json.loads((run/'owner/expected.json').read_text())
    keys=json.loads((run/'keyset/ready.json').read_text())
    reuse=cfg.get('keysetReuse')
    if reuse:
        try:record=json.loads((run/'config/keyset-reuse.json').read_text())
        except (OSError,json.JSONDecodeError) as error:raise ValueError('missing sealed keyset-reuse record') from error
        if record!=reuse or not isinstance(reuse.get('baseManifestSha256'),str):
            raise ValueError('keyset-reuse record differs from campaign configuration')
    onchain=validate_run(run) if cfg.get('version') == CAMPAIGN_VERSION else None
    if cfg.get('nonlinearProtocol') == 'bounty-v2':
        from bounty_evidence import economic_observation
        economics = {'profile':'bounty-economics-observations-v1', 'analysisComplete':False,
                     'configuration':cfg['bountyEconomics'],
                     'cases':[{'case':c['name'], 'group':c.get('group'),
                               **economic_observation(c,app['receipts'])}
                              for c in app['cases'] if c['half']=='nonlinear']}
        (run/'reports/bounty-economics.json').write_text(json.dumps(economics,indent=2)+'\n')
    if app['status']!='passed' or keys['status']!='passed' or not keys['fullPreprocessing'] or keys['preloadedFheKey']:
        raise ValueError('incomplete real-threshold pipeline')
    if keys['parameters']!=cfg['parameters'] or (not cfg['smoke'] and cfg['parameters']!='Default'
            and not (cfg.get('pocPlan') or cfg.get('policyRefreshPlan'))):raise ValueError('parameter downgrade or unpublishable profile')
    if app['chain']['consensus']!='QBFT' or len(app['chain']['validators'])!=4 or app['chain']['advancedBlock']<=app['chain']['observedBlock']:raise ValueError('missing live QBFT consensus evidence')
    workloads=cfg.get('nonlinearWorkloads',['regulatory','regional'])
    if not workloads or len(set(workloads))!=len(workloads) or not set(workloads)<= {'regulatory','regional'}:
        raise ValueError('invalid nonlinear selection')
    if len(workloads)!=2 and not (cfg.get('readinessOnly') and cfg['smoke'] and cfg['parameters']=='Test'):
        raise ValueError('partial workload selection is readiness-only')
    poc_design=validate_full_cases(cfg,app,json.loads((run/'reports/paired.json').read_text())) if cfg.get('pocPlan') else None
    refresh_design=validate_policy_refresh(cfg,app,onchain) if cfg.get('policyRefreshPlan') else None
    design=poc_design or refresh_design
    wanted=design['fullCases'] if design else (0 if cfg['half']=='nonlinear' else len(cfg['linearSizes'])*cfg['repeats'])+(0 if cfg['half']=='linear' else len(workloads)*cfg['repeats'])
    actual_nonlinear={c['name'] for c in app['cases'] if c['half']=='nonlinear'}
    expected_nonlinear={j['name'] for j in design['jobs'] if j['half']=='nonlinear' and j['fullCase']} if design else (set() if cfg['half']=='linear' else {f'{w}_qoe_compliance-{i}' for w in workloads for i in range(cfg['repeats'])})
    if actual_nonlinear!=expected_nonlinear:raise ValueError('wrong nonlinear workload coverage')
    if len(app['cases'])!=wanted or app['kmsCalls']!=wanted:raise ValueError('missing workload or output')
    rows=[]
    for i,case in enumerate(app['cases']):
        result=json.loads((run/f'recipient/result-{i}.json').read_text())
        if result['name']!=case['name'] or result['actual']!=expected[case['name']] or result['outputDigest']!=case['outputDigest']:
            raise ValueError('recipient correctness/output binding failure')
        if result['responses']!=3 or result['directUserAndPublicDenied']!=4 or result['negativeResponseChecks']!=4 or result['directAdministrativeDenied']!=28 or result['changedReservedWireDenied']!=4:raise ValueError('missing threshold/ingress validation')
        if case['half']=='nonlinear' and len(case['metrics']['disputes'])!=1:raise ValueError('missing real-FHE dispute')
        if not case['dataset']:raise ValueError('missing dataset provenance')
        rows.append({'case':case['name'],'half':case['half'],'dataset':case['dataset']['id'],'records':case['n'],
            'repeat':case['repeat'],'parameters':cfg['parameters'],'chain_id':cfg['chainId'],
            'owner_preparation_ms':case['ownerPreparationMs'],'release_ms':case['releaseMs'],
            'workflow_ms':case['endToEndMs'],'kms_ms':result['kmsSeconds']*1000,
            'recipient_ms':result['recipientSeconds']*1000,'request_json_bytes':result['requestBytes'],
            'submit_ms':result['submitSeconds']*1000,'poll_count':result['polls'],
            'gas_used':case['gasUsed'],'transaction_count':case['transactionCount'],'calldata_bytes':case['calldataBytes'],
            'response_json_bytes':result['responseBytes'],'threshold_responses':result['responses'],
            'operator_fhe_ms':case['metrics'].get('operatorMs'),
            'audit_ms':case['metrics'].get('auditMs'),
            'finalization_ms':case['metrics'].get('finalizationMs'),
            'baseline_ms':case['metrics'].get('fullReaggregationMs',case['metrics'].get('baseline',{}).get('fullReplayWallMs')),
            'aggregate_ms':case['metrics'].get('aggregateMs'),
            'public_conversion_ms':case['metrics'].get('publicConversionMs'),
            'relayer_verification_ms':case['metrics'].get('relayerVerificationMs'),
            'owner_admission_ms':case['metrics'].get('ownerAdmissionMs'),
            'dispute_workflow_ms':case['metrics'].get('disputeWorkflowMs'),
            'dispute_gas_used':case['metrics'].get('disputeCosts',{}).get('gasUsed'),
            'dispute_transaction_count':case['metrics'].get('disputeCosts',{}).get('transactionCount'),
            'dispute_calldata_bytes':case['metrics'].get('disputeCosts',{}).get('calldataBytes'),
            'correct':True,'output_digest':result['outputDigest']})
        if scheduling_version:
            scheduling=case['metrics'].get('scheduling',{})
            rows[-1].update({
                'nonlinear_scheduling_version':scheduling.get('version'),
                'baseline_during_finalization_ms':scheduling.get('elapsedMs'),
                'audit_commit_margin_s':scheduling['commitDeadline']-scheduling['commitTimestamp'] if scheduling else None,
                'audit_open_margin_s':scheduling['openDeadline']-scheduling['openTimestamp'] if scheduling else None})
    comparison = comparative_report(cfg, app, run)
    if comparison is not None:
        (run / COMPARATIVE_REPORT).write_text(json.dumps(comparison,indent=2)+'\n')
    report={'classification':cfg.get('classification','smoke-not-evaluation' if cfg['smoke'] else 'dataset-real-threshold-besu'),
            'parameters':cfg['parameters'],'setup':keys,'rows':rows,
            'limitations':['single Docker host; no independent administrative security claim',
                           'Default completion is functional/performance evidence, not a cryptographic proof',
                           'three repetitions are descriptive, not a p95 estimate'],
            'timingScope':{'workflow_ms':'case orchestration through recipient response; excludes prior owner encryption/setup and later adversarial test',
                           'release_ms':'recipient request construction, owner verification, on-chain reservation, KMS processing and recipient reconstruction'},
            'sizeScope':'request_json_bytes and response_json_bytes are JSON adapter representations, not protobuf/gRPC/TLS traffic'}
    if scheduling_version:
        report['nonlinearSchedulingVersion']=scheduling_version
        report['timingScope']['finalization_ms']=(
            'audit commitment through finality and bond return, including the complete baseline after audit opening. '
            'Do not add baseline_ms to this overlapping interval or treat it as isolated proposed latency.')
    if reuse:
        report['keysetReuse']=reuse
        report['limitations'].append('this run restored a sealed local Default keyset base; PRSS, preprocessing, and DKG were not re-executed')
    if onchain:
        report['onChainReleaseEvidence']=onchain
        (run/'reports/onchain-release-evidence.json').write_text(json.dumps(onchain,indent=2,sort_keys=True)+'\n')
    if poc_design:report['limitations']=['insecure Test functional PoC; no confidentiality/secure-performance claim',
        'one host/keyset; off-chain repeated encryption is not independent population sampling',
        'five full cases per configuration are descriptive, not tail or failure-rate estimates']
    elif refresh_design:report['limitations']=[
        'insecure Test functional evidence on one host; no confidentiality, secure-performance or independent-administration claim',
        'standalone V3 full-case refresh; no identity claim about the legacy source closure, keyset or ciphertext fixtures',
        'paired comparison measurements were neither executed nor imported',
        'five full cases per configuration are descriptive, not tail or failure-rate estimates']
    (run/'reports/results.json').write_text(json.dumps(report,indent=2))
    with (run/'reports/results.csv').open('w') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    if poc_design:
        export_poc(run,cfg,app)
        print('Complete Test pair/full-case coverage verified; component fragment excludes KMS/release performance. Publication still requires diagnostic/implementation review.')
        return
    if refresh_design:
        write_policy_refresh_evidence(run,cfg,app,onchain)
        (run/'reports/POLICY-REFRESH-V3-NOT-PUBLISHED.txt').write_text(
            'Standalone complete V3 full-case evidence. No paired measurements were executed or imported.\n'
            'This run is not composed with the legacy campaign and is not analysis-complete.\n'
            'KMS and decryption timings remain raw diagnostics and are excluded from evaluation output.\n')
        print('Complete standalone V3 full-case coverage verified with validate_run; no paired measurements or evaluation fragment were produced.')
        return
    if cfg.get('readinessOnly'):
        # Retain every raw diagnostic; keep decryption diagnostics separate.
        (run/'reports/READINESS-ONLY.txt').write_text(
            'Insecure Test functional admission only. No comparative performance or confidentiality claim.\n'
            'Raw KMS/release diagnostics are retained, not exported to evaluation tables.\n')
        print('Test readiness outputs verified; raw CSV/JSON retained with separate diagnostic scope.')
        return
    print('Recipient outputs, dataset provenance and complete workflow verified; CSV/JSON exported.')

if __name__=='__main__':export(Path(sys.argv[1]).resolve())
