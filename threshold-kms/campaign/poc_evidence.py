"""Complete-Test gate and dependency-aware, explicitly conditional summaries."""
import collections
import csv
import datetime
import hashlib
import json
import math
import random
import statistics as st
from poc_plan import (TEST_POC_DISCLOSURE_BATCH_SIZE, TEST_POC_WINDOW_SECONDS,
                      plan, validate_timing_window)


def require(value, message):
    if not value:
        raise ValueError(message)


def validate_pairs(cfg, paired):
    design = plan(cfg['half'])
    require(cfg.get('pocPlan') == design, 'changed or incomplete PoC design')
    require(cfg['parameters'] == 'Test' and not cfg['smoke'] and not cfg.get('readinessOnly')
            and cfg['classification'] == design['classification'], 'not the explicit complete Test profile')
    validate_timing_window(cfg['windowSeconds'], cfg['disclosureBatchSize'])
    require(cfg['windowSeconds'] == TEST_POC_WINDOW_SECONDS
            and cfg['disclosureBatchSize'] == TEST_POC_DISCLOSURE_BATCH_SIZE
            and cfg['selectionProfile'] == design['selectionProfile'], 'changed validated execution selection')
    require(paired['status'] == 'passed' and paired['profile'] == design['profile']
            and paired['designSha256'] == design['designSha256'], 'incomplete/mismatched paired evidence')
    require(len(paired['rows']) == len(design['jobs']), 'missing paired or warm-up rows')
    digests = set()
    previous_end = None
    for row, job in zip(paired['rows'], design['jobs'], strict=True):
        require(all(row.get(k) == v for k, v in job.items()), 'wrong pair order, selection or warm-up classification')
        digest = row['fixtureDigest']
        require(isinstance(digest, str) and len(digest) == 66 and digest.startswith('0x')
                and digest not in digests, 'missing or reused ciphertext fixture')
        digests.add(digest)
        expected_scope = ('admission-and-aggregate-verification-v1' if job['half'] == 'linear'
                          else 'one-vs-two-public-replays-component-v1')
        require(row['scope'] == expected_scope, 'wrong paired comparison scope')
        begin = datetime.datetime.fromisoformat(row['wallStarted'].replace('Z', '+00:00'))
        end = datetime.datetime.fromisoformat(row['wallFinished'].replace('Z', '+00:00'))
        require(begin <= end and (previous_end is None or begin >= previous_end), 'overlapping/reordered pairs')
        previous_end = end
        prior = begin
        for variant in job['order']:
            observation = row['observations'][variant]
            require(isinstance(observation['ms'], (int, float)) and math.isfinite(observation['ms'])
                    and observation['ms'] > 0, 'invalid paired time')
            a = datetime.datetime.fromisoformat(observation['startedAt'].replace('Z', '+00:00'))
            b = datetime.datetime.fromisoformat(observation['finishedAt'].replace('Z', '+00:00'))
            require(prior <= a <= b <= end, 'overlapping/reordered variants')
            prior = b
            evidence = observation['evidence']
            if job['half'] == 'linear':
                require(evidence['accepted'] and evidence['verifiedSignatures'] == job['n']
                        and evidence['plaintextOpenings'] == 0, 'failed linear paired verification')
            else:
                checks = evidence if variant == 'baseline' else [evidence]
                require(len(checks) == (2 if variant == 'baseline' else 1), 'missing public replay')
                for check in checks:
                    require(check['index'] is None and check['plaintextOpenings'] == 0
                            and check['operatorRoot'] == check['replayRoot']
                            and check['contextDigest'] == digest, 'failed/mismatched public replay')
        if job['half'] == 'nonlinear':
            root = row['observations']['proposed']['evidence']['operatorRoot']
            require(all(c['operatorRoot'] == root for c in row['observations']['baseline']['evidence']), 'unmatched baseline ciphertext trace')
    return design


def validate_full_cases(cfg, app, paired):
    design = validate_pairs(cfg, paired)
    wanted = [j for j in design['jobs'] if j['fullCase']]
    require(len(app['cases']) == len(wanted) and app['kmsCalls'] == len(wanted), 'incomplete full-case/release grid')
    for case, job in zip(app['cases'], wanted, strict=True):
        require(all(case.get(k) == v for k, v in job.items()), 'wrong preselected full case')
        require(case['finalOutputKmsCalls'] == 1, 'wrong case release count')
        scopes = case['receiptScopes']
        require(sum(v['transactionCount'] for v in scopes.values()) == case['transactionCount']
                and sum(int(v['gasUsed']) for v in scopes.values()) == int(case['gasUsed'])
                and sum(v['calldataBytes'] for v in scopes.values()) == case['calldataBytes'], 'cost scopes do not reconcile')
        if job['half'] == 'linear':
            require(case['metrics']['baselineProfile'] == 'ordinary-bls-canonical-vector-v1', 'obsolete BLS baseline')
        else:
            disputes = case['metrics']['disputes']
            require(len(disputes) == 1, 'missing full dispute')
            expected_leaves = ({16:128,32:256,50:512} if job['workload']=='regional_qoe_compliance' else {16:64,32:128,50:128})[job['n']]
            require(case['metrics']['leaves'] == expected_leaves, 'wrong dataset circuit size')
            terminal = case['metrics']['leaves'] - 1
            fault = {'early': 0, 'middle': terminal//2, 'terminal': terminal}[job['faultPosition']]
            d = disputes[0]
            require(d['faultIndex'] == fault and d['settlement']['index'] == fault
                    and d['settlement']['state'][:3] == [3, 2, True], 'fault coverage or settlement mismatch')
            require(len(d['settlement']['certificates']) == 2 and
                    all(c['plaintextOpenings'] == 0 for c in d['settlement']['certificates']), 'invalid leaf evidence')
    return design


def quantile(values, probability):
    values = sorted(values)
    pos = (len(values)-1)*probability
    lo = int(pos)
    return values[lo] + (pos-lo)*(values[min(lo+1, len(values)-1)]-values[lo])


def paired_summary(rows):
    # One observation is a paired timing difference, not a dataset participant.
    # Average adjacent counterbalanced pairs before moving-block resampling.
    p = [r['observations']['proposed']['ms'] for r in rows]
    b = [r['observations']['baseline']['ms'] for r in rows]
    require(len(p) in (30, 100), 'unexpected measured sample size')
    differences = [y-x for x,y in zip(p,b)]
    blocks = [st.mean(differences[i:i+2]) for i in range(0,len(p),2)]
    size = math.ceil(len(blocks)**(1/3))
    rng = random.Random('vcfhe-poc-block-ci-v1:'+rows[0]['group'])
    boot = []
    for _ in range(4000):
        sample = []
        while len(sample) < len(blocks):
            start = rng.randrange(len(blocks))
            sample.extend(blocks[(start+j)%len(blocks)] for j in range(size))
        boot.append(st.mean(sample[:len(blocks)]))
    avg = st.mean(blocks)
    denominator = sum((x-avg)**2 for x in blocks)
    acf = sum((a-avg)*(b-avg) for a,b in zip(blocks,blocks[1:]))/denominator if denominator else 0
    drift = st.mean(blocks[len(blocks)//2:])-st.mean(blocks[:len(blocks)//2])
    sd = st.stdev(blocks)
    return {'group': rows[0]['group'], 'half': rows[0]['half'], 'n': rows[0]['n'], 'pairs': len(p),
            'scope': rows[0]['scope'], 'proposedMeanMs': st.mean(p), 'baselineMeanMs': st.mean(b),
            'proposedMedianMs': st.median(p), 'baselineMedianMs': st.median(b),
            'proposedSdMs': st.stdev(p), 'baselineSdMs': st.stdev(b),
            'pairedDifferenceMs': st.mean(differences), 'pairedDifferenceSdMs': st.stdev(differences),
            'conditional95IntervalMs': [quantile(boot,.025),quantile(boot,.975)],
            'method': 'circular moving-block percentile bootstrap of two-pair counterbalanced means',
            'resamples': 4000, 'blockLengthInTwoPairMeans': size,
            'blockLag1Autocorrelation': acf, 'lateMinusEarlyBlockMeanMs': drift,
            'temporalReviewFlag': abs(acf)>.5 or (abs(drift)>.5*sd if sd else drift!=0),
            'requiresVisualDiagnosticReview': True,
            'limitations': 'Conditional on this host/keyset/panel and approximately stationary short-range dependence; pointwise, not simultaneous intervals; no secure performance inference.'}


def export_poc(run, cfg, app):
    paired = json.loads((run/'reports/paired.json').read_text())
    design = validate_full_cases(cfg, app, paired)
    groups = collections.defaultdict(list)
    observations = []
    for row in paired['rows']:
        if not row['warmup']:
            groups[row['group']].append(row)
        observations.append({k:row[k] for k in ['name','group','half','n','repeat','warmup','fullCase','ordinal','fixtureDigest','scope','wallStarted','wallFinished']} |
                            {'order': '/'.join(row['order']), 'proposed_ms': row['observations']['proposed']['ms'],
                             'baseline_ms': row['observations']['baseline']['ms'], 'operator_ms': row['operatorMs'],
                             'shared_preparation_ms': row['sharedPreparationMs']})
    summary = {'nonlinearProtocol':cfg.get('nonlinearProtocol','canonical'),
               'classification':design['classification'], 'designSha256':design['designSha256'],
               'measuredPairs':design['measuredPairs'],'fullCases':design['fullCases'],
               'groups':[paired_summary(rows) for rows in groups.values()], 'analysisComplete':False,
               'pending':'Review time-series/QQ diagnostics and implementation claims; complete opposite half if separate.'}
    (run/'reports/paired-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    with (run/'reports/paired-observations.csv').open('w') as f:
        w=csv.DictWriter(f,fieldnames=list(observations[0]));w.writeheader();w.writerows(observations)
    return summary
