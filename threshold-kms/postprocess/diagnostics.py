#!/usr/bin/env python3
"""Derived paired diagnostics only; no run mutation, collection or publication."""
import argparse
import collections
import csv
import json
from pathlib import Path
import statistics as st
import sys

sys.dont_write_bytecode = True
from verify_composite import read, require, sha, MODULE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--composite', type=Path, required=True)
    args = parser.parse_args()
    base = args.composite.resolve()
    require(base.parent == MODULE / 'composites', 'not a composite directory')
    provenance = read(base / 'provenance.json')
    require(provenance['validation'] == 'passed' and provenance['analysisComplete'] is False,
            'unvalidated or misclassified provenance')
    if provenance.get('kind') == 'single-complete-run':
        from single_run import load
        _, original, sealed = load(base)
        for rel in ['reports/paired.json', 'config/campaign.json']:
            sealed(rel)
    else:
        original, segment = Path(provenance['originalRun']), Path(provenance['continuationRun'])
        require(sha(segment / 'original-preservation.json') == provenance['originalPreservationSha256']
                and sha(segment / 'segment-seal.json') == provenance['segmentSealSha256'], 'changed evidence anchors')
        inventory = read(segment / 'original-preservation.json')['files']
        for rel in ['reports/paired.json', 'config/campaign.json']:
            require(sha(original / rel) == inventory[rel], 'changed paired input')
    source = read(original / 'state.json')['source']
    cache = Path(provenance['sourceCache']) / 'app'
    for rel in ['threshold-kms/campaign/poc_evidence.py', 'threshold-kms/campaign/poc_plan.py']:
        require(sha(cache / rel) == source[rel], 'changed statistical method')
    sys.path.insert(0, str(cache / 'threshold-kms/campaign'))
    import poc_evidence
    paired = read(original / 'reports/paired.json')
    poc_evidence.validate_pairs(read(original / 'config/campaign.json'), paired)
    output = base / 'diagnostics'
    require(not output.exists(), 'diagnostics already exist; retain them')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    output.mkdir()
    groups = collections.defaultdict(list)
    rows = []
    for row in paired['rows']:
        if not row['warmup']:
            groups[row['group']].append(row)
        rows.append({k: row[k] for k in ['name', 'group', 'half', 'n', 'repeat', 'warmup', 'fullCase',
                                       'ordinal', 'fixtureDigest', 'scope', 'wallStarted', 'wallFinished']} |
                    {'order': '/'.join(row['order']), 'proposed_ms': row['observations']['proposed']['ms'],
                     'baseline_ms': row['observations']['baseline']['ms'], 'operator_ms': row['operatorMs'],
                     'shared_preparation_ms': row['sharedPreparationMs']})
    with (output / 'paired-observations.csv').open('x') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    summaries = []
    for name, values in groups.items():
        summary = poc_evidence.paired_summary(values)
        p = [r['observations']['proposed']['ms'] for r in values]
        b = [r['observations']['baseline']['ms'] for r in values]
        d = [y - x for x, y in zip(p, b)]
        blocks = [st.mean(d[i:i+2]) for i in range(0, len(d), 2)]
        mean = st.mean(blocks)
        denom = sum((x-mean)**2 for x in blocks)
        acf = [sum((x-mean)*(y-mean) for x, y in zip(blocks, blocks[k:]))/denom if denom else 0
               for k in range(1, min(10, len(blocks)-1)+1)]
        q1, q3 = poc_evidence.quantile(d, .25), poc_evidence.quantile(d, .75)
        outliers = [i for i, x in enumerate(d) if x < q1-1.5*(q3-q1) or x > q3+1.5*(q3-q1)]
        summary.update(iqrFlaggedPairIndices=outliers, excludedPairs=0,
                       differenceMinMs=min(d), differenceMaxMs=max(d), blockAutocorrelations=acf,
                       descriptiveReductionPercent=100*(1-st.mean(p)/st.mean(b)),
                       normalityTest='No IID normality hypothesis test; Q-Q is descriptive only.',
                       visualReview='pending')
        summaries.append(summary)
        fig, axes = plt.subplots(2, 2, figsize=(11, 7), constrained_layout=True)
        ax = axes[0, 0]
        ax.plot(range(1, len(p)+1), p, label='Proposed', color='#0072B2')
        ax.plot(range(1, len(b)+1), b, label='Baseline', color='#D55E00', linestyle='--')
        ax.set(xlabel='Measured pair (execution order)', ylabel='Component time (ms)')
        ax.legend()
        ax = axes[0, 1]
        ax.plot(range(1, len(d)+1), d, '.-', color='#0072B2', alpha=.65, label='Pair difference')
        ax.plot([i*2+1.5 for i in range(len(blocks))], blocks, color='#D55E00', label='Two-pair mean')
        ax.axhline(st.mean(d), color='black', linestyle=':', label='Overall mean')
        ax.set(xlabel='Measured pair (execution order)', ylabel='Baseline minus proposed (ms)')
        ax.legend(fontsize=8)
        ax = axes[1, 0]
        theoretical = [st.NormalDist().inv_cdf((i+.625)/(len(d)+.25)) for i in range(len(d))]
        ax.scatter(theoretical, sorted(d), s=13, color='#0072B2')
        ax.plot(theoretical, [st.mean(d)+st.stdev(d)*x for x in theoretical], color='black', linestyle=':')
        ax.set(xlabel='Standard-normal theoretical quantile', ylabel='Ordered pair difference (ms)',
               title='Descriptive Q-Q; normality is not assumed')
        ax = axes[1, 1]
        ax.stem(range(1, len(acf)+1), acf)
        ax.axhline(0, color='black', linewidth=.7)
        ax.set(xlabel='Lag (two-pair means)', ylabel='Sample autocorrelation', ylim=(-1, 1))
        for ax in axes.flat:
            ax.grid(alpha=.2)
        fig.suptitle(name+' | Test INSECURE | all valid observations retained')
        fig.savefig(output / (name+'.png'), dpi=140)
        plt.close(fig)
    report = {'profile': 'test-poc-paired-diagnostics-v1', 'analysisComplete': False,
              'provenanceSha256': sha(base / 'provenance.json'), 'scriptSha256': sha(Path(__file__)),
              'matplotlibVersion': matplotlib.__version__, 'pythonVersion': sys.version,
              'measuredPairs': sum(len(v) for v in groups.values()), 'warmups': sum(r['warmup'] for r in paired['rows']),
              'groups': summaries, 'excludedPairs': 0,
              'scope': 'Fixed host/keyset/panel; pointwise conditional bootstrap, not population/secure-profile inference.',
              'reviewRequired': 'Inspect time series/Q-Q/ACF and qualify nonstationarity; do not change collection or discard valid outliers.'}
    (output / 'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    files = {p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file()}
    (output / 'diagnostic-hashes.json').write_text(json.dumps(files, indent=2)+'\n')
    print(json.dumps({'measuredPairs': report['measuredPairs'], 'groups': len(groups),
                      'flaggedGroups': [s['group'] for s in summaries if s['temporalReviewFlag']],
                      'output': str(output)}, indent=2))


if __name__ == '__main__':
    main()
