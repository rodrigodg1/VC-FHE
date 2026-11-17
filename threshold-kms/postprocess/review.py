"""Separate automated numerical validation from an optional human plot review."""
import csv
import json
import math
from pathlib import Path
import statistics
from verify_composite import read, require, sha, verify_files

AUTO_NAME = 'analysis-validation.json'


def evidence_path(base):
    manual = base/'diagnostic-review.json'
    return manual if manual.exists() else base/AUTO_NAME


def automated_record(base):
    """Validate retained observations without inventing a visual review."""
    provenance = read(base/'provenance.json')
    summary = read(base/'diagnostics/summary.json')
    manifest = read(base/'diagnostics/diagnostic-hashes.json')
    verify_files(base/'diagnostics', manifest)
    require(summary['provenanceSha256'] == sha(base/'provenance.json')
            and summary['scriptSha256'] == sha(Path(__file__).with_name('diagnostics.py')),
            'diagnostic source or provenance changed')
    require(summary['measuredPairs'] == provenance['measuredPairs']
            and summary['warmups'] == provenance['warmups']
            and summary['excludedPairs'] == 0, 'diagnostic counts or exclusions differ')
    with (base/'diagnostics/paired-observations.csv').open() as stream:
        rows = list(csv.DictReader(stream))
    require(all(r['warmup'] in ('True', 'False') for r in rows), 'invalid warm-up marker')
    measured = [r for r in rows if r['warmup'] == 'False']
    require(len(measured) == provenance['measuredPairs']
            and len(rows)-len(measured) == provenance['warmups'], 'diagnostic observations incomplete')
    require(len({r['name'] for r in rows}) == len(rows), 'duplicate diagnostic observation')
    groups = summary['groups']
    require(len({g['group'] for g in groups}) == len(groups)
            and {g['group'] for g in groups} == {r['group'] for r in measured}, 'diagnostic group mismatch')
    require({p for p in manifest if p.endswith('.png')} == {g['group']+'.png' for g in groups},
            'diagnostic plot coverage mismatch')
    for group in groups:
        subset = [r for r in measured if r['group'] == group['group']]
        require(len(subset) == group['pairs'] and group['excludedPairs'] == 0,
                'diagnostic group count or exclusions differ')
        proposed = [float(r['proposed_ms']) for r in subset]
        baseline = [float(r['baseline_ms']) for r in subset]
        require(all(math.isfinite(v) and v >= 0 for v in proposed+baseline), 'invalid diagnostic timing')
        expected = {'proposedMeanMs': statistics.mean(proposed),
                    'baselineMeanMs': statistics.mean(baseline),
                    'pairedDifferenceMs': statistics.mean(b-p for p,b in zip(proposed,baseline))}
        require(all(math.isclose(group[k], value, rel_tol=1e-10, abs_tol=1e-8)
                    for k,value in expected.items()), 'diagnostic mean differs from observations')
        interval = group['conditional95IntervalMs']
        require(len(interval) == 2 and all(math.isfinite(v) for v in interval)
                and interval[0] <= interval[1], 'invalid conditional interval')
    return dict(schema='automatic-analysis-validation-v1',
                provenanceSha256=sha(base/'provenance.json'),
                summarySha256=sha(base/'diagnostics/summary.json'),
                diagnosticManifestSha256=sha(base/'diagnostics/diagnostic-hashes.json'),
                scriptSha256=sha(Path(__file__)), measuredPairs=summary['measuredPairs'],
                warmupsExcluded=summary['warmups'], excludedMeasuredObservations=0,
                temporalFlags=[g['group'] for g in groups if g['temporalReviewFlag']],
                iqrFlaggedPairs=sum(len(g['iqrFlaggedPairIndices']) for g in groups),
                visualReviewPerformed=False,
                scope='Automatic data validation and descriptive export. No claim of visual review, stationarity or production performance.')


def ensure_automated(base):
    report = automated_record(base)
    path = base/AUTO_NAME
    if path.exists():
        require(read(path) == report, 'stale automated analysis validation')
    else:
        path.write_text(json.dumps(report, indent=2)+'\n')
    return report


def template(base):
    summary = read(base/'diagnostics/summary.json')
    return dict(provenanceSha256=sha(base/'provenance.json'),
                summarySha256=sha(base/'diagnostics/summary.json'),
                diagnosticManifestSha256=sha(base/'diagnostics/diagnostic-hashes.json'),
                measuredPairs=summary['measuredPairs'], warmupsExcluded=summary['warmups'],
                excludedMeasuredObservations=0, plannedAnalysisPreserved=False,
                plotsVisuallyInspected=[], reviewer='', findings='')


def validate(base):
    if evidence_path(base).name == AUTO_NAME:
        expected = automated_record(base)
        require(read(base/AUTO_NAME) == expected, 'automatic analysis validation mismatch')
        return expected
    expected = template(base)
    actual = read(base/'diagnostic-review.json')
    manifest = read(base/'diagnostics/diagnostic-hashes.json')
    verify_files(base/'diagnostics',manifest)
    for key in ['provenanceSha256','summarySha256','diagnosticManifestSha256',
                'measuredPairs','warmupsExcluded','excludedMeasuredObservations']:
        require(actual.get(key)==expected[key], 'diagnostic review mismatch: '+key)
    require(actual.get('plannedAnalysisPreserved') is True, 'analysis plan not reviewed')
    plots = actual.get('plotsVisuallyInspected',[])
    require(len(plots)==len(set(plots)) and set(plots)=={p for p in manifest if p.endswith('.png')},
            'incomplete diagnostic plot review')
    require(bool(actual.get('reviewer','').strip()) and bool(actual.get('findings','').strip()),
            'missing reviewer or diagnostic findings')
    return actual
