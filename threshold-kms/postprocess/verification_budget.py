"""Case-wise verification CPU, honest-audit deadlines and paired-order checks.

This is presentation-only reanalysis of the retained geographic campaign.
Context is counted once in each alternative. The two correct-task alternatives
share the measured honest context. The faulty-task branch has its own context.
These are recorded worker CPU budgets, not elapsed or total protocol costs.
"""
import gzip
import hashlib
import json
import math
import statistics as st
from pathlib import Path

from verify_composite import require

GROUPS = [f'{w}-{n}' for w in ['regulatory_qoe_compliance', 'regional_qoe_compliance']
          for n in [16, 32, 50]]


def load_retained(metrics):
    """Verify the input files against both retained and collection inventories."""
    metrics = Path(metrics)
    manifest = json.loads((metrics/'manifest.json').read_text())['files']
    inputs = {}
    def checked(name):
        path = metrics/name
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        require(manifest.get(name) == digest, 'changed retained metric input: '+name)
        inputs[name] = digest
        return path
    coverage = json.loads(checked('retained-v1/coverage.json').read_text())
    rows = []
    for segment, count in [('c3', 10), ('c4', 17)]:
        name = 'workflows/'+segment+'.jsonl.gz'
        path = checked('retained-v1/'+name)
        expected = coverage['outputs'][name]
        require(inputs['retained-v1/'+name] == expected['sha256'] and
                path.stat().st_size == expected['bytes'], 'retained workflow binding mismatch')
        with gzip.open(path, 'rt') as stream:
            records = [json.loads(line) for line in stream]
        require(len(records) == expected['records'] == count and
                all(r['segment'] == segment and r['case'] == r['data']['name'] for r in records),
                'retained workflow segment mismatch')
        rows.extend(r['data'] for r in records)
    require(len({r['name'] for r in rows}) == 27, 'incomplete or repeated workflow cases')
    return rows, inputs


def cpu(workers, fhe_only=False):
    total = 0
    for worker in workers:
        require(worker['status'] == 'completed' and worker['exitCode'] == 0 and
                worker['executionScope'] == 'controller-only-remote-fhe-excluded',
                'worker scope does not permit disjoint CPU sums')
        processes = worker['publicWorkerResources']
        require(all(p['status'] == 'completed' and p['exitCode'] == 0 for p in processes),
                'incomplete FHE process')
        for process in ([worker] if not fhe_only else []) + processes:
            resources = process['resources']
            value = resources['totalCpuMs']
            require(resources['scope'] == 'command-and-waited-descendants' and
                    isinstance(value, (int, float)) and math.isfinite(value) and value >= 0,
                    'invalid measured process CPU')
            require(math.isclose(value, resources['userCpuMs']+resources['systemCpuMs'], abs_tol=1e-7),
                    'CPU components do not sum')
            total += value
    return total/1000


def derive(workflows, observations, pairs):
    lookup = {}
    for row in observations:
        key = (row['case'], row['cohort'], row['step'], row['metric'])
        require(key not in lookup, 'duplicate published observation')
        lookup[key] = float(row['value'])
    records, worker_ids, fhe_ids = [], set(), set()
    for row in workflows:
        if row['half'] != 'nonlinear':
            continue
        require(row['fullCase'] is True and row['warmup'] is False and row['group'] in GROUPS,
                'unexpected verification case')
        workers = row['metrics']['roleWork'] + row['metrics']['adjudicatorWork']
        require(len(workers) == 12, 'unexpected verification-worker inventory')
        for w in workers:
            require(w['measurementId'] not in worker_ids, 'reused worker CPU measurement')
            worker_ids.add(w['measurementId'])
            for p in w['publicWorkerResources']:
                require(p['requestId'] not in fhe_ids, 'reused FHE CPU measurement')
                fhe_ids.add(p['requestId'])
        def select(purpose, phase, count, native_count):
            selected = [w for w in workers if (w['purpose'], w['phase']) == (purpose, phase)]
            require(len(selected) == count and
                    sum(len(w['publicWorkerResources']) for w in selected) == native_count,
                    'incomplete verification workers: '+purpose+' '+phase)
            return selected
        ah = select('auditor-full-recomputation', 'honest', 1, 1)
        af = select('auditor-full-recomputation', 'challenged', 1, 1)
        ch = select('context-certification', 'honest', 2, 0)
        cf = select('context-certification', 'challenged', 2, 0)
        full = select('full-execution-certification', 'honest', 2, 2)
        leaf = select('leaf-result-certification', 'challenged', 2, 2)
        honest_ids = {w['taskId'] for w in ah+ch+full}
        faulty_ids = {w['taskId'] for w in af+cf+leaf}
        require(len(honest_ids) == len(faulty_ids) == 1 and honest_ids != faulty_ids,
                'verification task/phase mismatch')
        def match(value, metric):
            key = (row['name'], 'full', 'comparison', metric)
            require(key in lookup and math.isclose(value*1000, lookup[key], abs_tol=1e-6),
                    'CPU does not match published observation: '+metric)
        for ws, name in [(full, 'full'), (leaf, 'leaf'), (ch+cf, 'context')]:
            match(cpu(ws)-cpu(ws, True), 'adjudicator_'+name+'_complete_cpu_ms')
        for ws, name in [(full, 'honest_baseline'), (leaf, 'challenged_leaf'),
                         (ah, 'honest_auditor'), (af, 'challenged_auditor')]:
            match(cpu(ws, True), 'remote_fhe_'+name+'_complete_cpu_ms')
        scheduling = row['metrics']['scheduling']
        require(scheduling['version'] == 'audit-first-baseline-in-finality-wait-v1' and
                scheduling['baselinePlacement'] == 'after-audit-opening', 'unknown deadline scope')
        margin = scheduling['commitDeadline']-scheduling['commitTimestamp']
        require(isinstance(margin, int) and 0 <= margin <= 120, 'invalid honest commitment margin')
        records.append(dict(case=row['name'], group=row['group'], fault_position=row['faultPosition'],
            context_honest_s=cpu(ch), context_faulty_s=cpu(cf),
            audit_honest_s=cpu(ah), audit_faulty_s=cpu(af),
            leaf_checks_s=cpu(leaf)-cpu(leaf, True), leaf_fhe_s=cpu(leaf, True),
            full_checks_s=cpu(full)-cpu(full, True), full_fhe_s=cpu(full, True),
            honest_cpu_s=cpu(ch+ah), faulty_cpu_s=cpu(cf+af+leaf), baseline_cpu_s=cpu(ch+full),
            faulty_fhe_s=cpu(af+leaf, True), honest_commit_margin_s=margin))
    expected = {r['case'] for r in observations if r['group'] in GROUPS and r['cohort'] == 'full'}
    require(len(records) == 18 and {r['case'] for r in records} == expected, 'verification case grid mismatch')
    for group in GROUPS:
        rows = [r for r in records if r['group'] == group]
        require(len(rows) == 3 and {r['fault_position'] for r in rows} == {'early', 'middle', 'terminal'},
                'incomplete preselected fault positions')
    order = []
    for group in GROUPS:
        measured = [p for p in pairs if p['group'] == group and str(p['warmup']).lower() == 'false']
        require(len(measured) == 30 and len({p['name'] for p in measured}) == 30,
                'incomplete paired comparison group')
        for sequence in ['baseline/proposed', 'proposed/baseline']:
            rows = [p for p in measured if p['order'] == sequence]
            require(len(rows) == 15, 'unbalanced method orders')
            p, b = [[float(r[key]) for r in rows] for key in ['proposed_ms', 'baseline_ms']]
            require(all(math.isfinite(v) and v > 0 for v in p+b), 'invalid paired duration')
            order.append(dict(group=group, order=sequence, n=15,
                proposed_mean_ms=st.mean(p), baseline_mean_ms=st.mean(b),
                reduction_pct=100*(1-st.mean(p)/st.mean(b))))
    return dict(cases=records, orders=order)


def summary(evidence, group, keys):
    """Sum each case before calculating SD, retaining component covariance."""
    values = [sum(r[k] for k in keys) for r in evidence['cases'] if r['group'] == group]
    require(len(values) == 3, 'incomplete CPU summary')
    return st.mean(values), st.stdev(values), len(values)


