"""Validate optional versioned comparison observations without changing protocols.

Legacy campaigns have no such observations. New campaigns must retain every
selected full case. Byte models are not network measurements, and process CPU
is not elapsed workflow time or evidence of independent administration.
"""
import collections
import datetime
import hashlib
import json
import math
from pathlib import Path
import re

VERSION = 'comparative-metrics-v1'
REPORT = 'reports/comparative-metrics.json'
PURPOSES = {'context-certification': 'context', 'full-execution-certification': 'full',
            'leaf-result-certification': 'leaf'}


def require(value, message):
    if not value:
        raise ValueError('comparative metrics: ' + message)


def number(value, name, *, integer=False):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0
            and (not integer or int(value) == value), 'invalid ' + name)
    return value


def close(actual, expected, name):
    require(type(actual) in (int, float) and math.isfinite(actual)
            and math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-9), 'inconsistent ' + name)


def linear_observation(case, run=None):
    m = case['metrics'].get('communication')
    require(isinstance(m, dict) and m.get('schema') == 'vcfhe-linear-communication-v1',
            'missing linear communication observations')
    n, width = case['n'], m.get('coordinateWidth')
    number(n, 'input count', integer=True)
    number(width, 'coordinate width', integer=True)
    require(1 <= n <= 33 and width > 0 and width % 8 == 0
            and m.get('inputCount') == n and m.get('dimension') == 9 * width,
            'linear shape differs from the case')
    op = m.get('operation')
    require(op in ('SUM', 'SUB') and (not case.get('plan') or case['plan']['op'] == op),
            'linear operation differs')
    require(m.get('evidenceClass') == 'serialized-byte-accounting-not-network-measurement'
            and m.get('networkTransferMeasured') is False
            and m.get('cryptographicOrFheValidationPerformed') is False, 'wrong linear evidence scope')
    observed, model = m['observed'], m['sizeModel']
    canonical, inputs = 9 * width * 32, n * width * 8
    require(observed['canonicalAggregateBytes'] == canonical
            and case['metrics']['aggregateBytes'] == canonical
            and re.fullmatch('[0-9a-f]{64}', observed['canonicalAggregateSha256']) is not None,
            'canonical aggregate size or digest differs')
    witness = observed.get('kmsInputWitnessSerializedBytes')
    require(witness is not None, 'missing actual all-input release witness size')
    number(witness, 'release witness size', integer=True)
    require(model.get('inputCoordinateBytes') == 8 and model.get('packedInputPayloadBytes') == inputs
            and model.get('baselineReconstructsAggregate') is True
            and model.get('canonicalAggregateEncoding') == '32-byte-big-endian-field-coordinates',
            'invalid compact-input baseline')

    def scenario(value, payload):
        require(value.get('proposedAggregatePayloadBytes') == payload
                and value.get('baselineInputPayloadBytes') == inputs
                and value.get('baselineAdditionalAggregatePayloadBytes') == 0
                and value.get('proposedMinusBaselineBytes') == payload - inputs,
                'inconsistent recipient payload scenario')
        close(value.get('proposedReductionFraction'), (inputs - payload) / inputs, 'payload reduction')

    scenario(m['coldInputCache'], canonical)
    warm = m['warmAuthenticatedInputAndAggregateCache']
    require(all(warm.get(k) == 0 for k in ('proposedAggregatePayloadBytes', 'baselineInputPayloadBytes',
                                          'baselineAdditionalAggregatePayloadBytes')),
            'warm cache must account for reuse by both alternatives')
    compact = m['compactSum']
    if op == 'SUM':
        compact_bytes = math.ceil(n / 4) * width * 9
        require(compact.get('available') is True
                and compact.get('status') == 'hypothetical-transport-not-used-by-protocol'
                and compact.get('coordinateBytes') == 9
                and compact.get('populatedGroups') == math.ceil(n / 4)
                and compact.get('encodedBytes') == compact_bytes
                and compact.get('roundTripCanonicalBytesEqual') is True,
                'invalid hypothetical SUM encoding evidence')
        scenario(compact['coldInputCache'], compact_bytes)
    else:
        require(compact.get('available') is False and bool(compact.get('reason')),
                'SUB cannot claim the SUM encoding')
    if run is not None:
        name = case['name']
        require(isinstance(name, str) and Path(name).name == name and name not in ('.', '..'), 'invalid case path')
        payload = (Path(run) / 'fixtures' / name / 'aggregate.bin').read_bytes()
        require(len(payload) == canonical and hashlib.sha256(payload).hexdigest() == observed['canonicalAggregateSha256'],
                'linear bytes differ from retained aggregate')
        digest = case.get('linearWitnessDigest')
        require(isinstance(digest, str) and re.fullmatch('0x[0-9a-fA-F]{64}', digest), 'missing release witness digest')
        require((Path(run) / 'release-evidence' / (digest[2:] + '.json')).stat().st_size == witness,
                'release witness size differs from retained bytes')
    return m


def adjudicator_observation(case):
    rows = case['metrics'].get('adjudicatorWork')
    require(isinstance(rows, list) and bool(rows), 'missing adjudicator worker observations')
    by_purpose, ids = {}, set()
    for row in rows:
        require(row.get('schema') == 'role-process-resources-v1' and row.get('role') == 'adjudicator'
                and row.get('purpose') in PURPOSES
                and row.get('executionScope') == 'controller-only-remote-fhe-excluded',
                'wrong worker measurement scope')
        identity = row.get('measurementId')
        require(isinstance(identity, str) and identity and identity not in ids, 'missing or reused worker identity')
        ids.add(identity)
        require(row.get('status') == 'completed' and row.get('exitCode') == 0 and row.get('signal') is None,
                'unsuccessful adjudicator worker in completed case')
        require(isinstance(row.get('taskId'), str) and re.fullmatch('0x[0-9a-fA-F]{64}', row['taskId']),
                'worker lacks task binding')
        elapsed = number(row.get('elapsedMs'), 'worker elapsed time')
        start = datetime.datetime.fromisoformat(row['startedAt'].replace('Z', '+00:00'))
        end = datetime.datetime.fromisoformat(row['finishedAt'].replace('Z', '+00:00'))
        require(start <= end, 'worker timestamps are reversed')
        resources = row['resources']
        require(resources.get('scope') == 'command-and-waited-descendants'
                and resources.get('maxRssScope') == 'process-high-water-not-simultaneous-tree-peak',
                'invalid process-resource scope')
        if row.get('nativeFheElapsedMs') is not None:
            number(row['nativeFheElapsedMs'], 'native FHE elapsed time')
        cpu = resources.get('totalCpuMs')
        if cpu is not None:
            number(cpu, 'total CPU time')
            close(cpu, number(resources.get('userCpuMs'), 'user CPU')
                  + number(resources.get('systemCpuMs'), 'system CPU'), 'CPU sum')
            require(resources.get('unavailableReason') is None, 'measured CPU has an unavailable reason')
        else:
            require(resources.get('userCpuMs') is None and resources.get('systemCpuMs') is None
                    and bool(resources.get('unavailableReason')), 'missing CPU silently represented')
        rss = resources.get('maxRssBytes')
        if rss is not None:
            number(rss, 'maximum worker RSS', integer=True)
        purpose = row['purpose']
        bucket = by_purpose.setdefault(purpose, {'workerInvocations': 0, 'completedWorkers': 0, 'failedWorkers': 0,
            'summedWorkerElapsedMs': 0, 'cpuMeasuredWorkers': 0, 'measuredCpuMs': None,
            'completeCpuMs': None, 'maxObservedWorkerRssBytes': None, 'nativeFheElapsedMs': None,
            'executionScopes': ['controller-only-remote-fhe-excluded']})
        bucket['workerInvocations'] += 1
        bucket['completedWorkers'] += 1
        bucket['summedWorkerElapsedMs'] += elapsed
        if cpu is not None:
            bucket['cpuMeasuredWorkers'] += 1
            bucket['measuredCpuMs'] = (bucket['measuredCpuMs'] or 0) + cpu
        if rss is not None:
            bucket['maxObservedWorkerRssBytes'] = max(bucket['maxObservedWorkerRssBytes'] or 0, rss)
    for bucket in by_purpose.values():
        if bucket['cpuMeasuredWorkers'] == bucket['workerInvocations']:
            bucket['completeCpuMs'] = bucket['measuredCpuMs']
    metrics = case['metrics']
    expected_full = len(metrics['baseline']['certificates'])
    expected_leaf = sum(len(d['settlement']['certificates']) for d in metrics['disputes'])
    require(expected_full == 2 and expected_leaf == 2 * len(metrics['disputes']), 'unexpected certified worker counts')
    expected = {'context-certification': 2 * (1 + len(metrics['disputes'])),
                'full-execution-certification': expected_full, 'leaf-result-certification': expected_leaf}
    require({p: b['completedWorkers'] for p, b in by_purpose.items()} == expected,
            'worker observations do not cover context, baseline and disputed certificates')
    contexts = collections.Counter(r['taskId'] for r in rows if r['purpose'] == 'context-certification')
    full_tasks = collections.Counter(r['taskId'] for r in rows if r['purpose'] == 'full-execution-certification')
    leaf_tasks = collections.Counter(r['taskId'] for r in rows if r['purpose'] == 'leaf-result-certification')
    require(len(contexts) == 1 + len(metrics['disputes']) and all(n == 2 for n in contexts.values())
            and len(full_tasks) == 1 and all(n == 2 for n in full_tasks.values())
            and len(leaf_tasks) == len(metrics['disputes']) and all(n == 2 for n in leaf_tasks.values())
            and not (full_tasks.keys() & leaf_tasks.keys())
            and contexts.keys() == full_tasks.keys() | leaf_tasks.keys(), 'worker task coverage differs')
    summary = {'schema': 'role-process-resources-v1', 'recordedWorkers': len(rows), 'byPurpose': by_purpose,
        'completedContextWorkers': expected['context-certification'],
        'completedFullExecutionWorkers': expected_full, 'completedLeafResultWorkers': expected_leaf,
        'scope': 'recorded-workers-only', 'independentAdministrationEstablished': False,
        'executionScopes': ['controller-only-remote-fhe-excluded'], 'fheCpuMs': None,
        'fullProtocolCpuMs': None, 'simultaneousTreePeakRssBytes': None}
    supplied = metrics.get('adjudicatorWorkSummary')
    if supplied is not None:
        require(supplied == summary, 'worker summary differs from raw observations')
    return summary


def process_values(row, schema):
    require(row.get('schema') == schema and row.get('status') == 'completed'
            and row.get('exitCode') == 0 and row.get('signal') is None, 'failed or missing process measurement')
    elapsed = number(row.get('elapsedMs'), 'process elapsed time')
    start = datetime.datetime.fromisoformat(row['startedAt'].replace('Z', '+00:00'))
    end = datetime.datetime.fromisoformat(row['finishedAt'].replace('Z', '+00:00'))
    require(start <= end, 'process timestamps reversed')
    r = row['resources']
    require(r.get('scope') == 'command-and-waited-descendants'
            and r.get('maxRssScope') == 'process-high-water-not-simultaneous-tree-peak', 'wrong process scope')
    cpu = r.get('totalCpuMs')
    if cpu is None:
        require(r.get('userCpuMs') is None and r.get('systemCpuMs') is None
                and bool(r.get('unavailableReason')), 'missing process CPU is not explicit')
    else:
        close(cpu, number(r.get('userCpuMs'), 'process user CPU')
              + number(r.get('systemCpuMs'), 'process system CPU'), 'process CPU sum')
        require(r.get('unavailableReason') is None, 'process CPU scope inconsistent')
    rss = r.get('maxRssBytes')
    if rss is not None:
        number(rss, 'process RSS', integer=True)
    return elapsed, cpu, rss


def remote_fhe_observation(case):
    """Count actual remote Rust work separately from its RPC controllers."""
    metrics = case['metrics']
    auxiliary = metrics.get('roleWork')
    require(isinstance(auxiliary, list) and len(auxiliary) == 4, 'missing honest/challenged operator and auditor observations')
    expected = {('operator', 'operator-execution', 'honest'), ('operator', 'operator-execution', 'challenged'),
                ('auditor', 'auditor-full-recomputation', 'honest'), ('auditor', 'auditor-full-recomputation', 'challenged')}
    require({(r.get('role'), r.get('purpose'), r.get('phase')) for r in auxiliary} == expected,
            'wrong auxiliary role/phase coverage')
    honest_tasks = {r['taskId'] for r in metrics['adjudicatorWork'] if r['purpose'] == 'full-execution-certification'}
    challenged_tasks = {r['taskId'] for r in metrics['adjudicatorWork'] if r['purpose'] == 'leaf-result-certification'}
    if case.get('submitAuthorization'):
        require(honest_tasks == {case['submitAuthorization']['taskId']}, 'worker task differs from authorized output')
    ids, request_ids, groups = set(), set(), {}
    for parent in [*metrics['adjudicatorWork'], *auxiliary]:
        process_values(parent, 'role-process-resources-v1')
        identity = parent.get('measurementId')
        require(isinstance(identity, str) and identity and identity not in ids, 'duplicate role measurement identity')
        ids.add(identity)
        require(parent.get('executionScope') == 'controller-only-remote-fhe-excluded'
                and isinstance(parent.get('taskId'), str) and re.fullmatch('0x[0-9a-fA-F]{64}', parent['taskId']),
                'missing controller scope or role task binding')
        commands = parent.get('publicWorkerResources')
        purpose, role = parent['purpose'], parent['role']
        require(isinstance(commands, list) and len(commands) == (0 if purpose == 'context-certification' else 1),
                'missing or unexpected remote FHE command coverage')
        phase = parent.get('phase')
        require(phase in ('honest', 'challenged')
                and (purpose != 'full-execution-certification' or phase == 'honest')
                and (purpose != 'leaf-result-certification' or phase == 'challenged'), 'wrong remote phase')
        require(parent['taskId'] in (honest_tasks if phase == 'honest' else challenged_tasks),
                'role phase does not match its task')
        key = role + ':' + purpose + ':' + phase
        bucket = groups.setdefault(key, {'role': role, 'purpose': purpose,
            'phase': phase,
            'controllerWorkers': 0, 'remoteCommands': 0, 'summedRemoteElapsedMs': 0,
            'cpuMeasuredCommands': 0, 'measuredRemoteCpuMs': None, 'completeRemoteCpuMs': None,
            'maxObservedRemoteRssBytes': None})
        bucket['controllerWorkers'] += 1
        for command in commands:
            elapsed, cpu, rss = process_values(command, 'public-fhe-process-resources-v1')
            request_id = command.get('requestId')
            require(isinstance(request_id, str) and request_id and request_id not in request_ids,
                    'missing or reused remote request identity')
            request_ids.add(request_id)
            operation = ('leaf' if purpose == 'leaf-result-certification'
                         else 'execute-canonical-fault-fixture' if role == 'operator' and parent['phase'] == 'challenged'
                         else 'execute-canonical')
            require(command.get('action') == 'kms-circuit' and command.get('operation') == operation,
                    'remote command does not match role purpose')
            bucket['remoteCommands'] += 1
            bucket['summedRemoteElapsedMs'] += elapsed
            if cpu is not None:
                bucket['cpuMeasuredCommands'] += 1
                bucket['measuredRemoteCpuMs'] = (bucket['measuredRemoteCpuMs'] or 0) + cpu
            if rss is not None:
                bucket['maxObservedRemoteRssBytes'] = max(bucket['maxObservedRemoteRssBytes'] or 0, rss)
    for bucket in groups.values():
        if bucket['remoteCommands'] and bucket['cpuMeasuredCommands'] == bucket['remoteCommands']:
            bucket['completeRemoteCpuMs'] = bucket['measuredRemoteCpuMs']
    return {'schema': 'public-fhe-process-resources-v1', 'byRolePurpose': groups,
        'scope': 'remote-Rust-commands-only-controller-and-chain-costs-excluded',
        'fullProtocolCpuMs': None, 'independentAdministrationEstablished': False}


def build_report(cfg, app, run=None):
    marker = cfg.get('comparativeMetricsVersion')
    if marker is None:
        return None
    require(marker == VERSION, 'unknown comparison observation version')
    require(app.get('status') == 'passed', 'incomplete application report')
    selected = {'linear', 'nonlinear'} if cfg['half'] == 'both' else {cfg['half']}
    require(selected <= {'linear', 'nonlinear'}, 'invalid selected halves')
    cases, seen, seen_halves, worker_ids, request_ids = [], set(), set(), set(), set()
    for case in app['cases']:
        require(case['half'] in selected and case['name'] not in seen, 'wrong or duplicate case')
        seen.add(case['name'])
        seen_halves.add(case['half'])
        row = {'case': case['name'], 'group': case.get('group'), 'half': case['half'], 'n': case['n']}
        if case['half'] == 'linear':
            row['communication'] = linear_observation(case, run)
        else:
            row['adjudicatorWorkSummary'] = adjudicator_observation(case)
            row['remoteFheWorkSummary'] = remote_fhe_observation(case)
            for measurement in [*case['metrics']['adjudicatorWork'], *case['metrics']['roleWork']]:
                require(measurement['measurementId'] not in worker_ids, 'worker evidence reused across cases')
                worker_ids.add(measurement['measurementId'])
                for remote in measurement['publicWorkerResources']:
                    require(remote['requestId'] not in request_ids, 'remote command evidence reused across cases')
                    request_ids.add(remote['requestId'])
        cases.append(row)
    require(seen_halves == selected, 'missing selected comparison half')
    return {'version': VERSION, 'analysisComplete': False, 'half': cfg['half'], 'cases': cases,
        'limitations': ['Serialized byte accounting is not network traffic. Compact SUM is hypothetical transport.',
            'Local adjudicator process CPU excludes FHE work delegated to the separate public worker. Summed worker elapsed time is not workflow wall time.',
            'Zero result certification after context does not remove audit coverage or context certification.',
            'No independent-administration, diligence, confidentiality or secure-profile claim.']}


def validate_report(run, sealed_files=None):
    run = Path(run)
    cfg = json.loads((run / 'config/campaign.json').read_text())
    if cfg.get('comparativeMetricsVersion') is None:
        return None
    if sealed_files is not None:
        require(REPORT in sealed_files and 'reports/application.json' in sealed_files,
                'missing sealed comparison report or source observations')
    expected = build_report(cfg, json.loads((run / 'reports/application.json').read_text()), run)
    if sealed_files is not None:
        app = json.loads((run / 'reports/application.json').read_text())
        for case in app['cases']:
            if case['half'] == 'linear':
                require('fixtures/' + case['name'] + '/aggregate.bin' in sealed_files
                        and 'release-evidence/' + case['linearWitnessDigest'][2:] + '.json' in sealed_files,
                        'unsealed linear comparison source bytes')
    require((run / REPORT).is_file(), 'missing comparison report')
    require(json.loads((run / REPORT).read_text()) == expected, 'comparison report differs from raw observations')
    return expected


def numeric_rows(report):
    """Full-case observations. Omit a nullable metric for an entire incomplete group."""
    rows = []
    for case in report['cases']:
        values = {}
        if case['half'] == 'linear':
            m = case['communication']
            values = {'linear_canonical_aggregate_bytes': ('bytes', m['observed']['canonicalAggregateBytes']),
                'linear_cold_baseline_input_bytes': ('bytes', m['sizeModel']['packedInputPayloadBytes']),
                'linear_kms_input_witness_json_bytes': ('bytes', m['observed']['kmsInputWitnessSerializedBytes']),
                'linear_cold_current_reduction_fraction': ('fraction', m['coldInputCache']['proposedReductionFraction'])}
            if m['compactSum']['available']:
                values.update({'linear_hypothetical_sum_bytes': ('bytes', m['compactSum']['encodedBytes']),
                    'linear_hypothetical_sum_reduction_fraction': ('fraction', m['compactSum']['coldInputCache']['proposedReductionFraction'])})
        else:
            for purpose, bucket in case['adjudicatorWorkSummary']['byPurpose'].items():
                prefix = 'adjudicator_' + PURPOSES[purpose] + '_'
                for name, field, unit in [('worker_invocations', 'workerInvocations', 'workers'),
                    ('summed_worker_elapsed_ms', 'summedWorkerElapsedMs', 'ms'),
                    ('cpu_measured_workers', 'cpuMeasuredWorkers', 'workers'),
                    ('complete_cpu_ms', 'completeCpuMs', 'ms'),
                    ('max_observed_worker_rss_bytes', 'maxObservedWorkerRssBytes', 'bytes')]:
                    values[prefix + name] = (unit, bucket[field])
            for bucket in case['remoteFheWorkSummary']['byRolePurpose'].values():
                role, purpose = bucket['role'], bucket['purpose']
                short = ({'context-certification': 'context', 'full-execution-certification': 'baseline',
                          'leaf-result-certification': 'leaf'}[purpose] if role == 'adjudicator'
                         else 'operator_fault_fixture' if role == 'operator' and bucket['phase'] == 'challenged'
                         else role)
                prefix = 'remote_fhe_' + bucket['phase'] + '_' + short + '_'
                for name, field, unit in [('commands', 'remoteCommands', 'commands'),
                    ('summed_elapsed_ms', 'summedRemoteElapsedMs', 'ms'),
                    ('cpu_measured_commands', 'cpuMeasuredCommands', 'commands'),
                    ('complete_cpu_ms', 'completeRemoteCpuMs', 'ms'),
                    ('max_observed_rss_bytes', 'maxObservedRemoteRssBytes', 'bytes')]:
                    values[prefix + name] = (unit, bucket[field])
        for metric, (unit, value) in values.items():
            rows.append({**{k: case[k] for k in ('case', 'group', 'half', 'n')},
                         'metric': metric, 'unit': unit, 'value': value})
    unavailable = {(r['group'], r['metric']) for r in rows if r['value'] is None}
    return [r for r in rows if (r['group'], r['metric']) not in unavailable]
