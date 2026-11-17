"""Synthetic validator fixtures, not experiments or cryptographic evidence."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from comparative_evidence import VERSION, REPORT, build_report, numeric_rows, validate_report


def linear_case():
    n, width = 2, 8
    canonical, inputs, compact = 9 * width * 32, n * width * 8, width * 9
    scenario = lambda p: {'proposedAggregatePayloadBytes': p, 'baselineInputPayloadBytes': inputs,
        'baselineAdditionalAggregatePayloadBytes': 0, 'proposedMinusBaselineBytes': p-inputs,
        'proposedReductionFraction': (inputs-p)/inputs}
    communication = {'schema': 'vcfhe-linear-communication-v1', 'operation': 'SUM', 'inputCount': n,
        'coordinateWidth': width, 'dimension': 9*width,
        'evidenceClass': 'serialized-byte-accounting-not-network-measurement',
        'networkTransferMeasured': False, 'cryptographicOrFheValidationPerformed': False,
        'observed': {'canonicalAggregateBytes': canonical,
            'canonicalAggregateSha256': hashlib.sha256(bytes(canonical)).hexdigest(),
            'kmsInputWitnessSerializedBytes': 2},
        'sizeModel': {'inputCoordinateBytes': 8, 'packedInputPayloadBytes': inputs,
            'baselineReconstructsAggregate': True, 'canonicalAggregateEncoding': '32-byte-big-endian-field-coordinates'},
        'coldInputCache': scenario(canonical),
        'warmAuthenticatedInputAndAggregateCache': {'proposedAggregatePayloadBytes': 0,
            'baselineInputPayloadBytes': 0, 'baselineAdditionalAggregatePayloadBytes': 0},
        'compactSum': {'available': True, 'status': 'hypothetical-transport-not-used-by-protocol',
            'coordinateBytes': 9, 'populatedGroups': 1, 'encodedBytes': compact,
            'roundTripCanonicalBytesEqual': True, 'coldInputCache': scenario(compact)}}
    return {'name': 'linear-unit', 'group': 'linear-unit', 'half': 'linear', 'n': n, 'plan': {'op': 'SUM'},
        'linearWitnessDigest': '0x'+'c'*64,
        'metrics': {'aggregateBytes': canonical, 'communication': communication}}


def nonlinear_case():
    rows = []
    for purpose, tasks in [('context-certification', ['a', 'b']),
                           ('full-execution-certification', ['a']), ('leaf-result-certification', ['b'])]:
        for task in tasks:
            for signer in range(2):
                rows.append({'schema': 'role-process-resources-v1', 'measurementId': f'{purpose}-{task}-{signer}',
                    'role': 'adjudicator', 'purpose': purpose, 'taskId': '0x'+task*64,
                    'phase': 'honest' if task == 'a' else 'challenged',
                    'executionScope': 'controller-only-remote-fhe-excluded',
                    'status': 'completed', 'exitCode': 0, 'signal': None, 'elapsedMs': 5,
                    'startedAt': '2026-10-23T01:00:00Z', 'finishedAt': '2026-10-23T01:00:01Z',
                    'nativeFheElapsedMs': None, 'resources': {'scope': 'command-and-waited-descendants',
                        'userCpuMs': 1, 'systemCpuMs': 2, 'totalCpuMs': 3, 'maxRssBytes': 1024,
                        'maxRssScope': 'process-high-water-not-simultaneous-tree-peak',
                        'source': 'synthetic-unit-test', 'unavailableReason': None}})
    auxiliary = []
    for role, purpose in [('operator', 'operator-execution'), ('auditor', 'auditor-full-recomputation')]:
        for phase, task in [('honest', 'a'), ('challenged', 'b')]:
            row = copy.deepcopy(rows[0])
            row.update(role=role, purpose=purpose, phase=phase, taskId='0x'+task*64,
                       measurementId=role+'-'+phase)
            auxiliary.append(row)
    for row in [*rows, *auxiliary]:
        remote = copy.deepcopy(row)
        remote.update(schema='public-fhe-process-resources-v1', requestId=row['measurementId'],
                      action='kms-circuit', operation='leaf' if row['purpose'] == 'leaf-result-certification'
                      else 'execute-canonical-fault-fixture' if row['role'] == 'operator' and row['phase'] == 'challenged'
                      else 'execute-canonical')
        row['publicWorkerResources'] = [] if row['purpose'] == 'context-certification' else [remote]
    return {'name': 'nonlinear-unit', 'group': 'nonlinear-unit', 'half': 'nonlinear', 'n': 2,
        'metrics': {'adjudicatorWork': rows, 'roleWork': auxiliary, 'baseline': {'certificates': [{}, {}]},
                    'disputes': [{'settlement': {'certificates': [{}, {}]}}]}}


def application(half='both'):
    cases = [linear_case(), nonlinear_case()]
    return {'comparativeMetricsVersion': VERSION, 'half': half}, {
        'status': 'passed', 'cases': [c for c in cases if half == 'both' or c['half'] == half]}


class ComparativeEvidenceTests(unittest.TestCase):
    def test_selected_halves_and_negative_current_transport_result_preserved(self):
        for half in ('linear', 'nonlinear', 'both'):
            cfg, app = application(half)
            report = build_report(cfg, app)
            self.assertFalse(report['analysisComplete'])
            self.assertEqual({c['half'] for c in report['cases']}, {'linear', 'nonlinear'} if half == 'both' else {half})
            rows = numeric_rows(report)
            if half != 'nonlinear':
                value = next(r['value'] for r in rows if r['metric'] == 'linear_cold_current_reduction_fraction')
                self.assertLess(value, 0)

    def test_historical_absence_is_not_fabricated_as_zero(self):
        self.assertIsNone(build_report({'half': 'linear'}, {'cases': []}))
        cfg, app = application('linear')
        del app['cases'][0]['metrics']['communication']
        with self.assertRaisesRegex(ValueError, 'missing linear'): build_report(cfg, app)
        cfg['comparativeMetricsVersion'] = 'unknown'
        with self.assertRaisesRegex(ValueError, 'version'): build_report(cfg, app)

    def test_false_network_claim_or_unfair_baseline_is_rejected(self):
        for mutate in [lambda m: m.update(networkTransferMeasured=True),
            lambda m: m['coldInputCache'].update(baselineAdditionalAggregatePayloadBytes=2304),
            lambda m: m['compactSum'].update(status='production'),
            lambda m: m['compactSum'].update(encodedBytes=1),
            lambda m: m['observed'].update(kmsInputWitnessSerializedBytes=None)]:
            cfg, app = application('linear'); mutate(app['cases'][0]['metrics']['communication'])
            with self.assertRaises(ValueError): build_report(cfg, app)

    def test_worker_counts_task_binding_duplicates_and_cpu_fail_closed(self):
        for mutate in [lambda rows: rows.pop(), lambda rows: rows[0].update(taskId=None),
            lambda rows: rows[0].update(measurementId=rows[1]['measurementId']),
            lambda rows: rows[0].update(exitCode=1),
            lambda rows: rows[0]['resources'].update(totalCpuMs=0),
            lambda rows: rows[0].update(elapsedMs=float('nan'))]:
            cfg, app = application('nonlinear'); mutate(app['cases'][0]['metrics']['adjudicatorWork'])
            with self.assertRaises(ValueError): build_report(cfg, app)

    def test_missing_remote_or_controller_mislabeled_as_fhe_is_rejected(self):
        for mutate in [lambda m: m.pop('roleWork'),
            lambda m: m['adjudicatorWork'][-1].update(publicWorkerResources=[]),
            lambda m: m['adjudicatorWork'][0].update(executionScope='local-command-with-waited-fhe-descendants'),
            lambda m: m['roleWork'][0]['publicWorkerResources'][0].update(operation='leaf')]:
            cfg, app = application('nonlinear'); mutate(app['cases'][0]['metrics'])
            with self.assertRaises(ValueError): build_report(cfg, app)

    def test_missing_cpu_is_null_and_optional_group_mean_is_omitted(self):
        cfg, app = application('nonlinear')
        second = copy.deepcopy(app['cases'][0]); second['name'] += '-second'
        for measurement in [*second['metrics']['adjudicatorWork'], *second['metrics']['roleWork']]:
            measurement['measurementId'] += '-second'
            for remote in measurement['publicWorkerResources']:
                remote['requestId'] += '-second'
        row = second['metrics']['adjudicatorWork'][0]
        row['resources'].update(userCpuMs=None, systemCpuMs=None, totalCpuMs=None,
                                unavailableReason='unavailable-in-unit-fixture')
        app['cases'].append(second)
        report = build_report(cfg, app)
        bucket = report['cases'][1]['adjudicatorWorkSummary']['byPurpose']['context-certification']
        self.assertIsNone(bucket['completeCpuMs'])
        self.assertEqual(bucket['measuredCpuMs'], 9)
        rows = numeric_rows(report)
        self.assertFalse(any(r['metric'] == 'adjudicator_context_complete_cpu_ms' for r in rows))
        self.assertEqual(len([r for r in rows if r['metric'] == 'adjudicator_context_cpu_measured_workers']), 2)

    def test_report_and_retained_payload_are_rechecked(self):
        cfg, app = application('linear')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for folder in ('config', 'reports', 'fixtures/linear-unit', 'release-evidence'):
                (root/folder).mkdir(parents=True, exist_ok=True)
            (root/'config/campaign.json').write_text(json.dumps(cfg))
            (root/'reports/application.json').write_text(json.dumps(app))
            (root/'fixtures/linear-unit/aggregate.bin').write_bytes(bytes(2304))
            (root/'release-evidence'/('c'*64+'.json')).write_text('{}')
            report = build_report(cfg, app, root)
            (root/REPORT).write_text(json.dumps(report))
            sealed = {REPORT, 'reports/application.json', 'fixtures/linear-unit/aggregate.bin',
                      'release-evidence/'+'c'*64+'.json'}
            self.assertEqual(validate_report(root, sealed), report)
            with self.assertRaisesRegex(ValueError, 'sealed'): validate_report(root, {'reports/application.json'})
            with self.assertRaisesRegex(ValueError, 'unsealed'): validate_report(root, {REPORT, 'reports/application.json'})
            altered = copy.deepcopy(report)
            altered['cases'][0]['communication']['compactSum']['encodedBytes'] = 1
            (root/REPORT).write_text(json.dumps(altered))
            with self.assertRaisesRegex(ValueError, 'differs'): validate_report(root)
            (root/REPORT).write_text(json.dumps(build_report(cfg, app, root)))
            (root/'fixtures/linear-unit/aggregate.bin').write_bytes(bytes(2303)+b'x')
            with self.assertRaisesRegex(ValueError, 'retained'): validate_report(root)


if __name__ == '__main__':
    unittest.main()
