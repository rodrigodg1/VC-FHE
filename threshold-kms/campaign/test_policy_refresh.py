import copy
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import policy_refresh
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.SimpleNamespace(
        LOCK_EX=1, LOCK_NB=2, flock=lambda *_args: None))
import run as campaign
from poc_plan import plan as poc_plan


def fixture(half):
    design = policy_refresh.plan(half)
    cfg = {
        'version': campaign.VERSION,
        'half': half,
        'parameters': 'Test',
        'smoke': False,
        'readinessOnly': False,
        'classification': policy_refresh.CLASSIFICATION,
        'policyLineage': policy_refresh.REQUIRED_POLICY_LINEAGE,
        'windowSeconds': design['windowSeconds'],
        'disclosureBatchSize': design['disclosureBatchSize'],
        'selectionProfile': design['selectionProfile'],
        'policyRefreshPlan': design,
        'runId': 'run-fixture-' + half,
        'policyRefreshAttempt': {
            'attemptId': 'attempt-' + half,
            'requestedHalf': half,
            'claimedScopes': (['linear', 'nonlinear'] if half == 'both' else [half]),
            'runId': 'run-fixture-' + half,
            'runDirectory': '/preserved/run-fixture-' + half,
            'designSha256': design['designSha256'],
            'createdUnixNs': 1,
            'status': 'permanently-claimed',
        },
    }
    cases = []
    for job in design['jobs']:
        case = copy.deepcopy(job)
        case.update(finalOutputKmsCalls=1,
                    receiptScopes={'policy': {'transactionCount': 1,
                                              'gasUsed': '5',
                                              'calldataBytes': 4}},
                    transactionCount=1, gasUsed='5', calldataBytes=4,
                    metrics={'baselineProfile': 'ordinary-bls-canonical-vector-v1'})
        if job['half'] == 'nonlinear':
            leaves = ({16: 128, 32: 256, 50: 512}
                      if job['workload'] == 'regional_qoe_compliance'
                      else {16: 64, 32: 128, 50: 128})[job['n']]
            fault = {'early': 0, 'middle': (leaves - 1) // 2,
                     'terminal': leaves - 1}[job['faultPosition']]
            case['metrics'] = {
                'leaves': leaves,
                'disputes': [{'faultIndex': fault,
                              'settlement': {'index': fault,
                                             'state': [3, 2, True],
                                             'certificates': [
                                                 {'plaintextOpenings': 0},
                                                 {'plaintextOpenings': 0}]}}],
            }
        cases.append(case)
    app = {'status': 'passed', 'kmsCalls': len(cases), 'cases': cases,
           'keys': {'keysetDigest': '0x' + '12' * 32}}
    app['config'] = copy.deepcopy(cfg)
    onchain = {'status': 'passed', 'policyVersion': 3, 'validatorCount': 4,
               'validatorConfirmationQuorum': 3, 'caseCount': len(cases),
               'ownerIdentitySetSha256': '56' * 32,
               'inputSha256': '34' * 32,
               'cases': [{'name': case['name']} for case in cases]}
    return cfg, app, onchain


def passive_fixture(cfg, current_spent=2):
    design = cfg['policyRefreshPlan']
    keys = {
        'status': 'passed', 'parameters': 'Test', 'parties': 4,
        'corruptionThreshold': 1, 'fullPreprocessing': True,
        'preloadedFheKey': False, 'keyId': '0x' + '11' * 32,
        'keyEpoch': '0x' + '22' * 32, 'mpcContext': '0x' + '33' * 32,
        'keysetDigest': '0x' + '44' * 32,
    }
    cases = []
    expected = {}
    for job in design['jobs']:
        record_ids = [
            '0x' + hashlib.sha256(
                f"{job['half']}:{job['group']}:{index}".encode()).hexdigest()
            for index in range(job['n'])
        ]
        cases.append(copy.deepcopy(job) | {
            'recordIds': record_ids,
            'releaseLimits': [18] * len(record_ids),
            'initialSpent': [0] * len(record_ids),
        })
        for record_id in record_ids:
            expected[record_id] = expected.get(record_id, 0) + 1
    records = [{
        'recordId': record_id, 'releaseLimit': 18,
        'currentSpent': current_spent, 'plannedCharges': count,
        'remainingAfterPlan': 18 - current_spent - count,
    } for record_id, count in sorted(expected.items())]
    report = {
        'schema': policy_refresh.PREFLIGHT_SCHEMA, 'status': 'passed',
        'profile': design['profile'], 'designSha256': design['designSha256'],
        'half': design['half'], 'parameters': 'Test',
        'keysetDigest': keys['keysetDigest'], 'caseCount': len(cases),
        'caseNames': [case['name'] for case in cases],
        'view': {'blockNumber': 17, 'blockHash': '0x' + '55' * 32,
                 'parentHash': '0x' + '66' * 32, 'validatorCount': 4,
                 'confirmationQuorum': 3, 'participantCount': 4,
                 'supporterCount': 4},
        'recordCount': len(records),
        'maxCurrentSpent': current_spent,
        'maxPlannedCharges': max(row['plannedCharges'] for row in records),
        'minRemainingAfterPlan': min(row['remainingAfterPlan'] for row in records),
        'limits': {'minimum': 18, 'maximum': 18}, 'records': records,
    }
    return {'keys': keys, 'owners': [], 'cases': cases}, keys, report


class PolicyRefreshTests(unittest.TestCase):
    def test_first_attempt_reserves_the_requested_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / '.policy-state'
            design = policy_refresh.plan('linear')
            claim = policy_refresh.reserve_attempt(
                root, 'linear', 'run-linear-1', Path(temp) / 'run-linear-1', design)
            self.assertEqual(claim['claimedScopes'], ['linear'])
            saved = json.loads((root / policy_refresh.ATTEMPT_FILE).read_text())
            self.assertEqual(set(saved['claims']), {'linear'})
            self.assertEqual(saved['claims']['linear']['attemptId'], claim['attemptId'])
            self.assertEqual(saved['claims']['linear']['status'], 'permanently-claimed')

    def test_combined_and_split_attempts_cannot_overlap(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'combined'
            policy_refresh.reserve_attempt(
                root, 'both', 'run-both', Path(temp) / 'run-both',
                policy_refresh.plan('both'))
            for half in ('linear', 'nonlinear', 'both'):
                with self.assertRaisesRegex(ValueError, 'separately reviewed continuation'):
                    policy_refresh.reserve_attempt(
                        root, half, 'run-replay-' + half,
                        Path(temp) / ('run-replay-' + half), policy_refresh.plan(half))

            root = Path(temp) / 'split'
            linear = policy_refresh.reserve_attempt(
                root, 'linear', 'run-linear', Path(temp) / 'run-linear',
                policy_refresh.plan('linear'))
            nonlinear = policy_refresh.reserve_attempt(
                root, 'nonlinear', 'run-nonlinear', Path(temp) / 'run-nonlinear',
                policy_refresh.plan('nonlinear'))
            self.assertNotEqual(linear['attemptId'], nonlinear['attemptId'])
            saved = json.loads((root / policy_refresh.ATTEMPT_FILE).read_text())
            self.assertEqual(set(saved['claims']), {'linear', 'nonlinear'})
            with self.assertRaisesRegex(ValueError, 'scope already claimed'):
                policy_refresh.reserve_attempt(
                    root, 'both', 'run-both-after-split',
                    Path(temp) / 'run-both-after-split', policy_refresh.plan('both'))

    def test_failed_attempt_claim_is_never_released_automatically(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / '.policy-state'
            policy_refresh.reserve_attempt(
                root, 'linear', 'run-that-failed', Path(temp) / 'run-that-failed',
                policy_refresh.plan('linear'))
            # A campaign failure has no cleanup path for this permanent claim.
            with self.assertRaisesRegex(ValueError, 'Do not start a fresh run'):
                policy_refresh.assert_attempt_available(root, 'linear')
            saved = json.loads((root / policy_refresh.ATTEMPT_FILE).read_text())
            self.assertEqual(saved['claims']['linear']['runId'], 'run-that-failed')

    def test_list_and_check_do_not_create_or_change_attempt_claims(self):
        with tempfile.TemporaryDirectory() as temp:
            module = Path(temp) / 'module'
            module.mkdir()
            state = module / '.policy-state'
            common = ['--policy-refresh-v3', '--half', 'linear',
                      '--fhe-params', 'Test', '--allow-insecure-test']
            with patch.object(campaign, 'MODULE', module), \
                 patch.object(sys, 'argv', ['run.py', *common, '--list']), \
                 patch.object(campaign, 'reserve_policy_refresh_attempt') as reserve:
                campaign.main()
                reserve.assert_not_called()
            self.assertFalse(state.exists())

            run_dir = Path(temp) / 'preserved-run'
            before = {'sentinel': 'unchanged'}
            state.mkdir()
            claims = state / policy_refresh.ATTEMPT_FILE
            claims.write_text(json.dumps(before))
            with patch.object(campaign, 'MODULE', module), \
                 patch.object(sys, 'argv', ['run.py', *common, '--check',
                                            '--run-dir', str(run_dir)]), \
                 patch.object(campaign, 'verify', return_value={'status': 'checked'}), \
                 patch.object(campaign, 'reserve_policy_refresh_attempt') as reserve:
                campaign.main()
                reserve.assert_not_called()
            self.assertEqual(json.loads(claims.read_text()), before)

    def test_incomplete_refresh_never_instructs_a_fresh_replay(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp) / 'incomplete-run'
            run_dir.mkdir()
            argv = ['run.py', '--policy-refresh-v3', '--resume', '--run-dir',
                    str(run_dir)]
            with patch.object(sys, 'argv', argv), \
                 self.assertRaisesRegex(
                     ValueError, 'separately reviewed continuation.*preserved evidence and keyset'):
                campaign.main()

    def test_plan_selects_only_frozen_full_case_indices(self):
        expected = {
            'linear': (15, [0, 24, 49, 74, 99]),
            'nonlinear': (30, [0, 7, 14, 22, 29]),
            'both': (45, None),
        }
        for half, (count, repeats) in expected.items():
            design = policy_refresh.plan(half)
            self.assertEqual(design['fullCases'], count)
            self.assertEqual(design['pairedMeasurementsExecuted'], 0)
            self.assertFalse(design['legacyEvidenceImported'])
            self.assertTrue(all(job['fullCase'] for job in design['jobs']))
            self.assertFalse(any('warmup' in job or 'order' in job for job in design['jobs']))
            for group in dict.fromkeys(job['group'] for job in design['jobs']):
                group_repeats = ([0, 24, 49, 74, 99]
                                 if next(job for job in design['jobs']
                                         if job['group'] == group)['half'] == 'linear'
                                 else [0, 7, 14, 22, 29])
                self.assertEqual([job['repeat'] for job in design['jobs']
                                  if job['group'] == group], repeats or group_repeats)
            source = [job for job in poc_plan(half)['jobs'] if job['fullCase']]
            self.assertEqual(
                [(job['name'], job['repeat'], job['faultPosition'])
                 for job in design['jobs']],
                [(job['name'], job['repeat'], job['faultPosition'])
                 for job in source])
        with self.assertRaises(ValueError):
            policy_refresh.plan('partial')

    def test_cli_is_explicit_and_cannot_expand_to_pairs_or_smoke(self):
        base = ['--policy-refresh-v3', '--half', 'linear']
        for argv in [base,
                     base + ['--fhe-params', 'Test', '--allow-insecure-test', '--smoke'],
                     base + ['--fhe-params', 'Test', '--allow-insecure-test',
                             '--new-policy-lineage']]:
            with self.assertRaises(ValueError):
                campaign.selection(campaign.parser().parse_args(argv))
        args = campaign.parser().parse_args(base + [
            '--fhe-params', 'Test', '--allow-insecure-test'])
        selected = campaign.selection(args)
        self.assertNotIn('pocPlan', selected)
        self.assertEqual(selected['policyRefreshPlan']['fullCases'], 15)
        self.assertIsNone(selected['repeats'])
        combined = campaign.selection(campaign.parser().parse_args([
            '--policy-refresh-v3', '--half', 'both', '--fhe-params', 'Test',
            '--allow-insecure-test']))
        self.assertEqual(combined['policyRefreshPlan']['fullCases'], 45)

        invalid_threads = campaign.parser().parse_args([
            '--policy-refresh-v3', '--half', 'both', '--fhe-params', 'Test',
            '--allow-insecure-test', '--kms-threads', '2'])
        with self.assertRaisesRegex(ValueError, '--kms-threads 1'):
            campaign.validate_execution_profile(invalid_threads)
        valid_threads = campaign.parser().parse_args([
            '--policy-refresh-v3', '--half', 'both', '--fhe-params', 'Test',
            '--allow-insecure-test', '--kms-threads', '1'])
        campaign.validate_execution_profile(valid_threads)

    def test_passive_preclaim_binds_keyset_case_sequence_and_capacity(self):
        for half in ('linear', 'nonlinear', 'both'):
            cfg, _app, _onchain = fixture(half)
            prepared, keys, report = passive_fixture(cfg)
            self.assertEqual(
                policy_refresh.validate_prepared_preflight(cfg, prepared, keys, report),
                cfg['policyRefreshPlan'])

            changed = copy.deepcopy(keys)
            changed['status'] = 'failed'
            with self.assertRaisesRegex(ValueError, 'keyset'):
                policy_refresh.validate_prepared_preflight(cfg, prepared, changed, report)

            changed = copy.deepcopy(prepared)
            changed['cases'][0], changed['cases'][1] = changed['cases'][1], changed['cases'][0]
            with self.assertRaisesRegex(ValueError, 'case sequence'):
                policy_refresh.validate_prepared_preflight(cfg, changed, keys, report)

            changed = copy.deepcopy(report)
            changed['records'][0]['plannedCharges'] += 1
            with self.assertRaisesRegex(ValueError, 'release plan'):
                policy_refresh.validate_prepared_preflight(cfg, prepared, keys, changed)

    def test_attempt_activation_occurs_only_after_validated_passive_gate(self):
        cfg, _app, _onchain = fixture('linear')
        cfg.pop('policyRefreshAttempt')
        _prepared, _keys, report = passive_fixture(cfg)
        state = {'status': 'running', 'config': copy.deepcopy(cfg), 'stages': []}
        attempt = {
            'attemptId': 'attempt-after-preflight', 'requestedHalf': 'linear',
            'claimedScopes': ['linear'], 'runId': cfg['runId'],
            'runDirectory': '/preserved/run',
            'designSha256': cfg['policyRefreshPlan']['designSha256'],
            'createdUnixNs': 1, 'status': 'permanently-claimed',
        }
        events = []

        def waited(*_args):
            events.append('validated-preflight')
            return {'preflight': report}

        def reserved(*_args):
            self.assertEqual(events, ['validated-preflight'])
            self.assertNotIn('policyRefreshAttempt', cfg)
            events.append('reserved-claim')
            return attempt

        def persisted(path, value):
            self.assertIn('policyRefreshAttempt', cfg)
            events.append('write-' + Path(path).name)

        with tempfile.TemporaryDirectory() as temp, \
             patch.object(campaign, 'wait_policy_refresh_preclaim', side_effect=waited), \
             patch.object(campaign, 'reserve_policy_refresh_attempt', side_effect=reserved), \
             patch.object(campaign, 'write', side_effect=persisted), \
             patch('builtins.print'):
            result = campaign.activate_policy_refresh_attempt(
                Path(temp), ['docker', 'compose'], cfg, state, 10)
        self.assertEqual(result, attempt)
        self.assertEqual(events, ['validated-preflight', 'reserved-claim',
                                  'write-campaign.json', 'write-state.json'])
        self.assertEqual(state['config']['policyRefreshAttempt'], attempt)

    def test_wait_gate_requires_exact_files_and_all_passive_services(self):
        cfg, _app, _onchain = fixture('linear')
        cfg.pop('policyRefreshAttempt')
        prepared, keys, report = passive_fixture(cfg)
        with tempfile.TemporaryDirectory() as temp:
            run = Path(temp)
            (run / 'fixtures').mkdir()
            (run / 'keyset').mkdir()
            (run / 'reports').mkdir()
            (run / 'fixtures/prepared.json').write_text(json.dumps(prepared))
            (run / 'keyset/ready.json').write_text(json.dumps(keys))
            (run / 'reports/release-capacity-preflight.json').write_text(json.dumps(report))
            with patch.object(campaign, 'require_running') as running:
                result = campaign.wait_policy_refresh_preclaim(
                    run, ['docker', 'compose'], cfg, 1)
            self.assertEqual(result['design'], cfg['policyRefreshPlan'])
            self.assertEqual(running.call_count, 2)
            for call in running.call_args_list:
                self.assertEqual(call.args[1], list(campaign.POLICY_REFRESH_PASSIVE_ROLES))

    def test_preclaim_failure_never_reserves_attempt(self):
        cfg, _app, _onchain = fixture('linear')
        cfg.pop('policyRefreshAttempt')
        state = {'status': 'running', 'config': copy.deepcopy(cfg), 'stages': []}
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(campaign, 'wait_policy_refresh_preclaim',
                          side_effect=ValueError('invalid prepared sequence')), \
             patch.object(campaign, 'reserve_policy_refresh_attempt') as reserve, \
             self.assertRaisesRegex(ValueError, 'invalid prepared sequence'):
            campaign.activate_policy_refresh_attempt(
                Path(temp), ['docker', 'compose'], cfg, state, 10)
        reserve.assert_not_called()
        self.assertNotIn('policyRefreshAttempt', cfg)

    def test_evaluation_and_owner_transactions_are_both_post_claim(self):
        runner = (Path(__file__).parent / 'run.py').read_text()
        activation = runner.index(
            'activate_policy_refresh_attempt(run,compose,cfg,state,a.timeout)')
        self.assertLess(runner.index('for name,args in infrastructure_stages(run,compose,bool(reuse)):'),
                        activation)
        self.assertLess(
            activation,
            runner.index("stage('evaluation',compose+['run','--rm','evaluate'])"))
        self.assertEqual(runner.count('reserve_policy_refresh_attempt('), 1)
        self.assertEqual(set(campaign.POLICY_REFRESH_PASSIVE_ROLES), {
            'kms1', 'kms2', 'kms3', 'kms4', 'public-store',
            'owner', 'worker', 'recipient'})
        owner = (Path(__file__).parent / 'owner.mjs').read_text()
        self.assertLess(owner.index("atomic('/reports/release-capacity-preflight.json'"),
                        owner.index("atomic('/fixtures/prepared.json'"))
        transaction = owner.split("if(r.action==='transaction'){", 1)[1].split(
            "if(r.action==='bls')", 1)[0]
        self.assertLess(transaction.index('await requirePolicyRefreshClaim();'),
                        transaction.index('wallet.signTransaction(tx)'))
        self.assertIn("json('/config/campaign.json')", owner)
        self.assertIn("json('/reports/release-capacity-preflight.json')", owner)

    def test_refresh_reuses_persistent_policy_state_and_live_counters(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module = root / 'module'
            module.mkdir()
            legacy = module / '.policy-state' / 'onchain' / 'deployment.json'
            legacy.parent.mkdir(parents=True)
            deployment = {
                'schema': 'vcfhe-release-policy-deployment-v3',
                'status': 'deployed',
                'chainId': '46853',
                'policyVersion': '3',
                'legacyMigrationInput': {'ownersSha256': '12' * 32},
            }
            legacy.write_text(json.dumps(deployment))
            owners = module / '.policy-state' / 'owner' / 'identities.json'
            owners.parent.mkdir(parents=True, exist_ok=True)
            owners.write_text('[]')
            run = root / 'run'
            run.mkdir()
            args = campaign.parser().parse_args([
                '--policy-refresh-v3', '--half', 'linear', '--fhe-params', 'Test',
                '--allow-insecure-test'])
            portable_write = lambda path, value: Path(path).write_text(json.dumps(value))
            with patch.object(campaign, 'MODULE', module), \
                 patch.object(campaign.os, 'getuid', return_value=1000, create=True), \
                 patch.object(campaign.os, 'getgid', return_value=1000, create=True), \
                 patch.object(campaign, 'write', side_effect=portable_write):
                self.assertEqual(campaign.policy_lineage(args), 'existing-on-chain-lineage')
                campaign.configuration(run, args, 'image:immutable')
            compose = json.loads((run / 'compose.json').read_text())
            identity_mounts = compose['services']['identities']['volumes']
            self.assertTrue(all(str(module / '.policy-state') in value['source']
                                for value in identity_mounts
                                if value['target'] != '/provision/config'))
            policy_service = compose['services']['policy-init']
            self.assertEqual(policy_service['environment']['VCFHE_REQUIRE_EXISTING_POLICY'], '1')
            self.assertFalse(any(value['target'] == '/migration/ledger.json'
                                 for value in policy_service['volumes']))
            self.assertEqual(json.loads(legacy.read_text()), deployment)

    def test_refresh_rejects_pending_or_unbound_policy_state(self):
        with tempfile.TemporaryDirectory() as temp:
            module = Path(temp)
            deployment = module / '.policy-state' / 'onchain' / 'deployment.json'
            owners = module / '.policy-state' / 'owner' / 'identities.json'
            deployment.parent.mkdir(parents=True)
            owners.parent.mkdir(parents=True)
            owners.write_text('[]')
            args = campaign.parser().parse_args([
                '--policy-refresh-v3', '--half', 'linear', '--fhe-params', 'Test',
                '--allow-insecure-test'])
            base = {'schema': 'vcfhe-release-policy-deployment-v3',
                    'status': 'pending', 'chainId': '46853', 'policyVersion': '3',
                    'legacyMigrationInput': {'ownersSha256': '12' * 32}}
            deployment.write_text(json.dumps(base))
            with patch.object(campaign, 'MODULE', module), \
                 self.assertRaisesRegex(ValueError, 'completed V3 deployment'):
                campaign.policy_lineage(args)
            base['status'] = 'deployed'
            base['legacyMigrationInput'] = {}
            deployment.write_text(json.dumps(base))
            with patch.object(campaign, 'MODULE', module), \
                 self.assertRaisesRegex(ValueError, 'completed V3 deployment'):
                campaign.policy_lineage(args)

    def test_refresh_rejects_legacy_migration_as_a_policy_lineage(self):
        with tempfile.TemporaryDirectory() as temp:
            module = Path(temp)
            ledger = module / '.policy-state' / 'gateway' / 'ledger.json'
            owners = module / '.policy-state' / 'owner' / 'identities.json'
            ledger.parent.mkdir(parents=True)
            owners.parent.mkdir(parents=True)
            ledger.write_text('{}')
            owners.write_text('[]')
            args = campaign.parser().parse_args([
                '--policy-refresh-v3', '--half', 'linear', '--fhe-params', 'Test',
                '--allow-insecure-test'])
            with patch.object(campaign, 'MODULE', module), \
                 self.assertRaisesRegex(ValueError, 'existing V3 on-chain lineage'):
                campaign.policy_lineage(args)

    def test_complete_application_and_v3_evidence_are_both_required(self):
        for half, count in (('linear', 15), ('nonlinear', 30), ('both', 45)):
            cfg, app, onchain = fixture(half)
            design = policy_refresh.validate_application(cfg, app, onchain)
            self.assertEqual(design['fullCases'], count)
            summary = policy_refresh.evidence_summary(cfg, app, onchain)
            self.assertEqual(summary['pairedMeasurementsExecuted'], 0)
            self.assertEqual(summary['comparisonPairsExecuted'], 0)
            self.assertFalse(summary['legacyEvidenceImported'])
            changed = copy.deepcopy(onchain)
            changed['validatorConfirmationQuorum'] = 2
            with self.assertRaises(ValueError):
                policy_refresh.validate_application(cfg, app, changed)
            changed = copy.deepcopy(app)
            changed['cases'].pop()
            with self.assertRaises(ValueError):
                policy_refresh.validate_application(cfg, changed, onchain)
            changed = copy.deepcopy(app)
            changed['config']['windowSeconds'] += 1
            with self.assertRaisesRegex(ValueError, 'exact V3 policy-refresh configuration'):
                policy_refresh.validate_application(cfg, changed, onchain)
            changed_cfg = copy.deepcopy(cfg)
            changed_app = copy.deepcopy(app)
            changed_cfg.pop('policyRefreshAttempt')
            changed_app['config'] = copy.deepcopy(changed_cfg)
            with self.assertRaisesRegex(ValueError, 'durable V3 policy-refresh attempt claim'):
                policy_refresh.validate_application(changed_cfg, changed_app, onchain)

    def test_directory_check_calls_v3_validate_run_and_rejects_paired_report(self):
        cfg, app, onchain = fixture('linear')
        prepared, keys, preflight = passive_fixture(cfg)
        with tempfile.TemporaryDirectory() as temp:
            run = Path(temp)
            (run / 'config').mkdir()
            (run / 'reports').mkdir()
            (run / 'fixtures').mkdir()
            (run / 'keyset').mkdir()
            (run / 'config' / 'campaign.json').write_text(json.dumps(cfg))
            (run / 'fixtures' / 'prepared.json').write_text(json.dumps(prepared))
            (run / 'keyset' / 'ready.json').write_text(json.dumps(keys))
            (run / 'reports' / 'release-capacity-preflight.json').write_text(
                json.dumps(preflight))
            (run / 'reports' / 'application.json').write_text(json.dumps(app))
            with patch('onchain_evidence.validate_run', return_value=onchain) as validate:
                summary = policy_refresh.validate_run_directory(run, require_report=False)
                validate.assert_called_once_with(run.resolve())
            (run / 'reports' / 'policy-refresh-v3-evidence.json').write_text(
                json.dumps(summary))
            (run / 'reports' / 'results.json').write_text(json.dumps({
                'onChainReleaseEvidence': onchain}))
            (run / 'reports' / 'onchain-release-evidence.json').write_text(
                json.dumps(onchain))
            with patch('onchain_evidence.validate_run', return_value=onchain):
                self.assertEqual(policy_refresh.validate_run_directory(run), summary)
                (run / 'reports' / 'results.json').write_text(json.dumps({
                    'onChainReleaseEvidence': onchain | {'caseCount': 14}}))
                with self.assertRaisesRegex(ValueError, 'results report'):
                    policy_refresh.validate_run_directory(run)
                (run / 'reports' / 'results.json').write_text(json.dumps({
                    'onChainReleaseEvidence': onchain}))
                (run / 'reports' / 'paired.json').write_text('{}')
                with self.assertRaisesRegex(ValueError, 'paired measurements'):
                    policy_refresh.validate_run_directory(run)

    def test_evaluator_never_routes_refresh_plan_to_run_pairs(self):
        source = (Path(__file__).parent / 'evaluate.mjs').read_text()
        self.assertIn('if(cfg.pocPlan)await runPairs(cfg,prepared);', source)
        self.assertNotIn('if(casePlan)await runPairs', source)
        self.assertIn('cfg.pocPlan??cfg.policyRefreshPlan', source)
        self.assertIn('auditorFundingLeafCount:cfg.readinessOnly||casePlan?', source)
        owner = (Path(__file__).parent / 'owner.mjs').read_text()
        self.assertIn("if(casePlan)assert.equal(item.fullCase,true", owner)
        self.assertIn('owner identity set differs from the deployed cumulative-policy lineage',
                      owner)

    def test_verify_derives_refresh_from_sealed_config_and_checks_every_claim(self):
        cfg, app, onchain = fixture('linear')
        summary = policy_refresh.evidence_summary(cfg, app, onchain)
        with tempfile.TemporaryDirectory() as temp:
            run = Path(temp)
            (run / 'config').mkdir()
            (run / 'reports').mkdir()
            for directory in ('fixtures','keyset','bin','build-evidence'):
                (run / directory).mkdir()
            source = {'campaign/run.py': 'source-digest'}
            (run / 'config/campaign.json').write_text(json.dumps(cfg))
            for name in ('owners.json','release-policy.json'):
                (run / 'config' / name).write_text('{}')
            (run / 'fixtures/prepared.json').write_text('{}')
            for name in ('ready.json','encryption-key.bin','evaluation-key.bin'):
                (run / 'keyset' / name).write_bytes(b'keyset-evidence')
            for name in ('kms-campaign','kms-server','kms-gen-keys','kms-init'):
                (run / 'bin' / name).write_bytes(b'binary-evidence')
            (run / 'build-evidence/vcfhe-adapter.json').write_text('{}')
            with gzip.open(run / 'build-evidence/installed-files.json.gz','wt',encoding='utf-8') as stream:
                json.dump({'campaign/run.py': {'bytes': 1, 'sha256': 'source-digest'}}, stream)
            for name in ('fhe-pod-package-lock.json','fhe-pod-installed-lock.json',
                         'BN254-Signatures-package-lock.json',
                         'BN254-Signatures-installed-lock.json'):
                (run / 'build-evidence' / name).write_text('{}')
            state = {'status': 'passed', 'source': source, 'config': cfg, 'datasets': {}}
            (run / 'state.json').write_text(json.dumps(state))
            for name in ('application.json', 'results.json', 'onchain-release-evidence.json',
                         'release-capacity-preflight.json',
                         'policy-refresh-v3-evidence.json'):
                (run / 'reports' / name).write_text('{}')
            files = {path.relative_to(run).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in run.rglob('*') if path.is_file()}
            base = {
                'version': campaign.VERSION, 'source': source, 'files': files,
                'classification': summary['classification'], 'parameters': cfg['parameters'],
                'halves': ['linear'], 'evidenceProfile': summary['profile'],
                'designSha256': summary['designSha256'],
                'policyLineage': summary['policyLineage'],
                'policyRefreshAttemptId': summary['policyRefreshAttemptId'],
                'legacyEvidenceImported': summary['legacyEvidenceImported'],
                'pairedMeasurementsExecuted': summary['pairedMeasurementsExecuted'],
            }

            def save(value):
                value['sealPayloadSha256'] = campaign.seal_payload_sha256(value)
                (run / 'seal.json').write_text(json.dumps(value))

            save(copy.deepcopy(base))
            with patch.object(campaign, 'source_manifest', return_value=source), \
                 patch.object(campaign, 'validate_policy_refresh_run', return_value=summary) as validate:
                self.assertEqual(campaign.verify(run)['evidenceProfile'], summary['profile'])
                validate.assert_called_once_with(run.resolve())

            changed = copy.deepcopy(base)
            changed['files'].pop('reports/release-capacity-preflight.json')
            save(changed)
            with patch.object(campaign, 'source_manifest', return_value=source), \
                 patch.object(campaign, 'validate_policy_refresh_run', return_value=summary), \
                 self.assertRaisesRegex(ValueError, 'omits a validated report'):
                campaign.verify(run)

            changed = copy.deepcopy(base)
            changed['files'].pop('keyset/evaluation-key.bin')
            save(changed)
            with patch.object(campaign, 'source_manifest', return_value=source), \
                 patch.object(campaign, 'validate_policy_refresh_run', return_value=summary), \
                 self.assertRaisesRegex(ValueError, 'critical keyset'):
                campaign.verify(run)

            changed = copy.deepcopy(base)
            changed['files']['../outside.json'] = '00' * 32
            save(changed)
            with patch.object(campaign, 'source_manifest', return_value=source), \
                 self.assertRaisesRegex(ValueError, 'noncanonical seal file path'):
                campaign.verify(run)

            inventory_path = run / 'build-evidence/installed-files.json.gz'
            with gzip.open(inventory_path,'wt',encoding='utf-8') as stream:
                json.dump({'campaign/run.py': {'bytes': 1, 'sha256': 'attacker-source'}}, stream)
            changed = copy.deepcopy(base)
            changed['files']['build-evidence/installed-files.json.gz'] = hashlib.sha256(
                inventory_path.read_bytes()).hexdigest()
            save(changed)
            with patch.object(campaign, 'source_manifest', return_value=source), \
                 patch.object(campaign, 'validate_policy_refresh_run', return_value=summary), \
                 self.assertRaisesRegex(ValueError, 'installed source differs'):
                campaign.verify(run)
            with gzip.open(inventory_path,'wt',encoding='utf-8') as stream:
                json.dump({'campaign/run.py': {'bytes': 1, 'sha256': 'source-digest'}}, stream)
            base['files']['build-evidence/installed-files.json.gz'] = hashlib.sha256(
                inventory_path.read_bytes()).hexdigest()

            mutations = {
                'classification': 'dataset-real-threshold-besu',
                'parameters': 'Default',
                'halves': ['nonlinear'],
                'evidenceProfile': 'wrong-profile',
                'designSha256': '00' * 32,
                'policyLineage': 'new-lineage',
                'policyRefreshAttemptId': 'different-attempt',
                'legacyEvidenceImported': True,
                'pairedMeasurementsExecuted': 1,
            }
            for field, value in mutations.items():
                changed = copy.deepcopy(base)
                changed[field] = value
                save(changed)
                with self.subTest(field=field), \
                     patch.object(campaign, 'source_manifest', return_value=source), \
                     patch.object(campaign, 'validate_policy_refresh_run', return_value=summary), \
                     self.assertRaises(ValueError):
                    campaign.verify(run)

            changed = copy.deepcopy(base)
            save(changed)
            changed['sealPayloadSha256'] = 'ff' * 32
            (run / 'seal.json').write_text(json.dumps(changed))
            with patch.object(campaign, 'source_manifest', return_value=source), \
                 patch.object(campaign, 'validate_policy_refresh_run', return_value=summary), \
                 self.assertRaisesRegex(ValueError, 'metadata digest'):
                campaign.verify(run)


if __name__ == '__main__':
    unittest.main()
