"""Frozen V3 full-case refresh plan and fail-closed evidence checks.

This profile reruns only the full cases whose measured workflow changed when
the trusted release gateway was replaced by the V3 on-chain policy. It does
not execute, import, or relabel the paired component measurements.
"""
import hashlib
import json
import os
from pathlib import Path
import time
import uuid


if os.name == 'nt':
    import msvcrt
else:
    import fcntl

from poc_plan import plan as poc_plan, validate_timing_window


PROFILE = 'v3-policy-refresh-full-cases-v1'
CLASSIFICATION = 'test-insecure-v3-policy-refresh-complete'
SCHEMA = 'vcfhe-v3-policy-refresh-evidence-v1'
PREFLIGHT_SCHEMA = 'vcfhe-v3-policy-refresh-capacity-preflight-v1'
REQUIRED_POLICY_LINEAGE = 'existing-on-chain-lineage'
ATTEMPT_SCHEMA = 'vcfhe-v3-policy-refresh-attempt-claims-v1'
ATTEMPT_FILE = 'v3-policy-refresh-attempts.json'
ATTEMPT_LOCK = 'v3-policy-refresh-attempts.lock'
RECOVERY_MESSAGE = (
    'Do not start a fresh run or replay releases. Recovery requires a separately '
    'reviewed continuation that reuses the preserved evidence and keyset.'
)


def require(value, message):
    if not value:
        raise ValueError(message)


def _scopes(half):
    if half == 'both':
        return ('linear', 'nonlinear')
    if half in ('linear', 'nonlinear'):
        return (half,)
    raise ValueError('unknown V3 policy-refresh campaign half')


def _empty_attempts():
    return {
        'schema': ATTEMPT_SCHEMA,
        'profile': PROFILE,
        'policyLineage': REQUIRED_POLICY_LINEAGE,
        'claims': {},
    }


def _read_attempts(state_root):
    path = Path(state_root) / ATTEMPT_FILE
    if not path.exists():
        return _empty_attempts()
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError('V3 policy-refresh attempt claims are unreadable; ' +
                         RECOVERY_MESSAGE) from error
    require(isinstance(value, dict)
            and value.get('schema') == ATTEMPT_SCHEMA
            and value.get('profile') == PROFILE
            and value.get('policyLineage') == REQUIRED_POLICY_LINEAGE
            and isinstance(value.get('claims'), dict),
            'V3 policy-refresh attempt claims have an unknown format; ' +
            RECOVERY_MESSAGE)
    for scope, claim in value['claims'].items():
        require(scope in ('linear', 'nonlinear')
                and isinstance(claim, dict)
                and claim.get('scope') == scope
                and claim.get('requestedHalf') in ('linear', 'nonlinear', 'both')
                and scope in _scopes(claim['requestedHalf'])
                and claim.get('claimedScopes') == list(_scopes(claim['requestedHalf']))
                and isinstance(claim.get('attemptId'), str) and claim['attemptId']
                and isinstance(claim.get('runId'), str) and claim['runId']
                and isinstance(claim.get('runDirectory'), str) and claim['runDirectory']
                and isinstance(claim.get('designSha256'), str)
                and len(claim['designSha256']) == 64
                and all(character in '0123456789abcdef'
                        for character in claim['designSha256'].lower())
                and isinstance(claim.get('createdUnixNs'), int)
                and claim['createdUnixNs'] > 0
                and claim.get('status') == 'permanently-claimed',
                'V3 policy-refresh attempt claims are malformed; ' + RECOVERY_MESSAGE)
    combined = [claim for claim in value['claims'].values()
                if claim['requestedHalf'] == 'both']
    if combined:
        require(set(value['claims']) == {'linear', 'nonlinear'}
                and len(combined) == 2
                and all({key: claim[key] for key in claim if key != 'scope'}
                        == {key: combined[0][key] for key in combined[0]
                            if key != 'scope'}
                        for claim in combined[1:]),
                'combined V3 policy-refresh attempt claim is incomplete; ' +
                RECOVERY_MESSAGE)
    return value


def _conflicts(value, half):
    return [value['claims'][scope] for scope in _scopes(half)
            if scope in value['claims']]


def assert_attempt_available(state_root, half):
    """Read-only early check; reserve_attempt performs the atomic decision."""
    conflicts = _conflicts(_read_attempts(state_root), half)
    if conflicts:
        occupied = ', '.join(sorted(claim['scope'] for claim in conflicts))
        runs = ', '.join(sorted({claim['runId'] for claim in conflicts}))
        raise ValueError(
            f'V3 policy-refresh scope already claimed ({occupied}) by {runs}. ' +
            RECOVERY_MESSAGE)


class _AttemptLock:
    def __init__(self, path):
        self.path = Path(path)
        self.handle = None

    def __enter__(self):
        self.handle = self.path.open('a+b')
        if os.name == 'nt':
            self.handle.seek(0, os.SEEK_END)
            if self.handle.tell() == 0:
                self.handle.write(b'\0')
                self.handle.flush()
                os.fsync(self.handle.fileno())
            self.handle.seek(0)
            msvcrt.locking(self.handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            fcntl.flock(self.handle, fcntl.LOCK_EX)
        return self.handle

    def __exit__(self, exc_type, exc_value, traceback):
        if os.name == 'nt':
            self.handle.seek(0)
            msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(self.handle, fcntl.LOCK_UN)
        self.handle.close()


def _write_attempts(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x', encoding='utf-8') as stream:
            os.chmod(temporary, 0o600)
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        if os.name != 'nt':
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def reserve_attempt(state_root, half, run_id, run_directory, design):
    """Permanently claim release scopes after preflight and before evaluation."""
    expected = plan(half)
    require(design == expected, 'cannot claim a changed V3 policy-refresh design')
    require(isinstance(run_id, str) and run_id,
            'V3 policy-refresh attempt requires a run identifier')
    run_directory = str(Path(run_directory).resolve())
    root = Path(state_root)
    root.mkdir(parents=True, exist_ok=True)
    with _AttemptLock(root / ATTEMPT_LOCK):
        value = _read_attempts(root)
        conflicts = _conflicts(value, half)
        if conflicts:
            occupied = ', '.join(sorted(claim['scope'] for claim in conflicts))
            runs = ', '.join(sorted({claim['runId'] for claim in conflicts}))
            raise ValueError(
                f'V3 policy-refresh scope already claimed ({occupied}) by {runs}. ' +
                RECOVERY_MESSAGE)
        attempt_id = uuid.uuid4().hex
        common = {
            'attemptId': attempt_id,
            'requestedHalf': half,
            'claimedScopes': list(_scopes(half)),
            'runId': run_id,
            'runDirectory': run_directory,
            'designSha256': design['designSha256'],
            'createdUnixNs': time.time_ns(),
            'status': 'permanently-claimed',
        }
        for scope in _scopes(half):
            value['claims'][scope] = common | {'scope': scope}
        _write_attempts(root / ATTEMPT_FILE, value)
    return common


def plan(half):
    """Select the frozen full-case indices without constructing paired jobs."""
    if half not in ('both', 'linear', 'nonlinear'):
        raise ValueError('unknown V3 policy-refresh campaign half')
    source = poc_plan(half)
    jobs = []
    for job in source['jobs']:
        if not job['fullCase']:
            continue
        jobs.append({key: job[key] for key in
                     ('name', 'group', 'half', 'workload', 'n', 'repeat',
                      'fullCase', 'faultPosition')} |
                    {'sourceOrdinal': job['ordinal']})
    result = {
        'profile': PROFILE,
        'half': half,
        'parameters': 'Test',
        'classification': CLASSIFICATION,
        'sourceProfile': source['profile'],
        'sourceDesignSha256': source['designSha256'],
        'globalSourceDesignSha256': poc_plan('both')['designSha256'],
        'selectionRule': 'preselected full-case repeat indices from the frozen Test PoC design',
        'windowSeconds': source['windowSeconds'],
        'disclosureBatchSize': source['disclosureBatchSize'],
        'selectionProfile': source['selectionProfile'],
        'freshEncryptionPerCase': True,
        'newThresholdSetup': True,
        'pairedMeasurementsExecuted': 0,
        'legacyEvidenceImported': False,
        'fullCases': len(jobs),
        'jobs': jobs,
    }
    expected = {'linear': 15, 'nonlinear': 30, 'both': 45}[half]
    require(len(jobs) == expected, 'changed V3 policy-refresh full-case count')
    validate_timing_window(result['windowSeconds'], result['disclosureBatchSize'])
    result['designSha256'] = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return result


def validate_preclaim_config(cfg):
    """Validate the immutable refresh design before a durable attempt exists."""
    expected = plan(cfg.get('half'))
    require(cfg.get('policyRefreshPlan') == expected,
            'changed or incomplete V3 policy-refresh design')
    require(not cfg.get('pocPlan'),
            'V3 policy refresh cannot contain the paired Test PoC plan')
    require(cfg.get('parameters') == 'Test' and not cfg.get('smoke')
            and not cfg.get('readinessOnly'),
            'V3 policy refresh must be the complete explicit Test profile')
    require(cfg.get('classification') == CLASSIFICATION,
            'wrong V3 policy-refresh classification')
    require(cfg.get('policyLineage') == REQUIRED_POLICY_LINEAGE,
            'V3 policy refresh must reuse the existing on-chain policy lineage and live counters')
    require(cfg.get('windowSeconds') == expected['windowSeconds']
            and cfg.get('disclosureBatchSize') == expected['disclosureBatchSize']
            and cfg.get('selectionProfile') == expected['selectionProfile'],
            'changed V3 policy-refresh execution selection')
    return expected


def validate_config(cfg):
    expected = validate_preclaim_config(cfg)
    attempt = cfg.get('policyRefreshAttempt')
    require(isinstance(attempt, dict)
            and isinstance(attempt.get('attemptId'), str) and attempt['attemptId']
            and attempt.get('requestedHalf') == cfg.get('half')
            and attempt.get('claimedScopes') == list(_scopes(cfg.get('half')))
            and attempt.get('runId') == cfg.get('runId')
            and attempt.get('designSha256') == expected['designSha256']
            and attempt.get('status') == 'permanently-claimed',
            'missing or changed durable V3 policy-refresh attempt claim')
    return expected


def _hex_word(value):
    return (isinstance(value, str) and len(value) == 66 and value.startswith('0x')
            and all(character in '0123456789abcdef' for character in value[2:].lower()))


def validate_prepared_preflight(cfg, prepared, keyset, report):
    """Validate the passive owner preparation before reserving a release attempt."""
    design = validate_preclaim_config(cfg)
    require(isinstance(prepared, dict) and isinstance(keyset, dict)
            and prepared.get('keys') == keyset,
            'prepared fixtures are not bound to the completed threshold keyset')
    require(keyset.get('status') == 'passed'
            and keyset.get('parameters') == cfg.get('parameters')
            and type(keyset.get('parties')) is int and keyset['parties'] == 4
            and type(keyset.get('corruptionThreshold')) is int
            and keyset['corruptionThreshold'] == 1
            and keyset.get('fullPreprocessing') is True
            and keyset.get('preloadedFheKey') is False
            and all(_hex_word(keyset.get(field)) for field in
                    ('keyId', 'keyEpoch', 'mpcContext', 'keysetDigest')),
            'threshold keyset is incomplete or has the wrong status')

    cases = prepared.get('cases')
    jobs = design['jobs']
    require(isinstance(cases, list) and len(cases) == len(jobs),
            'prepared fixtures have the wrong V3 policy-refresh case count')
    expected_records = {}
    for case, job in zip(cases, jobs, strict=True):
        require(isinstance(case, dict)
                and all(case.get(key) == value for key, value in job.items()),
                'prepared fixtures have the wrong V3 policy-refresh case sequence')
        record_ids = case.get('recordIds')
        limits = case.get('releaseLimits')
        initial = case.get('initialSpent')
        require(isinstance(record_ids, list) and record_ids
                and isinstance(limits, list) and isinstance(initial, list)
                and len(record_ids) == len(limits) == len(initial) == job['n']
                and len(set(record_ids)) == len(record_ids),
                'prepared case has incomplete protected-record capacity inputs')
        for record_id, limit, initial_spent in zip(record_ids, limits, initial, strict=True):
            require(_hex_word(record_id)
                    and isinstance(limit, int) and not isinstance(limit, bool) and limit > 0
                    and isinstance(initial_spent, int) and not isinstance(initial_spent, bool)
                    and 0 <= initial_spent <= limit,
                    'prepared case has invalid protected-record capacity inputs')
            current = expected_records.setdefault(record_id, {
                'releaseLimit': limit, 'minimumCurrentSpent': initial_spent,
                'plannedCharges': 0})
            require(current['releaseLimit'] == limit,
                    'protected-record release limit changed across prepared cases')
            current['minimumCurrentSpent'] = max(current['minimumCurrentSpent'], initial_spent)
            current['plannedCharges'] += 1

    require(isinstance(report, dict)
            and report.get('schema') == PREFLIGHT_SCHEMA
            and report.get('status') == 'passed'
            and report.get('profile') == design['profile']
            and report.get('designSha256') == design['designSha256']
            and report.get('half') == design['half']
            and report.get('parameters') == cfg.get('parameters')
            and report.get('keysetDigest') == keyset['keysetDigest']
            and report.get('caseCount') == len(jobs)
            and report.get('caseNames') == [job['name'] for job in jobs],
            'capacity preflight is not bound to the exact prepared refresh')
    view = report.get('view')
    require(isinstance(view, dict)
            and isinstance(view.get('blockNumber'), int)
            and not isinstance(view['blockNumber'], bool) and view['blockNumber'] >= 0
            and _hex_word(view.get('blockHash')) and _hex_word(view.get('parentHash'))
            and view.get('validatorCount') == 4
            and view.get('confirmationQuorum') == 3
            and isinstance(view.get('participantCount'), int)
            and 3 <= view['participantCount'] <= 4
            and isinstance(view.get('supporterCount'), int)
            and 3 <= view['supporterCount'] <= view['participantCount'],
            'capacity preflight has no valid quorum-pinned block view')

    records = report.get('records')
    require(isinstance(records, list)
            and all(isinstance(row, dict) for row in records)
            and [row.get('recordId') for row in records]
            == sorted(expected_records)
            and report.get('recordCount') == len(expected_records),
            'capacity preflight covers a different protected-record set')
    normalized = []
    for row in records:
        require(isinstance(row, dict) and set(row) == {
                    'recordId', 'releaseLimit', 'currentSpent',
                    'plannedCharges', 'remainingAfterPlan'},
                'capacity preflight record has an unknown format')
        expected = expected_records.get(row['recordId'])
        require(expected is not None
                and row.get('releaseLimit') == expected['releaseLimit']
                and row.get('plannedCharges') == expected['plannedCharges']
                and isinstance(row.get('currentSpent'), int)
                and not isinstance(row['currentSpent'], bool)
                and expected['minimumCurrentSpent'] <= row['currentSpent']
                and row['currentSpent'] + row['plannedCharges'] <= row['releaseLimit']
                and row.get('remainingAfterPlan')
                == row['releaseLimit'] - row['currentSpent'] - row['plannedCharges'],
                'capacity preflight record does not match the prepared release plan')
        normalized.append(row)
    limits = [row['releaseLimit'] for row in normalized]
    require(normalized
            and report.get('maxCurrentSpent') == max(row['currentSpent'] for row in normalized)
            and report.get('maxPlannedCharges') == max(row['plannedCharges'] for row in normalized)
            and report.get('minRemainingAfterPlan') == min(row['remainingAfterPlan'] for row in normalized)
            and report.get('limits') == {'minimum': min(limits), 'maximum': max(limits)},
            'capacity preflight summary does not match its protected-record rows')
    return design


def _validate_case(case, job):
    require(all(case.get(key) == value for key, value in job.items()),
            'wrong preselected V3 policy-refresh case')
    require(case.get('finalOutputKmsCalls') == 1,
            'wrong V3 policy-refresh release count')
    scopes = case.get('receiptScopes')
    require(isinstance(scopes, dict) and scopes,
            'missing V3 policy-refresh transaction scopes')
    require(sum(value['transactionCount'] for value in scopes.values())
            == case.get('transactionCount')
            and sum(int(value['gasUsed']) for value in scopes.values())
            == int(case.get('gasUsed'))
            and sum(value['calldataBytes'] for value in scopes.values())
            == case.get('calldataBytes'),
            'V3 policy-refresh transaction scopes do not reconcile')
    metrics = case.get('metrics', {})
    if job['half'] == 'linear':
        require(metrics.get('baselineProfile') == 'ordinary-bls-canonical-vector-v1',
                'obsolete linear full-case baseline')
        return
    expected_leaves = ({16: 128, 32: 256, 50: 512}
                       if job['workload'] == 'regional_qoe_compliance'
                       else {16: 64, 32: 128, 50: 128})[job['n']]
    require(metrics.get('leaves') == expected_leaves,
            'wrong V3 policy-refresh dataset circuit size')
    disputes = metrics.get('disputes', [])
    require(len(disputes) == 1, 'missing V3 policy-refresh full dispute')
    terminal = expected_leaves - 1
    fault = {'early': 0, 'middle': terminal // 2, 'terminal': terminal}[
        job['faultPosition']]
    dispute = disputes[0]
    settlement = dispute.get('settlement', {})
    require(dispute.get('faultIndex') == fault
            and settlement.get('index') == fault
            and settlement.get('state', [])[:3] == [3, 2, True],
            'V3 policy-refresh fault coverage or settlement mismatch')
    certificates = settlement.get('certificates', [])
    require(len(certificates) == 2
            and all(value.get('plaintextOpenings') == 0 for value in certificates),
            'invalid V3 policy-refresh leaf evidence')


def validate_application(cfg, app, onchain):
    design = validate_config(cfg)
    require(app.get('config') == cfg,
            'application evidence is not bound to the exact V3 policy-refresh configuration')
    jobs = design['jobs']
    cases = app.get('cases', [])
    require(app.get('status') == 'passed', 'V3 policy-refresh application did not pass')
    require(len(cases) == design['fullCases']
            and app.get('kmsCalls') == design['fullCases'],
            'incomplete V3 policy-refresh full-case/release grid')
    for case, job in zip(cases, jobs, strict=True):
        _validate_case(case, job)
    require(onchain.get('status') == 'passed'
            and onchain.get('policyVersion') == 3
            and onchain.get('validatorCount') == 4
            and onchain.get('validatorConfirmationQuorum') == 3
            and isinstance(onchain.get('ownerIdentitySetSha256'), str)
            and len(onchain['ownerIdentitySetSha256']) == 64
            and all(character in '0123456789abcdef'
                    for character in onchain['ownerIdentitySetSha256'].lower()),
            'missing validated V3 on-chain release evidence')
    require(onchain.get('caseCount') == design['fullCases'],
            'V3 on-chain evidence has the wrong case count')
    require([case.get('name') for case in onchain.get('cases', [])]
            == [job['name'] for job in jobs],
            'V3 on-chain evidence covers a different case sequence')
    return design


def evidence_summary(cfg, app, onchain):
    design = validate_application(cfg, app, onchain)
    keyset = app.get('keys', {})
    return {
        'schema': SCHEMA,
        'status': 'passed',
        'classification': CLASSIFICATION,
        'half': design['half'],
        'profile': design['profile'],
        'designSha256': design['designSha256'],
        'sourceDesignSha256': design['sourceDesignSha256'],
        'globalSourceDesignSha256': design['globalSourceDesignSha256'],
        'fullCases': design['fullCases'],
        'caseNames': [job['name'] for job in design['jobs']],
        'repeatIndicesByGroup': {
            group: [job['repeat'] for job in design['jobs'] if job['group'] == group]
            for group in dict.fromkeys(job['group'] for job in design['jobs'])
        },
        'faultPositions': {
            job['name']: job['faultPosition'] for job in design['jobs']
            if job['half'] == 'nonlinear'
        },
        'policyVersion': onchain['policyVersion'],
        'validatorConfirmationQuorum': onchain['validatorConfirmationQuorum'],
        'onChainEvidenceInputSha256': onchain['inputSha256'],
        'ownerIdentitySetSha256': onchain['ownerIdentitySetSha256'],
        'policyLineage': cfg['policyLineage'],
        'policyRefreshAttemptId': cfg['policyRefreshAttempt']['attemptId'],
        'keysetDigest': keyset.get('keysetDigest'),
        'pairedMeasurementsExecuted': design['pairedMeasurementsExecuted'],
        'comparisonPairsExecuted': 0,
        'legacyEvidenceImported': design['legacyEvidenceImported'],
        'analysisComplete': False,
        'limitations': [
            'Insecure Test parameters on one host do not establish confidentiality, secure-profile performance, or independent administration.',
            'This standalone refresh makes no identity claim about the legacy paired campaign source closure, keyset, or ciphertext fixtures.',
            'No legacy paired measurements are imported or relabelled as V3 evidence.',
            'The refresh reuses the persistent V3 on-chain policy and its live cumulative counters. It does not reset policy state.',
            'A cross-path shared-keyset claim requires one combined half=both refresh. Separate linear and nonlinear invocations generate separate keysets.',
            'Publication requires a separate reviewed composition gate.'
        ],
    }


def write_evidence(run, cfg, app, onchain):
    summary = evidence_summary(cfg, app, onchain)
    target = Path(run) / 'reports' / 'policy-refresh-v3-evidence.json'
    target.write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n',
                      encoding='utf-8')
    return summary


def validate_run_directory(run, require_report=True):
    """Re-run the V3 validator and policy-refresh checks for a sealed run."""
    from onchain_evidence import validate_run as validate_onchain_run

    run = Path(run).resolve()
    cfg = json.loads((run / 'config' / 'campaign.json').read_text(encoding='utf-8'))
    prepared = json.loads((run / 'fixtures' / 'prepared.json').read_text(encoding='utf-8'))
    keyset = json.loads((run / 'keyset' / 'ready.json').read_text(encoding='utf-8'))
    preflight = json.loads((run / 'reports' / 'release-capacity-preflight.json').read_text(
        encoding='utf-8'))
    validate_prepared_preflight(cfg, prepared, keyset, preflight)
    app = json.loads((run / 'reports' / 'application.json').read_text(encoding='utf-8'))
    require(not (run / 'reports' / 'paired.json').exists(),
            'V3 policy-refresh evidence unexpectedly contains paired measurements')
    onchain = validate_onchain_run(run)
    summary = evidence_summary(cfg, app, onchain)
    if require_report:
        recorded = json.loads((run / 'reports' / 'policy-refresh-v3-evidence.json').read_text(
            encoding='utf-8'))
        require(recorded == summary, 'changed V3 policy-refresh evidence summary')
        results = json.loads((run / 'reports' / 'results.json').read_text(encoding='utf-8'))
        exported_onchain = json.loads((run / 'reports' / 'onchain-release-evidence.json').read_text(
            encoding='utf-8'))
        require(results.get('onChainReleaseEvidence') == onchain,
                'results report is not bound to the revalidated V3 on-chain evidence')
        require(exported_onchain == onchain,
                'exported V3 on-chain evidence differs from the revalidated raw evidence')
    return summary
