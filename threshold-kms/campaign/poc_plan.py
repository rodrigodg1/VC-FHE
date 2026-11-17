"""Frozen design of the approved Test PoC; this module does not launch runs.

Two distinct warm-up fixtures per configuration are never included in the 480
measured pairs. Each block of two pairs has opposite variant order, with the
first order fixed by a public hash before data collection. Full-case indices
are preselected, not chosen using measured performance. All pairs use fresh
owner encryption; only full cases may request recipient release.
"""
import argparse
import hashlib
import json

PROFILE = 'test-poc-paired-v1'
SEED = 'vcfhe-approved-poc-2026-09-16-v1'
LINEAR_SIZES = (10, 16, 27)
NONLINEAR_SIZES = (16, 32, 50)
FULL_REPEATS = {'linear': (0, 24, 49, 74, 99), 'nonlinear': (0, 7, 14, 22, 29)}
TEST_POC_WINDOW_SECONDS = 120
TEST_POC_DISCLOSURE_BATCH_SIZE = 64
TEST_POC_MAX_TRACE_LEAVES = 512
# Conservative observation from the passed V3 Test smoke: sequential receipts
# were separated by at most four 2-second QBFT blocks. This is an evaluation
# admission budget, not a bound supplied by the protocol or a deployment value.
TEST_POC_TX_INCLUSION_BUDGET_SECONDS = 8
TEST_POC_TIMING_MARGIN_SECONDS = 16


def validate_timing_window(window_seconds=TEST_POC_WINDOW_SECONDS,
                           disclosure_batch_size=TEST_POC_DISCLOSURE_BATCH_SIZE):
    """Reject a clearly infeasible Test-only window without certifying liveness."""
    values = [window_seconds, disclosure_batch_size, TEST_POC_MAX_TRACE_LEAVES,
              TEST_POC_TX_INCLUSION_BUDGET_SECONDS, TEST_POC_TIMING_MARGIN_SECONDS]
    if (any(not isinstance(value, int) or value < 1 for value in values)
            or disclosure_batch_size > 64):
        raise ValueError('invalid Test PoC timing parameter')
    disclosure_transactions = ((TEST_POC_MAX_TRACE_LEAVES + disclosure_batch_size - 1)
                               // disclosure_batch_size)
    phase_transactions = max(8, disclosure_transactions)  # six openings + seal/proof, or disclosure batches
    exclusive_floor = (phase_transactions * TEST_POC_TX_INCLUSION_BUDGET_SECONDS
                       + TEST_POC_TIMING_MARGIN_SECONDS)
    if window_seconds <= exclusive_floor:
        raise ValueError(f'Test PoC window must exceed {exclusive_floor} seconds; '
                         'this admission check does not establish deployment liveness')
    if window_seconds < TEST_POC_WINDOW_SECONDS:
        raise ValueError(f'Test PoC protocol window remains {TEST_POC_WINDOW_SECONDS} seconds; '
                         'a shorter value requires a separate largest-case validation under representative load')
    return {'windowSeconds': window_seconds, 'exclusiveFloorSeconds': exclusive_floor,
            'maximumTraceLeaves': TEST_POC_MAX_TRACE_LEAVES,
            'disclosureBatchSize': disclosure_batch_size,
            'maximumDisclosureBatches': disclosure_transactions,
            'transactionInclusionBudgetSeconds': TEST_POC_TX_INCLUSION_BUDGET_SECONDS,
            'marginSeconds': TEST_POC_TIMING_MARGIN_SECONDS}


def plan(half='both'):
    if half not in ('both', 'linear', 'nonlinear'):
        raise ValueError('unknown campaign half')
    groups = []
    if half != 'nonlinear':
        groups.extend(('linear', 'linear-acr', n, 100) for n in LINEAR_SIZES)
    if half != 'linear':
        groups.extend(('nonlinear', w + '_qoe_compliance', n, 30)
                      for w in ('regulatory', 'regional') for n in NONLINEAR_SIZES)
    jobs = []
    for kind, workload, n, repetitions in groups:
        group = f'{workload}-{n}'
        for repeat in range(-2, repetitions):
            warmup = repeat < 0
            block = (repeat + 2 if warmup else repeat) // 2
            digest = hashlib.sha256(f'{SEED}:{group}:{warmup}:{block}'.encode()).digest()
            reverse = bool((digest[0] & 1) ^ (repeat & 1))
            full = repeat in FULL_REPEATS[kind]
            fault = None
            if full and kind == 'nonlinear':
                fault = ('early', 'middle', 'terminal')[FULL_REPEATS[kind].index(repeat) % 3]
            jobs.append({'name': f'{group}-' + (f'warmup{repeat+2}' if warmup else str(repeat)),
                         'group': group, 'half': kind, 'workload': workload,
                         'n': n, 'repeat': repeat, 'warmup': warmup,
                         'fullCase': full, 'faultPosition': fault,
                         'order': ['baseline', 'proposed'] if reverse else ['proposed', 'baseline'],
                         'ordinal': len(jobs)})
    validate_timing_window()
    result = {'profile': PROFILE, 'seed': SEED, 'half': half,
              'parameters': 'Test', 'classification': 'test-insecure-functional-poc',
              'windowSeconds': TEST_POC_WINDOW_SECONDS,
              'disclosureBatchSize': TEST_POC_DISCLOSURE_BATCH_SIZE,
              'selectionProfile': 'poc-disjoint-panels-v1',
              'freshEncryptionPerJob': True, 'sharedCiphertextsWithinPair': True,
              'measurementPhaseBeforeFullCases': True,
              'warmupsPerConfiguration': 2,
              'measuredPairs': sum(not j['warmup'] for j in jobs),
              'fullCases': sum(j['fullCase'] for j in jobs), 'jobs': jobs}
    result['designSha256'] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--half', choices=('both', 'linear', 'nonlinear'), default='both')
    print(json.dumps(plan(parser.parse_args().half), indent=2))
