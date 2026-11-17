#!/usr/bin/env python3
"""Read-only validation of an explicitly continued Test campaign.

Never changes a run, ledger or campaign seal. Optional output is an exclusive new
directory under threshold-kms/composites; it is NOT a analysis completion.
The original measured validator is loaded from its verified source cache.
"""
import argparse
import collections
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
MODULE = HERE.parent
ROOT = MODULE.parent
PROFILE = 'same-keyset-full-case-continuation-v1'


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def ledger_wire_sha(value):
    # The ledger uses JS JSON.stringify; recovery's write() pretty-prints its
    # snapshot without reordering keys. Bind the exact original compact bytes.
    return hashlib.sha256(json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def member(root, name):
    p = Path(name)
    require(not p.is_absolute() and '..' not in p.parts, 'unsafe inventory path')
    # No symlinked ancestor may redirect a sealed file outside its run.
    for ancestor in p.parents:
        require(not (root / ancestor).is_symlink(), 'symlinked inventory ancestor')
    return root / p


def verify_files(root, files):
    for i, (name, digest) in enumerate(files.items(), 1):
        p = member(root, name)
        if isinstance(digest, dict):
            require(set(digest) == {'symlink'} and p.is_symlink()
                    and os.readlink(p) == digest['symlink'], 'changed inventoried link: ' + name)
        else:
            require(p.is_file() and not p.is_symlink() and sha(p) == digest,
                    'changed inventoried file: ' + name)
        if i % 50000 == 0:
            print(f'Verified {i} entries in {root.name}', flush=True)


def unchanged_subset(before, after, label):
    require(all(k in after and after[k] == v for k, v in before.items()),
            'changed prior ' + label)


def verify_ledger(before, after, cases, requests, limit):
    require(before['domain'] == after['domain'] and before['version'] == after['version'],
            'changed policy domain/version')
    for field in ['slots', 'consents', 'requests']:
        unchanged_subset(before[field], after[field], field)
    new_slots = {r['slot'] for r in requests}
    require(len(new_slots) == len(cases), 'duplicate continuation slot')
    require(set(after['slots']) - set(before['slots']) == new_slots, 'unexpected new release slots')
    require(set(after['consents']) - set(before['consents']) == new_slots, 'unexpected new consents')
    require(set(after['requests']) - set(before['requests']) == {r['requestId'] for r in requests},
            'unexpected new MPC request')
    charges = collections.Counter(r for c in cases for r in c['recordIds'])
    owners = {}
    for case in cases:
        require(len(set(case['recordIds'])) == case['n'], 'invalid protected record selection')
        for rid, owner in zip(case['recordIds'], case['owners'], strict=True):
            owner = owner.lower()
            require(rid not in owners or owners[rid] == owner, 'record owner changed')
            owners[rid] = owner
    require(set(after['records']) == set(before['records']) | set(charges), 'changed record inventory')
    for rid, record in after['records'].items():
        old = before['records'].get(rid, {'owner': owners.get(rid), 'limit': limit, 'spent': 0})
        require(set(record) == {'owner', 'limit', 'spent'} and record['owner'] == old['owner']
                and record['limit'] == old['limit']
                and type(record['spent']) is int and record['spent'] == old['spent'] + charges[rid]
                and 0 <= record['spent'] <= record['limit'], 'invalid cumulative record delta')
    for case, request in zip(cases, requests, strict=True):
        slot = request['slot']
        require(after['slots'][slot] == {'state': 'released', 'requestId': request['requestId'],
                                        'kmsRequestDigest': request['kmsRequestDigest']},
                'slot/request binding mismatch')
        require(after['requests'][request['requestId']] == slot, 'request replay mapping mismatch')
        saved = after['consents'][slot]
        consent = saved['consent']
        require(saved['id'] == request['consentId'] and consent['recordIds'] == case['recordIds']
                and request['recipient'] in consent['recipients'], 'consent/record/recipient mismatch')
        for field in ['slot', 'domain', 'chainId', 'game', 'keyId', 'keyEpoch', 'keysetDigest',
                      'mpcContext', 'programDigest', 'profileDigest', 'contextDigest', 'outputType']:
            require(consent[field] == request[field], 'consent context mismatch: ' + field)
    return {'newReleases': len(new_slots), 'chargedRecords': len(charges),
            'maximumAdditionalCharge': max(charges.values())}


def validate(original, segment):
    require(original.parent == segment.parent == MODULE / 'runs' and original != segment,
            'runs must be distinct direct children of threshold-kms/runs')
    preservation = read(segment / 'original-preservation.json')
    seal = read(segment / 'segment-seal.json')
    require(preservation['classification'] == 'failed-run-preservation-only', 'wrong preservation class')
    require(seal['profile'] == PROFILE and seal['classification'] == 'continuation-not-standalone-evaluation',
            'wrong continuation seal class')
    verify_files(original, preservation['files'])
    verify_files(segment, seal['files'])
    old = read(original / 'state.json')
    state = read(segment / 'state.json')
    plan = read(segment / 'plan.json')
    require(old['status'] == 'failed' and not (original / 'seal.json').exists(), 'predecessor relabelled')
    require(state['status'] == 'passed' and state['analysisComplete'] is False
            and state['planSha256'] == sha(segment / 'plan.json')
            and state['originalRun'] == plan['originalRun'] == str(original), 'invalid continuation state')
    for field, rel in [('preservationSha256', 'original-preservation.json'), ('configSha256', 'config/campaign.json'),
                       ('composeSha256', 'compose.json'), ('preparedSha256', 'fixtures/prepared.json')]:
        require(plan[field] == sha(segment / rel), 'changed continuation plan binding: ' + field)
    require(plan['profile'] == PROFILE and plan['imageId'] == old['imageId'], 'image/profile divergence')
    cache_id = hashlib.sha256(json.dumps(old['source'], sort_keys=True).encode()).hexdigest()
    cache = MODULE / '.cache' / cache_id
    saved = read(cache / 'complete.json')
    require(saved['source'] == old['source'] and saved['upstream'] == old['upstream'], 'wrong measured cache')
    verify_files(cache / 'app', old['source'])
    verify_files(MODULE / 'recovery', plan['recoverySource'])
    verify_files(segment / 'overlays', plan['overlays'])
    for name, metadata in old['datasets'].items():
        require(sha(member(ROOT, name)) == metadata['sha256'], 'changed source dataset')
    owner_source = (cache / 'app/threshold-kms/campaign/owner.mjs').read_text()
    evaluation_source = (cache / 'app/threshold-kms/campaign/evaluate.mjs').read_text()
    guard = ("assert.equal(cfg.recovery.profile, '" + PROFILE + "');\n"
             " assert.deepEqual(prepared.cases.map(c=>c.name),cfg.recovery.remainingCases);\n"
             " await waitFile('/owner-rpc/recovery-ready.json',60);")
    for source, anchor, replacement, name in [
        (owner_source, 'await prepare();', (MODULE / 'recovery/owner-restore.mjs').read_text(), 'owner'),
        (evaluation_source, 'if(cfg.pocPlan)await runPairs(cfg,prepared);', guard, 'evaluate')]:
        require(source.count(anchor) == 1 and source.replace(anchor, replacement)
                == (segment / 'overlays' / (name + '.mjs')).read_text(), 'unexpected measured overlay')
    cfg = read(original / 'config/campaign.json')
    new_cfg = read(segment / 'config/campaign.json')
    prior = read(original / 'reports/application.json')
    app = read(segment / 'reports/application.json')
    require(cfg == old['config'] == prior['config'] and app['config'] == new_cfg, 'config/report divergence')
    require(new_cfg['runId'] == segment.name and new_cfg['recovery'] == {k: v for k, v in plan.items()
            if k not in ['recoverySource', 'overlays', 'preservationSha256', 'configSha256', 'composeSha256', 'preparedSha256']},
            'unexpected recovery configuration')
    require({k: v for k, v in new_cfg.items() if k not in ['runId', 'recovery']}
            == {k: v for k, v in cfg.items() if k != 'runId'}, 'changed measured parameters')
    prepared = read(original / 'fixtures/prepared.json')
    continued = read(segment / 'fixtures/prepared.json')
    keys = read(original / 'keyset/ready.json')
    require(keys == prepared['keys'] == continued['keys'] == prior['keys'] == app['keys']
            and keys['parameters'] == 'Test' and keys['status'] == 'passed'
            and keys['fullPreprocessing'] is True and keys['preloadedFheKey'] is False
            and keys['parties'] == 4, 'keyset/preprocessing mismatch')
    require(prior['status'] == 'failed' and app['status'] == 'passed'
            and prior['plaintextInGateway'] is False and app['plaintextInGateway'] is False,
            'application status/plaintext boundary mismatch')
    before_cases, after_cases = prior['cases'], app['cases']
    require(len(before_cases) == plan['completedCases'] and [c['name'] for c in after_cases] == plan['remainingCases'],
            'wrong prefix/suffix selection')
    wanted = {c['name']: c for c in prepared['cases']}
    require(continued['cases'] == [wanted[n] for n in plan['remainingCases']], 'changed encrypted input metadata')
    for case in continued['cases']:
        prefix = 'fixtures/' + case['name'] + '/public/'
        a = {k: v for k, v in preservation['files'].items() if k.startswith(prefix)}
        b = {k: v for k, v in seal['files'].items() if k.startswith(prefix)}
        require(a and a == b, 'continuation ciphertext closure differs')
    ready = read(segment / 'owner-rpc/recovery-ready.json')
    require(ready == {'names': plan['remainingCases'], 'keysetDigest': keys['keysetDigest']}, 'owner restore incomplete')
    # Import ONLY the verified measured validator; do not run campaign entry points.
    sys.path.insert(0, str(cache / 'app/threshold-kms/campaign'))
    import poc_evidence
    require(Path(poc_evidence.__file__).resolve().is_relative_to(cache), 'wrong validator import')
    paired = read(original / 'reports/paired.json')
    combined = {'cases': before_cases + after_cases, 'kmsCalls': prior['kmsCalls'] + app['kmsCalls']}
    design = poc_evidence.validate_full_cases(cfg, combined, paired)
    require(design['designSha256'] == plan['designSha256'], 'changed design fingerprint')
    expected = read(original / 'owner/expected.json')
    all_requests = []
    case_origins = []
    for run, cases in [(original, before_cases), (segment, after_cases)]:
        require(len(cases) == len(list((run / 'recipient').glob('result-*.json'))), 'unexpected recipient files')
        for prefix in ['request', 'wire', 'approved', 'responses']:
            require({p.name for p in (run / 'exchange').glob(prefix + '-*.json')}
                    == {f'{prefix}-{i}.json' for i in range(len(cases))}, 'ambiguous exchange closure')
        for i, case in enumerate(cases):
            result = read(run / f'recipient/result-{i}.json')
            request = read(run / f'exchange/wire-{i}.json')['request']
            require(result['name'] == case['name'] and result['actual'] == expected[case['name']]
                    and result['outputDigest'] == case['outputDigest'] == request['outputDigest'], 'incorrect recipient output')
            require([result[k] for k in ['responses', 'directUserAndPublicDenied', 'directAdministrativeDenied',
                    'changedSignedWireDenied', 'negativeResponseChecks']] == [3, 4, 28, 4, 4], 'recipient security checks missing')
            require(request['keysetDigest'] == keys['keysetDigest'], 'wrong request keyset')
            if case['half'] == 'nonlinear':
                require(case['metrics'].get('disputeCosts'), 'missing settled dispute cost evidence')
            all_requests.append(request)
            case_origins.append({'name': case['name'], 'run': str(run), 'caseIndex': i,
                                 'outputDigest': case['outputDigest']})
    require(len({r['requestId'] for r in all_requests}) == len(all_requests)
            and len({r['slot'] for r in all_requests}) == len(all_requests), 'replayed request/slot')
    # Slot Keccak uses the unchanged repository ethers dependency, not SHA3.
    labels = [f'{segment.name}:{c["name"]}:final' for c in after_cases]
    code = 'const {id}=require(process.argv[1]);console.log(JSON.stringify(JSON.parse(process.argv[2]).map(id)));'
    slots = json.loads(subprocess.check_output(['node', '-e', code, str(ROOT / 'fhe-pod/node_modules/ethers'),
                                               json.dumps(labels)], text=True))
    requests = all_requests[len(before_cases):]
    require(slots == [r['slot'] for r in requests], 'incorrect new slot labels')
    before = read(segment / 'reports/ledger-before.json')
    require(ledger_wire_sha(before) == plan['ledgerSha256Before'], 'wrong policy checkpoint')
    ledger_result = verify_ledger(before, app['ledger'], after_cases, requests, cfg['ownerReleaseLimit'])
    for request in all_requests[:len(before_cases)]:
        require(before['slots'][request['slot']] == {'state': 'released', 'requestId': request['requestId'],
                'kmsRequestDigest': request['kmsRequestDigest']}, 'missing predecessor release in checkpoint')
    return {'profile': 'test-poc-composite-evidence-v1', 'validation': 'passed', 'analysisComplete': False,
            'originalRun': str(original), 'continuationRun': str(segment),
            'originalPreservationSha256': sha(segment / 'original-preservation.json'),
            'segmentSealSha256': sha(segment / 'segment-seal.json'), 'planSha256': sha(segment / 'plan.json'),
            'verifierSha256': sha(Path(__file__)), 'sourceCache': str(cache),
            'designSha256': design['designSha256'], 'imageId': plan['imageId'], 'keysetDigest': keys['keysetDigest'],
            'measuredPairs': design['measuredPairs'], 'warmups': sum(r['warmup'] for r in paired['rows']),
            'fullCases': len(combined['cases']), 'prefixCases': len(before_cases), 'suffixCases': len(after_cases),
            'caseOrigins': case_origins, 'ledgerDelta': ledger_result,
            'classification': 'Test INSECURE; single-host functional PoC; interrupted full-case campaign',
            'limitations': ['All paired observations precede the interruption.',
                            'Full-case costs span two execution segments and are descriptive.',
                            'Aborted-attempt receipts remain diagnostic, not a completed repetition.',
                            'No secure-parameter performance/confidentiality or independent-party claim.'],
            'pending': ['workflow-stage export', 'statistical diagnostics', 'numerical package validation']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--segment', type=Path, required=True)
    parser.add_argument('--output', type=Path, help='New direct child of threshold-kms/composites, never a run')
    args = parser.parse_args()
    output = args.output.resolve() if args.output else None
    if output:
        require(output.parent == MODULE / 'composites' and not output.exists(), 'output must be a new composite directory')
    result = validate(args.original.resolve(), args.segment.resolve())
    if output:
        output.mkdir(parents=True, exist_ok=False)
        with (output / 'provenance.json').open('x') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'caseOrigins'}, indent=2))


if __name__ == '__main__':
    main()
