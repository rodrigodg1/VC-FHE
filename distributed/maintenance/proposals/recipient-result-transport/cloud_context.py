"""Cloud-only context transform used by distributed image preparation.

Call only on a NEW distributed copy, before buildInputs/distributed-source.json
are calculated. The shared local campaign and copied app/localSource stay exact.
This module performs no compilation, SDK, network or protocol operation.
"""
import hashlib
import json
from pathlib import Path
import shutil
import types

HERE = Path(__file__).resolve().parent
NATIVE = 'core-client/tests/integration/integration_test.rs'
TRANSPORT = 'threshold-kms/campaign/transport.rs'
VALIDATOR = 'threshold-kms/src/recipient_validation.rs'
STAGED = 'distributed/maintenance/proposals/recipient-result-transport'
VERSION = 'distributed-accepted-submit-results-v1'
EXPECTED_TRANSPORT = 'ac97b5b7199c4d002d83380db5173742cf5dbd9949ebc14728e5233b9d9953ba'
EXPECTED_VALIDATOR = '8b5cf6bb7b28e97edc63bcd032dbb029315ef1673b88451d922a51858f45cce1'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_inputs():
    return {p.relative_to(HERE).as_posix(): sha(p) for p in sorted(HERE.rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts and p.suffix in {'.py', '.rs', '.md'}}


def verify_source_inputs(provenance):
    if provenance.get('version') != VERSION or provenance.get('sourceFiles') != source_inputs():
        raise ValueError('The prepared cloud native transform has stale proposal inputs')


def _regular(path, context):
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(context):
        raise ValueError('Cloud context input is missing, linked or outside its fresh context')
    if path.stat().st_nlink != 1:
        raise ValueError('Cloud context input is hardlinked to another source view')
    return path


def _local_source(context, local_source):
    for name, expected in local_source.items():
        p = Path(name)
        if p.is_absolute() or '..' in p.parts or '\\' in name:
            raise ValueError('Invalid original localSource path')
        if sha(_regular(context/'app'/p, context)) != expected:
            raise ValueError('Copied shared localSource differs from the original source manifest')


def transform(context, local_source):
    context = Path(context).resolve()
    if not context.is_dir() or any((context/name).exists() for name in ['complete.json', 'distributed-source.json', 'published-image.json']):
        raise ValueError('Native adaptation requires a new, unsealed distributed context copy')
    _local_source(context, local_source)
    original_path = _regular(context/'app'/TRANSPORT, context)
    validator_path = _regular(context/'app'/VALIDATOR, context)
    if (sha(original_path) != EXPECTED_TRANSPORT or sha(validator_path) != EXPECTED_VALIDATOR
            or local_source.get(TRANSPORT) != EXPECTED_TRANSPORT
            or local_source.get(VALIDATOR) != EXPECTED_VALIDATOR):
        raise ValueError('Original recipient and validator identities differ from the reviewed source')
    inputs = source_inputs()
    staged = context/'app'/STAGED
    if staged.exists() or staged.is_symlink():
        raise ValueError('Cloud recipient proposal was already staged')
    for name, expected in inputs.items():
        source = HERE/name
        if source.is_symlink() or sha(source) != expected:
            raise ValueError('Native proposal source changed during staging')
        target = staged/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if sha(target) != expected:
            raise ValueError('Staged proposal source differs from the reviewed input')
    module = types.ModuleType('staged_cloud_recipient_proposal')
    module.__file__ = str(staged/'prepare.py')
    exec(compile((staged/'prepare.py').read_text(), STAGED+'/prepare.py', 'exec'), module.__dict__)
    original = original_path.read_text()
    candidate = module.render(original)
    native_path = _regular(context/'upstream'/NATIVE, context)
    metadata_path = _regular(context/'upstream/vcfhe-adapter.json', context)
    before = native_path.read_text()
    if before.count(original) != 1 or not before.endswith(original):
        raise ValueError('The original appended native transport section changed')
    metadata = json.loads(metadata_path.read_text())
    entry = metadata.get('files', {}).get(NATIVE, {})
    if entry.get('adapted') != sha(native_path) or 'distributedRecipientTransport' in metadata:
        raise ValueError('Original native adaptation evidence does not bind the copied source')
    after = before[:-len(original)] + candidate
    compiled = {
        'version': VERSION, 'nativePath': NATIVE,
        'originalNativeSha256': hashlib.sha256(before.encode()).hexdigest(),
        'adaptedNativeSha256': hashlib.sha256(after.encode()).hexdigest(),
        'originalTransportSha256': EXPECTED_TRANSPORT,
        'candidateTransportSha256': hashlib.sha256(candidate.encode()).hexdigest(),
        'recipientValidatorSha256': EXPECTED_VALIDATOR,
        'acquisitionFunctionSha256': inputs['acquire-accepted-results.rs'],
        'loopbackTestSourceSha256': inputs['transport-regressions.rs'],
        'acceptedSubmitThreshold': 3, 'authenticatedResponseThreshold': 3,
        'userDecryptResubmissions': 0, 'localCampaignChanged': False,
    }
    native_path.write_text(after)
    metadata['files'][NATIVE]['adapted'] = compiled['adaptedNativeSha256']
    metadata['distributedRecipientTransport'] = compiled
    metadata_path.write_text(json.dumps(metadata, indent=2)+'\n')
    provenance = {'schema':'vcfhe-distributed-native-recipient-transform-v1', 'version':VERSION,
        'sourceFiles':inputs, 'stagedSourceDirectory':STAGED,
        'originalLocalSourcePreserved':True, 'compiled':compiled}
    (staged/'provenance.json').write_text(json.dumps(provenance, indent=2)+'\n')
    _local_source(context, local_source)
    verify_source_inputs(provenance)
    return provenance
