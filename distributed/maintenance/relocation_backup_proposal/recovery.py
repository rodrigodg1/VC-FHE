"""Separately versioned backup recovery after an explicit workspace relocation.

Nothing runs on import. prepare() is local only. backup_after_review() explicitly
invokes the original four-host backup only after its recorded preflight repeats.
No function restarts a VM or participant or changes original run state.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import types

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[1]
RUN_PARENT = SOURCE.parent / 'threshold-kms/runs'
SCHEMA = 'vcfhe-relocated-smoke-backup-recovery-v1'
ANCHOR = '    run = _scope(config, run, allow_failed)\n'
REPLACEMENT = '    run = _scope(config, run, allow_failed, allow_cleanup_retry=True)\n'


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024*1024), b''):
            value.update(block)
    return value.hexdigest()


def physical(path):
    value = Path(path).absolute()
    if any(p.is_symlink() for p in [value, *value.parents]) or value != value.resolve():
        raise ValueError('Use the explicit physical path without symlink components')
    return value


def write(path, value):
    path = physical(path)
    with path.open('x') as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump(value, output, indent=2); output.write('\n')
        output.flush(); os.fsync(output.fileno())
    parent = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(parent)
    finally: os.close(parent)


def isolated_cleanup(source, record):
    """Compile a private namespace with one exact, provenance-recorded change."""
    source = physical(source)
    actual = {p.name:sha(p) for p in source.iterdir()
              if p.is_file() and p.suffix in ('.py', '.mjs', '.sh')}
    if actual != record.get('distributedSource'):
        raise ValueError('Current adapters differ from the original frozen A11 source closure')
    text = (source/'smoke_cleanup.py').read_text()
    if text.count(ANCHOR) != 1:
        raise ValueError('Frozen inspect_plan scope anchor changed')
    changed = text.replace(ANCHOR, REPLACEMENT)
    # Imported helpers must come from the same source-bound directory.
    sys.path.insert(0, str(source))
    try:
        for name in ('gcp', 'privacy', 'remote', 'topology'):
            existing = sys.modules.get(name)
            if existing is not None and Path(existing.__file__).resolve().parent != source:
                raise ValueError('A cleanup dependency was imported from another source tree')
        module = types.ModuleType('vcfhe_relocated_cleanup_isolated')
        module.__file__ = str(source/'smoke_cleanup.py')
        exec(compile(changed, module.__file__, 'exec'), module.__dict__)
    finally:
        sys.path.remove(str(source))
    provenance = {'originalSha256':hashlib.sha256(text.encode()).hexdigest(),
                  'isolatedSha256':hashlib.sha256(changed.encode()).hexdigest(),
                  'changeCount':1, 'function':'inspect_plan',
                  'original':ANCHOR.strip(), 'replacement':REPLACEMENT.strip(),
                  'scopeFunctionChanged':False, 'backupChanged':False,
                  'verifyBackupChanged':False, 'applyChanged':False}
    return module, provenance


def original_success(module, run, config, record):
    """Use the original seal verifier and require its collected three cases."""
    run = physical(run)
    # The existing scope implementation is used unchanged. It explicitly
    # permits this terminal cleanup status only with a passing smoke result.
    module._scope(config, run, allow_cleanup_retry=True)
    launch = module._read(run/'launch-state.json')
    if launch.get('status') != 'smoke-complete-cleanup-failed':
        raise ValueError('Recovery is restricted to the original cleanup-failed terminal status')
    for name in ('Full evaluation', 'Collect and validate evidence'):
        rows = [row for row in launch.get('stages', []) if row.get('name') == name]
        if len(rows) != 1 or rows[0].get('status') != 'passed':
            raise ValueError('Original evaluation and collection must both have passed')
    import deployment
    original = deployment.campaign_module()
    if original.source_manifest() != record['localSource']:
        raise ValueError('Protocol source differs from the original image closure')
    original.verify(run)  # Actual original verifier, never a passing substitute.
    cfg = module._read(run/'config/campaign.json')
    state = module._read(run/'state.json')
    seal = module._read(run/'seal.json')
    if (not cfg.get('smoke') or not cfg.get('readinessOnly') or cfg.get('pocPlan')
            or cfg.get('classification') != 'test-insecure-distributed-smoke-not-evaluation'
            or state.get('status') != 'passed' or state.get('config') != cfg
            or seal.get('source') != record['localSource']
            or module._read(run/'distributed/source.json') != record):
        raise ValueError('Missing original sealed distributed smoke scope')
    application = module._read(run/'reports/application.json')
    if application.get('status') != 'passed':
        raise ValueError('Original application did not pass')
    from smoke import validate_cases
    summary = validate_cases(application['cases'])
    if module._read(run/'distributed/smoke-result.json') != dict(status='passed', **summary):
        raise ValueError('Original smoke result differs from the three collected cases')
    if not {'state.json', 'config/campaign.json', 'reports/application.json',
            'distributed/source.json', 'distributed/execution.json'}.issubset(seal['files']):
        raise ValueError('Original seal omits critical collected smoke evidence')
    execution = module._read(run/'distributed/execution.json')
    if (execution.get('status') != 'completed' or execution.get('fullCases') != 3
            or execution.get('measuredPairs') != 0 or execution.get('warmups') != 0):
        raise ValueError('Incomplete original distributed execution')
    _, terraform_sha = module._state(config, run)
    names = ['launch-state.json', 'state.json', 'seal.json', 'distributed-config.json',
             'config/campaign.json', 'reports/application.json', 'distributed/source.json',
             'distributed/execution.json', 'distributed/smoke-result.json',
             'terraform/main.tf.json', 'terraform/terraform.tfvars.json', 'terraform/terraform.tfstate']
    return {'files':{name:sha(run/name) for name in names}, 'terraformStateSha256':terraform_sha,
            'originalLaunchStatus':launch['status'], 'threeCaseSummary':summary}


def prepare(logical_run, physical_run, destination, build, provenance_path):
    """Local-only review plan. Does not inspect, restart or back up cloud hosts."""
    run, destination = physical(physical_run), physical(destination)
    if run.parent != RUN_PARENT.resolve() or destination.parent != run:
        raise ValueError('Recovery must use a direct physical run child and fresh backup inside it')
    logical = Path(logical_run).absolute()
    if logical.resolve(strict=True) != run:
        raise ValueError('Logical and physical paths do not identify the same intact run')
    if destination.exists():
        raise ValueError('Existing backup is preserved. Select a fresh destination')
    record_file = physical(build)/'distributed-source.json'
    record = json.loads(record_file.read_text())
    module, change = isolated_cleanup(SOURCE, record)
    config = module._read(run/'distributed-config.json')
    module._private(run); module._private(destination)
    evidence = original_success(module, run, config, record)
    value = {'schema':SCHEMA, 'status':'prepared-local-only',
             'createdAt':datetime.now(timezone.utc).isoformat(),
             'logicalRunIdentity':str(logical), 'physicalRun':str(run),
             'backupDestination':str(destination), 'frozenBuild':str(record_file.parent),
             'frozenRecordSha256':sha(record_file), 'helperSha256':sha(Path(__file__)),
             'isolatedChange':change, 'originalEvidence':evidence,
             'originalLaunchStateRewritten':False, 'cloudActions':[],
             'reviewRequiredBeforeBackup':True,
             'backupOnlyVmRestartPlan':{
                 'mayBeRequired':True, 'automaticallyExecuted':False,
                 'scope':'Only the four same original stopped VM identities. All actor '
                         'containers must remain stopped with restart:no. Inspect before '
                         'and after any separately authorized infrastructure restart.',
                 'backupRequirement':'Original four entire /srv/vcfhe TAR archives, original '
                                     'run evidence and original verify_backup must actually pass.'}}
    write(provenance_path, value)
    return value


def backup_after_review(provenance_path):
    """Explicit future action. This function is never invoked by preparation."""
    provenance_path = physical(provenance_path)
    item = json.loads(provenance_path.read_text())
    if item.get('schema') != SCHEMA or item.get('status') != 'prepared-local-only':
        raise ValueError('An unchanged prepared relocation recovery record is required')
    if item.get('helperSha256') != sha(Path(__file__)):
        raise ValueError('Maintenance helper changed after review')
    record_file = physical(item['frozenBuild'])/'distributed-source.json'
    if sha(record_file) != item['frozenRecordSha256']:
        raise ValueError('Original image closure changed')
    record = json.loads(record_file.read_text())
    module, change = isolated_cleanup(SOURCE, record)
    run = physical(item['physicalRun'])
    config = module._read(run/'distributed-config.json')
    if change != item['isolatedChange'] or original_success(module, run, config, record) != item['originalEvidence']:
        raise ValueError('Original successful smoke evidence changed after review')
    # This unchanged original code performs exact live identity/attachment
    # checks, stops actors, creates ALL four raw TARs and verifies every backup.
    manifest = module.backup(config, run, physical(item['backupDestination']))
    if sha(run/'launch-state.json') != item['originalEvidence']['files']['launch-state.json']:
        raise ValueError('Original launch state changed during backup recovery')
    receipt = {'schema':SCHEMA, 'status':'original-backup-actually-verified',
               'provenanceSha256':sha(provenance_path),
               'backupManifestSha256':sha(Path(item['backupDestination'])/'backup.local.json'),
               'originalLaunchStateRewritten':False, 'originalManifestSchema':manifest['schema'],
               'resourceRemovalPerformed':False}
    write(provenance_path.with_name(provenance_path.stem+'.complete.local.json'), receipt)
    return receipt
