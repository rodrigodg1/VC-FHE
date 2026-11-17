"""Controller storage prerequisite for the full distributed campaign only.

This is a planning operating minimum, not a total-storage upper bound. It
does not allocate files, create resources or change the experiment design.
"""
from pathlib import Path
from os import stat as filesystem_stat
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FULL_MINIMUM_FREE_BYTES = 50 * 2**30


def existing_directory(path):
    """Inspect the filesystem of a future destination without creating it."""
    current = Path(path).expanduser().resolve()
    while not current.exists():
        parent = current.parent
        if parent == current:
            raise ValueError('no existing storage ancestor for ' + str(path))
        current = parent
    if not current.is_dir():
        raise ValueError('storage destination ancestor must be a directory')
    return current


def check_full_controller_storage(config, run=None, temporary_directory=None):
    if config.get('execution_mode') == 'smoke':
        return {'schema': 'vcfhe-controller-storage-v1', 'status': 'not-applicable-smoke',
                'policyChanged': False, 'filesystemChecks': []}
    run_path = Path(run) if run is not None else ROOT / 'threshold-kms/runs'
    temporary_path = (Path(temporary_directory) if temporary_directory is not None
                      else Path(tempfile.gettempdir()))
    checks = []
    volumes = {}
    for purpose, requested in [('run-evidence', run_path), ('temporary-tar', temporary_path)]:
        inspected = existing_directory(requested)
        free = shutil.disk_usage(inspected).free
        device = filesystem_stat(inspected).st_dev
        checks.append({'purpose': purpose, 'requestedPath': str(requested.resolve()),
                       'inspectedExistingDirectory': str(inspected),
                       'device': device, 'freeBytes': free})
        group = volumes.setdefault(device, {'device': device, 'purposes': [],
                                            'freeBytes': free,
                                            'requiredFreeBytes': FULL_MINIMUM_FREE_BYTES})
        group['purposes'].append(purpose)
        group['freeBytes'] = min(group['freeBytes'], free)
    failed = [row for row in volumes.values() if row['freeBytes'] < FULL_MINIMUM_FREE_BYTES]
    if failed:
        labels = ', '.join('/'.join(row['purposes']) for row in failed)
        raise ValueError('Full distributed campaign requires at least 50 GiB free on '
                         'the run-evidence and temporary-TAR filesystems. Insufficient: '
                         + labels + '. Shared filesystem capacity is checked once, not '
                         'summed twice. This is planning headroom, not a proved total '
                         'storage bound. Preserve existing evidence and use suitable '
                         'storage before retrying. This check starts no cloud actions.')
    return {'schema': 'vcfhe-controller-storage-v1', 'status': 'passed',
            'scope': 'full-controller-storage-operating-prerequisite',
            'minimumFreeBytesPerFilesystem': FULL_MINIMUM_FREE_BYTES,
            'sameFilesystemCapacityNotAddedTwice': True,
            'totalStorageUpperBoundEstablished': False,
            'filesystemChecks': checks, 'uniqueFilesystems': list(volumes.values())}
