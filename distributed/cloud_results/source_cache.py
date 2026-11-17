"""Reuse exact public source caches without touching participant state."""
import hashlib
from pathlib import Path
import shutil


def inventory(folder):
    folder = Path(folder)
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError('Public source cache must be a real directory')
    result = {}
    for file in sorted(folder.rglob('*')):
        if file.is_symlink():
            raise ValueError('Linked public source cache entry refused')
        name = file.relative_to(folder).as_posix()
        if file.is_dir():
            result[name] = {'kind': 'directory'}
        elif file.is_file():
            digest = hashlib.sha256()
            with file.open('rb') as stream:
                for block in iter(lambda: stream.read(1024*1024), b''):
                    digest.update(block)
            result[name] = {'kind': 'file', 'bytes': file.stat().st_size,
                            'sha256': digest.hexdigest()}
        else:
            raise ValueError('Special file in public source cache')
    if 'complete.json' not in result or result['complete.json']['kind'] != 'file':
        raise ValueError('Public source cache is incomplete')
    return result


def restore(source, target):
    """Input archive must already have passed verify_extracted()."""
    source, target = Path(source), Path(target)
    expected = inventory(source)
    reused = target.exists() or target.is_symlink()
    if reused:
        if inventory(target) != expected:
            raise ValueError('Existing public source cache differs. Preserve it and inspect before retrying')
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, target)
        if inventory(target) != expected:
            raise ValueError('Public source cache copy failed verification')
    return {'status': 'verified-reuse' if reused else 'verified-copy',
            'files': sum(v['kind'] == 'file' for v in expected.values()),
            'participantStateChanged': False}
