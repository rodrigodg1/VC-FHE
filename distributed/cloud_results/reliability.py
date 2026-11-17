"""Offline regression gate for future preparations, including both recovery paths.

No test here starts a campaign. Passing is not evidence of cloud completion.
Separate processes keep legacy and completed-prefix helpers from shadowing one
another. Failed checks stop preparation before its source archive is created.
"""
from pathlib import Path
import hashlib
import os
import subprocess
import sys

HERE = Path(__file__).resolve().parents[1]
SUITES = ('tests', 'maintenance/workflow-recovery',
          'maintenance/completed-prefix-recovery')


def commands(root=HERE):
    root = Path(root)
    result = []
    for name in SUITES:
        folder = root / name
        if not folder.is_dir() or not list(folder.glob('test_*.py')):
            raise ValueError('Required offline regression suite missing: ' + name)
        result.append([sys.executable, '-m', 'unittest', 'discover', '-s', str(folder), '-v'])
    scripts = sorted((root / 'tests').glob('*.test.mjs'))
    if not scripts:
        raise ValueError('Required Node regressions missing')
    result.append(['node', '--test', *map(str, scripts)])
    return result


def run(root=HERE):
    root = Path(root)
    def source_hashes():
        paths = set(root.glob('*.py')) | set(root.glob('*.mjs')) | set(root.glob('*.sh'))
        for folder in (*SUITES, 'cloud_results'):
            paths.update(p for p in (root/folder).glob('*')
                         if p.suffix in ('.py', '.mjs', '.sh'))
        return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(paths) if p.is_file()}
    before = source_hashes()
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
    passed = []
    for index, command in enumerate(commands(root), 1):
        print(f'OFFLINE CHECK {index}/4: ' + ('Node' if index == 4 else SUITES[index-1]),
              file=sys.stderr, flush=True)
        # No shell, package installation, cloud provisioning or workflow replay.
        subprocess.run(command, check=True, timeout=600, env=env,
                       stdout=sys.stderr, stderr=sys.stderr)
        passed.append('node-tests' if index == 4 else SUITES[index-1])
    if source_hashes() != before:
        raise ValueError('Sources changed during offline checks. No passing receipt can be retained')
    tests = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
             for name in SUITES for p in sorted((root/name).glob('*'))
             if p.is_file() and (p.name.startswith('test_') or p.name.endswith('.test.mjs'))}
    return {'schema': 'cloud-preparation-regressions-v1', 'status': 'passed',
            'suites': passed, 'testSources': tests, 'checkedSources': before,
            'scope': 'offline-regressions-only',
            'cloudExecutionValidated': False, 'protocolOperations': 0}
