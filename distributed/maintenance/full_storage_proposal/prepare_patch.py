"""Render an unapplied, source-bound storage gate for post-smoke review."""
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[1]


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('proposal source drift: ' + old[:80])
    return text.replace(old, new)


def hashes(values):
    return {name: hashlib.sha256(value.encode()).hexdigest() for name, value in values.items()}


def render():
    original = {name: (SOURCE/name).read_text() for name in ('cli.py', 'launch.py')}
    candidate = dict(original)
    candidate['storage_preflight.py'] = (HERE/'storage_preflight.py').read_text()
    candidate['cli.py'] = once(candidate['cli.py'],
        "        for path in [args.config,args.build]:require_private(path)\n        from cloud_tools import ensure",
        "        for path in [args.config,args.build]:require_private(path)\n"
        "        if args.command=='cloud-run':\n"
        "            from storage_preflight import check_full_controller_storage\n"
        "            check_full_controller_storage(config,args.run)\n"
        "        from cloud_tools import ensure")
    candidate['launch.py'] = once(candidate['launch.py'],
        "def check_launch(config,quote,build,*,elapsed_hours=0):\n    topology.validate(config)\n",
        "def check_launch(config,quote,build,*,elapsed_hours=0):\n    topology.validate(config)\n"
        "    from storage_preflight import check_full_controller_storage\n"
        "    check_full_controller_storage(config)\n")
    patch = ''
    for name, value in candidate.items():
        old = original.get(name, '')
        patch += ''.join(difflib.unified_diff(old.splitlines(True), value.splitlines(True),
            fromfile='a/VC-FHE/distributed/'+name if name in original else '/dev/null',
            tofile='b/VC-FHE/distributed/'+name))
    return original, candidate, patch


if __name__ == '__main__':
    original, candidate, patch = render()
    (HERE/'proposal.patch').write_text(patch)
    (HERE/'proposal.json').write_text(json.dumps({
        'schema': 'vcfhe-full-storage-proposal-v1', 'status': 'unapplied',
        'source': hashes(original), 'candidate': hashes(candidate),
        'minimumGiB': 50, 'fullOnly': True, 'cloudBuildAloneUnchanged': True,
        'changesProtocol': False, 'cloudActions': [],
        'futurePrivateConfigSuggestion': {'state_disk_gib': 100,
            'mustRequoteBeforeLaunch': True, 'applied': False},
        'planningBasis': 'Offline A7 payload projection requires about29.7GiB for '
            'temporaryTAR plus extracted nonlinear and linear numeric data, before '
            'otherfiles andfilesystem overhead.50GiB is operating headroom, not a '
            'proved complete-storage bound.'}, indent=2)+'\n')
