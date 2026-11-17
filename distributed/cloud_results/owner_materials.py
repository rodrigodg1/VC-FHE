"""Collect bounded public owner witnesses required by the original validator.

Never transfer the entire owner directory. It also holds encryption jobs and
plaintext source values, which are unnecessary for public verification.
"""
import re
from cloud_results.common import read, write, require, sha


def public_paths(application):
    require(application.get('status') == 'passed', 'Owner evidence requires completed application reports')
    cases = application.get('cases')
    require(isinstance(cases, list) and 1 <= len(cases) <= 27, 'Invalid completed case inventory')
    result = []
    names = set()
    for case in cases:
        name, half, n = case.get('name'), case.get('half'), case.get('n')
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,120}', name), 'Unsafe owner case name')
        require(name not in names, 'Duplicate owner case')
        names.add(name)
        require(type(n) is int and half in ('linear', 'nonlinear'), 'Invalid owner case shape')
        require(n in ((10, 16, 27) if half == 'linear' else (16, 32, 50)), 'Unexpected owner case size')
        base = 'owner/' + name + '/'
        if half == 'nonlinear':
            result.append(base + 'approved-context.json')
        else:
            result.append(base + 'coordinates.json')
            result.extend(base + 'input-' + str(i) + '.bin' for i in range(n))
    return result


def collect(campaign):
    """Run before the unchanged collector. Only existing public files are read."""
    control = campaign.run / 'distributed/owner-evidence-control'
    require(not control.exists(), 'Public owner acquisition was already attempted')
    campaign.remote('coordinator-1').download(campaign.root('coordinator-1'),
        ['reports/application.json'], control)
    report = control / 'reports/application.json'
    paths = public_paths(read(report))
    campaign.remote('owner-1').download(campaign.root('owner-1'), paths, campaign.run)
    inventory = {}
    for name in paths:
        file = campaign.run / name
        require(file.is_file() and not file.is_symlink(), 'Missing or linked public owner witness')
        inventory[name] = sha(file)
    proof = {'schema': 'public-owner-witness-acquisition-v1', 'status': 'passed',
        'applicationReportSha256': sha(report), 'files': inventory,
        'scope': 'Existing approved contexts, public linear coordinates and ciphertext inputs only',
        'privateOwnerDirectoryCopied': False, 'protocolRequestsRepeated': 0}
    write(campaign.run / 'distributed/public-owner-witnesses.json', proof, new=True)
    return proof
