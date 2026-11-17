"""Package sealed public WAN measurements with checksum validation."""
import hashlib
import json
import os
from pathlib import Path
import re
import uuid

from privacy import PATTERNS

PUBLIC_FILES=frozenset({
    'network-connections.csv','network-delay-summary.csv','application-delay-summary.csv',
    'deadline-margins.csv','role-communication.csv','communication-summary.csv',
    'participant-work.csv','owner-encryption.csv','summary.json',
})
PROFILE='gcp-four-hosts-role-local-v1'
README='''# Sealed distributed supplementary measurements

These files are copies of the public supplementary measurements bound by the
campaign seal. They contain neither participant credentials nor private KMS state.
The manifest binds the source seal and each copied file. This package retains numerical observations without replacing raw-run verification.

- `network-connections.csv` retains TCP connection observations and failed attempts.
  `network-delay-summary.csv` summarizes them. TCP connection time is not application
  response time. Startup samples remain present and are not protocol failure rates.
- `application-delay-summary.csv` describe cross-host
  request-to-response time including TLS, transfer and remote handler processing.
  They do not isolate network-only RTT. Sample percentiles are not guarantees.
- `deadline-margins.csv` uses contract deadlines and mined block timestamps.
  It does not subtract unsynchronized host clocks.
- `role-communication.csv`, `communication-summary.csv` count serialized role-RPC JSON, including base64.
  They exclude TLS/IP framing, Besu P2P and KMS gRPC. Host NIC totals have a different scope.
- `participant-work.csv` separates controller CPU and native FHE CPU from elapsed
  handler time. Accumulated CPU differs from elapsed time. Parallel executions may have
  lower elapsed time without using less CPU. Peak RSS values must not be added.
- `owner-encryption.csv` records owner encryption work. `summary.json` retains
  the supplementary scope and observed audit-deadline margin.

Missing measurements must not be converted into zeros. KMS/decryption timings are
not included in this evaluation supplement.
'''


def sha(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):value.update(block)
    return value.hexdigest()


def root(path):
    path=Path(path)
    if path.is_symlink() or not path.is_dir():raise ValueError('package root must be an existing directory')
    return path.resolve()


def file_under(directory,name):
    if not isinstance(name,str):raise ValueError('package paths must be strings')
    relative=Path(name)
    if relative.is_absolute() or '..' in relative.parts or '\\' in str(name):
        raise ValueError('unsafe package path')
    path=directory
    for part in relative.parts:
        path=path/part
        if path.is_symlink():raise ValueError('symlink in public package')
    if not path.is_file() or not path.resolve().is_relative_to(directory):
        raise ValueError('missing public package file: '+str(name))
    return path


def read_json(path):
    try:value=json.loads(Path(path).read_text())
    except (OSError,UnicodeError,json.JSONDecodeError) as error:
        raise ValueError('unreadable package metadata') from error
    if not isinstance(value,dict):raise ValueError('package metadata must be an object')
    return value


def public_payload(path):
    payload=Path(path).read_bytes()
    try:text=payload.decode('utf-8')
    except UnicodeError as error:raise ValueError('public supplementary files must be UTF-8 text') from error
    if any(pattern.search(text) for pattern in PATTERNS.values()):
        raise ValueError('private authentication or account material in supplementary file')
    if re.search(r'/(?:Users|home)/[^\s"\']+',text):
        raise ValueError('private absolute path in supplementary file')
    return payload


def atomic_new(path,payload):
    path=Path(path)
    if path.is_symlink():raise ValueError('symlink at package destination')
    if path.exists():
        if not path.is_file() or path.read_bytes()!=payload:raise ValueError('existing package metadata differs')
        return
    pending=path.with_name('.'+path.name+'-'+uuid.uuid4().hex+'.pending')
    with pending.open('xb') as stream:
        stream.write(payload);stream.flush();os.fsync(stream.fileno())
    if path.exists() or path.is_symlink():raise ValueError('package destination appeared during creation')
    pending.replace(path)


def json_bytes(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()


def package_supplement(run,base):
    run,base=root(run),root(base)
    seal_file=file_under(run,'seal.json');seal_hash=sha(seal_file)
    seal=read_json(seal_file);sealed=seal.get('files')
    if not isinstance(sealed,dict):raise ValueError('campaign seal has no file inventory')
    source=run/'distributed/supplement'
    if any(p.is_symlink() for p in [run/'distributed',source]) or not source.is_dir():
        raise ValueError('missing or linked supplementary directory')
    if {p.name for p in source.iterdir()}!=PUBLIC_FILES:
        raise ValueError('supplement contains missing, private or unexpected files')
    prefix='distributed/supplement/'
    for name in sealed:
        if not isinstance(name,str):raise ValueError('sealed paths must be strings')
        if name.startswith(prefix) and name[len(prefix):] not in PUBLIC_FILES:
            raise ValueError('unexpected or unsafe sealed supplementary path')
    contents={};hashes={}
    for name in sorted(PUBLIC_FILES):
        source_name=prefix+name
        expected=sealed.get(source_name)
        if not isinstance(expected,str) or not re.fullmatch('[0-9a-f]{64}',expected):
            raise ValueError('supplementary file is unsealed: '+name)
        payload=public_payload(file_under(run,source_name))
        if hashlib.sha256(payload).hexdigest()!=expected:
            raise ValueError('sealed supplementary file changed: '+name)
        contents[name]=payload;hashes[name]=expected
    metadata=read_json(source/'summary.json')
    private_fields={'privateKey','private_key','credentials','login','email','projectId','project_id',
                    'operatorPrincipal','mnemonic','access_token','refresh_token'}
    def check_fields(value):
        if isinstance(value,dict):
            if private_fields&set(value):raise ValueError('private fields in supplementary summary')
            for child in value.values():check_fields(child)
        elif isinstance(value,list):
            for child in value:check_fields(child)
    check_fields(metadata)
    manifest={'schema':'sealed-cloud-supplement-v1','sourceSealSha256':seal_hash,
        'sourceDirectory':'distributed/supplement','files':hashes,
        'readmeSha256':hashlib.sha256(README.encode()).hexdigest(),
        'scope':'Public CSV and summary data only. TCP, handler-inclusive RPC, CPU and elapsed scopes remain distinct.',
        'reportUpdated':False}
    output=base/'distributed-supplement'
    expected_names=PUBLIC_FILES|{'manifest.json','README.md'}
    if output.is_symlink():raise ValueError('linked supplementary output')
    if output.exists():
        if not output.is_dir() or {p.name for p in output.iterdir()}!=expected_names:
            raise ValueError('existing supplementary output is incomplete or contains unexpected files')
        if read_json(file_under(output,'manifest.json'))!=manifest:
            raise ValueError('existing supplementary output belongs to different evidence')
        for name,expected in hashes.items():
            if sha(file_under(output,name))!=expected:raise ValueError('copied supplementary file changed')
        if file_under(output,'README.md').read_bytes()!=README.encode():
            raise ValueError('supplementary scope documentation changed')
        return manifest
    pending=base/('.distributed-supplement-'+uuid.uuid4().hex+'.pending')
    pending.mkdir(mode=0o700)
    for name,payload in contents.items():atomic_new(pending/name,payload)
    atomic_new(pending/'README.md',README.encode())
    atomic_new(pending/'manifest.json',json_bytes(manifest))
    if sha(seal_file)!=seal_hash:raise ValueError('campaign seal changed during packaging')
    for name,expected in hashes.items():
        if sha(file_under(run,prefix+name))!=expected:raise ValueError('supplement changed during packaging')
    if output.exists() or output.is_symlink():raise ValueError('supplementary output appeared during packaging')
    pending.replace(output)
    return manifest


def package_index(run,base):
    run,base=root(run),root(base)
    provenance=read_json(file_under(base,'provenance.json'))
    if tuple(provenance.get(k) for k in ('measuredPairs','warmups','fullCases'))!=(480,18,27):
        raise ValueError('Incomplete distributed result design')
    if provenance.get('validation')!='passed' or provenance.get('sealSha256')!=sha(file_under(run,'seal.json')):
        raise ValueError('Result provenance and source seal differ')
    manifest=read_json(file_under(base,'analysis-package.json'))
    if manifest.get('schema')!='poc-analysis-package-v1' or manifest['provenanceSha256']!=sha(base/'provenance.json'):
        raise ValueError('Missing validated analysis package')
    for name,expected in manifest['files'].items():
        if sha(file_under(base,name))!=expected:raise ValueError('Generated result changed')
    package_supplement(run,base)
    result={'schema':'poc-cloud-result-index-v1','source':'cloud','measuredPairs':480,'warmups':18,'fullCases':27,
            'analysisPackageSha256':sha(base/'analysis-package.json'),
            'supplementManifestSha256':sha(base/'distributed-supplement/manifest.json')}
    atomic_new(base/'cloud-results.json',json_bytes(result))
    atomic_new(base/'CLOUD-RESULTS.md',b'# Cloud results\n\nSee METRICS.md, metrics.csv, figures/ and distributed-supplement/.\n')
    return result
