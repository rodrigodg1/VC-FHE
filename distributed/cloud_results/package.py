"""Bounded evaluation-result delivery after original cloud-side validation."""
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile

from cloud_results.common import MAX_PACKAGE_BYTES, ROOT, VERSION, digest, now, private, read, require, safe_file, sha, write

EXTENSIONS={'.csv','.pdf','.png','.svg','.json','.md','.txt','.log'}
FORBIDDEN={'fixtures','bin','private','identity','transport','recipient','keyset','.policy-state','node_modules','.git'}


def allowed(name):
    p=Path(name)
    require(not p.is_absolute() and '..' not in p.parts and '\\' not in name and p.parts,
            'Unsafe delivered path')
    extensions=EXTENSIONS
    require(not (set(p.parts)&FORBIDDEN) and p.suffix in extensions and not p.name.endswith(('.local.json','.key','.pem')),
            'Raw state or non-result file cannot enter the local evaluation package')
    require(p.parts[0] in ('composite','proof'), 'Unknown delivery category')


def validation_receipt(run, base):
    """Invoke the unmodified verification and guarded WAN derivation before export."""
    import deployment
    from postprocess_adapter import verify
    run,base=Path(run),Path(base)
    module=deployment.campaign_module()
    module.verify(run)
    processor=verify(run/'distributed/generators')
    import subprocess,sys
    with tempfile.TemporaryDirectory() as tmp:
        result=Path(tmp)/'validated.json'
        subprocess.run([sys.executable,'-c',
            'import sys,json;sys.path.insert(0,sys.argv[1]);from single_run import validate;'
            'from refresh import validate_derived;from pathlib import Path;'
            'p=validate(Path(sys.argv[2]));validate_derived(Path(sys.argv[3]));'
            'Path(sys.argv[4]).write_text(json.dumps(p))',
            str(processor),str(run),str(base),str(result)],check=True)
        provenance=read(result)
    require(tuple(provenance.get(k) for k in ('measuredPairs','warmups','fullCases'))==(480,18,27),
            'Only the complete validated distributed design can export an evaluation package')
    require(provenance.get('validation')=='passed','Original cloud validation did not pass')
    require(provenance.get('distributedExecution',{}).get('executionProfile')=='gcp-four-hosts-role-local-v1',
            'Result source is not the distributed campaign')
    return {'schema':'original-cloud-validation-v1','status':'passed','validatedAt':now(),
        'sourceSealSha256':sha(run/'seal.json'),'provenanceSha256':sha(base/'provenance.json'),
        'sourceDigest':provenance['distributedExecution']['sourceSha256'],
        'measuredPairs':480,'warmups':18,'fullCases':27,
        'validatorSources':{p.name:sha(p) for p in sorted(processor.glob('*.py'))},
        'scope':'Original validators executed beside complete raw evidence in the cloud. No claim of local raw validation.'}




def build_results(run, base, destination, raw_receipt):
    """Export validated tables, plots and data without compiling a implementation."""
    run,base,destination=map(Path,(run,base,destination))
    require(not destination.exists(),'Result export directory already exists')
    proof=validation_receipt(run,base)
    status=read(base/'distributed-results.json')
    require(status.get('status')=='results-ready',
            'Standalone result derivation did not finish')
    require(raw_receipt.get('status')=='verified-cloud-preservation',
            'Raw evidence has no durable cloud readback')
    selection={}
    for p in sorted(base.rglob('*')):
        relative=p.relative_to(base)
        if not p.is_file() :
            continue
        name='composite/'+relative.as_posix();allowed(name)
        require(not p.is_symlink(),'Linked derived result')
        selection[name]=p
    selection['proof/seal.json']=run/'seal.json'
    destination.mkdir(mode=0o700)
    write(destination/'validation.json',proof,new=True)
    write(destination/'preservation.json',raw_receipt,new=True)
    selection['proof/cloud-validation.json']=destination/'validation.json'
    selection['proof/cloud-preservation.json']=destination/'preservation.json'
    files={};total=0
    for name,source in selection.items():
        allowed(name)
        require(source.is_file() and not source.is_symlink(),'Missing or linked result')
        total+=source.stat().st_size
        require(total<=MAX_PACKAGE_BYTES,'Result package exceeds its local size cap')
        files[name]={'sha256':sha(source),'bytes':source.stat().st_size}
    manifest={'schema':'cloud-results-delivery-v1','version':VERSION,'createdAt':now(),
        'files':files,'totalBytes':total,'maximumBytes':MAX_PACKAGE_BYTES,'rawEvidenceDownloaded':False,
        'measuredPairs':480,'warmups':18,'fullCases':27,
        'validationSha256':sha(destination/'validation.json'),'preservationSha256':sha(destination/'preservation.json'),
        'cloudControllerSourceSha256':sha(run/'distributed/cloud-controller-source.json')}
    write(destination/'manifest.json',manifest,new=True)
    archive=destination/'results.tar'
    with tarfile.open(archive,'w') as tar:
        tar.add(destination/'manifest.json',arcname='manifest.json',recursive=False)
        for name,source in selection.items():
            require(sha(source)==files[name]['sha256'],'Result changed during export')
            tar.add(source,arcname=name,recursive=False)
    require(archive.stat().st_size<=MAX_PACKAGE_BYTES,'Result archive plus TAR headers exceeds local cap')
    return {'sha256':sha(archive),'bytes':archive.stat().st_size,
            'manifestSha256':sha(destination/'manifest.json'),'archive':str(archive)}


def verify_results(destination, manifest):
    """Check that standalone delivery retains the full numerical package."""
    destination=Path(destination)
    require(manifest.get('schema')=='cloud-results-delivery-v1','Not a standalone result delivery')
    require(all(Path(name).parts[0] in {'composite','proof'} for name in manifest['files']),
            'Unexpected implementation or compiler tree in standalone delivery')
    proof=read(destination/'proof/cloud-validation.json')
    require(tuple(proof.get(k) for k in ('measuredPairs','warmups','fullCases'))==(480,18,27)
            and proof.get('status')=='passed','Incomplete original cloud validation')
    for name,field in [('cloud-validation.json','validationSha256'),('cloud-preservation.json','preservationSha256')]:
        require(sha(destination/'proof'/name)==manifest[field],'Cloud validation or preservation receipt changed')
    base=destination/'composite'
    require(sha(base/'provenance.json')==proof['provenanceSha256'],'Delivered provenance differs')
    values=read(base/'analysis-package.json')
    require(values.get('schema')=='poc-analysis-package-v1' and values.get('half')=='both'
            and values.get('preliminary') is False and values.get('provenanceSha256')==sha(base/'provenance.json'),
            'Incomplete numerical package')
    required={'workflow/observations.csv','workflow/summary.json','metrics.csv','METRICS.md',
              *('figures/'+n+s for n in ('linear-cost','nonlinear-work','workflow-gas')
                for s in ('.pdf','.png','.svg','.csv','.json'))}
    require(required<=values['files'].keys(),'Missing tables or selected plots')
    for name,expected in values['files'].items():
        require('composite/'+name in manifest['files'] and sha(safe_file(base,name))==expected,
                'Missing or changed generated result')
    require(read(base/'distributed-results.json').get('status')=='results-ready','Missing completed derivation')


def unpack(archive, destination, expected):
    """Reject oversized, extra, linked, changed or raw inputs before installation."""
    archive,destination=Path(archive),private(destination)
    require(not destination.exists(),'Local result destination already exists')
    require(archive.stat().st_size==expected['bytes']<=MAX_PACKAGE_BYTES and sha(archive)==expected['sha256'],
            'Transferred evaluation archive differs')
    with tarfile.open(archive,'r:') as tar:
        members=tar.getmembers();names=[m.name for m in members]
        require(len(names)==len(set(names)) and all(m.isfile() for m in members),'Duplicate, linked or special result entry')
        require(len(members)<=5000 and sum(m.size for m in members)<=MAX_PACKAGE_BYTES,'Oversized result inventory')
        require('manifest.json' in names,'Missing delivery manifest')
        raw=tar.extractfile(tar.getmember('manifest.json')).read()
        import hashlib
        require(hashlib.sha256(raw).hexdigest()==expected['manifestSha256'],'Delivery manifest changed')
        manifest=json.loads(raw)
        require(manifest.get('schema') =='cloud-results-delivery-v1'
                and tuple(manifest.get(k) for k in ('measuredPairs','warmups','fullCases'))==(480,18,27),
                'Wrong result design or delivery format')
        require(set(names)==set(manifest['files'])|{'manifest.json'},'Unexpected or missing delivered file')
        for member in members:
            if member.name!='manifest.json':
                allowed(member.name)
                require(member.size==manifest['files'][member.name]['bytes'],'Result length mismatch')
        destination.mkdir(mode=0o700,parents=True)
        for member in members:
            target=destination/member.name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with target.open('xb') as out,tar.extractfile(member) as source:
                os.fchmod(out.fileno(),0o600);shutil.copyfileobj(source,out);out.flush();os.fsync(out.fileno())
            if member.name!='manifest.json':require(sha(target)==manifest['files'][member.name]['sha256'],'Result hash mismatch')
    proof=read(destination/'proof/cloud-validation.json');preservation=read(destination/'proof/cloud-preservation.json')
    require(proof.get('status')=='passed' and preservation.get('status')=='verified-cloud-preservation',
            'Missing cloud validation or raw preservation proof')
    require(sha(destination/'proof/seal.json')==proof['sourceSealSha256'],'Source seal differs')
    if manifest['schema']=='cloud-results-delivery-v1':verify_results(destination,manifest)
    write(destination/'local-copy-verified.json',{'schema':'cloud-evaluation-local-copy-v1','status':'verified',
        'verifiedAt':now(),'manifestSha256':expected['manifestSha256'],'archiveSha256':expected['sha256'],
        'files':manifest['files'],'rawEvidenceDownloaded':False},new=True)
    return manifest


def verify_local(destination):
    destination=private(destination);receipt=read(destination/'local-copy-verified.json')
    require(receipt.get('status')=='verified','Local result copy is not verified')
    require(sha(destination/'manifest.json')==receipt['manifestSha256'],'Local delivery manifest changed')
    manifest=read(destination/'manifest.json')
    require(receipt['files']==manifest['files'],'Local receipt inventory differs')
    for name,item in receipt['files'].items():require(sha(safe_file(destination,name))==item['sha256'],'Local result changed')
    if manifest['schema']=='cloud-results-delivery-v1':verify_results(destination,manifest)
    return receipt


def verify_delivery_ready(destination):
    """Require a complete verified local result package before cleanup."""
    return verify_local(destination)
