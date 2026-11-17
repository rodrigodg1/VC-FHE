"""Freeze public runner inputs and small publication references, excluding secrets."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

from cloud_results.common import REPOSITORY, ROOT, check_full, digest, private, read, require, sha, sources, write
from cloud_results.infra import inner_config,names


def select_repository():
    from source_bundle import public_sources
    return {'repository/VC-FHE/'+name: path for name,path in public_sources(ROOT).items()}


def prepare(config, quote, build, output):
    import image,deployment,topology
    cfg=inner_config(check_full(config));output=private(output);build=Path(build).resolve()
    require(not output.exists(),'Controller preparation already exists')
    record=read(build/'distributed-source.json');published=read(build/'published-image.json')
    require(record['localSource']==deployment.campaign_module().source_manifest(),'Protocol source changed')
    image.verify_inputs(build,record);image.verify_adapter_sources(record)
    require(published.get('buildStatus')=='SUCCESS' and published.get('sourceSha256')==topology.digest(record)
            and published.get('cleanup',{}).get('status')=='passed','Published image or builder cleanup not verified')
    require(cfg['images']=={'campaign':published['digest'],'besu':published['besuDigest']},'Pinned images differ')
    from cloud_results.smoke_gate import validate as validate_smoke
    smoke_proof=validate_smoke(build,record)
    require(quote.get('cloud_controller',{}).get('version')=='cloud-controller-results-v1',
            'Use a quote that includes the cloud controller, storage and transfer')
    require(quote['campaign']==cfg['campaign'],'Quote identifies another campaign')
    from cloud_results.reliability import run as offline_checks
    regression_proof=offline_checks()
    selection=select_repository()
    for name,expected in record['localSource'].items():
        path=ROOT/name
        require(sha(path)==expected,'Protocol source changed before bundling')
        selection['repository/VC-FHE/'+name]=path
    for top in ('app','upstream'):
        for p in sorted((build/top).rglob('*')):
            if p.is_file():
                require(not p.is_symlink(),'Linked prepared build input requires review')
                selection['build/'+p.relative_to(build).as_posix()]=p
    for name in ('Dockerfile','distributed-source.json','published-image.json','gce-builder/cleanup.local.json','successful-smoke.local.json'):
        selection['build/'+name]=build/name
    if smoke_proof.get('schema')=='source-matched-postcollection-functional-smoke-v1':
        selection['build/postcollection-smoke-attestation.local.json']=build/'postcollection-smoke-attestation.local.json'
    cache=Path(record['baseContext'])
    require(cache.is_dir() and (cache/'complete.json').is_file(),'Original public source cache missing')
    for p in sorted(cache.rglob('*')):
        if p.is_file():
            require(not p.is_symlink(),'Linked original source cache')
            selection['source-cache/'+cache.name+'/'+p.relative_to(cache).as_posix()]=p
    output.mkdir(parents=True,mode=0o700)
    write(output/'inner-config.local.json',cfg,new=True)
    write(output/'quote.local.json',quote,new=True)
    write(output/'preparation-regressions.local.json',regression_proof,new=True)
    selection['job/preparation-regressions.local.json']=output/'preparation-regressions.local.json'
    selection['job/config.local.json']=output/'inner-config.local.json'
    selection['job/quote.local.json']=output/'quote.local.json'
    before={name:{'sha256':sha(p),'bytes':p.stat().st_size} for name,p in selection.items()}
    manifest={'schema':'cloud-controller-source-v1','version':'cloud-controller-results-v1',
        'files':before,'controllerSources':sources(),'protocolImageSourceSha256':topology.digest(record),
        'localProtocolSource':record['localSource'],'distributedSource':record['distributedSource'],
        'innerConfigSha256':digest(cfg),'originalOuterPrincipal':config['operator_principal'],
        'jobId':digest({'campaign':cfg['campaign'],'output':str(output)})[:32],
        'cacheDirectory':cache.name,'runName':'run-wan-'+cfg['campaign'],'names':names(config)}
    write(output/'source-manifest.local.json',manifest,new=True)
    archive=output/'controller-source.tar.gz'
    with tarfile.open(archive,'w:gz',compresslevel=1) as tar:
        tar.add(output/'source-manifest.local.json',arcname='source-manifest.json',recursive=False)
        for name,p in selection.items():
            require(sha(p)==before[name]['sha256'],'Source changed during controller packaging')
            tar.add(p,arcname=name,recursive=False)
    for name,p in selection.items():require(sha(p)==before[name]['sha256'],'Source changed during packaging')
    receipt={'schema':'cloud-controller-preparation-v1','status':'prepared-not-started',
        'sourceArchive':archive.name,'sourceArchiveSha256':sha(archive),'sourceBytes':archive.stat().st_size,
        'sourceManifestSha256':sha(output/'source-manifest.local.json'),'runName':manifest['runName'],
        'protocolImageSourceSha256':manifest['protocolImageSourceSha256'],'controllerSources':manifest['controllerSources'],
        'cloudResourcesCreated':False,'smokeStarted':False,'fullCampaignStarted':False}
    write(output/'prepared.local.json',receipt,new=True)
    write(output/'outer-config.local.json',config,new=True)
    return receipt


def verify_extracted(root):
    root=Path(root);manifest=read(root/'source-manifest.json')
    require(manifest['controllerSources']==sources(),'Controller source changed after preparation')
    from cloud_results.common import safe_file
    for name,item in manifest['files'].items():
        path=safe_file(root,name)
        require(path.stat().st_size==item['bytes'] and sha(path)==item['sha256'],'Frozen controller source differs: '+name)
    return manifest
