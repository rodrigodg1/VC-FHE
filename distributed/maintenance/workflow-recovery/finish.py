#!/usr/bin/env python3
"""Select the explicit continuation terminal, then retain all original delivery guards."""
import argparse
import json
from pathlib import Path
import sys
import urllib.error


def finish(prepared, expected_manifest_sha256, continuation='workflows-c1'):
    prepared=Path(prepared).resolve()
    root=Path(__file__).resolve().parents[2]
    sys.path.insert(0,str(root))
    from cloud_results import cli
    from cloud_results.common import read,require,sha,write,VERSION
    from cloud_results.infra import names
    from cloud_results.storage import Store
    config,_,_,source=cli.verify_prepared(prepared)
    store=Store(names(config)['bucket'],config['project_id'])
    require(continuation in ('workflows-c1','workflows-c2','workflows-c3'),'Unexpected continuation selector')
    job=source['jobId']+'-'+continuation
    name='runs/'+job+'/terminal.json'
    meta=store.metadata(name)
    receipt={'bucket':store.bucket,'object':name,'generation':meta['generation'],'bytes':int(meta['size']),
        'md5Hash':meta['md5Hash'],'sha256':meta['metadata']['vcfhe-sha256']}
    destination=prepared/'continuation-terminal-download.local.json'
    if not destination.exists():store.download(receipt,destination,maximum=2*1024**2)
    require(sha(destination)==receipt['sha256'],'Retained continuation terminal changed')
    terminal=read(destination)
    require(terminal['schema']==VERSION and terminal['status']=='awaiting-verified-local-delivery'
        and terminal['continuationProfile']=='distributed-same-keyset-workflows-only-v1'
        and terminal['parentFailurePreserved'] is True and terminal['comparisonsReused']==480
        and terminal['warmupsReused']==18 and terminal['fullCampaignCompleted'] is True,'Incomplete continuation terminal')
    manifest_receipt=terminal['continuationManifest']
    require(manifest_receipt['object']=='runs/'+job+'/continuation-manifest.json'
        and manifest_receipt['sha256']==expected_manifest_sha256,'Wrong authorized continuation manifest')
    manifest_file=prepared/'continuation-manifest-download.local.json'
    if not manifest_file.exists():store.download(manifest_receipt,manifest_file,maximum=4*1024**2)
    require(sha(manifest_file)==expected_manifest_sha256,'Continuation manifest differs')
    manifest=read(manifest_file)
    scratch=manifest.get('archiveScratch',{})
    require(set(scratch)<= {'host-1'},'Unexpected scratch cleanup scope')
    import smoke_cleanup
    def check_scratch(removed=False):
        for row in scratch.values():
            live=smoke_cleanup._cloud(['compute','disks','describe',row['name'],'--zone',row['zone'],
                '--project',config['project_id']],missing=True)
            if removed:
                require(live is None,'Automatically deleted archive scratch disk remains')
            elif live is not None:
                require(str(live['id'])==str(row['diskId'])
                    and live['labels']['experiment']==config['campaign']
                    and live['labels']['vcfhe-purpose']=='archive-c1','Scratch disk identity changed')
            else:
                require((prepared/'protocol-teardown-complete.local.json').exists(),
                    'Scratch disk disappeared before validated delivery and teardown')
    check_scratch()
    store.verify(terminal['continuationSources'])
    # Only the terminal's location changes. Original raw preservation checks,
    # full package verification, integrity checks and resource deletion
    # identity guards remain in the unmodified delivery implementation.
    original=cli.terminal
    cli.terminal=lambda path:terminal if Path(path).resolve()==prepared else original(path)
    try:
        result=cli.finish(prepared,execute=True)
        check_scratch(removed=True)
        write(prepared/'continuation-scratch-teardown.local.json',{'status':'verified-absent',
            'diskCount':len(scratch),'removedWithOwnedInstance':True})
        return result
    finally:cli.terminal=original


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prepared',type=Path,required=True)
    p.add_argument('--manifest-sha256',required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
    if not a.execute:raise SystemExit('Explicit --execute required. No transfer or cleanup occurred.')
    print(json.dumps(finish(a.prepared,a.manifest_sha256)))
