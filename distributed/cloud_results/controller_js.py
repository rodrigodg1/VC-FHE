"""Install controller libraries with the image's recorded Linux lock correction.

Only the extraneous bundled Darwin fsevents optional flag changes in a separate
installation directory. Repository manifests, versions and integrity pins stay
unchanged. This module never starts Docker or a protocol actor.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cloud_results.common import read, write, require, sha

ENTRY='node_modules/ganache/node_modules/fsevents'
VERSION='controller-linux-js-dependencies-v1'


def linux_lock(original):
    lock=json.loads(original)
    entry=lock.get('packages',{}).get(ENTRY)
    if entry is None:
        return original,False
    require(entry.get('version')=='2.3.2' and entry.get('os')==['darwin']
            and entry.get('extraneous') is True and 'optional' not in entry,
            'Unexpected Darwin-only dependency. Review the lock rather than forcing installation')
    entry['optional']=True
    adapted=(json.dumps(lock,indent=2)+'\n').encode()
    del entry['optional']
    require((json.dumps(lock,indent=2)+'\n').encode()==original,
            'Linux adaptation must reconstruct the exact original lock')
    return adapted,True


def install(root,build,project,cache,report):
    root,build,project,cache,report=map(Path,(root,build,project,cache,report))
    root=root.resolve();project=project.resolve()
    require(project in (root/'fhe-pod',root/'BN254-Signatures'),'Unknown controller project')
    record=read(build/'distributed-source.json');name=project.name
    for file in ('package.json','package-lock.json'):
        require(sha(project/file)==record['localSource'][name+'/'+file], 'Original controller manifest changed')
    original=(project/'package-lock.json').read_bytes();adapted,changed=linux_lock(original)
    key=hashlib.sha256(original).hexdigest()
    target=cache/name/key;marker=target/'complete.local.json'
    expected={'schema':VERSION,'project':name,'originalLockSha256':key,
        'installedLockSha256':hashlib.sha256(adapted).hexdigest(),
        'packageManifestSha256':sha(project/'package.json'),'darwinOptionalFlagCorrected':changed,
        'versionsChanged':False,'integrityChecksDisabled':False,'protocolOperations':0}
    if marker.exists():
        prior=read(marker)
        require(all(prior.get(k)==v for k,v in expected.items()),'Cached controller dependency identity differs')
        require((target/'node_modules/.package-lock.json').is_file()
                and sha(target/'node_modules/.package-lock.json')==prior['nodeModuleLockSha256'],
                'Cached controller installation changed')
    else:
        require(not target.exists(),'Incomplete controller dependency attempt must be inspected, not overwritten')
        target.mkdir(parents=True,mode=0o700)
        shutil.copy2(project/'package.json',target/'package.json')
        (target/'package-lock.json').write_bytes(adapted)
        subprocess.run(['npm','--prefix',str(target),'ci','--ignore-scripts','--no-audit','--no-fund','--fetch-retries=3'],check=True)
        require(sha(target/'package-lock.json')==expected['installedLockSha256'],'Installation changed its pinned lock')
        expected['nodeModuleLockSha256']=sha(target/'node_modules/.package-lock.json')
        write(marker,expected,new=True)
    modules=project/'node_modules'
    if modules.is_symlink():
        require(modules.resolve()==(target/'node_modules').resolve(),'Another controller module directory is linked')
    else:
        if modules.exists():
            preserved=cache/'preserved-incomplete'/(name+'-'+uuid.uuid4().hex)
            preserved.parent.mkdir(parents=True,exist_ok=True);modules.rename(preserved)
        modules.symlink_to(target/'node_modules',target_is_directory=True)
    # Same original readiness check, using exactly the source-locked versions.
    script='const fs=require("node:fs"),{createRequire}=require("node:module"),d=process.argv[1],r=createRequire(d+"/package.json"),l=JSON.parse(fs.readFileSync(d+"/package-lock.json"));for(const n of ["ethers","solc"]){if(JSON.parse(fs.readFileSync(d+"/node_modules/"+n+"/package.json")).version!==l.packages["node_modules/"+n].version)throw Error("version mismatch");r(n)}'
    subprocess.run(['node','-e',script,str(project)],check=True)
    require(sha(project/'package-lock.json')==key and sha(project/'package.json')==expected['packageManifestSha256'],
            'Original repository manifests changed')
    result=read(report) if report.exists() else {'schema':VERSION,'projects':{},'protocolOperations':0}
    result['projects'][name]=read(marker);write(report,result)
    return result['projects'][name]


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['root','build','project','cache','report']:parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();install(args.root,args.build,args.project,args.cache,args.report)
