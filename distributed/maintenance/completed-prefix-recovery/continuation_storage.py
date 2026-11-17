"""Exact ownership checks for a separate, off-path archive scratch disk."""
from pathlib import Path


def check_layout(actual, expected, attached, scratch):
    if scratch is None:
        if attached != expected or len(actual['disks']) != 2:
            raise ValueError('Unexpected disk attachment')
        return
    matches=[d for d in actual['disks'] if d['source']==scratch['source']]
    if (attached != expected | {scratch['name']} or len(actual['disks']) != 3
        or len(matches)!=1 or matches[0].get('autoDelete') is not True
        or matches[0].get('deviceName')!='vcfhe-archive-c1'
        or str(actual['id'])!=str(scratch['vmId'])):
        raise ValueError('Archive scratch attachment or automatic deletion differs')


def record(campaign, host):
    from cloud_results.common import read
    host_id=host if isinstance(host,str) else host['id']
    manifest=read(campaign.run/'distributed/workflow-continuation/manifest.json')
    entries=manifest.get('archiveScratch',{})
    if set(entries)-{'host-1'}:
        raise ValueError('Unexpected archive scratch host')
    return entries.get(host_id)


def archive_scratch_path(campaign, host):
    from cloud_results.common import digest,require
    scratch=record(campaign,host)
    if scratch is None:return '/var/tmp'
    from cloud_results.common import read
    parent=read(campaign.run/'distributed/workflow-continuation/manifest.json')['parentRun']
    require(Path(parent).name==parent,'Unsafe predecessor identity')
    expected='/var/tmp/vcfhe-private-archive-'+digest({'run':str(campaign.run.with_name(parent)),'config':digest(campaign.config)})[:32]
    require(scratch['mountpoint']==expected,'Archive scratch path differs')
    return expected


def validate_archive_attachment(campaign,host,actual,expected,attached):
    from cloud_results.common import require
    import smoke_cleanup
    scratch=record(campaign,host)
    check_layout(actual,expected,attached,scratch)
    if scratch is None:return
    disk=smoke_cleanup._cloud(smoke_cleanup._args(campaign.config,
        ['compute','disks','describe',scratch['name'],'--zone',host['zone']]))
    require(str(disk['id'])==str(scratch['diskId']) and int(disk['sizeGb'])==300
        and disk['type'].endswith('/pd-standard') and disk.get('users')==[actual['selfLink']]
        and disk.get('labels',{}).get('experiment')==campaign.config['campaign']
        and disk['labels'].get('vcfhe-purpose')=='archive-c1','Archive scratch ownership differs')
    root=archive_scratch_path(campaign,host)
    remote=campaign.remotes[host['id']]
    import json
    script="import json,subprocess;print(json.dumps({'target':subprocess.check_output(['findmnt','-n','-o','TARGET','--target',"+repr(root)+"],text=True).strip(),'uuid':subprocess.check_output(['findmnt','-n','-o','UUID','--target',"+repr(root)+"],text=True).strip()}))"
    mounted=remote.json(['sudo','python3','-c',script])
    require(mounted=={'target':root,'uuid':scratch['filesystemUuid']},'Archive scratch filesystem changed')


def capacity_preflight(campaign):
    """Check measured free space plus explicit growth and archive/readback reserves."""
    from concurrent.futures import ThreadPoolExecutor
    from cloud_results.common import require,now,write
    import shutil
    gib=1024**3
    def inspect(host):
        remote=campaign.remotes[host['id']]
        used=int(remote.text(['sudo','du','-sb','/srv/vcfhe']).split()[0])
        data=int(remote.text(['df','-B1','--output=avail','/srv/vcfhe']).splitlines()[-1])
        archive=int(remote.text(['df','-B1','--output=avail',archive_scratch_path(campaign,host)]).splitlines()[-1])
        require(data>16*gib,'Less than reserved workflow growth remains')
        require(archive>2*(used+16*gib)+gib,'Insufficient archive and full-readback reserve')
        return {'host':host['id'],'sourceBytes':used,'dataFreeBytes':data,'archiveFreeBytes':archive,
            'workflowGrowthReserveBytes':16*gib}
    rows=list(ThreadPoolExecutor(max_workers=4).map(inspect,campaign.plan['hosts']))
    controller=shutil.disk_usage(campaign.run).free
    require(controller>2*48*gib+gib,'Insufficient controller archive and readback reserve')
    require(sum(r['sourceBytes']+16*gib for r in rows)+48*gib<=256*gib,'Archive allowance insufficient')
    result={'status':'passed-with-explicit-growth-reserves','observedAt':now(),'hosts':rows,
        'controllerFreeBytes':controller,'controllerArchiveReserveBytes':48*gib,'archiveAllowanceBytes':256*gib}
    write(campaign.run/'distributed/workflow-continuation/capacity-preflight.json',result)
    return result
