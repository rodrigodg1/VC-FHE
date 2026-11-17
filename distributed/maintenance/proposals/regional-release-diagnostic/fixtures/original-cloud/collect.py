"""Collect only protocol reports and public evidence, then run original validators."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import deployment
import topology
from remote import read_host_profile

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n')

def distributed_deployment_files(campaign):
    """Bind the four actual Compose files and QBFT configurations.

    The local runner's top-level Compose/Besu descriptors do not describe this
    deployment. Preserve the files used by the distributed launcher instead.
    """
    run=campaign.run;files={};hosts=[]
    def reference(name):
        digest=sha(run/name);files[name]=digest
        return {'path':name,'sha256':digest}
    for host in campaign.plan['hosts']:
        name=f'compose/{host["id"]}/compose.json'
        if json.loads((run/name).read_text())!=campaign.compose[host['id']]:
            raise ValueError('preserved Compose differs from launched host: '+host['id'])
        hosts.append({'host':host['id'],'compose':reference(name)})
    validators=[];genesis=None;peers=None
    for i in range(1,5):
        node=f'validator-{i}';base=f'validator-config/{node}/'
        current=json.loads((run/(base+'genesis.json')).read_text())
        static=json.loads((run/(base+'static-nodes.json')).read_text())
        if current.get('config',{}).get('chainId')!=46853:
            raise ValueError('preserved distributed genesis has the wrong chain ID')
        if genesis is not None and (current!=genesis or static!=peers):
            raise ValueError('preserved validators disagree on genesis or static peers')
        genesis,peers=current,static
        validators.append({'node':node,'genesis':reference(base+'genesis.json'),
                           'staticPeers':reference(base+'static-nodes.json')})
    expected=sorted(campaign.identities[f'validator-{i}']['address'].lower() for i in range(1,5))
    if json.loads((run/'network/validators.json').read_text())!=expected:
        raise ValueError('preserved validator set differs from enrolled identities')
    record={'schema':'vcfhe-distributed-deployment-evidence-v1','chainId':46853,
            'hosts':hosts,'validators':validators,'validatorSet':reference('network/validators.json'),
            'publicIdentities':reference('distributed/public-identities.json')}
    write(run/'distributed/deployment.json',record)
    files['distributed/deployment.json']=sha(run/'distributed/deployment.json')
    return files

def collect_seal_files(campaign,module):
    """Use the original evidence roots with the real distributed descriptors."""
    run=campaign.run
    files={p.relative_to(run).as_posix():sha(p)
           for folder in module.SEALED_ARTIFACT_FOLDERS for p in (run/folder).rglob('*')
           if p.is_file() and not p.name.endswith('.key')}
    files.update({p.relative_to(run).as_posix():sha(p) for p in (run/'recipient').glob('result-*.json')})
    files.update({name:sha(run/name) for name in ['state.json','distributed-adapter.json']})
    files.update(distributed_deployment_files(campaign))
    return files

def collect(campaign):
    run=campaign.run;module=deployment.campaign_module()
    import time
    for host,r in campaign.remotes.items():r.run(['sudo','touch',campaign.base+'/'+host+'/stop-sampler'])
    time.sleep(12)
    for host,r in campaign.remotes.items():
        r.download(campaign.base+'/'+host,['host-observations.jsonl'],run/'distributed/samples'/host)
    remote=campaign.remote('coordinator-1')
    # Reports contain no owner private keys, recipient private keys or KMS shares.
    remote.download(campaign.root('coordinator-1'),['reports','fixtures','release-evidence','keyset','config'],run)
    coordinator=run
    campaign.remote('owner-1').download(campaign.root('owner-1'),['owner/expected.json'],run)
    app=json.loads((run/'reports/application.json').read_text())
    cfg=json.loads((run/'config/campaign.json').read_text())
    if cfg.get('smoke'):
        from smoke import validate_cases
        validate_cases(app['cases'])
    else:
        from experiment_plan import plan
        if len(app['cases'])!=plan('both')['fullCases']:raise ValueError('incomplete distributed full-case coverage')
    for i in range(len(app['cases'])):
        campaign.remote('recipient-1').download(campaign.root('recipient-1'),[f'recipient/result-{i}.json'],run)
    inventory=[]
    for name,node in campaign.nodes.items():
        if node['role']=='validator':continue
        target=coordinator if name=='coordinator-1' else run/'collected'/name
        if name!='coordinator-1':campaign.remote(name).download(campaign.root(name),['reports'],target)
        for record in (target/'reports/distributed').glob('*.task.json'):
            dest=run/'distributed/tasks'/name/record.name;dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(record,dest);inventory.append({'path':str(dest.relative_to(run)),'sha256':sha(dest)})
    write(run/'distributed/task-inventory.json',inventory)
    # Installed closure and measured executables are evidence, never rebuilt.
    image=campaign.config['images']['campaign'];extract=campaign.base+'/collected-image'
    remote.run(['sudo','install','-d','-m','700',extract+'/bin'])
    holder=remote.text(['sudo','docker','create',image])
    try:
        for binary in ['kms-campaign','kms-server','kms-gen-keys','kms-init']:
            remote.run(['sudo','docker','cp',holder+':/usr/local/bin/'+binary,extract+'/bin/'+binary])
        remote.run(['sudo','docker','cp',holder+':/app/threshold-kms/campaign/build-evidence',extract+'/build-evidence'])
        remote.run(['sudo','docker','cp',holder+':/app/threshold-kms/campaign/distributed-adapter.json',extract+'/distributed-adapter.json'])
    finally:remote.run(['sudo','docker','rm',holder],stdout=subprocess.DEVNULL)
    # Installed execution view may contain a build-time symlink to /tmp. Do not
    # follow it or transfer a runtime cache. It is not a source file.
    remote.run(['sudo','find',extract+'/build-evidence','-type','l','-delete'])
    remote.download(extract,['bin','build-evidence','distributed-adapter.json'],run)
    binary=sha(run/'bin/kms-campaign')
    if any(p['binarySha256']!=binary for p in campaign.identities.values()):raise ValueError('executed binary identity mismatch')
    hosts=[]
    for host in campaign.plan['hosts']:
        r=campaign.remotes[host['id']]
        report=read_host_profile(r)
        report.update(host=host['id'],region=host['region'],imageDigest=image,binarySha256=binary)
        write(run/'distributed/hosts'/f'{host["id"]}.json',report);hosts.append(host)
    cfg=json.loads((run/'config/campaign.json').read_text())
    source=module.source_manifest()
    if source!=campaign.record['localSource']:raise ValueError('protocol source changed during campaign')
    state={'version':module.VERSION,'status':'validating','config':cfg,'source':source,'upstream':module.PIN,
           'datasets':campaign.datasets,'imageId':image,'resources':{},'hostEnvironment':None,
           'distributedSourceSha256':topology.digest(campaign.record),'stages':campaign.state['stages']}
    write(run/'state.json',state)
    subprocess.run([sys.executable,str(Path(__file__).with_name('experiment_plan.py')),str(run)],check=True)
    app=json.loads((run/'reports/application.json').read_text())
    paired=json.loads((run/'reports/paired.json').read_text()) if (run/'reports/paired.json').exists() else {'rows':[]}
    summary={'executionProfile':'gcp-four-hosts-role-local-v1','status':'completed','hosts':hosts,
        'roles':campaign.plan['nodes'],'administration':'same-gcp-project',
        'pairTiming':'coordinator-request-response-including-public-transfer','imageDigest':image,
        'binarySha256':binary,'sourceSha256':topology.digest(campaign.record),
        'measuredPairs':sum(not row['warmup'] for row in paired['rows']),
        'warmups':sum(row['warmup'] for row in paired['rows']),'fullCases':len(app['cases'])}
    write(run/'distributed/execution.json',summary)
    # These are conclusions of the unchanged validator, not invented booleans.
    from supplement import generate
    generate(run,campaign.plan)
    state['status']='passed'
    (run/'state.json').write_text(json.dumps(state,indent=2)+'\n')
    files=collect_seal_files(campaign,module)
    files.update({str(p.relative_to(run)):sha(p) for p in (run/'distributed').rglob('*') if p.is_file()})
    files.update({str(p.relative_to(run)):sha(p) for p in (run/'collected').glob('*/reports/distributed/*') if p.is_file()})
    files.update({str(p.relative_to(run)):sha(p) for p in (run/'reports/distributed').glob('*') if p.is_file()})
    files['distributed-adapter.json']=sha(run/'distributed-adapter.json')
    seal={'version':module.VERSION,'source':source,'files':files,'parameters':cfg['parameters'],
          'classification':cfg['classification'],'halves':['linear','nonlinear']}
    write(run/'seal.json',seal)
    try:
        module.verify(run)
        if cfg.get('smoke'):
            from smoke import validate_cases
            summary=validate_cases(app['cases'])
            write(run/'distributed/smoke-result.json',dict(status='passed',**summary))
        else:
            from postprocess_adapter import validate
            validate(run)
    except BaseException:
        # Retain the failed seal for diagnosis. A failed state cannot publish.
        state['status']='failed';(run/'state.json').write_text(json.dumps(state,indent=2)+'\n');raise

