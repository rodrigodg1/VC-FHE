"""Reuse a published native stage for reviewed experiment-controller changes."""
import copy
import hashlib
from pathlib import Path
import re
from cloud_results.common import read,write,require,sha
import image
import topology


def render(dockerfile, native_digest):
    require(re.fullmatch(r'[a-z0-9./_-]+@sha256:[a-f0-9]{64}',native_digest),
            'An immutable private native-stage digest is required')
    anchor='FROM node AS runtime\n'
    require(dockerfile.count(anchor)==1 and dockerfile.count('FROM rust:')==1,
            'Reviewed multi-stage Dockerfile layout changed')
    preamble=dockerfile.split('FROM rust:',1)[0]
    runtime=anchor+dockerfile.split(anchor,1)[1]
    result=preamble+'# Native FHE/KMS binaries are imported unchanged from the existing successful build.\nFROM '+native_digest+' AS build\n'+runtime
    require('cargo build' not in result and 'cargo test' not in result,'Native recompilation is forbidden in this route')
    return result


def prepare(config, original_context, smoke_run, output, native_digest):
    original_context,smoke_run,output=map(Path,(original_context,smoke_run,output))
    old=read(original_context/'distributed-source.json');publication=read(original_context/'published-image.json')
    require(publication.get('buildStatus')=='SUCCESS' and publication['sourceSha256']==topology.digest(old),
            'Missing source-bound successful native build')
    require(native_digest.startswith(publication['digest'].rsplit('/',1)[0]+'/native-cache@sha256:'),
            'Native stage must remain in the source-bound private image repository')
    require(read(smoke_run/'distributed/source.json')==old,'Reference used another native source closure')
    require(read(smoke_run/'smoke-cleanup.local.json').get('status')=='passed','Original infrastructure cleanup must finish first')
    identities=read(smoke_run/'distributed/public-identities.json')
    hashes={row['binarySha256'] for row in identities.values()}
    require(len(identities)==21 and len(hashes)==1,'Missing exact enrolled native binary identity')
    native_hashes={'kms-campaign':hashes.pop()}
    require(re.fullmatch('[a-f0-9]{64}',native_hashes['kms-campaign']),'Invalid native binary digest')
    execution=read(smoke_run/'launch-state.json')
    successful=(smoke_run/'distributed/smoke-result.json').is_file() and read(smoke_run/'distributed/smoke-result.json').get('status')=='passed'
    if successful:image.deployment.campaign_module().verify(smoke_run)
    else:
        require(execution['status']=='failed' and not any(t['name']=='Four-core PRSS, preprocessing and DKG' for t in execution['stages']),
                'An unsealed native reference is permitted only for an interrupted pre-KMS harness')
    require(old['localSource']==image.deployment.campaign_module().source_manifest(),
            'FHE/protocol source changed. Budget-only native reuse refused')
    record=image.prepare(image.ROOT/'threshold-kms/.cache',output)
    upstream=lambda r:{k:v for k,v in r['buildInputs'].items() if k.startswith('upstream/')}
    require(upstream(old)==upstream(record),'Native upstream input changed')
    changed={k for k in set(old['distributedSource'])|set(record['distributedSource'])
             if old['distributedSource'].get(k)!=record['distributedSource'].get(k)}
    require(changed=={'topology.py','worker.mjs','agreement-control-policy.mjs'},'Unexpected adapter change outside the reviewed financial and diagnostic controls')
    before=(original_context/'app/distributed/topology.py').read_text()
    expected=before.replace('budget["maximum"] <= 50','budget["maximum"] <= 100').replace("author's USD 50 total budget","author's USD 100 total budget")
    require((output/'app/distributed/topology.py').read_text()==expected and expected!=before,
            'Unexpected role, protocol or topology modification')
    old_worker=(original_context/'app/distributed/worker.mjs').read_text()
    control_start=old_worker.index('    const fullCase=config.pocPlan?')
    control_end=old_worker.index('    assert.equal(b.taskId',control_start)
    expected_worker=("import {allowsAdversarialAgreementControl} from './agreement-control-policy.mjs';\n"+
        old_worker[:control_start]+'    assert.ok(allowsAdversarialAgreementControl(config,b.caseName));\n'+old_worker[control_end:])
    require((output/'app/distributed/worker.mjs').read_text()==expected_worker,'Unexpected worker modification')
    proposal=Path(image.HERE)/'maintenance/proposals/regional-agreement-classification/agreement-control-policy.mjs'
    require((output/'app/distributed/agreement-control-policy.mjs').read_bytes()==proposal.read_bytes(),
            'Diagnostic-control policy differs from its regression-tested proposal')
    docker=(output/'Dockerfile').read_text()
    native_before=docker.split('FROM node AS runtime\n',1)[0]
    require(native_before==(original_context/'Dockerfile').read_text().split('FROM node AS runtime\n',1)[0],
            'Native Docker build definition changed')
    (output/'Dockerfile').write_text(render(docker,native_digest))
    record['dockerfileSha256']=sha(output/'Dockerfile')
    record['nativeLayerReuse']={'schema':'published-native-reuse-v1','sourceImageSha256':topology.digest(old),
        'sourceEvidenceKind':'sealed-smoke' if successful else 'interrupted-before-KMS',
        'sourceSealSha256':sha(smoke_run/'seal.json') if successful else None,
        'enrolledIdentitiesSha256':sha(smoke_run/'distributed/public-identities.json'),'nativeStageDigest':native_digest,
        'upstreamInputsSha256':topology.digest(upstream(old)),'expectedNativeBinaries':native_hashes,
        'changedAdapters':sorted(changed),'changeScope':'Authorized budget ceiling and experiment-only negative-control eligibility',
        'nativeCompilationAllowed':False,'successfulWorkflowsRepeated':False}
    write(output/'distributed-source.json',record)
    image.verify_inputs(output,record);image.verify_adapter_sources(record)
    return record


def launch_smoke(config,quote,context,run_dir):
    """Original smoke with a pre-KMS native identity check, never another case."""
    import launch
    require(config.get('execution_mode')=='smoke' and config.get('diagnostic_profile')=='regional-output-release-v1',
            'Only the one-case regional diagnostic is authorized here')
    class CheckedSmoke(launch.Campaign):
        def initialize(self):
            super().initialize()
            target=self.run/'distributed/native-reuse-controller.py'
            target.write_bytes(Path(__file__).read_bytes())
            tls_controller=self.run/'distributed/public-tls-controller.py'
            tls_controller.write_bytes(Path(__file__).with_name('public_tls.py').read_bytes())
            owner_controller=self.run/'distributed/public-owner-witness-controller.py'
            owner_controller.write_bytes(Path(__file__).with_name('owner_materials.py').read_bytes())
            write(self.run/'distributed/native-reuse-controller.json',{
                'sourceSha256':sha(target),'publicTlsControllerSha256':sha(tls_controller),
                'publicOwnerWitnessControllerSha256':sha(owner_controller),
                'scope':'Native identity verification, readable public KMS certificates and public owner witness collection',
                'originalProtocolMethodsUsed':True},new=True)
        def collect(self):
            from cloud_results.owner_materials import collect as collect_public_owner_witnesses
            collect_public_owner_witnesses(self)
            return super().collect()
        def kms(self):
            from cloud_results.public_tls import readable_public_exchange
            with readable_public_exchange(self):
                return super().kms()
        def enrollment(self):
            super().enrollment()
            proof=self.record['nativeLayerReuse']
            expected=proof['expectedNativeBinaries']['kms-campaign']
            require(len(self.identities)==21 and all(v['binarySha256']==expected for v in self.identities.values()),
                    'Reused native binary differs before KMS setup')
            write(self.run/'distributed/native-reuse-validation.json',{'status':'passed',
                'enrolledRoles':21,'binarySha256':expected,'nativeRecompiled':False,
                'sourceImageSha256':proof['sourceImageSha256']},new=True)
    return CheckedSmoke(config,quote,context,run_dir).run_all()
