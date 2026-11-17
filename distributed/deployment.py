from diagnostic_profile import apply_campaign_profile
"""Per-host Docker declarations. Rendering does not create or contact VMs."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import topology
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent

def campaign_module():
    directory=ROOT/'threshold-kms/campaign'
    sys.path.insert(0,str(directory))
    spec=importlib.util.spec_from_file_location('local_campaign_runner',directory/'run.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def campaign_config(config,run_id):
    module=campaign_module()
    smoke=config.get('execution_mode')=='smoke'
    mode=['--poc-readiness','--smoke'] if smoke else ['--poc']
    args=module.parser().parse_args([*mode,'--fhe-params','Test','--allow-insecure-test',
        '--half','both','--nonlinear-protocol','bounty-v2','--kms-threads','1'])
    selected=module.selection(args)
    selected['windowSeconds']=config['window_seconds']
    if smoke:
        from smoke import CLASSIFICATION
        selected['classification']=CLASSIFICATION
    else:
        from experiment_plan import VERSION,plan
        selected['pocPlan']=plan('both')
        selected['distributedPlan']=VERSION
    common={'version':module.VERSION,'half':'both','parameters':'Test','smoke':smoke,
        'comparativeMetricsVersion':module.COMPARATIVE_METRICS_VERSION,
        'availabilityControlsVersion':module.AVAILABILITY_VERSION,
        'nonlinearSchedulingVersion':module.SCHEDULING_VERSION,**selected,
        'rpcUrl':'http://node1:8545','ownerRpcUrls':[f'http://node{i}:8545' for i in range(1,5)],
        'chainId':'46853','timeoutSeconds':86400,'kmsRayonThreads':1,'kmsTokioThreads':1,
        'infrastructureOrder':'besu-policy-before-kms-v3','targetCell':args.target_cell,
        'runId':run_id,'policyDomain':module.VERSION,'ownerReleaseLimit':18,
        'policyLineage':{'kind':'explicit-new-distributed-lineage','continuityWithLocalRun':False},
        'executionProfile':'gcp-four-hosts-role-local-v1'}
    return apply_campaign_profile(config,common)

def manifests(config,run_id):
    plan=topology.plan(config)
    nodes=plan['nodes']
    addresses={f'node{n["index"]}':n['private_ip'] for n in nodes if n['role']=='validator'}
    addresses.update({f'kms{n["index"]}':n['private_ip'] for n in nodes if n['role']=='kms'})
    app_image=config['images']['campaign'] or 'UNSET_CAMPAIGN_IMAGE_DIGEST'
    besu_image=config['images']['besu'] or 'UNSET_BESU_IMAGE_DIGEST'
    result={h['id']:{'name':config['campaign']+'-'+h['id'],'services':{}} for h in plan['hosts']}
    for node in nodes:
        root=node['state_directory']
        def mount(source,target,readonly=False):
            return {'type':'bind','source':root+'/'+source,'target':target,'read_only':readonly}
        base={'image':app_image,'user':'10001:10001','network_mode':'host','read_only':True,
            'init':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],
            'tmpfs':['/tmp:rw,nosuid,nodev,size=512m'],'extra_hosts':addresses,
            'environment':{'RAYON_NUM_THREADS':'1','RUST_LOG':'warn','NODE_ENV':'production',
                'VCFHE_FHE_PARAMS':'Test','VCFHE_ALLOW_INSECURE':'1','VCFHE_KMS_MAX_POLLS':'864000',
                'AWS_EC2_METADATA_DISABLED':'true'},'restart':'no'}
        services=result[node['host']]['services']
        if node['role']=='validator':
            services[node['id']]={'image':besu_image,'user':'10001:10001','network_mode':'host',
                'read_only':True,'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],
                # Besu loads its packaged JNA/Netty libraries from java.io.tmpdir.
                'tmpfs':['/tmp:rw,nosuid,nodev,exec,size=256m'],'restart':'no',
                'volumes':[mount('identity','/identity',True),mount('config','/config',True),mount('chain','/chain')],
                'command':['--data-path=/chain','--genesis-file=/config/genesis.json',
                    '--node-private-key-file=/identity/nodekey','--p2p-host='+node['private_ip'],
                    '--p2p-port=30303','--nat-method=NONE','--discovery-enabled=false','--static-nodes-file=/config/static-nodes.json',
                    '--rpc-http-enabled','--rpc-http-host=0.0.0.0','--rpc-http-port=8545',
                    '--rpc-http-api=ETH,NET,WEB3,QBFT','--host-allowlist=*','--min-gas-price=0']}
            continue
        volumes=[mount('config','/config',True),mount('identity','/identity',True),mount('transport','/transport'),
            mount('reports','/reports'),mount('fixtures','/fixtures'),mount('keyset','/keyset'),
            mount('release-evidence','/release-evidence'),mount('exchange','/exchange'),mount('worker-rpc','/worker-rpc')]
        if node['role']=='owner':
            volumes += [mount('owner','/owner'),mount('owner-rpc','/owner-rpc'),mount('datasets','/datasets',True)]
        if node['role']=='recipient':
            volumes += [mount('recipient','/recipient'),mount('identity','/recipient-identity',True)]
        services[node['id']]={**base,'entrypoint':['node','/app/distributed/service.mjs'],'volumes':volumes}
        if node['role']=='kms':
            services[node['id']+'-core']={**base,'command':['core'],
                'environment':{**base['environment'],'VCFHE_PARTY':str(node['index']),
                    'VCFHE_POLICY_RPC_URLS':','.join(f'http://node{i}:8545' for i in range(1,5)),
                    'VCFHE_RELEASE_POLICY_CONFIG':'/config/release-policy.json'},
                'volumes':[mount('config','/config',True),mount('private','/private'),mount('public','/public'),
                    mount('release-evidence','/release-evidence',True),mount('keyset','/release-keyset',True)]}
            services[node['id']+'-public']={**base,'command':['public-store'],'volumes':[mount('public','/public',True)]}
        if node['role']=='coordinator':
            for stage in ('init','setup','policy-init'):
                services[stage]={**base,'command':[stage],
                    'environment':{**base['environment'],'VCFHE_POLICY_RPC_URL':'http://node1:8545',
                        'VCFHE_EXPECTED_CHAIN_ID':'46853','VCFHE_ALLOW_NEW_POLICY_LINEAGE':'1'},
                    'volumes':[mount('config','/config'),mount('keyset','/keyset'),
                        mount('identity','/identity',True),
                        mount('identity/setup','/setup-identity',True),mount('policy-state','/policy-state')]}
    return result
