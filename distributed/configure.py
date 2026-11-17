"""Render public participant settings after node-local enrollment."""
import json
from pathlib import Path
import re
import topology
import deployment

def render(config,identities,genesis_hash,output,run_id):
    plan=topology.plan(config)
    nodes={n['id']:n for n in plan['nodes']}
    if set(identities)!=set(nodes):raise ValueError('all 21 public role identities are required')
    if not re.fullmatch(r'0x[0-9a-fA-F]{64}',genesis_hash):raise ValueError('measured genesis block hash required')
    addresses={}
    fingerprints=set()
    for name,pub in identities.items():
        if pub.get('node')!=name or pub.get('host')!=nodes[name]['host']:raise ValueError('misassigned public identity')
        if not re.fullmatch('0x[0-9a-fA-F]{40}',pub.get('address','')):raise ValueError('invalid public address')
        fingerprint=pub.get('fingerprint256','').replace(':','').lower()
        if not re.fullmatch('[0-9a-f]{64}',fingerprint) or fingerprint in fingerprints:raise ValueError('duplicate or invalid TLS identity')
        if any(key in pub for key in ['privateKey','signingKey','secret','mnemonic']):raise ValueError('private identity in public enrollment')
        fingerprints.add(fingerprint);addresses[name]=pub['address']
    if len(set(a.lower() for a in addresses.values()))!=21:raise ValueError('role identities must be distinct')
    binary={p.get('binarySha256') for p in identities.values()}
    if len(binary)!=1 or None in binary:raise ValueError('campaign binary differs across nodes')
    output=Path(output)
    if output.exists():raise ValueError('use a new configured bundle directory')
    output.mkdir(parents=True)
    common=deployment.campaign_config(config,run_id)
    ca='\n'.join(p['certificate'].strip() for p in identities.values())+'\n'
    module=deployment.campaign_module()
    client='kms_type = "threshold"\nnum_majority = 2\nnum_reconstruct = 3\ndecryption_mode = "NoiseFloodSmall"\nfhe_params = "Test"\n'
    for i in range(1,5):
        client+=f'\n[[cores]]\nparty_id = {i}\naddress = "kms{i}:50100"\ns3_endpoint = "http://kms{i}:8080"\nobject_folder = "PUB-p{i}"\n'
    for name,node in nodes.items():
        folder=output/name;folder.mkdir()
        if node['role']=='validator':continue
        peers=[]
        for peer,pub in identities.items():
            other=nodes[peer]
            if other['role']=='validator':continue
            operations=['public-manifest','get-chunk','missing-chunks','put-chunk']
            if peer=='coordinator-1':operations+=['task','bind-contract','transaction']
            peers.append({'node':peer,'fingerprint256':pub['fingerprint256'],
                'url':f'https://{other["private_ip"]}:{9449 if other["role"]=="kms" else other["ports"][0]}/v1/role',
                'operations':operations})
        role={'campaign':config['campaign'],'node':name,'role':node['role'],'host':node['host'],
            'port':9449 if node['role']=='kms' else node['ports'][0],
            'rpcUrl':common['rpcUrl'],'chainId':common['chainId'],'genesisHash':genesis_hash,
            'identities':addresses,'peers':peers,'timeoutSeconds':common['timeoutSeconds'],
            'allowAdversarialAgreementControls':True,
            'tls':{'key':'/identity/tls.key','cert':'/identity/tls.crt','ca':'/config/ca.pem'}}
        if node['role']=='owner':role['ownerIndex']=node['index']-1
        for filename,value in [('role.json',role),('campaign.json',common),
                               ('owners.json',[addresses[f'owner-{i}'] for i in range(1,5)])]:
            (folder/filename).write_text(json.dumps(value,indent=2)+'\n' if filename!='owners.json' else json.dumps(value,separators=(',',':')))
        (folder/'ca.pem').write_text(ca)
        (folder/'client.toml').write_text(client)
        (folder/'recipient-address.txt').write_text(addresses['recipient-1'])
        (folder/'setup-public.hex').write_text(identities['coordinator-1']['setupPublicKey'])
        if node['role']=='kms':(folder/f'core-{node["index"]}.toml').write_text(module.core_config(node['index'],1,1))
    return {'directory':str(output),'participants':21,'privateKeysWritten':False,
            'genesisHash':genesis_hash,'binarySha256':next(iter(binary))}
