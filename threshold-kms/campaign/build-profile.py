#!/usr/bin/env python3
"""Deterministic, guarded adapter of pinned upstream sources (no MPC changes)."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1]
PIN = '986537258d8c0348f497b1860ccf63252bc238f3'

def profile():
    spec = importlib.util.spec_from_file_location('profile', MODULE/'scripts/kms-profile-build.py')
    p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
    return p

def once(source, before, after):
    if source.count(before) != 1:
        raise ValueError('pinned source layout changed: '+before[:80])
    return source.replace(before, after)

def add_locked_dependency(lock, package, dependency, before):
    marker='[[package]]\nname = "'+package+'"'
    if lock.count(marker)!=1:raise ValueError('pinned lock package changed: '+package)
    start=lock.index(marker);end=lock.find('[[package]]',start+1)
    if end<0:end=len(lock)
    section=lock[start:end]
    if f' "{dependency}",\n' in section:raise ValueError('lock dependency already present: '+package+'/'+dependency)
    section=once(section,f' "{before}",\n',f' "{dependency}",\n "{before}",\n')
    return lock[:start]+section+lock[end:]

def onchain_release_source():
    return (MODULE/'src/onchain_release.rs').read_text()

def linear_release_source():
    return (MODULE/'src/linear_release.rs').read_text()

def onchain_guard(operation):
    function={'USER_DECRYPT_REQUEST':'authorize_user_decrypt',
              'USER_DECRYPT_RESULT':'authorize_user_decryption_result'}.get(operation)
    if not function:raise ValueError('unsupported on-chain release operation: '+operation)
    return f'            vcfhe_onchain_release::{function}(request.get_ref()).await?;\n'

SETUP_METHODS = ['key_gen_preproc','get_key_gen_preproc_result','key_gen','get_key_gen_result','new_mpc_epoch','get_epoch_result']
DISABLED_METHODS = ['partial_key_gen_preproc','abort_key_gen','crs_gen','get_crs_gen_result','abort_crs_gen',
    'insecure_key_gen','get_insecure_key_gen_result','insecure_crs_gen','get_insecure_crs_gen_result',
    'new_mpc_context','destroy_mpc_context','destroy_mpc_epoch','new_custodian_context','destroy_custodian_context',
    'custodian_backup_recovery','restore_from_backup','custodian_recovery_init']

def at_method(source, name, guard):
    marker='        async fn '+name+'('
    if source.count(marker)!=1:raise ValueError('pinned endpoint changed: '+name)
    start=source.index('{',source.index(marker))
    return source[:start+1]+'\n'+guard+source[start+1:]

def administrative_guard(operation):
    return '''
            {
                use signature::hazmat::PrehashVerifier;
                let key = std::fs::read_to_string("/config/setup-public.hex")
                    .map_err(|_| Status::permission_denied("setup trust unavailable"))?;
                let key = hex::decode(key.trim()).map_err(|_| Status::permission_denied("bad setup key"))?;
                let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&key)
                    .map_err(|_| Status::permission_denied("bad setup key"))?;
                let sig = request.metadata().get("x-vcfhe-setup-signature")
                    .and_then(|s| s.to_str().ok()).unwrap_or("");
                let sig = hex::decode(sig).map_err(|_| Status::permission_denied("setup authorization required"))?;
                let sig = k256::ecdsa::Signature::from_slice(&sig)
                    .map_err(|_| Status::permission_denied("setup authorization required"))?;
                let mut payload = b"VCFHE_SETUP_V1:OPERATION:".to_vec();
                payload.extend(serde_json::to_vec(request.get_ref())
                    .map_err(|_| Status::permission_denied("invalid setup request"))?);
                key.verify_prehash(alloy_primitives::keccak256(payload).as_slice(), &sig)
                    .map_err(|_| Status::permission_denied("unauthorized setup request"))?;
            }
'''.replace('OPERATION',operation)

def instrument(root):
    p = profile()
    paths = ['core-client/tests/integration/integration_test.rs', 'core-client/Cargo.toml',
             'core/service/Cargo.toml', 'Cargo.lock', 'core/service/src/engine/threshold/endpoint.rs',
             'core-client/src/keygen.rs','core/service/src/bin/kms-init.rs','core/grpc/build.rs']
    original = {name:(root/name).read_text() for name in paths}
    source = original[paths[0]]
    for name, content in [
        ('tops_compatible_fhe', (MODULE/'src/compatible_fhe.rs').read_text()),
        ('tops_micro_isa', (MODULE.parent/'fhe-pod/crates/tfhe-pod-demo/src/micro_isa.rs').read_text()),
        ('tops_recipient_validation', (MODULE/'src/recipient_validation.rs').read_text()),
        ('tops_kms_circuit', p.circuit_source()),
        ('tops_kms_circuit_bridge', (MODULE/'src/kms_circuit_bridge.rs').read_text()),
    ]:
        source += '\nmod '+name+' {\n'+content+'\n}\n'
    source += (MODULE/'campaign/transport.rs').read_text()
    client_manifest = once(original['core-client/Cargo.toml'], 'serial_test.workspace = true\n',
                    'serde_json.workspace = true\nrayon.workspace = true\nserial_test.workspace = true\n')
    client_manifest = once(client_manifest, 'serde = { workspace = true, features = ["derive"] }\n',
                    'serde = { workspace = true, features = ["derive"] }\nserde_json.workspace = true\n')
    service_manifest = once(original['core/service/Cargo.toml'], 'rsa.workspace = true\n',
                            'reqwest.workspace = true\nrsa.workspace = true\n')
    lock=original['Cargo.lock']
    lock=add_locked_dependency(lock,'kms-core-client','rayon','rcgen')
    lock=add_locked_dependency(lock,'kms-core-client','serde_json','serial_test')
    lock=add_locked_dependency(lock,'kms','reqwest','rsa')
    endpoint = original['core/service/src/engine/threshold/endpoint.rs']
    endpoint += '\nmod vcfhe_linear_release {\n'+linear_release_source()+'\n}\n'
    endpoint += '\nmod vcfhe_onchain_release {\n'+onchain_release_source()+'\n}\n'
    # Every core authorizes the exact request from its independently configured
    # chain view. No relayer or shared gateway credential can authorize MPC.
    for op in ['USER_DECRYPT_REQUEST', 'USER_DECRYPT_RESULT']:
        marker = '            METRICS.increment_request_counter(OP_'+op+');'
        endpoint = once(endpoint, marker, onchain_guard(op)+marker)
    for op in ['PUBLIC_DECRYPT_REQUEST', 'PUBLIC_DECRYPT_RESULT']:
        marker = '            METRICS.increment_request_counter(OP_'+op+');'
        endpoint = once(endpoint, marker, '            return Err(Status::permission_denied("public decryption disabled"));\n'+marker)
    for method in SETUP_METHODS:endpoint=at_method(endpoint,method,administrative_guard(method))
    for method in DISABLED_METHODS:endpoint=at_method(endpoint,method,'            return Err(Status::permission_denied("operation disabled in dataset campaign"));\n')
    helper=(MODULE/'campaign/admin-request.rs').read_text()
    keygen=original['core-client/src/keygen.rs']
    for method,argument,count in [('key_gen','req_cloned',1),('get_key_gen_result','request_id.into()',2),
                                  ('key_gen_preproc','req_cloned',1),('get_key_gen_preproc_result','request_id.into()',2)]:
        before=f'.{method}(tonic::Request::new({argument}))'
        after=f'.{method}(vcfhe_setup_request(tonic::Request::new({argument}), "{method}"))'
        if keygen.count(before)!=count:raise ValueError('pinned setup client changed: '+method)
        keygen=keygen.replace(before,after)
    keygen+='\n'+helper
    init=once(original['core/service/src/bin/kms-init.rs'],'.new_mpc_epoch(request)',
              '.new_mpc_epoch(vcfhe_setup_request(tonic::Request::new(request), "new_mpc_epoch"))')
    init=once(init,'.get_epoch_result(kms_grpc::kms::v1::RequestId::from(*DEFAULT_EPOCH_ID))',
              '.get_epoch_result(vcfhe_setup_request(tonic::Request::new(kms_grpc::kms::v1::RequestId::from(*DEFAULT_EPOCH_ID)), "get_epoch_result"))')
    init+='\n'+helper
    grpc=once(original['core/grpc/build.rs'],'.type_attribute("KeyGenRequest", DERIVES)',
              '.type_attribute("KeyGenRequest", DERIVES)\n        .type_attribute("KeyGenPreprocRequest", DERIVES)\n        .type_attribute("NewMpcEpochRequest", DERIVES)\n        .type_attribute("PreviousEpochInfo", DERIVES)\n        .type_attribute("KeyInfo", DERIVES)\n        .type_attribute("CrsInfo", DERIVES)')
    updated = {
        'core-client/tests/integration/integration_test.rs':source,
        'core-client/Cargo.toml':client_manifest,
        'core/service/Cargo.toml':service_manifest,
        'Cargo.lock':lock,
        'core/service/src/engine/threshold/endpoint.rs':endpoint,
        'core-client/src/keygen.rs':keygen,
        'core/service/src/bin/kms-init.rs':init,
        'core/grpc/build.rs':grpc,
    }
    evidence = {}
    for name, content in updated.items():
        (root/name).write_text(content)
        evidence[name] = {'original':hashlib.sha256(original[name].encode()).hexdigest(),
                          'adapted':hashlib.sha256(content.encode()).hexdigest()}
    (root/'vcfhe-adapter.json').write_text(json.dumps({'upstreamCommit':PIN,'files':evidence,
        'releaseAuthorization':'on-chain-release-policy-v3-per-core-check','setupAuthenticatedMethods':SETUP_METHODS,
        'disabledMethods':DISABLED_METHODS},indent=2))

if __name__ == '__main__':
    parser=argparse.ArgumentParser(); group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--source',type=Path); group.add_argument('--runtime',type=Path)
    a=parser.parse_args()
    if a.source: instrument(a.source)
    else:
        profile().build_runtime(a.runtime)
        target=a.runtime/'scripts/canonical-protocol.mjs'
        source=target.read_text().replace((MODULE/'scripts/kms-public-worker.mjs').as_uri(),
                                          (MODULE/'campaign/public-worker.mjs').as_uri())
        target.write_text(source)
        mapping=json.loads((a.runtime/'source-map.json').read_text())
        mapping['canonical-protocol.mjs']['compiledViewSha256']=hashlib.sha256(source.encode()).hexdigest()
        target=a.runtime/'scripts/evm-lib.mjs'
        source=once(target.read_text(),'export const contractsOutDir = path.join(projectRoot, "contracts", "out");',
                    'export const contractsOutDir = "/tmp/vcfhe-compiled-contracts";')
        target.write_text(source)
        mapping['evm-lib.mjs']['compiledViewSha256']=hashlib.sha256(source.encode()).hexdigest()
        target=a.runtime/'scripts/canonical-game-driver.mjs'
        source=once(target.read_text(),'  const identityFiles = [];',
                    '  const identityFiles = [];\n  const identityDir = path.join("/tmp/vcfhe-attesters", game.target);\n  await fs.mkdir(identityDir, { recursive: true, mode: 0o700 });')
        source=once(source,'const f = path.join(workDir, `attester-${i}.key`);',
                    'const f = path.join(identityDir, `attester-${i}.key`);')
        target.write_text(source)
        mapping['canonical-game-driver.mjs']['compiledViewSha256']=hashlib.sha256(source.encode()).hexdigest()
        (a.runtime/'source-map.json').write_text(json.dumps(mapping,indent=2))
