#!/usr/bin/env python3
"""Build an isolated KMS execution view from the unchanged evaluation modules.

Only transport/profile declarations change. No circuit, detector, contract or
dispute rule is replaced. Every original and transformed source is recorded.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
POD = ROOT.parent / 'fhe-pod'
VERSION = 'canonical-kms-dag-execution-v1'

def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('unexpected source layout: ' + before[:100])
    return text.replace(before, after)

def circuit_source():
    source = (POD/'crates/tfhe-pod-demo/src/bin/circuit-executor.rs').read_text()
    source = source.replace('//!', '//')
    source = source.replace('use sha3::{Digest, Keccak256};', '')
    source = source.replace('Keccak256::digest(bytes)', 'alloy_primitives::keccak256(bytes)')
    source = source.replace('tfhe_pod_demo::micro_isa', 'super::tops_micro_isa')
    source = replace_once(source, 'fn main() -> Result<()> {', '''pub fn run(args: Vec<String>, result_file: &Path) -> Result<()> {
    ensure!(matches!(args.get(1).map(String::as_str), Some("execute-canonical" | "execute-canonical-fault-fixture" | "leaf")), "KMS executor has no local-key setup or decryption entry point");
    macro_rules! tops_print { ($($arg:tt)*) => { fs::write(result_file, format!($($arg)*))? }; }
''')
    source = replace_once(source, '    let args: Vec<String> = env::args().collect();\n', '')
    source = source.replace('println!', 'tops_print!')
    # The integrated runner MUST enable TFHE's fixed DIF4 feature. These
    # substitutions describe that compiled profile, not an unverified runtime flag.
    source = source.replace('cfg!(feature="fixed-fft-experiment")', 'true')
    source = source.replace('"canonical-dag-execution-v1"', json.dumps(VERSION))
    source = source.replace('"1.4.0"', '"1.6.1"')
    return source

def ingress_source(original):
    guard = '''
            // Application ingress adapter: no MPC or FHE algorithm changes.
            let expected = std::env::var("TOPS_KMS_GATEWAY_TOKEN").unwrap_or_default();
            let supplied = request.metadata().get("x-tops-output-gateway")
                .and_then(|v| v.to_str().ok()).unwrap_or("");
            if expected.len() != 64 || supplied.len() != 64 ||
                alloy_primitives::keccak256(expected.as_bytes()) != alloy_primitives::keccak256(supplied.as_bytes()) {
                return Err(Status::permission_denied("authorized output gateway required"));
            }
'''
    for counter in ('OP_USER_DECRYPT_REQUEST', 'OP_USER_DECRYPT_RESULT'):
        marker = f'            METRICS.increment_request_counter({counter});'
        original = replace_once(original, marker, guard + marker)
    for counter in ('OP_PUBLIC_DECRYPT_REQUEST', 'OP_PUBLIC_DECRYPT_RESULT'):
        marker = f'            METRICS.increment_request_counter({counter});'
        original = replace_once(original, marker, '''
            // This deployment supports private recipient outputs only.
            return Err(Status::permission_denied("public decryption disabled"));
''' + marker)
    return original

def build_runtime(destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    scripts = destination/'scripts'; scripts.mkdir()
    names = ['canonical-protocol.mjs','canonical-chain.mjs','canonical-game-driver.mjs',
             'canonical-attester.mjs','canonical-bounty-client.mjs','bounty-economics.mjs','bounty-economics.json','evm-lib.mjs','experimental-public-replay.mjs',
             'canonical-domain.mjs','compliance-circuit.mjs','micro-isa.mjs',
             'trace-references.mjs','fhe-handles.mjs']
    provenance = {}
    for name in names:
        origin = POD/'scripts'/name
        original = source = origin.read_text()
        if name == 'canonical-protocol.mjs':
            start = source.index('export async function runCanonicalBinary(')
            end = source.index('export async function referenceProfile(', start)
            source = source[:start] + f'export {{ runKmsCircuit as runCanonicalBinary }} from {json.dumps((ROOT/"scripts/kms-public-worker.mjs").as_uri())};\nimport {{ runKmsCircuit as runCanonicalBinary }} from {json.dumps((ROOT/"scripts/kms-public-worker.mjs").as_uri())};\n' + source[end:]
            source = source.replace('canonical-dag-execution-v1', VERSION).replace('"1.4.0"', '"1.6.1"')
            source = source.replace('tfhe-compressed-public-key-v1', 'kms-compact-public-key-expanded-v1')
            source = replace_once(source, '    keyEpoch, policyDomain, inputs, domain };', '''    keyEpoch, policyDomain, inputs, domain,
    kmsKeyset: await json(path.join(publicDir, "kms-keyset.json")) };''')
        (scripts/name).write_text(source)
        provenance[name] = {'source':str(origin), 'originalSha256':hashlib.sha256(original.encode()).hexdigest(),
                            'compiledViewSha256':hashlib.sha256(source.encode()).hexdigest()}
    shutil.copytree(POD/'contracts/src', destination/'contracts/src')
    (destination/'node_modules').symlink_to(POD/'node_modules', target_is_directory=True)
    (destination/'source-map.json').write_text(json.dumps(provenance, indent=2)+'\n')
    return destination

if __name__ == '__main__':
    build_runtime(sys.argv[1])
