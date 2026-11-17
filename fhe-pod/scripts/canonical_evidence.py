#!/usr/bin/env python3
"""Source/binary freshness for canonical measurements; not a security proof."""
import argparse,hashlib,json,platform,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def digest(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def source_state(half):
 files=[ROOT/'fhe-pod/scripts'/name for name in ['run_canonical_evaluation.py','canonical_evidence.py',
   'canonical_support.py','publish_canonical_experiment.py']]
 if half=='nonlinear':
  base=ROOT/'fhe-pod'
  for name in ['canonical-protocol.mjs','canonical-chain.mjs','canonical-game-driver.mjs','canonical-attester.mjs',
   'canonical-evaluation.mjs','canonical-domain.mjs','output-release-policy.mjs','simulated-output-kms.mjs',
   'experimental-public-replay.mjs','compliance-circuit.mjs','micro-isa.mjs','application-lowering.mjs',
   'regulatory-fixtures.mjs','regulatory-fixtures.json','evm-lib.mjs',
   'canonical-profile-validation.mjs','canonical-integration.mjs','legacy-oracle-reconstruction.mjs',
   'canonical-preparation-costs.mjs']:
   files.append(base/'scripts'/name)
  files+=list((base/'contracts/src').glob('*.sol'))
  files+=list((base/'crates/tfhe-pod-demo/src').rglob('*.rs'))
  files+=[base/n for n in ['Cargo.toml','Cargo.lock','package-lock.json','crates/tfhe-pod-demo/Cargo.toml']]
  files+=[ROOT/'data'/n for n in ['MOS_BS_1_Driver_PRB_10.csv','MOS_BS_4_Driver_PRB_10.csv']]
 else:
  base=ROOT/'BN254-Signatures'
  files+=list((base/'contract').glob('*.sol'))
  files+=list((base/'src').rglob('*.rs'))
  files+=[base/n for n in ['Cargo.toml','Cargo.lock','package-lock.json','hardhat.config.js',
   'scripts/mklhs-lib.js','scripts/linear-v2-evaluation.js','scripts/linear-output-policy.mjs']]
  files+=[ROOT/'fhe-pod/scripts'/n for n in ['output-release-policy.mjs','simulated-output-kms.mjs','canonical-protocol.mjs']]
 return {str(p.relative_to(ROOT)):digest(p) for p in sorted(set(files))}
def state(half,binary):
 sources=source_state(half)
 return {'version':'canonical-source-v2','half':half,'sourceFiles':sources,
  'sourceHash':hashlib.sha256(json.dumps(sources,sort_keys=True).encode()).hexdigest(),
  'binary':str(Path(binary).resolve()),'binarySha256':digest(binary),'machine':platform.platform()}
def verify(snapshot):
 actual=state(snapshot['half'],snapshot['binary'])
 if actual!=snapshot:raise ValueError('source, dataset, binary or machine changed during/after the run')
 return actual
def main():
 p=argparse.ArgumentParser(description=__doc__);s=p.add_subparsers(dest='command',required=True)
 a=s.add_parser('snapshot');a.add_argument('--half',choices=['linear','nonlinear'],required=True);a.add_argument('--binary',required=True);a.add_argument('--out',required=True)
 a=s.add_parser('verify');a.add_argument('snapshot')
 a=s.add_parser('seal');a.add_argument('--snapshot',required=True);a.add_argument('--out',required=True);a.add_argument('artifacts',nargs='+')
 args=p.parse_args()
 if args.command=='snapshot':
  with open(args.out,'x') as f:json.dump(state(args.half,args.binary),f,indent=2)
 else:
  snapshot=json.loads(Path(args.snapshot).read_text());verify(snapshot)
  if args.command=='seal':
   artifact_hashes={str(Path(f).resolve()):digest(f) for f in args.artifacts}
   with open(args.out,'x') as f:json.dump({'snapshot':snapshot,'artifacts':artifact_hashes},f,indent=2)
 print('source/binary evidence verified')
if __name__=='__main__':
 try:main()
 except (ValueError,FileNotFoundError) as e:print(str(e),file=sys.stderr);sys.exit(1)
