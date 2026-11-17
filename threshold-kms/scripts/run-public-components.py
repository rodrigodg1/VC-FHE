#!/usr/bin/env python3
"""Public-FHE/BLS preflight using retained native-pilot public material; no decryption."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

MODULE = Path(__file__).resolve().parents[1]

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-report', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    origin = args.native_report.resolve(); native = json.loads(origin.read_text())
    detail = origin.with_suffix('.detail.json'); source = detail.with_suffix('.public')
    detail_data = json.loads(detail.read_text())
    if 'setupAndKeygenSeconds' not in detail_data:
        parser.error('native run has no completed key generation')
    binary = Path(native['binary'])
    if sha(binary) != native['binarySha256']:
        parser.error('native binary changed; recover the matching executable first')
    for field in ('fhe','microIsa','integration'):
        entry = native['sourceClosure'][field]
        if sha(Path(entry['path'])) != entry['sha256']:
            parser.error(f'compiled source changed: {field}')
    out = args.out.resolve(); root = out.with_suffix('.detail.public')
    if out.exists() or root.exists():
        parser.error('select a fresh report path; earlier files are preserved')
    root.mkdir(parents=True); (root/'bin').mkdir()
    worker = root/'bin/public-worker'; shutil.copy2(binary, worker)
    for name in ('encryption-key.bin','evaluation-key.bin','a.bin','b.bin'):
        shutil.copy2(source/name,root/name)
    sk,pk=root/'evaluation-key.bin',root/'encryption-key.bin'
    bridge=MODULE/'scripts/compatible-binding.cjs'
    original_binding=json.loads((source/'sum-carry-four/binding-input.json').read_text())
    report={'status':'running','classification':'public-FHE-and-EVM-component-only','evaluationEvidence':False,
            'thresholdDecryptionCalls':0,'fheParameters':native['fheParameters'],
            'nativeOrigin':str(origin),'nativeOriginSha256':sha(origin),'nativeOriginStatus':native['status'],
            'keyId':detail_data['keyId'],'files':{},'linear':[],'nonlinear':[],
            'limitation':'Checks public computation and byte replay; plaintext correctness still requires recipient threshold decryption.'}
    save=lambda:out.write_text(json.dumps(report,indent=2)+'\n')
    env={**os.environ,'RAYON_NUM_THREADS':'1'}
    def run(command,log,cwd=None,extra=None):
        with log.open('x') as f:
            subprocess.run(command,cwd=cwd,env={**env,**(extra or {})},stdout=f,stderr=subprocess.STDOUT,check=True,timeout=600)
    def public(job,file):
        file.write_text(json.dumps(job))
        run([str(worker),'tops_public_fhe_worker','--exact','--nocapture','--test-threads=1'],
            file.with_suffix('.log'),extra={'TOPS_FHE_WORKER_JOB':str(file)})
    save()
    try:
        cases=[('sum-carry-four','SUM',[127]*4,[[0,127]]*4),
               ('sub-carry-four','SUB',[511]+[127]*4,[[511,511]]+[[0,127]]*4),
               ('sum-33','SUM',[i%5+1 for i in range(33)],[[1,5]]*33),
               ('sub-33','SUB',[511]+[15]*32,[[511,511]]+[[0,15]]*32)]
        for name,op,values,bounds in cases:
            directory=root/name; directory.mkdir()
            plan={'profile':'kms-grouped-radix-v1','op':op,'bounds':bounds}
            public({'action':'prepare','evaluationKey':str(sk),'publicKey':str(pk),'plan':plan,'values':values},directory/'prepare.json')
            cfg={**original_binding,'directory':str(directory),'plan':plan,'evaluationKey':str(sk),'workerBinary':str(worker)}
            file=directory/'binding-input.json';file.write_text(json.dumps(cfg))
            run(['node',str(bridge),str(file)],directory/'binding.log',MODULE.parent/'BN254-Signatures')
            row=json.loads((directory/'binding.json').read_text());report['linear'].append({'name':name,'status':row['status'],'records':len(values),'dimension':row['profile']['dimension'],'aggregateBytes':row['aggregateBytes'],'independentProcesses':2});save()
        for op,scalar in [('ADD',0),('SUB',0),('MUL',0),('DIV',3),('MOD',3),('EQ',0),('LT',0),('GT',0),('MIN',0),('BITAND',0),('BITOR',0),('BITXOR',0),('SHR',2),('CAST_U8',0),('ADD_CHAIN',3)]:
            outputs=[]
            for i in range(2):
                output=root/f'{op}-{i}.bin';outputs.append(output)
                public({'action':'nonlinear','evaluationKey':str(sk),'left':str(root/'a.bin'),'right':str(root/'b.bin'),'opcode':op,'public':scalar,'output':str(output)},root/f'{op}-{i}.json')
            if outputs[0].read_bytes()!=outputs[1].read_bytes():raise ValueError(f'byte replay differs: {op}')
            report['nonlinear'].append({'opcode':op,'independentProcesses':2,'byteReplayMatches':True});save()
        report['status']='passed'
    except Exception as error:
        report.update(status='failed',error=str(error));raise
    finally:
        report['files']={str(p.relative_to(root)):sha(p) for p in root.rglob('*') if p.is_file()}
        report['sourceHashes']={str(p):sha(p) for p in [Path(__file__),bridge,MODULE/'src/compatible_fhe.rs',MODULE/'contracts/GroupedLinearVerification.sol']}
        save()
    print(json.dumps({'status':report['status'],'linearCases':len(report['linear']),'nonlinearOperations':len(report['nonlinear']),'thresholdDecryptionCalls':0}))

if __name__=='__main__':
    main()
