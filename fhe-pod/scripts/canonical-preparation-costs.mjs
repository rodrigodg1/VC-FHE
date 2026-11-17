// Separate preparation measurements over the exact measured public bundles.
// No FHE execution, finality response, or decryption is simulated as a cost here.
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert/strict';
import { ethers } from 'ethers';
import { createExecutionContext, hashJson, hashFile } from './canonical-protocol.mjs';
import { OutputReleasePolicy } from './output-release-policy.mjs';
const [sourceFile,outputFile]=process.argv.slice(2),binary=process.env.VCFHE_CIRCUIT_EXECUTOR;
if(!sourceFile||!outputFile||!binary)throw new Error('requires comparison report, new output file and canonical binary');
const source=JSON.parse(await fs.readFile(sourceFile,'utf8'));assert.equal(source.status,'passed');
const workDir=await fs.mkdtemp(path.join(os.tmpdir(),'tops-preparation-costs-'));
const report={status:'running',classification:'canonical-preparation-costs',sourceFile:path.resolve(sourceFile),
  sourceDigest:await hashFile(sourceFile),workDir,records:source.records,repeats:source.repeats,
  scope:'separate local preparation using measured public bundles and fresh owner signing identities; no FHE or chain latency',cases:[]};
await fs.writeFile(outputFile,JSON.stringify(report),{flag:'wx'});
const save=()=>fs.writeFile(outputFile,JSON.stringify(report,null,2));
try {
  for(const r of source.cases){
    const publicDir=path.join(source.workDir,`${r.workload}-${r.repeat}`,'public');
    let start=performance.now();const wallets=Array.from({length:4},()=>ethers.Wallet.createRandom());
    const row={workload:r.workload,repeat:r.repeat,ownerSigningKeySetupMs:performance.now()-start};
    const recordIds=[...new Set(r.context.inputs.map(i=>i.protectedId))];
    const records=r.context.inputs.map(i=>({id:i.id,protectedId:i.protectedId,owner:wallets[Number(BigInt(i.protectedId)%4n)].address}));
    start=performance.now();
    const context=await createExecutionContext({binary,publicDir,records,inputBounds:r.context.domain.inputBounds,
      keyEpoch:r.context.keyEpoch,policyDomain:r.context.policyDomain});
    row.publicContextMs=performance.now()-start;
    start=performance.now();
    const domain=context.policyDomain,sign=(w,b)=>w.signMessage(ethers.getBytes(hashJson(b)));
    const policy=new OutputReleasePolicy({domain,ledgerFile:path.join(workDir,`${r.workload}-${r.repeat}.json`),
      resolveFinalized:async()=>{throw new Error('preparation never resolves an output');},
      kms:{decryptAuthorized:async()=>{throw new Error('preparation never decrypts');}}});
    for(const id of recordIds){
      const wallet=wallets[Number(BigInt(id)%4n)],record={id,owner:wallet.address,releaseLimit:source.repeats*2};
      await policy.registerProtectedRecord(record,await sign(wallet,{kind:'protected-record-v1',domain,...record}));
    }
    const consent={kind:'final-output-consent-v1',domain,slot:ethers.id(`prep-slot-${r.workload}-${r.repeat}`),contextDigest:hashJson(context),
      programDigest:context.programDigest,keyEpoch:context.keyEpoch,game:'0x0000000000000000000000000000000000000001',chainId:source.chainId,
      recordIds,outputType:'bool',recipients:[wallets[0].address]};
    const signatures=Object.fromEntries(await Promise.all(wallets.map(async w=>[w.address.toLowerCase(),await sign(w,consent)])));
    await policy.registerConsent(consent,signatures);row.policyPreparationMs=performance.now()-start;
    row.protectedRecords=recordIds.length;row.encryptedInputs=records.length;
    assert.equal(Object.keys(policy.inspectLedger().records).length,recordIds.length);
    report.cases.push(row);await save();
  }
  assert.equal(report.sourceDigest,await hashFile(sourceFile));
  report.status='passed';
}catch(e){report.status='failed';report.error=String(e.stack??e);throw e;}
finally{await save();}
