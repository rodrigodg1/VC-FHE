// Complete revised comparison. Fresh encrypted input fixture per repetition;
// both paths share that fixture, profile, authenticated statement and signer set.
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import ganache from "ganache";
import { ethers } from "ethers";
import { allApplicationWorkloadSpecs, lowerWorkloadSpec } from "./application-lowering.mjs";
import { runCanonicalBinary, createExecutionContext, detectCanonicalFault, hashJson, hashFile } from "./canonical-protocol.mjs";
import { createCanonicalGame } from "./canonical-game-driver.mjs";
import { canonicalFinalityAdapter } from "./canonical-chain.mjs";
import { OutputReleasePolicy } from "./output-release-policy.mjs";
import { SimulatedOutputKms } from "./simulated-output-kms.mjs";
const args=process.argv.slice(2),option=(flag,fallback)=>{const i=args.indexOf(flag);return i<0?fallback:args[i+1];};
const reportFile=option("--report"),binary=process.env.VCFHE_CIRCUIT_EXECUTOR;
const repeats=Number(option("--repeats","3")),records=Number(option("--records","16"));
if(!reportFile||!binary||!Number.isInteger(repeats)||repeats<1||!Number.isInteger(records)||records<2||records>16)throw new Error("supply binary, --report NEW.json, --repeats and --records (2..16)");
const dir=await fs.mkdtemp(path.join(os.tmpdir(),"tops-canonical-evaluation-"));
const exec=promisify(execFile),python=process.env.PYTHON_BIN||"python3";
const evidenceScript=new URL("./canonical_evidence.py",import.meta.url).pathname;
const evidenceFile=path.join(dir,"source-start.json");
await exec(python,[evidenceScript,"snapshot","--half","nonlinear","--binary",binary,"--out",evidenceFile]);
const report={status:"running",version:"canonical-comparison-v1",classification:records===16&&repeats>=3?"revised-application-comparison":"component-validation",
 workDir:dir,repeats,records,evidence:JSON.parse(await fs.readFile(evidenceFile,"utf8")),kms:"local full-key simulation; no DKG/MPC performance",cases:[],receipts:[],
 hardware:{cpu:os.cpus()[0].model,arch:os.arch(),os:os.platform(),release:os.release(),ramBytes:os.totalmem()},
 comparison:"one covering public audit versus two full public recomputations; same 2-of-3 adjudicators and authenticated task front end"};
await fs.writeFile(reportFile,JSON.stringify(report),{flag:"wx"});const save=()=>fs.writeFile(reportFile,JSON.stringify(report,null,2));
let server,provider;
try {
 const rpc=option("--rpc-url");let signers,rpcUrl=rpc;
 if(rpc){
  provider=new ethers.JsonRpcProvider(rpc,undefined,{cacheTimeout:-1,pollingInterval:100});
  const mnemonic=process.env.VCFHE_MNEMONIC;if(!mnemonic)throw new Error("configured QBFT mnemonic required");
  signers=Array.from({length:12},(_,i)=>ethers.HDNodeWallet.fromPhrase(mnemonic,undefined,`m/44'/60'/0'/0/${i}`).connect(provider));
  report.chain="configured-rpc";
 }else{
  server=ganache.server({logging:{quiet:true},wallet:{totalAccounts:20},chain:{chainId:31337,time:new Date("2025-01-01T00:00:00Z")},miner:{timestampIncrement:0}});
  await server.listen(0,"127.0.0.1");rpcUrl=`http://127.0.0.1:${server.address().port}`;
  provider=new ethers.JsonRpcProvider(rpcUrl,undefined,{cacheTimeout:-1,pollingInterval:20});
  signers=Object.values(server.provider.getInitialAccounts()).slice(0,12).map(a=>new ethers.Wallet(a.secretKey,provider));report.chain="in-process EVM; time advanced for protocol phases";
 }
 report.chainId=String((await provider.getNetwork()).chainId);
 const advanceSeconds=async seconds=>{
  if(!rpc){await provider.send("evm_increaseTime",[seconds]);await provider.send("evm_mine",[]);return;}
  const target=Number((await provider.getBlock("latest")).timestamp)+seconds;
  while(Number((await provider.getBlock("latest")).timestamp)<=target)await new Promise(resolve=>setTimeout(resolve,1000));
 };
 const specs=allApplicationWorkloadSpecs().filter(s=>["regulatory_qoe_compliance","regional_qoe_compliance"].includes(s.id));
 report.datasetHashes={};
 for(const file of ["../data/MOS_BS_1_Driver_PRB_10.csv","../data/MOS_BS_4_Driver_PRB_10.csv"]){report.datasetHashes[file]=await hashFile(file);}
 for(const spec of specs)for(let repeat=0;repeat<repeats;repeat++){
  const row={workload:spec.id,repeat,receipts:[]};const caseDir=path.join(dir,`${spec.id}-${repeat}`);await fs.mkdir(caseDir);
  const regional=spec.id==="regional_qoe_compliance",op=structuredClone(spec.operation);
  op.valuesMilli=op.valuesMilli.slice(0,records);if(regional)op.cells=op.cells.slice(0,records);
  const lowered=lowerWorkloadSpec({...spec,operation:op}),program=lowered.program;
  const values=[...op.valuesMilli,...(op.cells??[])];
  await fs.writeFile(path.join(caseDir,"program.json"),JSON.stringify(program));
  await fs.writeFile(path.join(caseDir,"values.json"),JSON.stringify(values));
  const t0=performance.now();await runCanonicalBinary(binary,["setup",path.join(caseDir,"program.json"),path.join(caseDir,"values.json"),caseDir]);row.setupMs=performance.now()-t0;
  const publicDir=path.join(caseDir,"public"),honestDir=path.join(caseDir,"honest");
  const sourceIds=Array.from({length:records},(_,i)=>{
   const source=regional?(i<8?"BS_1":"BS_4"):"BS_1";
   return ethers.id(`${source}:row:${op.metadata.rowNumbers[i]}`);
  });
  const selected=values.map((_,i)=>{const id=sourceIds[i%records];const owner=signers[8+Number(BigInt(id)%4n)];
   return{id:program.inputs[i].id,protectedId:id,owner:owner.address};});
  const context=await createExecutionContext({binary,publicDir,keyEpoch:`${spec.id}:${repeat}`,policyDomain:"revised-shared-record-policy",
   records:selected,inputBounds:values.map((_,i)=>({min:"0",max:i<records?"5000":"647999999"}))});
  const game=await createCanonicalGame({provider,signers,context,binary,publicDir,workDir:caseDir,rpcUrl,advanceSeconds,
   windowSeconds:rpc?Number(process.env.VCFHE_CANONICAL_WINDOW_SECONDS||1800):200,
   receipt:r=>{row.receipts.push(r);report.receipts.push({...r,workload:spec.id,repeat});}});
  const recipient=signers[0],domain=context.policyDomain;
  const unique=[...new Map(context.inputs.map(r=>[r.protectedId,r])).values()];
  const sign=(w,b)=>w.signMessage(ethers.getBytes(hashJson(b)));
  const kms=new SimulatedOutputKms({decryptExact:r=>runCanonicalBinary(binary,["release-output",path.join(caseDir,"owner/client-key.bin"),
   path.join(honestDir,`result-${program.instructions.length-1}.ct`),r.outputDigest])});
  const policy=new OutputReleasePolicy({ledgerFile:path.join(dir,"shared-release-ledger.json"),domain,kms,
   resolveFinalized:canonicalFinalityAdapter({...game,context,publicDir,operatorDir:honestDir})});
  for(const r of unique)if(!policy.inspectLedger().records[r.protectedId]){
   const record={id:r.protectedId,owner:r.owner,releaseLimit:2*repeats};
   await policy.registerProtectedRecord(record,await sign(signers.find(w=>w.address===r.owner),{kind:"protected-record-v1",domain,...record}));
  }
  const consent={kind:"final-output-consent-v1",domain,slot:ethers.id(`${game.game.target}:output`),contextDigest:hashJson(context),
   programDigest:context.programDigest,keyEpoch:context.keyEpoch,game:game.game.target,chainId:report.chainId,
   recordIds:unique.map(r=>r.protectedId),outputType:"bool",recipients:[recipient.address]};
  const signatures=Object.fromEntries(await Promise.all(unique.map(async r=>[r.owner.toLowerCase(),await sign(signers.find(w=>w.address===r.owner),consent)])));
  const consentId=await policy.registerConsent(consent,signatures);
  const start=performance.now();const honest=await runCanonicalBinary(binary,["execute-canonical",publicDir,honestDir]);row.operatorMs=performance.now()-start;
  const expected=lowered.program?lowered.witnesses.at(-1).claimed:null;
  await runCanonicalBinary(binary,["owner-check",path.join(caseDir,"owner/client-key.bin"),honestDir,String(expected)]);
  const taskId=ethers.id(`${game.game.target}:honest`);await game.createTask(taskId,honestDir);
  row.baseline=await game.fullExecutionBaseline(taskId);assert.equal(row.baseline.accepted,true);
  const auditStart=performance.now();row.honestReplay=await detectCanonicalFault({context,binary,publicDir,operatorDir:honestDir,replayDir:path.join(caseDir,"honest-auditor")});
  row.honestAuditWallMs=performance.now()-auditStart;assert.equal(row.honestReplay.index,null);
  await game.acceptHonest(taskId);
  const request={kind:"final-output-release-v1",domain,requestId:ethers.id(`${taskId}:release`),taskId,slot:consent.slot,consentId,
   contextDigest:consent.contextDigest,keyEpoch:context.keyEpoch,game:game.game.target,chainId:report.chainId,
   outputDigest:honest.terminalHandle,recipient:recipient.address};
  const releaseStart=performance.now();row.output=await policy.release(request,await sign(recipient,request));row.simulatedReleaseMs=performance.now()-releaseStart;
  assert.equal(row.output.value,String(expected));
  const operatorDir=path.join(caseDir,"faulty"),replayDir=path.join(caseDir,"fault-auditor");
  const faultIndex=repeat%3===0?0:repeat%3===1?Math.floor(program.instructions.length/2):program.instructions.length-1;
  await runCanonicalBinary(binary,["execute-canonical-fault-fixture",publicDir,operatorDir,String(faultIndex),"7"]);
  const badTask=ethers.id(`${game.game.target}:faulty`);await game.createTask(badTask,operatorDir);
  const detectionStart=performance.now();row.detection=await detectCanonicalFault({context,binary,publicDir,operatorDir,replayDir});row.detectionWallMs=performance.now()-detectionStart;
  assert.equal(row.detection.index,faultIndex);
  const disputeStart=performance.now();row.settlement=await game.auditAndChallenge(badTask,row.detection,replayDir);row.disputeWallMs=performance.now()-disputeStart;
  assert.equal(row.settlement.state[1],2);
  row.leaves=program.instructions.length;row.context=context;row.auditPlaintextOpenings=0;row.runtimeBytes=game.runtimeBytes;
  let publicBytes=0,traceBytes=0;for(const f of await fs.readdir(publicDir))publicBytes+=(await fs.stat(path.join(publicDir,f))).size;
  for(const f of await fs.readdir(honestDir))traceBytes+=(await fs.stat(path.join(honestDir,f))).size;
  row.publicBundleBytes=publicBytes;row.traceBytes=traceBytes;
  report.cases.push(row);await save();console.log(`${spec.id} repetition ${repeat+1}/${repeats}: passed, ${row.leaves} leaves`);
 }
 await exec(python,[evidenceScript,"verify",evidenceFile]);
 report.status="passed";
}catch(e){report.status="failed";report.error=String(e.stack??e);throw e;}
finally{await save();provider?.destroy();if(server)await server.close();}
