import {nonlinearProfile} from './nonlinear-profile.mjs';
// Untrusted transaction relayer and public evaluation controller. Consent,
// cumulative budgets and exact final-output authorization live on chain. This
// role has no owner secret, recipient secret or KMS private vault.
import fs from 'node:fs/promises';
import {createProgress} from './progress.mjs';
const progress=createProgress('evaluation');
let progressCase={};
const showProgress=(phase,state='start')=>progress(phase,{...progressCase,state});
import assert from 'node:assert/strict';
import {ethers,json,atomic,waitFile,ownerRpc,OwnerSigner,cancelPending} from './common.mjs';
import {canonicalProgramRoot,computeConsentIdV3,computeReleaseDigestV3,kmsReleaseAuthorizationV3,kmsSubmitAuthorization,loadReleasePolicy,nonlinearInputTerms,outputTypeDigest,releaseRequestFromWire} from './onchain-policy.mjs';
import {linear} from './linear.mjs';
import {readLatestBlock,waitForChainTimestamp} from './chain-read.mjs';
import {transactionCosts as measureTransactionCosts} from './receipt-metrics.mjs';
import {measuredJsonCommand,summarizeAdjudicatorWork} from './adjudicator-metrics.mjs';
import {fileURLToPath} from 'node:url';
import {runPairs} from './paired.mjs';
import {createExecutionContext,runCanonicalBinary,detectCanonicalFault,hashJson} from './runtime/scripts/canonical-protocol.mjs';
import {createCanonicalGame} from './runtime/scripts/canonical-game-driver.mjs';
import {canonicalFinalityAdapter} from './runtime/scripts/canonical-chain.mjs';
const cfg=await json('/config/campaign.json');
const disputesOnly=cfg.readinessDisputesOnly==='bounty-v2-dispute-readiness-v1';
assert.ok(cfg.readinessDisputesOnly===undefined||disputesOnly,'unknown dispute-only readiness profile');
assert.ok(!disputesOnly||(cfg.readinessOnly&&cfg.smoke&&cfg.half==='nonlinear'&&
 cfg.parameters==='Test'&&cfg.nonlinearProtocol==='bounty-v2'&&!cfg.pocPlan&&!cfg.policyRefreshPlan),
 'dispute-only checks cannot replace full campaign cases');
const auditFirst=cfg.nonlinearSchedulingVersion==='audit-first-baseline-in-finality-wait-v1';
assert.ok(cfg.nonlinearSchedulingVersion===undefined||auditFirst,'unknown nonlinear scheduling version');
assert.ok(!auditFirst||(cfg.half!=='linear'&&cfg.nonlinearProtocol==='bounty-v2'),'invalid nonlinear scheduling scope');
assert.ok(!(cfg.pocPlan&&cfg.policyRefreshPlan),'paired and V3 policy-refresh plans are mutually exclusive');
const casePlan=cfg.pocPlan??cfg.policyRefreshPlan;
const prepared=await waitFile('/fixtures/prepared.json',cfg.timeoutSeconds),keys=prepared.keys;
if(cfg.policyRefreshPlan){
 const attempt=cfg.policyRefreshAttempt,preflight=await json('/reports/release-capacity-preflight.json');
 assert.ok(attempt&&attempt.status==='permanently-claimed','V3 refresh evaluation started before permanent claim');
 assert.equal(attempt.runId,cfg.runId);assert.equal(attempt.requestedHalf,cfg.half);
 assert.deepEqual(attempt.claimedScopes,cfg.half==='both'?['linear','nonlinear']:[cfg.half]);
 assert.equal(attempt.designSha256,cfg.policyRefreshPlan.designSha256);
 assert.equal(preflight.status,'passed');assert.equal(preflight.designSha256,cfg.policyRefreshPlan.designSha256);
 assert.deepEqual(preflight.caseNames,prepared.cases.map(item=>item.name));
}
class CampaignProvider extends ethers.JsonRpcProvider {
 async getBlock(tag,prefetch){
  if(tag!=='latest')return super.getBlock(tag,prefetch);
  return readLatestBlock(()=>super.getBlock(tag,prefetch),{onRetry:r=>console.warn('READ_ONLY_RPC_RETRY '+JSON.stringify(r))});
 }
}
const provider=new CampaignProvider(cfg.rpcUrl,undefined,{cacheTimeout:-1,pollingInterval:250});
const validatorProviders=Array.from({length:4},(_,i)=>new ethers.JsonRpcProvider(`http://node${i+1}:8545`,undefined,
 {cacheTimeout:-1,pollingInterval:250}));
// Reject pending transport/RPC waits so the durable policy's finally block can
// release its lock. Reserved budget is never refunded or replayed on shutdown.
for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{cancelPending(signal);provider.destroy();});
assert.equal(String((await provider.getNetwork()).chainId),cfg.chainId);
const validators=await provider.send('qbft_getValidatorsByBlockNumber',['latest']);
assert.equal(new Set(validators.map(a=>a.toLowerCase())).size,4,'four live QBFT validators required');
assert.ok(Number(BigInt(await provider.send('net_peerCount',[])))>=3,'validator peer set unavailable');
const firstBlock=await provider.getBlockNumber();
const blockDeadline=Date.now()+60000;
while(await provider.getBlockNumber()<=firstBlock){assert.ok(Date.now()<blockDeadline,'QBFT chain stalled');await new Promise(r=>setTimeout(r,1000));}
const mnemonic='test test test test test test test test test test test junk';
const signers=Array.from({length:8},(_,i)=>ethers.HDNodeWallet.fromPhrase(mnemonic,undefined,`m/44'/60'/0'/0/${i}`).connect(provider));
const recipient=(await fs.readFile('/config/recipient-address.txt','utf8')).trim();
const loadedPolicy=await loadReleasePolicy(provider),registry=loadedPolicy.contract.connect(signers[0]);
const policyDomain=await registry.policyDomain();
const report={version:cfg.version,receiptMetricsVersion:'mined-fee-v1',status:'running',config:cfg,keys,cases:[],receipts:[],policyEvents:[],
  protectedRecordBaselines:{},kmsCalls:0,
  plaintextInRelayer:false,onChainPolicy:{address:registry.target,runtimeCodeHash:loadedPolicy.config.runtimeCodeHash,
    version:Number(await registry.POLICY_VERSION()),domain:policyDomain,
    ownersSha256:loadedPolicy.config.ownersSha256}};
report.chain={chainId:cfg.chainId,consensus:'QBFT',validators,observedBlock:firstBlock,advancedBlock:await provider.getBlockNumber()};
const save=()=>atomic('/reports/application.json',report);
const evidenceValue=value=>typeof value==='bigint'?value.toString():Array.isArray(value)?value.map(evidenceValue)
 :value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([k,v])=>[k,evidenceValue(v)])):value;
const recordReceipt=(label,r)=>{
 assert.equal(r.status,1);const existing=report.receipts.find(row=>row.hash===r.hash);
 if(existing){assert.equal(existing.label,label,'transaction reconciled under a different scope');return r;}
 report.receipts.push({label,hash:r.hash,gasUsed:r.gasUsed.toString(),block:r.blockNumber,blockHash:r.blockHash});
 for(const log of r.logs){
  if(log.address.toLowerCase()!==registry.target.toLowerCase())continue;
  let parsed;try{parsed=registry.interface.parseLog(log);}catch{continue;}
  const args={};for(let i=0;i<parsed.fragment.inputs.length;i++)args[parsed.fragment.inputs[i].name]=evidenceValue(parsed.args[i]);
  const logIndex=Number(log.index??log.logIndex);
  assert.equal(report.policyEvents.some(row=>row.transactionHash===r.hash&&row.logIndex===logIndex),false,
   'duplicate release-policy event');
  report.policyEvents.push({name:parsed.name,transactionHash:r.hash,blockNumber:r.blockNumber,
   blockHash:r.blockHash,logIndex,args,topics:Array.from(log.topics),data:log.data});
 }
 return r;
};
const receipt=async(label,tx)=>recordReceipt(label,await tx.wait());
async function reconcileReceipt(label,send,verify,filter){
 try{return await receipt(label,await send());}
 catch(error){
  if(!await verify())throw error;
  const logs=await registry.queryFilter(filter,0,'latest');assert.equal(logs.length,1,`ambiguous ${label} event`);
  const mined=await provider.getTransactionReceipt(logs[0].transactionHash);assert.ok(mined,`missing ${label} receipt`);
  return recordReceipt(label,mined);
 }
}
const transactionCosts=receipts=>measureTransactionCosts(provider,receipts);
// canonical-game-driver supplies both the legacy relative delta and the exact
// timestamp immediately after the contract deadline. Use the latter so a block
// mined between the driver's read and this wait cannot extend the phase.
const advanceSeconds=(_seconds,targetTimestamp)=>waitForChainTimestamp(
 ()=>provider.getBlock('latest'),targetTimestamp);
const reservationObservation=async(p,index,blockTag,reservation,consentData,submitData,resultData)=>{
 const chainId=await p.send('eth_chainId',[]);
 if(String(BigInt(chainId))!==String(cfg.chainId))throw Error(`validator ${index+1} chain mismatch`);
 const block=await p.send('eth_getBlockByNumber',[blockTag,false]);
 if(!block||block.hash.toLowerCase()!==reservation.blockHash.toLowerCase())throw Error(`validator ${index+1} lacks reservation block`);
 const code=await p.send('eth_getCode',[registry.target,blockTag]);
 if(code==='0x'||ethers.keccak256(code)!==loadedPolicy.config.runtimeCodeHash)throw Error(`validator ${index+1} policy mismatch`);
 const consent=await p.send('eth_call',[{to:registry.target,data:consentData},blockTag]);
 const submit=await p.send('eth_call',[{to:registry.target,data:submitData},blockTag]);
 const result=await p.send('eth_call',[{to:registry.target,data:resultData},blockTag]);
 // Decode each response before preserving its exact calldata and return bytes.
 // The offline validator independently reconstructs these calls and the V3
 // ConsentState tuple. This binds the recorded authorization terms to the
 // state queried at the exact reservation block, rather than to a relayer
 // summary that could omit context or keyset fields.
 registry.interface.decodeFunctionResult('getConsent',consent);
 if(!registry.interface.decodeFunctionResult('isSubmitAuthorized',submit)[0]||
    !registry.interface.decodeFunctionResult('isResultAuthorized',result)[0])throw Error(`validator ${index+1} denies reservation`);
 return{validator:index+1,chainId:String(BigInt(chainId)),blockNumber:reservation.blockNumber,
  blockHash:block.hash,policyCodeHash:ethers.keccak256(code),policyCalls:{
   consent:{calldata:consentData,result:consent},
   submit:{calldata:submitData,result:submit},
   result:{calldata:resultData,result}}};
};
const boundedReservationObservation=(promise,timeoutMs,index)=>{
 let timer;
 return Promise.race([promise,new Promise((_,reject)=>{
  timer=setTimeout(()=>reject(Error(`validator ${index+1} reservation observation timed out`)),timeoutMs);
 })]).finally(()=>clearTimeout(timer));
};
async function confirmReservationAcrossValidators(reservation,submitAuthorization,releaseRequest){
 const blockTag=ethers.toQuantity(reservation.blockNumber),deadline=Date.now()+60000;
 assert.ok(reservation.blockHash,'reservation receipt has no block hash');
 const consentData=registry.interface.encodeFunctionData('getConsent',[submitAuthorization.consentId]);
 const submitData=registry.interface.encodeFunctionData('isSubmitAuthorized',[submitAuthorization]);
 const resultData=registry.interface.encodeFunctionData('isResultAuthorized',[
 releaseRequest.requestId,releaseRequest.requestKey,releaseRequest.resultQueryDigest]);
 while(true){
  const timeoutMs=Math.max(1,Math.min(5000,deadline-Date.now()));
  const settled=await Promise.allSettled(validatorProviders.map((p,index)=>boundedReservationObservation(
   reservationObservation(p,index,blockTag,reservation,consentData,submitData,resultData),timeoutMs,index)));
  const rows=settled.flatMap(row=>row.status==='fulfilled'?[row.value]:[]).sort((a,b)=>a.validator-b.validator);
  if(rows.length>=3)return rows;
  if(Date.now()>=deadline){
   const failures=settled.flatMap((row,index)=>row.status==='rejected'?[`validator ${index+1}: ${row.reason?.message??row.reason}`]:[]);
   throw Error(`reservation confirmation quorum failed: ${rows.length}/4 validators confirmed; ${failures.join('; ')}`);
  }
  await new Promise(resolve=>setTimeout(resolve,500));
 }
}
let index=0;
async function nonlinear(item,ownerSigners){
 const profile=nonlinearProfile(cfg.nonlinearProtocol);
 const dir=`/fixtures/${item.name}`,publicDir=dir+'/public',honestDir=dir+'/honest',binary='/usr/local/bin/kms-campaign';
 const program=await json(publicDir+'/program.json');
 const context=await createExecutionContext({binary,publicDir,keyEpoch:keys.keyEpoch,policyDomain:cfg.policyDomain,
   inputBounds:item.inputBounds,records:program.inputs.map((r,i)=>({id:r.id,protectedId:item.recordIds[i%item.n],owner:item.owners[i%item.n]}))});
 const comparative=cfg.comparativeMetricsVersion==='comparative-metrics-v1';
 const adjudicatorWork=[],roleWork=[];
 let workerSequence=0;
 const measure=async({role,purpose,taskId,phase,command,args,input})=>{
  if(role==='adjudicator')showProgress({'context-certification':'context-certification',
   'full-execution-certification':'full-certification','leaf-result-certification':'leaf-certification'}[purpose]);
  const target=role==='adjudicator'?adjudicatorWork:roleWork;
  const measurementId=`${item.name}-worker-${workerSequence++}`,outputDir=`/reports/resources/${item.name}`;
  const publicMetricsFile=`${outputDir}/${measurementId}.public.jsonl`;
  const metadata={taskId,phase};
  const remoteResources=async()=>{
   try{return (await fs.readFile(publicMetricsFile,'utf8')).trim().split('\n').filter(Boolean).map(line=>JSON.parse(line));}
   catch(error){if(error.code==='ENOENT')return [];throw error;}
  };
  const retain=async measurement=>{
   const observation={...measurement,...metadata,publicWorkerResources:await remoteResources()};
   await fs.writeFile(`${outputDir}/${measurementId}.observation.json`,JSON.stringify(observation,null,2)+'\n',{flag:'wx'});
   target.push(observation);
  };
  try{
   const result=await measuredJsonCommand({command,args,input,
    outputDir,measurementId,role,purpose,executionScope:'controller-only-remote-fhe-excluded',
    env:{...process.env,VCFHE_PUBLIC_WORKER_METRICS_FILE:publicMetricsFile}});
   const native=result.value?.evidence?.replayMs??result.value?.evidence?.elapsedMs??result.value?.replayMs??result.value?.elapsedMs;
   if(typeof native==='number'&&Number.isFinite(native)&&native>=0)result.measurement.nativeFheElapsedMs=native;
   await retain(result.measurement);return result.value;
  }catch(error){
   if(error.measurement)await retain(error.measurement);
   throw error;
  }
 };
 const workerRunner=comparative?request=>measure({role:'adjudicator',
  purpose:{context:'context-certification',full:'full-execution-certification',leaf:'leaf-result-certification'}[request.mode],
  taskId:request.taskId,phase:request.operatorDir===honestDir?'honest':'challenged',
  command:process.execPath,args:[fileURLToPath(new URL('./runtime/scripts/canonical-attester.mjs',import.meta.url))],input:request}):undefined;
 const game=await createCanonicalGame({provider,signers:[...signers,...ownerSigners],context,binary,publicDir,workDir:dir,
   workerRunner,
   nonlinearProtocol:profile.protocol,rpcUrl:cfg.rpcUrl,advanceSeconds,windowSeconds:cfg.windowSeconds,disclosureBatchSize:cfg.disclosureBatchSize,
   auditorFundingLeafCount:cfg.readinessOnly||casePlan?program.instructions.length:undefined,
   receipt:r=>report.receipts.push(r)});
 const deployment=name=>{const row=game.txs.find(value=>value.label===`deploy:${name}`);assert.ok(row);return row.txHash;};
 const workflow={schema:'vcfhe-workflow-deployment-v1',kind:profile.kind,
  game:game.game.target,availability:game.availability.target,verifier:game.verifier.target,
  objective:await game.game.objectiveVerifier(),canonicalSigners:game.identities.map(value=>value.address),
  deployments:{objective:deployment('ObjectiveMicroVerifier'),game:deployment(profile.game),
   availability:deployment(profile.availability),verifier:deployment('CanonicalLeafVerifier')}};
 for(const address of new Set(item.owners.map(value=>value.toLowerCase()))){
  const owner=ownerSigners.find(value=>value.address.toLowerCase()===address);assert.ok(owner);
  await ownerRpc({action:'bind-workflow',caseName:item.name,index:owner.index,workflow});
 }
 const taskId=ethers.id(`${item.name}:${game.game.target}`);
 const inputs=nonlinearInputTerms(context);
 const binding={chainId:cfg.chainId,game:game.game.target,taskId,contextDigest:hashJson(context),programDigest:context.programDigest,
    programRoot:canonicalProgramRoot(taskId,program),...inputs,
    keyId:keys.keyId,keyEpoch:keys.keyEpoch,mpcContext:keys.mpcContext,keysetDigest:keys.keysetDigest,
    profileDigest:hashJson(context.profile),workflowManifest:workflow};
 const terminal=program.instructions.length-1;
 const outputFile=honestDir+`/result-${terminal}.ct`,finality=canonicalFinalityAdapter({...game,context,publicDir,operatorDir:honestDir});
 const resolve=async r=>{const final=await finality(r);return final?{...binding,...final,taskId,aggregateDigest:final.outputDigest}:null;};
 const metrics={leaves:program.instructions.length,nonlinearProtocol:profile.protocol,
  ...(comparative?{adjudicatorWork,roleWork}:{}),
  ...(profile.economics?{economics:profile.economics}:{}),disputes:[]};
 const measuredAudit=async(request,taskId,phase)=>comparative?measure({role:'auditor',purpose:'auditor-full-recomputation',
  taskId,phase,command:process.execPath,args:[fileURLToPath(new URL('./public-audit-worker.mjs',import.meta.url))],input:request}):detectCanonicalFault(request);
 const measuredOperator=async(args,taskId,phase)=>comparative?measure({role:'operator',purpose:'operator-execution',
  taskId,phase,command:process.execPath,args:[fileURLToPath(new URL('./public-operation-worker.mjs',import.meta.url))],
  input:{binary,args}}):runCanonicalBinary(binary,args);
 const collectComparative=async()=>{
  if(comparative){
   metrics.adjudicatorWorkSummary=summarizeAdjudicatorWork(adjudicatorWork);
   metrics.roleWorkSummary=summarizeAdjudicatorWork(roleWork);
  }
 };
 const execute=async()=>{
  showProgress('operator-execution');
  let start=performance.now();const output=await measuredOperator(['execute-canonical',publicDir,honestDir],taskId,'honest');metrics.operatorMs=performance.now()-start;
  const created=await game.createTask(taskId,honestDir);
  assert.equal(created.plan.programTree.root,binding.programRoot,'canonical program-root derivation changed');
  const baseline=async()=>{
   metrics.baseline=await game.fullExecutionBaseline(taskId);assert.equal(metrics.baseline.accepted,true);
  };
  if(!auditFirst)await baseline();
  showProgress('auditor-recomputation');
  start=performance.now();const detection=await measuredAudit({context,binary,publicDir,operatorDir:honestDir,replayDir:dir+'/replay'},taskId,'honest');
  metrics.auditMs=performance.now()-start;assert.equal(detection.index,null);
  showProgress('honest-finalization');
  start=performance.now();
  const finalized=await game.acceptHonest(taskId,auditFirst?{duringFinalizationWait:baseline}:undefined);
  metrics.finalizationMs=performance.now()-start;
  if(auditFirst){
   assert.ok(finalized?.finalizationWaitWork&&metrics.baseline?.accepted,'scheduled baseline did not complete');
   metrics.scheduling={version:cfg.nonlinearSchedulingVersion,baselinePlacement:'after-audit-opening',
    finalizationIncludesBaseline:true,...finalized.finalizationWaitWork};
  }
  return {taskId,aggregateDigest:output.terminalHandle,outputDigest:output.terminalHandle,outputType:'bool'};
 };
 const disputes=async()=>{
  // Largest-size admission must exercise terminal disclosure/adjudication.
  const position=item.faultPosition;
  const faultIndex=cfg.readinessOnly?terminal:position?{early:0,middle:Math.floor(terminal/2),terminal}[position]:item.repeat%3===0?0:item.repeat%3===1?Math.floor(terminal/2):terminal;
  assert.ok(Number.isSafeInteger(faultIndex));
  const operatorDir=dir+'/fault',replayDir=dir+'/fault-replay';
  const task=ethers.id(`${item.name}:fault`);
  showProgress('faulty-execution');
  await measuredOperator(['execute-canonical-fault-fixture',publicDir,operatorDir,String(faultIndex),'7'],task,'challenged');
  await game.createTask(task,operatorDir);
  showProgress('trace-disclosure');
  const start=performance.now();
  await game.discloseBeforeAudit(task);
  showProgress('auditor-recomputation');
  const detection=await measuredAudit({context,binary,publicDir,operatorDir,replayDir},task,'challenged');
  assert.equal(detection.index,faultIndex);showProgress('dispute-settlement');
  const settlement=await game.auditAndChallenge(task,detection,replayDir);
  assert.equal(settlement.state[0],3);assert.equal(settlement.state[1],2);
  metrics.disputes.push({faultIndex,seconds:(performance.now()-start)/1000,settlement});
  showProgress('dispute-settlement','done');
 };
 return {binding,metrics,execute,resolve,outputFile,outputType:'bool',disputes,collectComparative};
}
try{
 await save();
 if(cfg.pocPlan)await runPairs(cfg,prepared);
 let fullCaseIndex=0;
 const fullCaseTotal=prepared.cases.filter(c=>!casePlan||c.fullCase).length;
 for(const item of prepared.cases.filter(c=>!casePlan||c.fullCase)){
  progressCase={caseName:item.name,current:++fullCaseIndex,total:fullCaseTotal,group:'full'};
  showProgress('full-case');showProgress('workflow-deploy');
  console.log('CASE '+item.name);const caseStart=performance.now(),receiptStart=report.receipts.length;
  const ownerSigners=prepared.owners.map((address,i)=>new OwnerSigner(address,i,provider,item.name));
  for(const owner of ownerSigners)if(await provider.getBalance(owner.address)<ethers.parseEther('1'))await receipt('fund-owner',await signers[0].sendTransaction({to:owner.address,value:ethers.parseEther('2')}));
  const w=await (item.half==='linear'?linear({item,keys,admin:signers[0],operator:signers[1],ownerSigners,receipt,progress:showProgress}):nonlinear(item,ownerSigners));
  if(disputesOnly){
   assert.equal(item.half,'nonlinear');assert.ok(w.disputes);
   const disputeStart=performance.now(),first=report.receipts.length;
   await w.disputes();w.metrics.disputeWorkflowMs=performance.now()-disputeStart;
   w.metrics.disputeCosts=await transactionCosts(report.receipts.slice(first));
   await w.collectComparative?.();
   report.cases.push({...item,metrics:w.metrics,workflowManifest:w.binding.workflowManifest,
    readinessScope:'dispute-only-no-output-release',...await transactionCosts(report.receipts.slice(receiptStart))});
   await save();showProgress('dispute-only-case','done');continue;
  }
  showProgress('owner-consent');
  for(let i=0;i<item.recordIds.length;i++){
   assert.equal(await registry.deriveProtectedId(item.owners[i],item.recordReferences[i]),item.recordIds[i]);
   let record=await registry.protectedRecords(item.recordIds[i]);
   if(record.owner===ethers.ZeroAddress){
   const owner=ownerSigners.find(s=>s.address.toLowerCase()===item.owners[i].toLowerCase());assert.ok(owner);
    await reconcileReceipt('protected-record-registration',()=>registry.connect(owner).registerProtectedRecord(
      item.recordIds[i],item.owners[i],item.recordReferences[i],item.releaseLimits[i],item.initialSpent[i]),async()=>{
       const current=await registry.protectedRecords(item.recordIds[i]);return current.owner.toLowerCase()===item.owners[i].toLowerCase()&&
        current.recordReference===item.recordReferences[i]&&Number(current.releaseLimit)===item.releaseLimits[i]&&
        Number(current.spent)>=item.initialSpent[i];
      },registry.filters.ProtectedRecordRegistered(item.recordIds[i],item.owners[i],item.recordReferences[i]));
    record=await registry.protectedRecords(item.recordIds[i]);
   }else{
    assert.equal(record.owner.toLowerCase(),item.owners[i].toLowerCase());
    assert.equal(record.recordReference,item.recordReferences[i]);
    assert.equal(Number(record.releaseLimit),item.releaseLimits[i]);
    assert.ok(Number(record.spent)>=item.initialSpent[i],'on-chain spend regressed below migrated counter');
   }
   if(!Object.hasOwn(report.protectedRecordBaselines,item.recordIds[i]))report.protectedRecordBaselines[item.recordIds[i]]={
    owner:record.owner,recordReference:record.recordReference,releaseLimit:Number(record.releaseLimit),spent:Number(record.spent)};
  }
  const consent={domain:policyDomain,chainId:cfg.chainId,workflowKind:item.half==='linear'?1:2,
   workflow:w.binding.game,taskId:w.binding.taskId,contextDigest:w.binding.contextDigest,
   programDigest:w.binding.programDigest,programRoot:w.binding.programRoot,profileDigest:w.binding.profileDigest,
   keysetDigest:w.binding.keysetDigest,keyId:w.binding.keyId,keyEpoch:w.binding.keyEpoch,
   mpcContext:w.binding.mpcContext,outputType:outputTypeDigest(w.outputType),recipient,
   slot:ethers.id(`${cfg.runId}:${item.name}:final:onchain-v3`),protectedRecordIds:item.recordIds,
   inputProtectedRecordIds:w.binding.inputProtectedRecordIds??[],inputBindings:w.binding.inputBindings};
  const consentId=computeConsentIdV3(registry.target,consent);
  assert.equal(consentId,await registry.computeConsentId(consent),'local and on-chain consent IDs differ');
  await reconcileReceipt('create-release-consent',()=>registry.createConsent(consent),async()=>{
   const state=await registry.getConsent(consentId);return state.exists&&state.taskId===consent.taskId&&
    state.slot===consent.slot&&state.recipient.toLowerCase()===recipient.toLowerCase();
  },registry.filters.ConsentCreated(consentId));
  for(const address of new Set(item.owners.map(value=>value.toLowerCase()))){
   const owner=ownerSigners.find(s=>s.address.toLowerCase()===address);assert.ok(owner);
   await reconcileReceipt('approve-release-consent',()=>registry.connect(owner).approveConsent(consentId),
    ()=>registry.consentApprovedBy(consentId,owner.address),registry.filters.ConsentApproved(consentId,owner.address));
  }
  const output=await w.execute();showProgress('recipient-verification');const releaseStart=performance.now();
  const authorization=kmsReleaseAuthorizationV3({policy:registry.target,policyDomain,consentId,
   binding:w.binding,output,recipient,workflowKind:consent.workflowKind,slot:consent.slot});
  await atomic(`/exchange/request-${index}.json`,{name:item.name,authorization,ciphertextHex:(await fs.readFile(w.outputFile)).toString('hex')});
  const activeWire=await waitFile(`/exchange/wire-${index}.json`,cfg.timeoutSeconds);
  const wire=Uint8Array.from(Buffer.from(activeWire.wire,'hex'));
  const getWire=Uint8Array.from(Buffer.from(activeWire.get,'hex')),r=activeWire.request;
  const releaseRequest=releaseRequestFromWire({consentId,decoded:r,wire,getWire});
  assert.deepEqual(activeWire.releaseRequest,releaseRequest,'recipient signed a different release request');
  assert.equal(releaseRequest.finalOutputDigest,output.outputDigest);
  assert.equal(releaseRequest.aggregateDigest,output.aggregateDigest);
  const final=await w.resolve(r);assert.ok(final,'finalized output did not match the approved computation');
  assert.equal(final.outputDigest,releaseRequest.finalOutputDigest);
  assert.deepEqual([...final.recordIds].sort(),[...item.recordIds].sort());
  await waitFile(`/exchange/pre-reservation-${index}.json`,cfg.timeoutSeconds);
  const submitAuthorization=kmsSubmitAuthorization(r,releaseRequest);
  assert.equal(await registry.isSubmitAuthorized(submitAuthorization),false);
  const expectedReleaseDigest=computeReleaseDigestV3(releaseRequest);
  assert.equal(expectedReleaseDigest,await registry.releaseStructHash(releaseRequest),'local and on-chain release digests differ');
  showProgress('release-approval');
  await reconcileReceipt('propose-exact-release',()=>registry.proposeRelease(releaseRequest,activeWire.recipientSignature),async()=>{
   const state=await registry.getRelease(releaseRequest.requestId);
   return state.exists&&state.releaseDigest===expectedReleaseDigest;
  },registry.filters.ReleaseProposed(releaseRequest.requestId));
  for(const address of new Set(item.owners.map(value=>value.toLowerCase()))){
   const owner=ownerSigners.find(s=>s.address.toLowerCase()===address);assert.ok(owner);
   await reconcileReceipt('approve-exact-release',()=>registry.connect(owner).approveRelease(releaseRequest.requestId,expectedReleaseDigest),
    ()=>registry.releaseApprovedBy(releaseRequest.requestId,owner.address),
    registry.filters.ReleaseApproved(releaseRequest.requestId,owner.address));
  }
  const reservation=await reconcileReceipt('reserve-exact-release',()=>registry.reserveRelease(releaseRequest,activeWire.recipientSignature),async()=>{
   const state=await registry.getRelease(releaseRequest.requestId);
   return state.reserved&&(await registry.requestByKey(releaseRequest.requestKey))===releaseRequest.requestId&&
    (await registry.requestBySlot(consent.slot))===releaseRequest.requestId;
  },registry.filters.ReleaseReserved(releaseRequest.requestId));
  assert.equal(await registry.isSubmitAuthorized(submitAuthorization),true);
  assert.equal(await registry.isResultAuthorized(releaseRequest.requestId,releaseRequest.requestKey,releaseRequest.resultQueryDigest),true);
  await assert.rejects(registry.reserveRelease(releaseRequest,activeWire.recipientSignature));
  const validatorConfirmations=await confirmReservationAcrossValidators(reservation,submitAuthorization,releaseRequest);
  await atomic(`/exchange/reserved-${index}.json`,{status:'reserved',requestId:releaseRequest.requestId,
   requestKey:releaseRequest.requestKey,submitWireDigest:releaseRequest.submitWireDigest,
   resultQueryDigest:releaseRequest.resultQueryDigest,transactionHash:reservation.hash,blockNumber:reservation.blockNumber,
   blockHash:reservation.blockHash,validatorConfirmations});
  showProgress('threshold-release');
  const encrypted=Buffer.from((await waitFile(`/exchange/responses-${index}.json`,cfg.timeoutSeconds)).bytes,'hex');
  report.kmsCalls+=1;
  const row={...item,metrics:w.metrics,releaseMs:performance.now()-releaseStart,endToEndMs:performance.now()-caseStart,
    consentId,releaseRequestId:releaseRequest.requestId,reservationTransaction:reservation.hash,
    reservationBlockHash:reservation.blockHash,validatorConfirmations,
    requestKey:releaseRequest.requestKey,submitWireDigest:releaseRequest.submitWireDigest,
    resultQueryDigest:releaseRequest.resultQueryDigest,aggregateDigest:releaseRequest.aggregateDigest,
    recipientEncryptionKeyDigest:releaseRequest.recipientEncryptionKeyDigest,recipient:releaseRequest.recipient,
    releaseSlot:consent.slot,outputDigest:output.outputDigest,recipientResponseBytes:encrypted.length,finalOutputKmsCalls:1,
     workflowKind:consent.workflowKind,workflowManifest:w.binding.workflowManifest,
     workflowManifestDigest:hashJson(w.binding.workflowManifest),inputBindingsDigest:submitAuthorization.inputBindingsDigest,
     linearWitnessDigest:w.binding.linearWitnessDigest??null,
     submitAuthorization:evidenceValue(submitAuthorization)};
  showProgress('recipient-recovery','done');
  // Byte accounting runs after timing endpoints and never changes the delivery.
  if(cfg.comparativeMetricsVersion==='comparative-metrics-v1')await w.collectCommunication?.();
  await w.collectComparative?.();
  Object.assign(row,await transactionCosts(report.receipts.slice(receiptStart)));
  report.cases.push(row);index++;await save();
  if(w.disputes){
   const start=performance.now(),first=report.receipts.length;await w.disputes();
   w.metrics.disputeWorkflowMs=performance.now()-start;
   w.metrics.disputeCosts=await transactionCosts(report.receipts.slice(first));
   await w.collectComparative?.();await save();
  }
  showProgress('full-case','done');
 }
 const protectedIds=disputesOnly?[]:[...new Set(report.cases.flatMap(row=>row.recordIds))];
 report.protectedRecords=Object.fromEntries(await Promise.all(protectedIds.map(async id=>{
  const record=await registry.protectedRecords(id);return [id,{owner:record.owner,recordReference:record.recordReference,
   releaseLimit:Number(record.releaseLimit),spent:Number(record.spent)}];
 })));
 report.status='passed';await save();await atomic('/exchange/complete.json',{status:'passed'});
}catch(e){report.status='failed';report.error=String(e.stack);await save();throw e;}
finally{provider.destroy();for(const validator of validatorProviders)validator.destroy();}
