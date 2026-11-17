// Native KMS transport lives in the parent; this application owns the durable
// authorization ledger and independently checks actual local-EVM finality.
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';
import {createInterface} from 'node:readline';
import {RecipientOutputPolicy,policyHash} from './recipient-output-policy.mjs';
import {inspectKmsRequest} from './kms-request-adapter.mjs';
import {runPublicWorker} from './kms-public-worker.mjs';
import {linearWorkflow} from './kms-linear-workflow.mjs';
const cfg=JSON.parse(await fs.readFile(process.argv[2],'utf8'));
const require=createRequire(new URL('../../fhe-pod/package.json',import.meta.url));
const ganache=require('ganache'),{ethers}=require('ethers');
const load=name=>import(pathToFileURL(path.join(cfg.runtime,'scripts',name)));
const {compileComplianceCircuit,evaluateCircuitReference}=await load('compliance-circuit.mjs');
const {createExecutionContext,runCanonicalBinary,detectCanonicalFault,canonicalTrace,hashJson}=await load('canonical-protocol.mjs');
const {createCanonicalGame}=await load('canonical-game-driver.mjs');
const {canonicalFinalityAdapter}=await load('canonical-chain.mjs');
// Keep machine-readable transport isolated from dependency diagnostics.
console.log=(...v)=>console.error(...v);
const lines=createInterface({input:process.stdin,crlfDelay:Infinity})[Symbol.asyncIterator]();
const send=v=>process.stdout.write(JSON.stringify(v)+'\n');
const receive=async()=>{const next=await lines.next();assert.equal(next.done,false,'native transport ended');return JSON.parse(next.value);};
const server=ganache.server({logging:{quiet:true},wallet:{totalAccounts:20},chain:{chainId:31337,time:new Date('2025-01-01T00:00:00Z')},miner:{timestampIncrement:0}});
await server.listen(0,'127.0.0.1');
const rpcUrl=`http://127.0.0.1:${server.address().port}`;
const provider=new ethers.JsonRpcProvider(rpcUrl,undefined,{cacheTimeout:-1,pollingInterval:20});
const signers=Object.values(server.provider.getInitialAccounts()).slice(0,12).map(a=>new ethers.Wallet(a.secretKey,provider));
const recipient=new ethers.Wallet('0x'+'43'.repeat(32));assert.equal(recipient.address,cfg.recipient);
const sign=(wallet,body)=>wallet.signMessage(ethers.getBytes(policyHash(body)));
const domain=ethers.id('kms-integrated-output-domain-v1'),resolved=new Map();
const report={status:'running',classification:'functional-integration; not performance benchmark',keyset:cfg.keysetDigest,
 partyIsolation:'same host; native loopback test topology',cases:[],receipts:[],kmsCalls:0,unauthorizedKmsCalls:0};
const reportFile=path.join(cfg.root,'application-report.json');
const save=()=>fs.writeFile(reportFile,JSON.stringify(report,null,2));
const policy=new RecipientOutputPolicy({ledgerFile:path.join(cfg.root,'recipient-ledger.json'),domain,
 inspectRequest:inspectKmsRequest,resolveFinalized:request=>resolved.get(request.contextDigest)?.(request),
 submitUserDecrypt:async wire=>{report.kmsCalls++;send({kind:'submit',wireDigest:ethers.keccak256(wire)});
  const result=await receive();assert.equal(result.kind,'encrypted-response');return Uint8Array.from(Buffer.from(result.bytes,'hex'));}});
const advanceSeconds=async seconds=>{await provider.send('evm_increaseTime',[seconds]);await provider.send('evm_mine',[]);};
async function authorize(w){
 resolved.set(w.binding.contextDigest,w.resolve);
 for(const r of w.records){const body={kind:'kms-protected-record-v2',domain,...r,releaseLimit:1};
  const owner=w.owners.find(o=>o.address.toLowerCase()===r.owner.toLowerCase());await policy.registerRecord(body,await sign(owner,body));}
 const consent={kind:'kms-final-consent-v2',domain,slot:ethers.id(`${w.name}:final-slot`),...w.binding,
  outputType:w.outputType,recordIds:w.records.map(r=>r.id),recipients:[recipient.address]};
 const signatures=Object.fromEntries(await Promise.all(w.owners.map(async o=>[o.address.toLowerCase(),await sign(o,consent)])));
 const missing={...signatures};delete missing[w.owners[0].address.toLowerCase()];
 await assert.rejects(policy.registerConsent(consent,missing));
 const consentId=await policy.registerConsent(consent,signatures);return {consent,consentId};
}
async function release(w,consent,consentId,output){
 const authorization={kind:'kms-recipient-release-v2',domain,slot:consent.slot,consentId,...w.binding,...output,recipient:recipient.address};
 send({kind:'request',name:w.name,authorization,ciphertextFile:w.outputFile,expected:w.expected});
 const received=await receive();assert.equal(received.kind,'wire');const wire=Uint8Array.from(Buffer.from(received.wire,'hex'));
 const decoded=inspectKmsRequest(wire);const {ciphertextCount,...body}=decoded;
 const request={...body,kmsRequestDigest:ethers.keccak256(wire)};
 const invoke=async(r=request,bytes=wire)=>policy.release(r,await sign(recipient,r),bytes);
 const before=report.kmsCalls;
 await assert.rejects(invoke({...request,kind:'audit-verdict'}));
 await assert.rejects(invoke({...request,outputDigest:ethers.id('substituted')}));
 await assert.rejects(invoke({...request,keyId:ethers.id('another-key')}));
 if(w.beforeRelease)await w.beforeRelease({invoke,request,wire});
 // A valid encryption of an individual input, with consistently rewritten
 // wire metadata, still fails the independently computed final-output check.
 const substitute=JSON.parse(Buffer.from(wire).toString()), input=await fs.readFile(w.inputFile), inputDigest=ethers.keccak256(input);
 substitute.typed_ciphertexts[0].ciphertext=[...input];substitute.typed_ciphertexts[0].external_handle=[...ethers.getBytes(inputDigest)];
 const inputContext=JSON.parse(Buffer.from(substitute.extra_data).toString());
 inputContext.outputDigest=inputDigest;inputContext.authorization.outputDigest=inputDigest;
 substitute.extra_data=[...Buffer.from(JSON.stringify(inputContext))];const inputWire=Uint8Array.from(Buffer.from(JSON.stringify(substitute)));
 const {ciphertextCount:inputCount,...inputRequest}=inspectKmsRequest(inputWire);
 await assert.rejects(invoke({...inputRequest,kmsRequestDigest:ethers.keccak256(inputWire)},inputWire),/finalized conversion/);
 if(w.attack){await w.attack({invoke,request,wire});}
 assert.equal(report.kmsCalls,before);
 const encrypted=await invoke();assert.ok(encrypted.length>0);assert.equal(report.kmsCalls,before+1);
 await assert.rejects(invoke(),/consumed/);assert.equal(report.kmsCalls,before+1);
 // An owner-approved second task/slot still cannot reset the stable record budget.
 const next={...consent,slot:ethers.id(`${w.name}:alias-slot`)};
 const signatures=Object.fromEntries(await Promise.all(w.owners.map(async o=>[o.address.toLowerCase(),await sign(o,next)])));
 const nextId=await policy.registerConsent(next,signatures),other=JSON.parse(Buffer.from(wire).toString());
 const context=JSON.parse(Buffer.from(other.extra_data).toString());
 context.authorization.slot=next.slot;context.authorization.consentId=nextId;other.extra_data=[...Buffer.from(JSON.stringify(context))];
 const otherWire=Uint8Array.from(Buffer.from(JSON.stringify(other))),{ciphertextCount:count,...otherBody}=inspectKmsRequest(otherWire);
 // Reusing the request ID already rejects; a fresh ID tests the record limit.
 other.request_id.request_id=ethers.id(`${w.name}:new-request`).slice(2);context.requestId=other.request_id.request_id;
 other.extra_data=[...Buffer.from(JSON.stringify(context))];const freshWire=Uint8Array.from(Buffer.from(JSON.stringify(other)));
 const {ciphertextCount:count2,...fresh}=inspectKmsRequest(freshWire);
 await assert.rejects(invoke({...fresh,kmsRequestDigest:ethers.keccak256(freshWire)},freshWire),/budget exhausted/);
 assert.equal(report.kmsCalls,before+1);
 report.cases.push({name:w.name,expected:w.expected,outputDigest:request.outputDigest,...w.evidence,
  finalOutputKmsCalls:1,negativeChecks:['missing-owner-consent','audit-verdict','changed-ciphertext','changed-key','replay','cross-slot-budget'],
  encryptedResponseBytes:encrypted.length});await save();
}
async function nonlinearWorkflow(regional){
 const name=regional?'regional_qoe_compliance':'regulatory_qoe_compliance',dir=path.join(cfg.root,name);await fs.mkdir(dir);
 const recordCount=16,values=Array.from({length:recordCount},(_,i)=>regional&&i%2===0?1000:3000).concat(regional?Array(recordCount).fill(2):[]);
 const program=compileComplianceCircuit({recordCount,regional,poorThresholdMilli:2000,targetPermille:950,targetCell:2});
 const publicDir=path.join(dir,'public'),honestDir=path.join(dir,'honest');
 await runPublicWorker(cfg.workerBinary,{action:'kms-encrypt-circuit',publicDir,publicKey:cfg.publicKey,evaluationKey:cfg.evaluationKey,
  program,values,keyset:{keyId:cfg.keyId,keyEpoch:cfg.keyEpoch,mpcContext:cfg.mpcContext,keysetDigest:cfg.keysetDigest,...cfg.keyDescriptor}},dir);
 const owners=signers.slice(8,10);
 const context=await createExecutionContext({binary:cfg.workerBinary,publicDir,keyEpoch:cfg.keyEpoch,policyDomain:domain,
  inputBounds:values.map((_,i)=>({min:'0',max:i<recordCount?'5000':'3'})),
  records:program.inputs.map((input,i)=>({id:input.id,protectedId:ethers.id(`${name}:record:${i%recordCount}`),owner:owners[(i%recordCount)%owners.length].address}))});
 const game=await createCanonicalGame({provider,signers,context,binary:cfg.workerBinary,publicDir,workDir:dir,rpcUrl,advanceSeconds,receipt:r=>report.receipts.push(r)});
 const binding={chainId:'31337',game:game.game.target,contextDigest:hashJson(context),programDigest:context.programDigest,
  keyId:cfg.keyId,keyEpoch:cfg.keyEpoch,mpcContext:cfg.mpcContext,keysetDigest:cfg.keysetDigest,profileDigest:hashJson(context.profile)};
 const records=[...new Map(context.inputs.map(r=>[r.protectedId,{id:r.protectedId,owner:r.owner}])).values()];
 const taskId=ethers.id(`${name}:honest`),terminal=program.instructions.length-1,outputFile=path.join(honestDir,`result-${terminal}.ct`);
 const finality=canonicalFinalityAdapter({...game,context,publicDir,operatorDir:honestDir});
 const resolve=async request=>{const final=await finality(request);return final?{...binding,...final,taskId,aggregateDigest:final.outputDigest}:null;};
 const evidence={recordCount,inputCiphertexts:values.length,leaves:program.instructions.length,runtimeBytes:game.runtimeBytes,context,disputes:[]};
 const execute=async()=>{
  await runCanonicalBinary(cfg.workerBinary,['execute-canonical',publicDir,honestDir]);
  await game.createTask(taskId,honestDir);
  const detection=await detectCanonicalFault({context,binary:cfg.workerBinary,publicDir,operatorDir:honestDir,replayDir:path.join(dir,'honest-replay')});
  assert.equal(detection.index,null);evidence.independentHonestReplay=detection;
  const trace=await canonicalTrace(context,publicDir,honestDir);return {taskId,aggregateDigest:trace.manifest.terminalHandle,outputDigest:trace.manifest.terminalHandle,outputType:'bool'};
 };
 const beforeRelease=async({invoke})=>{await assert.rejects(invoke(),/finalized/);await game.acceptHonest(taskId);};
 const attack=regional?null:async({invoke,wire})=>{
  // Undisclosed record reconstruction attempt: compute each low bit with real
  // FHE under the same key, then request it in place of the approved final bit.
  const attackDir=path.join(dir,'chosen-bit');await fs.mkdir(attackDir);let rejected=0;
  for(let bit=0;bit<16;bit++){
   const bundle=path.join(attackDir,`public-${bit}`);await fs.mkdir(bundle);
   for(const file of ['input-0.ct','server-key.bin','encryption-key.bin','kms-keyset.json'])await fs.link(path.join(publicDir,file),path.join(bundle,file));
   const p={version:'compliance-explicit-dag-v1',integerDomain:'checked-uint64',inputs:[{id:'victim',type:'uint64'}],instructions:[
    {index:0,opcode:'SHR',lhs:{kind:'input',index:0},rhs:{kind:'constant',value:String(bit)}},
    {index:1,opcode:'BITAND',lhs:{kind:'output',index:0},rhs:{kind:'constant',value:'1'}}],output:{kind:'output',index:1}};
   await fs.writeFile(path.join(bundle,'program.json'),JSON.stringify(p));
   const trace=path.join(attackDir,`trace-${bit}`);await runCanonicalBinary(cfg.workerBinary,['execute-canonical',bundle,trace]);
   const ciphertext=await fs.readFile(path.join(trace,'result-1.ct')),digest=ethers.keccak256(ciphertext);
   const altered=JSON.parse(Buffer.from(wire).toString());altered.typed_ciphertexts[0].ciphertext=[...ciphertext];altered.typed_ciphertexts[0].external_handle=[...ethers.getBytes(digest)];
   const c=JSON.parse(Buffer.from(altered.extra_data).toString());c.outputDigest=digest;c.authorization.outputDigest=digest;
   altered.extra_data=[...Buffer.from(JSON.stringify(c))];const alteredWire=Uint8Array.from(Buffer.from(JSON.stringify(altered)));
   const {ciphertextCount,...r}=inspectKmsRequest(alteredWire);
   await assert.rejects(invoke({...r,kmsRequestDigest:ethers.keccak256(alteredWire)},alteredWire),/finalized conversion/);rejected++;
  }
  evidence.recordReconstruction={attempts:16,rejected,obtainedRecordBits:0,kmsCalls:0,realFhePredicates:true};
 };
 const disputes=async()=>{
  for(const [label,faults] of [['early',[0,7]],['middle',[Math.floor(terminal/2),7]],['terminal',[terminal,7]],['multiple',[0,7,terminal,8]]]){
   const operatorDir=path.join(dir,`operator-${label}`),replayDir=path.join(dir,`auditor-${label}`);
   await runCanonicalBinary(cfg.workerBinary,['execute-canonical-fault-fixture',publicDir,operatorDir,...faults.map(String)]);
   const disputed=ethers.id(`${name}:${label}`);
   if(await game.game.getParticipantStake(signers[1].address)<ethers.parseEther('2'))await game.record('operatorTopup',game.game.connect(signers[1]).registerOperator({value:ethers.parseEther('2')}));
   // Cases are independent functional scenarios. Wrong opinions in a prior
   // case correctly consume collateral; restore an eligible challenger pool
   // before the next assignment instead of weakening the contract's bond rule.
   for(const auditor of signers.slice(2,5)) {
    if(await game.game.getParticipantStake(auditor.address)<ethers.parseEther('2'))
     await game.record('auditorTopup',game.game.connect(auditor).registerAuditor({value:ethers.parseEther('2')}));
   }
   await game.createTask(disputed,operatorDir);
   const detection=await detectCanonicalFault({context,binary:cfg.workerBinary,publicDir,operatorDir,replayDir});assert.equal(detection.index,faults[0]);
   const settlement=await game.auditAndChallenge(disputed,detection,replayDir,{afterAdmission:async({game:chain})=>{
    const stake=await chain.getParticipantStake(signers[1].address);await advanceSeconds(500);
    await assert.rejects(chain.timeoutDispute.staticCall(disputed));await assert.rejects(chain.finalizeUnchallenged.staticCall(disputed));assert.equal(await chain.getParticipantStake(signers[1].address),stake);
   }});
   assert.equal(settlement.state[0],3);assert.equal(settlement.state[1],2);
   assert.equal(settlement.certificates[0].evidence.operatorValid,false);assert.equal(settlement.certificates[0].evidence.challengerValid,true);
   evidence.disputes.push({label,injectedIndices:faults.filter((_,i)=>i%2===0),detection,settlement});await save();
  }
 };
 return {name,dir,binding,records,owners,execute,resolve,outputFile,inputFile:path.join(publicDir,'input-0.ct'),outputType:'bool',beforeRelease,attack,disputes,evidence,
  expected:Number(evaluateCircuitReference(program,values).value)};
}
try{
 await save();
 for(const [name,op,values,bounds] of [
  ['sum-carry-four','SUM',Array(4).fill(127),Array(4).fill([0,127])],
  ['sub-carry-four','SUB',[511,127,127,127,127],[[511,511],...Array(4).fill([0,127])]],
  ['sum-33','SUM',Array.from({length:33},(_,i)=>i%5+1),Array(33).fill([1,5])],
  ['sub-33','SUB',[511,...Array(32).fill(15)],[[511,511],...Array(32).fill([0,15])]]]){
  console.error(`TOPS_INTEGRATED ${name}`);const w=await linearWorkflow({cfg,signers,name,op,values,bounds});
  const {consent,consentId}=await authorize(w);await assert.rejects(fs.access(w.outputFile));const output=await w.execute();await release(w,consent,consentId,output);
 }
 for(const regional of [false,true]){
  const w=await nonlinearWorkflow(regional);console.error(`TOPS_INTEGRATED ${w.name}`);
  const {consent,consentId}=await authorize(w);await assert.rejects(fs.access(w.outputFile));const output=await w.execute();
  await release(w,consent,consentId,output);await w.disputes();
 }
 report.status='passed';report.ledger=policy.inspectLedger();await save();send({kind:'complete',report});
}catch(e){report.status='failed';report.error=String(e.stack);await save();throw e;}
finally{provider.destroy();await server.close();process.stdin.destroy();}
