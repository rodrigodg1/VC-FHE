import {nonlinearProfile} from './nonlinear-profile.mjs';
// Only this role mounts dataset records and owner signing identities.
import fs from 'node:fs/promises';
import {createProgress} from './progress.mjs';
const progress=createProgress('owner');
import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {createRequire} from 'node:module';
import {ethers,json,atomic} from './common.mjs';
import {assertExpectedWorkflow,bindExpectedWorkflow,canonicalConsentInputRoot,canonicalProgramRoot,compileReleasePolicy,computeConsentIdV3,computeReleaseDigestV3,nonlinearInputTerms,outputTypeDigest,ownerBoundProtectedId,releaseRequestFromWire} from './onchain-policy.mjs';
import {OwnerChainQuorum,OWNER_RPC_COUNT,OWNER_RPC_QUORUM} from './owner-chain-quorum.mjs';
import {inspectKmsRequest} from '../scripts/kms-request-adapter.mjs';
import {linearStatement} from './statement.mjs';
import {approveInputOrigins} from './owner-admission.mjs';
import {ordinarySign,ORDINARY_BLS_PROFILE} from './ordinary-bls.mjs';
import {prepareLinearBenchmark} from './paired-linear.mjs';
import {linearPanel,qoePanel,linearRecordIds,qoeRecordIds} from './poc-panels.mjs';
import {canonicalTrace,createExecutionContext,hashJson} from './runtime/scripts/canonical-protocol.mjs';
import {outputArtifactDigest,publicTracePlan} from './runtime/scripts/canonical-chain.mjs';
import {compileContracts,computeBoundResultHash} from './runtime/scripts/evm-lib.mjs';
import {runPublicWorker} from '../scripts/kms-public-worker.mjs';
import {compileComplianceCircuit,evaluateCircuitReference} from '/app/fhe-pod/scripts/compliance-circuit.mjs';
const L=createRequire('/app/BN254-Signatures/package.json')('/app/BN254-Signatures/scripts/mklhs-lib.js');
const cfg=await json('/config/campaign.json'),keys=await json('/keyset/ready.json');
// One PoC process drives four logical owner keys. This automates the test and
// does not establish independent owner administration. Authorization-critical
// reads nevertheless require three matching views from four distinct validators.
const ownerChain=new OwnerChainQuorum({rpcUrls:cfg.ownerRpcUrls,expectedChainId:cfg.chainId,
 providerFactory:url=>new ethers.JsonRpcProvider(url)}),providers=ownerChain.providers;
const policyConfig=await json('/config/release-policy.json'),policyArtifact=await compileReleasePolicy();
assert.equal(policyConfig.schema,'vcfhe-release-policy-config-v3');
assert.ok(ethers.isAddress(policyConfig.address)&&ethers.isHexString(policyConfig.runtimeCodeHash,32));
assert.equal(String(policyConfig.chainId),String(cfg.chainId));
const registries=providers.map(provider=>new ethers.Contract(policyConfig.address,policyArtifact.abi,provider));
const registry=registries[0],policyDomain=policyConfig.policyDomain;
function same(actual,expected,label){assert.equal(String(actual).toLowerCase(),String(expected).toLowerCase(),label);}
await ownerChain.withView('release-policy identity',async view=>{
 assert.ok(view.number>=Number(policyConfig.lastVerifiedBlockNumber),'release-policy checkpoint is ahead of the owner quorum');
 const identity=await ownerChain.read(view,'release-policy code and domain',async(provider,blockTag,index)=>{
  const contract=registries[index];
  const [code,version,chainId,domain,separator]=await Promise.all([provider.getCode(policyConfig.address,blockTag),
   contract.POLICY_VERSION({blockTag}),contract.deploymentChainId({blockTag}),contract.policyDomain({blockTag}),
   contract.DOMAIN_SEPARATOR({blockTag})]);
  return {codeHash:code==='0x'?ethers.ZeroHash:ethers.keccak256(code),version:String(version),chainId:String(chainId),domain,separator};
 });
 assert.equal(identity.codeHash,policyConfig.runtimeCodeHash,'release-policy runtime mismatch');
 assert.equal(identity.version,'3','release-policy version mismatch');
 assert.equal(identity.chainId,String(cfg.chainId),'release-policy deployment chain mismatch');
 assert.equal(identity.domain,policyConfig.policyDomain,'release-policy domain mismatch');
 assert.equal(identity.separator,policyConfig.domainSeparator,'release-policy separator mismatch');
 const anchors=await ownerChain.read(view,'release-policy deployment anchors',async provider=>{
  const [genesis,deployment,checkpoint,tx,receipt]=await Promise.all([provider.getBlock(0),provider.getBlock(Number(policyConfig.deploymentBlock)),
   provider.getBlock(Number(policyConfig.lastVerifiedBlockNumber)),provider.getTransaction(policyConfig.deploymentTransaction),
   provider.getTransactionReceipt(policyConfig.deploymentTransaction)]);
  return {genesisHash:genesis?.hash,deploymentHash:deployment?.hash,checkpointHash:checkpoint?.hash,
   tx:{hash:tx?.hash,to:tx?.to,data:tx?.data,
   blockNumber:tx?.blockNumber,blockHash:tx?.blockHash,chainId:String(tx?.chainId),from:tx?.from},
   receipt:{hash:receipt?.hash,status:receipt?.status,blockNumber:receipt?.blockNumber,blockHash:receipt?.blockHash,
    contractAddress:receipt?.contractAddress,from:receipt?.from,to:receipt?.to}};
 });
 assert.equal(anchors.genesisHash,policyConfig.genesisBlockHash,'release-policy genesis anchor changed');
 assert.equal(anchors.deploymentHash,policyConfig.deploymentBlockHash,'release-policy deployment block changed');
 assert.equal(anchors.checkpointHash,policyConfig.lastVerifiedBlockHash,'release-policy checkpoint changed');
 same(anchors.tx.hash,policyConfig.deploymentTransaction,'release-policy deployment transaction changed');
 same(anchors.receipt.hash,policyConfig.deploymentTransaction,'release-policy deployment receipt changed');
 assert.equal(anchors.tx.to,null,'release-policy deployment transaction has a recipient');
 assert.equal(anchors.tx.data,policyArtifact.bytecode,'release-policy deployment bytecode changed');
 assert.equal(anchors.tx.blockNumber,Number(policyConfig.deploymentBlock));
 assert.equal(anchors.tx.blockHash,policyConfig.deploymentBlockHash);
 assert.equal(anchors.tx.chainId,String(cfg.chainId));
 assert.equal(anchors.receipt.status,1);assert.equal(anchors.receipt.blockNumber,Number(policyConfig.deploymentBlock));
 assert.equal(anchors.receipt.blockHash,policyConfig.deploymentBlockHash);
 same(anchors.receipt.from,anchors.tx.from,'release-policy deployment sender changed');
 assert.equal(anchors.receipt.to,null,'release-policy deployment receipt has a recipient');
 assert.equal(ethers.getAddress(anchors.receipt.contractAddress),ethers.getAddress(policyConfig.address));
});
const loadedPolicy={config:policyConfig,abi:policyArtifact.abi};
const legacyRecords=loadedPolicy.config.legacyRecords??[];
assert.ok(Array.isArray(legacyRecords));
const legacyByReference=new Map(legacyRecords.map(record=>{
 assert.ok(ethers.isHexString(record.recordReference,32)&&ethers.isAddress(record.owner));
 assert.ok(Number.isSafeInteger(record.releaseLimit)&&record.releaseLimit>0&&Number.isSafeInteger(record.initialSpent)&&
  record.initialSpent>=0&&record.initialSpent<=record.releaseLimit);
 return [record.recordReference,record];
}));
assert.equal(legacyByReference.size,legacyRecords.length,'duplicate legacy protected record');
const wallets=(await json('/owner-identity/identities.json')).map((key,index)=>new ethers.Wallet(key,providers[index]));
assert.equal(wallets.length,providers.length,'owner identities and assigned validator RPCs differ');
assert.ok(!(cfg.pocPlan&&cfg.policyRefreshPlan),'paired and V3 policy-refresh plans are mutually exclusive');
const casePlan=cfg.pocPlan??cfg.policyRefreshPlan;
const owners=wallets.map(w=>w.address),cases=[],expected={},approvals=new Map(),admissions=new Map(),benchmarked=new Set();
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
assert.equal(policyConfig.ownersSha256,hash(Buffer.from(JSON.stringify(owners))),
 'owner identity set differs from the deployed cumulative-policy lineage');
const binary='/usr/local/bin/kms-campaign';
const publicKey='/keyset/encryption-key.bin',evaluationKey='/keyset/evaluation-key.bin';
const recordBudgets=(references,itemOwners)=>references.map((recordReference,index)=>{
 const legacy=legacyByReference.get(recordReference);
 if(!legacy)return{releaseLimit:cfg.ownerReleaseLimit,initialSpent:0};
 assert.equal(legacy.owner.toLowerCase(),itemOwners[index].toLowerCase(),'legacy protected-record owner changed');
 return{releaseLimit:legacy.releaseLimit,initialSpent:legacy.initialSpent};
});
function csv(text){const lines=text.trim().split(/\r?\n/);const delimiter=lines[0].includes('\t')?'\t':',';const header=lines.shift().split(delimiter).map(s=>s.trim());return lines.map((s,i)=>Object.fromEntries([...s.split(delimiter).map((v,j)=>[header[j],v.trim()]),['row',i]]));}
const recordOwner=id=>Number(BigInt(id)%BigInt(wallets.length));
async function prepare(){
 if(cfg.half!=='nonlinear'){
  const bytes=await fs.readFile('/datasets/linear.json'),data=JSON.parse(bytes);
  const query=data.queries.find(q=>q.query_id==='stav360_session_mos_sum');
  assert.ok(query&&query.dataset==='STAV360'&&query.values.length===16);
  const raw=await fs.readFile('/datasets/stav.csv');
  const panel=csv(raw.toString()).filter(r=>r.rating!==''&&r.video_title===query.scope.video&&r.video_tiling_pattern===query.scope.pattern)
    .sort((a,b)=>a.user.localeCompare(b.user)).slice(0,16);
  assert.deepEqual(panel.map(r=>r.user),query.owners);assert.deepEqual(panel.map(r=>Math.round(Number(r.rating))),query.values);
  assert.ok(query.values.every(v=>Number.isInteger(v)&&v>=1&&v<=5));
  assert.equal(query.values.reduce((a,b)=>a+b,0),query.expected.aggregate);
  const linearJobs=casePlan?.jobs.filter(j=>j.half==='linear')??cfg.linearSizes.flatMap(n=>Array.from({length:cfg.repeats},(_,repeat)=>({n,repeat,name:`linear-acr-${n}-${repeat}`})));
  for(const [jobIndex,job] of linearJobs.entries()){
   const {n,repeat,name}=job;
   const progressCase={caseName:name,current:jobIndex+1,total:linearJobs.length,group:'owner-linear'};
   progress('owner-encrypt',progressCase);
   const selected=cfg.selectionProfile==='poc-disjoint-panels-v1'?linearPanel(raw.toString(),query,n):panel.slice(0,n);
   assert.equal(selected.length,n);const dir=`/fixtures/${name}`;console.log('OWNER_PREPARE '+name);
   await fs.mkdir(dir);const values=selected.map(r=>Number(r.rating)),bounds=values.map(()=>[1,5]);
   const plan={profile:'kms-grouped-radix-v1',op:'SUM',bounds};
   const start=performance.now();
   await runPublicWorker(binary,{action:'prepare',publicKey,evaluationKey,plan,values},'/owner/'+name);
   // Copy ciphertexts/coordinates only. The job carrying values stays private.
   for(const file of await fs.readdir('/owner/'+name))if(file.endsWith('.bin')||file==='coordinates.json')await fs.copyFile('/owner/'+name+'/'+file,dir+'/'+file);
   const recordReferences=linearRecordIds(selected,query),itemOwners=recordReferences.map(id=>owners[recordOwner(id)]);
   const recordIds=recordReferences.map((id,i)=>ownerBoundProtectedId(cfg.chainId,registry.target,itemOwners[i],id));
   const budgets=recordBudgets(recordReferences,itemOwners);
   const item={...job,name,half:'linear',n,repeat,plan,recordReferences,recordIds,owners:itemOwners,
       releaseLimits:budgets.map(value=>value.releaseLimit),initialSpent:budgets.map(value=>value.initialSpent),
       dataset:{id:'STAV360',rawSha256:hash(raw),fixtureSha256:hash(bytes),queryId:query.query_id,
         selection:cfg.selectionProfile??`first ${n} of the fixed 16-user panel`,scope:query.scope},
       ownerPreparationMs:performance.now()-start};
   expected[name]=values.reduce((a,b)=>a+b,0);cases.push(item);
   progress('owner-encrypt',{...progressCase,state:'done'});
  }
 }
 if(cfg.half!=='linear'){
  const corpora={};for(const bs of ['1','4']){
   const bytes=await fs.readFile(`/datasets/qoe/MOS_BS_${bs}_Driver_PRB_10.csv`);
   const rows=csv(bytes.toString()).filter(r=>['MOS_3000kbps','Latitude','Longitude'].every(k=>r[k]!==''&&Number.isFinite(Number(r[k]))));
   assert.ok(rows.length>=cfg.records);corpora[bs]={rows,sha256:hash(bytes)};
  }
  const sample=(bs,n)=>Array.from({length:n},(_,i)=>({...corpora[bs].rows[i*Math.floor(corpora[bs].rows.length/n)],bs}));
  const nonlinearJobs=casePlan?.jobs.filter(j=>j.half==='nonlinear')??[false,true].flatMap(regional=>Array.from({length:cfg.repeats},(_,repeat)=>({regional,n:cfg.records,repeat,name:`${regional?'regional':'regulatory'}_qoe_compliance-${repeat}`})));
  const totalSelected=nonlinearJobs.filter(job=>!cfg.readinessOnly||cfg.nonlinearWorkloads.includes(
   (job.regional??job.workload==='regional_qoe_compliance')?'regional':'regulatory')).length;
  let preparedCount=0;
  for(const job of nonlinearJobs){
   const {n,repeat,name}=job,regional=job.regional??job.workload==='regional_qoe_compliance';
   if(cfg.readinessOnly&&!cfg.nonlinearWorkloads.includes(regional?'regional':'regulatory'))continue;
   const progressCase={caseName:name,current:++preparedCount,total:totalSelected,group:'owner-nonlinear'};
   progress('owner-encrypt',progressCase);
   const dir=`/fixtures/${name}`;console.log('OWNER_PREPARE '+name);
   await fs.mkdir(dir);
   const rows=cfg.selectionProfile==='poc-disjoint-panels-v1'?qoePanel(corpora,n,regional):regional?[...sample('1',n/2),...sample('4',n/2)]:sample('1',n);
   const cells=rows.map(r=>Math.floor((Number(r.Latitude)+90)/.01)*36000+Math.floor((Number(r.Longitude)+180)/.01));
   // The public query must not disclose a cell learned from a private record.
   const targetCell=cfg.targetCell,values=rows.map(r=>Math.round(Number(r.MOS_3000kbps)*1000)).concat(regional?cells:[]);
   assert.ok(values.slice(0,n).every(v=>Number.isInteger(v)&&v>=0&&v<=5000));
   const program=compileComplianceCircuit({recordCount:n,regional,poorThresholdMilli:2000,targetPermille:950,targetCell});
   const start=performance.now(),publicDir=dir+'/public';
   await runPublicWorker(binary,{action:'kms-encrypt-circuit',publicDir,publicKey,evaluationKey,program,values,
       keyset:{keyId:keys.keyId,keyEpoch:keys.keyEpoch,mpcContext:keys.mpcContext,keysetDigest:keys.keysetDigest,...keys.keyDescriptor}},'/owner/'+name);
   const recordReferences=qoeRecordIds(rows),itemOwners=recordReferences.map(id=>owners[recordOwner(id)]);
   const recordIds=recordReferences.map((id,i)=>ownerBoundProtectedId(cfg.chainId,registry.target,itemOwners[i],id));
   const budgets=recordBudgets(recordReferences,itemOwners);
   const item={...job,name,half:'nonlinear',n,repeat,regional,recordReferences,recordIds,owners:itemOwners,
       releaseLimits:budgets.map(value=>value.releaseLimit),initialSpent:budgets.map(value=>value.initialSpent),
       dataset:{id:'5G-QoERA',origin:'radio/MOS simulation corpus',sources:Object.fromEntries(Object.entries(corpora).map(([k,v])=>[k,v.sha256])),
         selection:cfg.selectionProfile??'deterministic stride',rows:rows.map(r=>({bs:r.bs,row:r.row})),mosEncoding:'round(MOS_3000kbps * 1000)',cellEncoding:'0.01 degree grid',publicTargetCell:targetCell},
       inputBounds:values.map((_,i)=>({min:'0',max:i<n?'5000':'647999999'})),ownerPreparationMs:performance.now()-start};
   const context=await createExecutionContext({binary,publicDir,keyEpoch:keys.keyEpoch,policyDomain:cfg.policyDomain,
    inputBounds:item.inputBounds,records:program.inputs.map((r,i)=>({id:r.id,protectedId:recordIds[i%n],owner:item.owners[i%n]}))});
   approvals.set(name,{context,program,contextDigest:hashJson(context),programDigest:context.programDigest,
    profileDigest:hashJson(context.profile),outputType:'bool',inputs:context.inputs,...nonlinearInputTerms(context)});
   await atomic('/owner/'+name+'/approved-context.json',context);cases.push(item);
   expected[name]=Number(evaluateCircuitReference(program,values).value);
   progress('owner-encrypt',{...progressCase,state:'done'});
  }
 }
 const currentSpent=new Map();
 const capacityView=await ownerChain.withView('protected-record baseline',async view=>{
  for(const item of cases.filter(item=>!casePlan||item.fullCase))for(let i=0;i<item.recordIds.length;i++){
   const id=item.recordIds[i];if(currentSpent.has(id))continue;
   const record=await ownerChain.read(view,`protected record ${id}`,(_provider,blockTag,index)=>
    registries[index].protectedRecords(id,{blockTag}));
   if(record.owner===ethers.ZeroAddress)currentSpent.set(id,item.initialSpent[i]);
   else{
    assert.equal(record.owner.toLowerCase(),item.owners[i].toLowerCase(),'registered protected-record owner changed');
    assert.equal(record.recordReference,item.recordReferences[i],'registered record reference changed');
    assert.equal(Number(record.releaseLimit),item.releaseLimits[i],'registered release limit changed');
    assert.ok(Number(record.spent)>=item.initialSpent[i],'on-chain spend regressed below migrated counter');
    currentSpent.set(id,Number(record.spent));
   }
  }
  return{blockNumber:view.number,blockHash:view.hash,parentHash:view.parentHash,
   validatorCount:OWNER_RPC_COUNT,confirmationQuorum:OWNER_RPC_QUORUM,
   participantCount:view.participants.length,supporterCount:view.supporters.length};
 });
 const planned=new Map();
 for(const item of cases.filter(item=>!casePlan||item.fullCase))for(let i=0;i<item.recordIds.length;i++){
  const current=planned.get(item.recordIds[i])??{count:0,releaseLimit:item.releaseLimits[i],currentSpent:currentSpent.get(item.recordIds[i])};
  assert.equal(current.releaseLimit,item.releaseLimits[i]);assert.equal(current.currentSpent,currentSpent.get(item.recordIds[i]));current.count+=1;
  planned.set(item.recordIds[i],current);
 }
 for(const value of planned.values())assert.ok(value.currentSpent+value.count<=value.releaseLimit,
  'planned releases exceed cumulative protected-record budget');
 if(cfg.policyRefreshPlan){
  const records=[...planned.entries()].map(([recordId,value])=>({recordId,releaseLimit:value.releaseLimit,
   currentSpent:value.currentSpent,plannedCharges:value.count,
   remainingAfterPlan:value.releaseLimit-value.currentSpent-value.count})).sort((a,b)=>
    a.recordId<b.recordId?-1:a.recordId>b.recordId?1:0);
  assert.ok(records.length>0,'V3 policy refresh has no protected records');
  const limits=records.map(record=>record.releaseLimit);
  await atomic('/reports/release-capacity-preflight.json',{
   schema:'vcfhe-v3-policy-refresh-capacity-preflight-v1',status:'passed',
   profile:cfg.policyRefreshPlan.profile,designSha256:cfg.policyRefreshPlan.designSha256,
   half:cfg.half,parameters:cfg.parameters,keysetDigest:keys.keysetDigest,
   caseCount:cases.length,caseNames:cases.map(item=>item.name),view:capacityView,
   recordCount:records.length,maxCurrentSpent:Math.max(...records.map(record=>record.currentSpent)),
   maxPlannedCharges:Math.max(...records.map(record=>record.plannedCharges)),
   minRemainingAfterPlan:Math.min(...records.map(record=>record.remainingAfterPlan)),
   limits:{minimum:Math.min(...limits),maximum:Math.max(...limits)},records});
 }
 await atomic('/owner/expected.json',expected);
 await atomic('/fixtures/prepared.json',{keys,owners,cases});
 }
await prepare();
const recipient=(await fs.readFile('/config/recipient-address.txt','utf8')).trim();
const allowedTx=new Set(['registerOwnerKey','admitRecord','bindProtectedRecord','registerInputOrigins',
 'registerProtectedRecord','approveConsent','approveRelease']);
const interfaces=[new ethers.Interface(['function registerOwnerKey(uint64,uint256[4])','function admitRecord(uint64,uint256[2],uint256[2])']),
 new ethers.Interface(['function bindProtectedRecord(uint64,bytes32,bytes32)']),
 new ethers.Interface(['function registerInputOrigins(bytes32[],bytes32[])']),new ethers.Interface(loadedPolicy.abi)];
async function verifyDeployment(view,artifact,address,transactionHash,args){
 assert.ok(ethers.isAddress(address)&&ethers.isHexString(transactionHash,32),'invalid workflow deployment reference');
 const deployment=await ownerChain.read(view,`workflow deployment ${address}`,async provider=>{
  const [tx,receipt]=await Promise.all([provider.getTransaction(transactionHash),provider.getTransactionReceipt(transactionHash)]);
  const included=receipt?.blockNumber==null?null:await provider.getBlock(receipt.blockNumber);
  return {tx:{hash:tx?.hash,to:tx?.to,data:tx?.data,blockNumber:tx?.blockNumber,blockHash:tx?.blockHash,
   chainId:String(tx?.chainId),from:tx?.from},receipt:{hash:receipt?.hash,status:receipt?.status,
   blockNumber:receipt?.blockNumber,blockHash:receipt?.blockHash,contractAddress:receipt?.contractAddress,
   from:receipt?.from,to:receipt?.to},included:{number:included?.number,hash:included?.hash}};
 });
 const {tx,receipt,included}=deployment;
 assert.ok(tx.hash&&receipt.hash&&receipt.status===1,'workflow deployment is not finalized');
 same(tx.hash,transactionHash,'workflow deployment transaction changed');same(receipt.hash,transactionHash,'workflow deployment receipt changed');
 assert.equal(tx.to,null,'workflow deployment transaction has a recipient');
 assert.ok(tx.blockNumber!==null&&tx.blockNumber<=view.number,'workflow deployment is outside the pinned view');
 assert.equal(tx.chainId,String(cfg.chainId),'workflow deployment is on another chain');
 same(receipt.contractAddress,address,'workflow deployment address changed');
 const constructorData=new ethers.Interface(artifact.abi).encodeDeploy(args);
 same(tx.data,ethers.concat([artifact.bytecode,constructorData]),'workflow deployment bytecode or constructor changed');
 assert.equal(receipt.blockNumber,tx.blockNumber,'workflow deployment transaction/receipt block differs');
 same(receipt.blockHash,tx.blockHash,'workflow deployment transaction/receipt hash differs');
 same(receipt.from,tx.from,'workflow deployment sender changed');assert.equal(receipt.to,null,'workflow deployment receipt has a recipient');
 assert.equal(included.number,receipt.blockNumber,'workflow deployment block unavailable');
 same(receipt.blockHash,included.hash,'workflow deployment block changed');
 return tx.from;
}
async function authenticateNonlinearWorkflow(binding,approved){
 const profile=nonlinearProfile(cfg.nonlinearProtocol);
 assert.equal(binding?.kind,profile.kind,'owner-selected nonlinear protocol changed');
 assert.ok(binding&&ethers.isAddress(binding.game)&&ethers.isAddress(binding.availability)&&
  ethers.isAddress(binding.verifier)&&ethers.isAddress(binding.objective),'invalid nonlinear workflow binding');
 assert.equal(new Set([binding.game,binding.availability,binding.verifier,binding.objective].map(v=>v.toLowerCase())).size,4,
  'nonlinear workflow contracts must be distinct');
 assert.ok(Array.isArray(binding.canonicalSigners)&&binding.canonicalSigners.length===3&&
  binding.canonicalSigners.every(ethers.isAddress),'invalid canonical signer set');
 assert.equal(new Set(binding.canonicalSigners.map(v=>v.toLowerCase())).size,3,'duplicate canonical signer');
 return ownerChain.withView('nonlinear workflow binding',async view=>{
  const artifacts=await compileContracts(),deployments=binding.deployments??{};
  const deployers=await Promise.all([
   verifyDeployment(view,artifacts.ObjectiveMicroVerifier,binding.objective,deployments.objective,[]),
   verifyDeployment(view,artifacts[profile.game],binding.game,deployments.game,
    [binding.objective,cfg.windowSeconds,cfg.windowSeconds,cfg.windowSeconds,binding.availability,binding.verifier,...profile.extraConstructorArgs]),
   verifyDeployment(view,artifacts[profile.availability],binding.availability,deployments.availability,
    [binding.game,cfg.windowSeconds]),
   verifyDeployment(view,artifacts.CanonicalLeafVerifier,binding.verifier,deployments.verifier,
    [binding.game,approved.profileDigest,binding.canonicalSigners,2])
  ]);
  assert.equal(new Set(deployers.map(v=>v.toLowerCase())).size,1,'workflow contracts have different deployers');
  const state=await ownerChain.read(view,'nonlinear workflow modules',async(provider,blockTag)=>{
   const game=new ethers.Contract(binding.game,[
    'function secureTraceMode() view returns(bool)',
    'function objectiveVerifier() view returns(address)','function availabilityModule() view returns(address)',
    'function leafDecisionVerifier() view returns(address)','function fhevmVerifier() view returns(address)',
    'function kmsVerdictVerifier() view returns(address)','function COMMIT_WINDOW_SECONDS() view returns(uint64)',
    'function OPEN_WINDOW_SECONDS() view returns(uint64)','function CHALLENGE_WINDOW_SECONDS() view returns(uint64)'
   ],provider);
   const availability=new ethers.Contract(binding.availability,[
    'function game() view returns(address)','function disclosureWindowSeconds() view returns(uint64)'
   ],provider);
   const verifier=new ethers.Contract(binding.verifier,[
    'function game() view returns(address)','function profileDigest() view returns(bytes32)',
    'function threshold() view returns(uint256)','function isSigner(address) view returns(bool)'
   ],provider);
   const values=await Promise.all([game.secureTraceMode({blockTag}),game.objectiveVerifier({blockTag}),
    game.availabilityModule({blockTag}),game.leafDecisionVerifier({blockTag}),game.fhevmVerifier({blockTag}),
    game.kmsVerdictVerifier({blockTag}),game.COMMIT_WINDOW_SECONDS({blockTag}),game.OPEN_WINDOW_SECONDS({blockTag}),
    game.CHALLENGE_WINDOW_SECONDS({blockTag}),availability.game({blockTag}),availability.disclosureWindowSeconds({blockTag}),
    verifier.game({blockTag}),verifier.profileDigest({blockTag}),verifier.threshold({blockTag}),
    Promise.all(binding.canonicalSigners.map(address=>verifier.isSigner(address,{blockTag}))),
    Promise.all([binding.game,binding.availability,binding.verifier,binding.objective].map(address=>provider.getCode(address,blockTag)))]);
   const [secure,objective,availabilityAddress,verifierAddress,fhevm,kms,commitWindow,openWindow,
    challengeWindow,availabilityGame,disclosureWindow,verifierGame,profile,threshold,signerChecks,codes]=values;
   return {secure,objective,availabilityAddress,verifierAddress,fhevm,kms,commitWindow:String(commitWindow),
    openWindow:String(openWindow),challengeWindow:String(challengeWindow),availabilityGame,
    disclosureWindow:String(disclosureWindow),verifierGame,profile,threshold:String(threshold),signerChecks,
    codeHashes:codes.map(code=>code==='0x'?ethers.ZeroHash:ethers.keccak256(code))};
  });
  assert.equal(state.secure,true,'insecure nonlinear workflow');
  same(state.objective,binding.objective,'objective verifier changed');same(state.availabilityAddress,binding.availability,'availability module changed');
  same(state.verifierAddress,binding.verifier,'canonical verifier changed');same(state.fhevm,ethers.ZeroAddress,'FHEVM backend must be absent');
  same(state.kms,ethers.ZeroAddress,'KMS verdict backend must be absent');
  for(const value of [state.commitWindow,state.openWindow,state.challengeWindow,state.disclosureWindow])
   assert.equal(Number(value),cfg.windowSeconds,'workflow window changed');
  same(state.availabilityGame,binding.game,'availability game changed');same(state.verifierGame,binding.game,'canonical verifier game changed');
  same(state.profile,approved.profileDigest,'canonical profile changed');assert.equal(Number(state.threshold),2,'canonical threshold changed');
  assert.ok(state.signerChecks.every(Boolean),'canonical signer set changed');
  assert.ok(state.codeHashes.every(codeHash=>codeHash!==ethers.ZeroHash),'workflow code unavailable');
  return {game:ethers.getAddress(binding.game),availability:ethers.getAddress(binding.availability),
   verifier:ethers.getAddress(binding.verifier),objective:ethers.getAddress(binding.objective),blockNumber:view.number,blockHash:view.hash,
   codeHashes:state.codeHashes,canonicalSigners:binding.canonicalSigners.map(ethers.getAddress)};
 });
}
async function expectedConsent(item,game){
 const approved=approvals.get(item.name);assert.ok(approved,'owner has no approved computation statement');
 assertExpectedWorkflow(approved,game);
 const taskId=ethers.id(`${item.name}:${approved.game}`),linear=item.half==='linear';
 return {approved,taskId,programRoot:linear?approved.programDigest:canonicalProgramRoot(taskId,approved.program),
  inputProtectedRecordIds:linear?[]:approved.inputProtectedRecordIds,
  inputBindings:linear?approved.context.ownerCiphertextDigests:approved.inputBindings};
}
async function validateConsent(view,item,consentId,wallet){
 const snapshot=await ownerChain.read(view,`consent ${consentId}`,async(_provider,blockTag,index)=>{
  const contract=registries[index],state=await contract.getConsent(consentId,{blockTag});
  const recordCount=Number(state.recordCount),inputCount=Number(state.actualInputCount);
  if(!Number.isSafeInteger(recordCount)||recordCount<1||recordCount>64||
     !Number.isSafeInteger(inputCount)||inputCount<0||inputCount>128)throw Error('malformed consent counts');
  const records=await Promise.all(Array.from({length:recordCount},(_,recordIndex)=>
   contract.getConsentRecord(consentId,recordIndex,{blockTag})));
  const inputs=await Promise.all(Array.from({length:inputCount},(_,inputIndex)=>
   contract.getConsentInput(consentId,inputIndex,{blockTag})));
  return {state,isOwner:await contract.isConsentOwner(consentId,wallet.address,{blockTag}),records,inputs};
 });
 const {state}=snapshot;assert.equal(state.exists,true,'unknown release consent');
 const expected=await expectedConsent(item,state.workflow);
 const expectedTerms={domain:policyDomain,chainId:BigInt(cfg.chainId),workflowKind:item.half==='linear'?1:2,
  workflow:expected.approved.game,taskId:expected.taskId,contextDigest:expected.approved.contextDigest,
  programDigest:expected.approved.programDigest,programRoot:expected.programRoot,
  profileDigest:expected.approved.profileDigest,keysetDigest:keys.keysetDigest,keyId:keys.keyId,keyEpoch:keys.keyEpoch,
  mpcContext:keys.mpcContext,outputType:outputTypeDigest(expected.approved.outputType),recipient,
  slot:ethers.id(`${cfg.runId}:${item.name}:final:onchain-v3`),protectedRecordIds:item.recordIds,
  inputProtectedRecordIds:expected.inputProtectedRecordIds,inputBindings:expected.inputBindings};
 same(consentId,computeConsentIdV3(registry.target,expectedTerms),'consent ID differs from the owner-approved terms');
 same(state.domain,policyDomain,'wrong policy domain');assert.equal(state.chainId,BigInt(cfg.chainId));
 assert.equal(Number(state.workflowKind),item.half==='linear'?1:2);same(state.taskId,expected.taskId,'wrong task');
 for(const [field,value] of [['contextDigest',expected.approved.contextDigest],['programDigest',expected.approved.programDigest],
  ['programRoot',expected.programRoot],['profileDigest',expected.approved.profileDigest],['keysetDigest',keys.keysetDigest],
  ['keyId',keys.keyId],['keyEpoch',keys.keyEpoch],['mpcContext',keys.mpcContext],
  ['outputType',outputTypeDigest(expected.approved.outputType)],['recipient',recipient],
  ['slot',ethers.id(`${cfg.runId}:${item.name}:final:onchain-v3`)]])same(state[field],value,`wrong consent ${field}`);
 assert.equal(Number(state.recordCount),item.recordIds.length);
 assert.equal(Number(state.requiredOwnerCount),new Set(item.owners.map(value=>value.toLowerCase())).size);
 assert.ok(item.owners.some(value=>value.toLowerCase()===wallet.address.toLowerCase()),'owner is not affected');
 assert.equal(snapshot.isOwner,true,'registry omitted affected owner');
 for(let i=0;i<item.recordIds.length;i++){
  const row=snapshot.records[i];
  same(row.protectedId,item.recordIds[i],'changed protected record');
  if(item.half==='linear')same(row.inputBinding,expected.inputBindings[i],'changed encrypted input binding');
  else same(row.inputBinding,ethers.ZeroHash,'nonlinear record carried an aggregate binding');
  same(row.owner,item.owners[i],'changed protected-record owner');
 }
 assert.equal(Number(state.actualInputCount),expected.inputProtectedRecordIds.length);
 if(item.half==='linear')assert.equal(Number(state.paddedInputCount),0);
 else{
  const ownerForRecord=id=>{const position=item.recordIds.indexOf(id);assert.ok(position>=0);return item.owners[position];};
  const root=canonicalConsentInputRoot(expected.taskId,expected.inputProtectedRecordIds,expected.inputBindings,ownerForRecord);
  same(state.inputRoot,root.inputRoot,'changed canonical input root');
  assert.equal(Number(state.paddedInputCount),root.paddedInputCount);
  for(let i=0;i<expected.inputProtectedRecordIds.length;i++){
   const row=snapshot.inputs[i];
   same(row.protectedId,expected.inputProtectedRecordIds[i],'changed canonical input record');
   same(row.inputBinding,expected.inputBindings[i],'changed canonical input ciphertext');
   same(row.owner,ownerForRecord(expected.inputProtectedRecordIds[i]),'changed canonical input owner');
  }
 }
 return {state,...expected};
}
async function validateLinearRelease(view,item,release,consent,wallet){
 const inputs=(await json(`/owner/${item.name}/coordinates.json`)).map(row=>row.map(BigInt));
 const width=inputs[0].length,dimension=9*width,aggregate=Array(dimension).fill(0n);
 for(let i=0;i<inputs.length;i++)for(let j=0;j<width;j++){
  const position=Math.floor(i/4)*width+j;aggregate[position]=L.mod(aggregate[position]+inputs[i][j],L.R);
 }
 const aggregateDigest=L.coordsDigest(aggregate);same(release.aggregateDigest,aggregateDigest,'changed linear aggregate');
 const result=await ownerChain.read(view,'linear accepted output',async(provider,blockTag)=>{
  const game=new ethers.Contract(consent.workflow,[
   'function getBoundResult(bytes32) view returns(uint256[2] outputCommitment,bytes32 outputDigest,address operator,bool accepted)'
  ],provider);
  return game.getBoundResult(consent.taskId,{blockTag});
 });
 assert.equal(result.accepted,true,'linear result is not accepted');
 same(result.outputDigest,aggregateDigest,'linear result binding changed');
 assert.deepEqual(Array.from(result.outputCommitment).map(BigInt),L.g1ToContract(L.commit(aggregate,L.commitGenerators(dimension))).map(BigInt));
 const directory=`/owner/${item.name}/release-${release.requestId.slice(2)}-${wallet.address.slice(2).toLowerCase()}`,
  aggregateFile=directory+'/aggregate.bin',outputFile=directory+'/output.bin';
 await fs.mkdir(directory,{recursive:true});
 const aggregateBytes=Buffer.concat(aggregate.map(L.be32));
 try{await fs.writeFile(aggregateFile,aggregateBytes,{flag:'wx'});}catch(error){
  if(error.code!=='EEXIST')throw error;
  assert.deepEqual(await fs.readFile(aggregateFile),aggregateBytes,'persisted owner aggregate changed');
 }
 let outputExists=true;try{await fs.access(outputFile);}catch(error){if(error.code==='ENOENT')outputExists=false;else throw error;}
 if(!outputExists)await runPublicWorker(binary,{action:'normalize',evaluationKey,plan:item.plan,
  aggregate:aggregateFile,aggregateDigest,output:outputFile},directory);
 const digest=ethers.keccak256(await fs.readFile(outputFile));same(release.finalOutputDigest,digest,'changed linear output ciphertext');
 return digest;
}
async function validateNonlinearRelease(view,item,release,consent,approved){
 assert.ok(approved.workflowBinding,'nonlinear workflow was not owner-authenticated');
 const trace=await canonicalTrace(approved.context,`/fixtures/${item.name}/public`,`/fixtures/${item.name}/honest`);
 const {plan,leaves}=publicTracePlan(consent.taskId,approved.context,trace.manifest);
 const artifact=outputArtifactDigest(approved.context,trace.manifest.terminalHandle);
 const state=await ownerChain.read(view,'nonlinear finality and result binding',async(provider,blockTag)=>{
  const game=new ethers.Contract(consent.workflow,[
   'function secureTraceMode() view returns(bool)','function availabilityModule() view returns(address)',
   'function leafDecisionVerifier() view returns(address)','function fhevmVerifier() view returns(address)',
   'function kmsVerdictVerifier() view returns(address)',
   'function getTaskStatus(bytes32) view returns(uint8 status,uint8 decision,bool challengeTriggered,address operator,address challenger)',
   'function getTaskResultBinding(bytes32) view returns(bytes32 resultHash,bytes32 operatorTraceRoot,uint32 leafCount)'
  ],provider);
  const [availabilityAddress,verifierAddress]=await Promise.all([
   game.availabilityModule({blockTag}),game.leafDecisionVerifier({blockTag})]);
  const availability=new ethers.Contract(availabilityAddress,[
   'function isCleared(bytes32) view returns(bool)',
   'function getTaskAuthorization(bytes32) view returns(tuple(address requester,address operator,bytes32 traceRoot,bytes32 resultHash,bytes32 inputRoot,bytes32 programRoot,bytes32 provenanceRoot,bytes32 outputAttestationHash,uint32 inputCount,uint32 leafCount,uint64 deadline,bool consumed))'
  ],provider);
  const verifier=new ethers.Contract(verifierAddress,[
   'function game() view returns(address)','function profileDigest() view returns(bytes32)','function contexts(bytes32) view returns(bytes32)'
  ],provider);
  const [secure,fhevm,kms,status,cleared,auth,binding,verifierGame,profile,contextDigest]=await Promise.all([
   game.secureTraceMode({blockTag}),game.fhevmVerifier({blockTag}),game.kmsVerdictVerifier({blockTag}),
   game.getTaskStatus(consent.taskId,{blockTag}),availability.isCleared(consent.taskId,{blockTag}),
   availability.getTaskAuthorization(consent.taskId,{blockTag}),game.getTaskResultBinding(consent.taskId,{blockTag}),
   verifier.game({blockTag}),verifier.profileDigest({blockTag}),verifier.contexts(consent.taskId,{blockTag})]);
  return {availabilityAddress,verifierAddress,secure,fhevm,kms,status,cleared,auth,binding,verifierGame,profile,contextDigest};
 });
 same(state.availabilityAddress,approved.workflowBinding.availability,'availability module changed after owner binding');
 same(state.verifierAddress,approved.workflowBinding.verifier,'canonical verifier changed after owner binding');
 assert.equal(state.secure,true,'insecure nonlinear workflow');same(state.fhevm,ethers.ZeroAddress,'FHEVM backend must be absent');
 same(state.kms,ethers.ZeroAddress,'KMS verdict backend must be absent');same(state.verifierGame,consent.workflow,'canonical verifier game changed');
 same(state.profile,hashJson(approved.context.profile),'canonical profile changed');same(state.contextDigest,hashJson(approved.context),'context certificate mismatch');
 assert.equal(Number(state.status.status),3,'nonlinear result is not final');assert.equal(Number(state.status.decision),1,'nonlinear result was rejected');
 assert.equal(state.status.challengeTriggered,false,'challenged nonlinear result cannot be released');assert.equal(state.cleared,true,'nonlinear trace is not cleared');
 assert.equal(state.auth.consumed,true,'nonlinear task authorization was not consumed');
 same(state.auth.traceRoot,trace.tree.root,'nonlinear trace root changed');same(state.auth.inputRoot,plan.inputTree.root,'nonlinear input root changed');
 same(state.auth.programRoot,plan.programTree.root,'nonlinear program root changed');same(state.auth.provenanceRoot,plan.provenanceTree.root,'nonlinear provenance root changed');
 same(state.auth.outputAttestationHash,artifact,'nonlinear output attestation changed');assert.equal(Number(state.auth.leafCount),leaves.length);
 same(state.binding.operatorTraceRoot,trace.tree.root,'nonlinear result trace changed');assert.equal(Number(state.binding.leafCount),leaves.length);
 same(state.binding.resultHash,computeBoundResultHash(consent.taskId,trace.tree.root,leaves.length,trace.manifest.terminalHandle,artifact),
  'nonlinear result binding changed');
 same(trace.manifest.terminalHandle,release.finalOutputDigest,'changed nonlinear output');
 same(release.aggregateDigest,release.finalOutputDigest,'nonlinear aggregate/output mismatch');return trace.manifest.terminalHandle;
}
async function inspectExactReleaseWire(release,consent){
 const matches=[];
 for(const name of await fs.readdir('/exchange')){
  if(!/^wire-\d+\.json$/.test(name))continue;
  const candidate=await json('/exchange/'+name);
  if(candidate.releaseRequest?.requestId?.toLowerCase()===release.requestId.toLowerCase())matches.push(candidate);
 }
 assert.equal(matches.length,1,'owner requires one exact recipient wire');
 const candidate=matches[0],wire=Uint8Array.from(Buffer.from(candidate.wire,'hex')),
  getWire=Uint8Array.from(Buffer.from(candidate.get,'hex'));
 const {ciphertextCount,...decoded}=inspectKmsRequest(wire);assert.equal(ciphertextCount,1);
 const request=releaseRequestFromWire({consentId:release.consentId,decoded,wire,getWire});
 for(const field of ['consentId','requestId','requestKey','submitWireDigest','resultQueryDigest','finalOutputDigest',
  'aggregateDigest','recipientEncryptionKeyDigest','recipient'])same(request[field],release[field],`wire changed ${field}`);
 assert.equal(decoded.policyVersion,3);same(decoded.policy,registry.target,'wire changed policy');
 same(decoded.policyDomain,consent.domain,'wire changed policy domain');
 assert.equal(BigInt(decoded.chainId),consent.chainId);assert.equal(Number(decoded.workflowKind),Number(consent.workflowKind));
 for(const [field,value] of [['game',consent.workflow],['taskId',consent.taskId],['contextDigest',consent.contextDigest],
  ['programDigest',consent.programDigest],['programRoot',consent.programRoot],['profileDigest',consent.profileDigest],
  ['keysetDigest',consent.keysetDigest],['keyId',consent.keyId],['keyEpoch',consent.keyEpoch],
  ['mpcContext',consent.mpcContext],['slot',consent.slot],['recipient',consent.recipient]])same(decoded[field],value,`wire changed ${field}`);
 same(outputTypeDigest(decoded.outputType),consent.outputType,'wire changed logical output type');
 return {decoded,request};
}
async function validateRelease(item,requestId,expectedReleaseDigest,wallet){
 assert.ok(ethers.isHexString(expectedReleaseDigest,32),'invalid expected release digest');
 return ownerChain.withView(`exact release ${requestId}`,async view=>{
  const release=await ownerChain.read(view,`release state ${requestId}`,(_provider,blockTag,index)=>
   registries[index].getRelease(requestId,{blockTag}));
  assert.equal(release.exists,true,'unknown exact release');assert.equal(release.reserved,false,'release already consumed');
  same(release.requestId,requestId,'changed request ID');
  same(release.releaseDigest,expectedReleaseDigest,'release digest differs from the owner-approved transaction');
  const consent=await validateConsent(view,item,release.consentId,wallet);
  same(release.recipient,recipient,'changed release recipient');
  for(const field of ['requestKey','submitWireDigest','resultQueryDigest','finalOutputDigest','aggregateDigest','recipientEncryptionKeyDigest','releaseDigest'])
   assert.notEqual(release[field],ethers.ZeroHash,`empty release ${field}`);
  const exact=await inspectExactReleaseWire(release,consent.state);
  same(expectedReleaseDigest,computeReleaseDigestV3(exact.request),'transaction release digest differs from the exact recipient wire');
  await (item.half==='linear'?validateLinearRelease(view,item,release,consent.state,wallet):
   validateNonlinearRelease(view,item,release,consent.state,consent.approved));
  return consent;
 });
}
async function requirePolicyRefreshClaim(){
 if(!cfg.policyRefreshPlan)return;
 // The owner starts before the permanent claim to prepare ciphertexts and run
 // the read-only capacity check. Reload the bind-mounted config before every
 // signing action so no transaction can escape that passive phase.
 const [live,preflight]=await Promise.all([json('/config/campaign.json'),
  json('/reports/release-capacity-preflight.json')]);
 assert.deepEqual(live.policyRefreshPlan,cfg.policyRefreshPlan,'V3 refresh plan changed after owner preparation');
 assert.equal(live.runId,cfg.runId,'V3 refresh run changed after owner preparation');
 const attempt=live.policyRefreshAttempt;
 assert.ok(attempt&&attempt.status==='permanently-claimed','V3 refresh transaction requested before permanent claim');
 assert.equal(attempt.runId,cfg.runId,'V3 refresh claim belongs to another run');
 assert.equal(attempt.requestedHalf,cfg.half,'V3 refresh claim has the wrong scope');
 assert.deepEqual(attempt.claimedScopes,cfg.half==='both'?['linear','nonlinear']:[cfg.half],
  'V3 refresh claim has incomplete scopes');
 assert.equal(attempt.designSha256,cfg.policyRefreshPlan.designSha256,'V3 refresh claim has the wrong design');
 assert.equal(preflight.status,'passed','V3 refresh capacity preflight did not pass');
 assert.equal(preflight.designSha256,cfg.policyRefreshPlan.designSha256,'V3 refresh capacity preflight changed');
 assert.deepEqual(preflight.caseNames,cases.map(item=>item.name),'V3 refresh prepared case sequence changed');
}
async function handle(r){
 const item=cases.find(c=>c.name===r.caseName);assert.ok(item,'unknown owner-approved dataset case');
 const wallet=wallets[r.index];assert.ok(wallet,'unknown owner');
 if(r.action==='benchmark'){
  assert.ok(cfg.pocPlan&&item.half==='linear');assert.equal(r.index,0);
  assert.ok(!benchmarked.has(item.name),'benchmark preparation cannot be replayed');
  // The owner independently fixes the benchmark domain and reads its original
  // encrypted coordinates, never caller-supplied vectors or a clear result.
  const inputs=await json(`/owner/${item.name}/coordinates.json`);
  const signed=prepareLinearBenchmark({inputs,caseName:item.name,keysetDigest:keys.keysetDigest,chainId:cfg.chainId});
  await atomic(`/fixtures/${item.name}/benchmark-admissions.json`,signed);
  benchmarked.add(item.name);
  return {path:`/fixtures/${item.name}/benchmark-admissions.json`};
 }
 if(casePlan)assert.equal(item.fullCase,true,'unselected fixtures cannot authorize a full case or release');
 if(r.action==='bind-workflow'){
  assert.equal(item.half,'nonlinear');assert.ok(item.owners.some(value=>value.toLowerCase()===wallet.address.toLowerCase()),
   'owner is not affected');
  const approved=approvals.get(item.name);assert.ok(approved,'owner has no approved computation statement');
  if(approved.game)assertExpectedWorkflow(approved,r.workflow?.game);
  const authenticated=await authenticateNonlinearWorkflow(r.workflow,approved);
  bindExpectedWorkflow(approved,authenticated.game);approved.workflowBinding=authenticated;
  return authenticated;
 }
 if(r.action==='transaction'){
   await requirePolicyRefreshClaim();
   const tx=r.transaction;assert.equal(String(tx.chainId),cfg.chainId);assert.equal(BigInt(tx.value??0),0n);
  let parsed;for(const abi of interfaces){try{parsed=abi.parseTransaction(tx);if(parsed)break;}catch{}}
  assert.ok(parsed&&allowedTx.has(parsed.name),'owner refuses unapproved transaction');
  if(['registerProtectedRecord','approveConsent','approveRelease'].includes(parsed.name)){
   same(tx.to,registry.target,'wrong release-policy registry');
   if(parsed.name==='registerProtectedRecord'){
    const [protectedId,recordOwner,recordReference,releaseLimit,initialSpent]=parsed.args;
    const position=item.recordIds.findIndex(value=>value===protectedId);assert.ok(position>=0,'unknown protected record');
    same(recordOwner,wallet.address,'changed protected-record owner');same(item.owners[position],wallet.address,'wrong data owner');
    same(recordReference,item.recordReferences[position],'changed record reference');
    same(protectedId,ownerBoundProtectedId(cfg.chainId,registry.target,wallet.address,recordReference),'unbound protected ID');
    assert.equal(Number(releaseLimit),item.releaseLimits[position]);assert.equal(Number(initialSpent),item.initialSpent[position]);
   }else if(parsed.name==='approveConsent')await ownerChain.withView(`consent approval ${parsed.args[0]}`,
     view=>validateConsent(view,item,parsed.args[0],wallet));
   else await validateRelease(item,parsed.args[0],parsed.args[1],wallet);
  }else if(parsed.name==='registerInputOrigins'){
   assert.equal(item.half,'nonlinear');
   const approved=approvals.get(item.name);assert.ok(approved.game&&approved.workflowBinding);
   same(tx.to,approved.workflowBinding.availability,'unapproved availability module');
   const tasks=[ethers.id(`${item.name}:${approved.game}`),ethers.id(`${item.name}:fault`)];
   approveInputOrigins({inputs:approved.inputs,owner:wallet.address,taskIds:tasks,
    handles:Array.from(parsed.args[0]),metadata:Array.from(parsed.args[1])});
  }else if(parsed.name==='bindProtectedRecord'){
   assert.equal(item.half,'linear');same(tx.to,approvals.get(item.name)?.game,'unapproved deployment');
   const input=Number(parsed.args[0]);assert.ok(input>=0&&input<item.n);same(item.owners[input],wallet.address,'wrong input owner');
   same(parsed.args[1],item.recordIds[input],'changed protected-record binding');
   const inputs=await json(`/owner/${item.name}/coordinates.json`);
   same(parsed.args[2],L.coordsDigest(inputs[input].map(BigInt)),'changed protected ciphertext');
  }else{
   assert.equal(tx.to.toLowerCase(),approvals.get(item.name)?.game?.toLowerCase(),'unapproved deployment');
   const a=admissions.get(`${item.name}:${Number(parsed.args[0])}`);assert.ok(a&&a.owner===wallet.address);
   const wanted=parsed.name==='registerOwnerKey'?[a.pk]:[a.commitment,a.signature];
   for(let i=0;i<wanted.length;i++)assert.deepEqual(Array.from(parsed.args[i+1]).map(String),wanted[i]);
  }
  return wallet.signTransaction(tx);
 }
 if(r.action==='bls'){
  assert.equal(item.half,'linear');assert.ok(r.input>=0&&r.input<item.n);
  assert.equal(item.owners[r.input],wallet.address);
  const inputs=await json(`/owner/${item.name}/coordinates.json`);
  const statement=linearStatement({item,keys,inputs,binaryDigest:ethers.keccak256(await fs.readFile(binary)),game:r.game,chainId:cfg.chainId});
  assert.equal(statement.tag,r.datasetTag);const previous=approvals.get(item.name);
  if(previous)assert.equal(previous.game,r.game);else approvals.set(item.name,{...statement,game:r.game});
  const coords=inputs[r.input].map(BigInt),dimension=9*coords.length;
  const vector=Array(dimension).fill(0n),group=Math.floor(r.input/4);coords.forEach((v,j)=>vector[group*coords.length+j]=v);
  let started=performance.now();const commitment=L.commit(vector,L.commitGenerators(dimension));
  const commitmentMs=performance.now()-started;
  started=performance.now();const {sk,pk}=L.keygen(()=>randomBytes(32));const keygenMs=performance.now()-started;
  started=performance.now();const signature=L.sign(sk,commitment,r.datasetTag,r.input,{pk,op:0,totalItems:item.n});
  const proposalSignMs=performance.now()-started;
  started=performance.now();const baselineSignature=ordinarySign(sk,{pk,datasetTag:r.datasetTag,index:r.input,op:0,totalItems:item.n,vector});
  const baselineSignMs=performance.now()-started;
  const signed={pk:L.g2ToContract(pk).map(String),commitment:L.g1ToContract(commitment).map(String),signature:L.g1ToContract(signature).map(String),
   baselineSignature,baselineProfile:ORDINARY_BLS_PROFILE,
   preparationTimings:{keygenMs,commitmentMs,proposalSignMs,baselineSignMs}};
  admissions.set(`${item.name}:${r.input}`,{...signed,owner:wallet.address});return signed;
 }
 throw Error('unapproved owner action');
}
while(true){
 for(const name of await fs.readdir('/owner-rpc'))if(name.endsWith('.request')){
  const result='/owner-rpc/'+name.replace('.request','.response');
  try{await fs.access(result);continue;}catch{}
  let response;try{response={value:await handle(await json('/owner-rpc/'+name))};}catch(e){response={error:String(e)};}
  await atomic(result,response);
 }
 await new Promise(r=>setTimeout(r,100));
}
