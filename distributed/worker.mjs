import {allowsAdversarialAgreementControl} from './agreement-control-policy.mjs';
// One controller per task. Canonical FHE executes in the role's sibling worker.
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {authorizeTask,localIdentity} from './adapter-policy.mjs';
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const {task,cfg}=JSON.parse(Buffer.concat(chunks).toString());authorizeTask(cfg.role,task);
const campaign='/app/threshold-kms/campaign/';
const binary='/usr/local/bin/kms-campaign';
const b=task.body;
let value;
if(task.name==='canonical-execute'){
  const {runCanonicalBinary}=await import(campaign+'runtime/scripts/canonical-protocol.mjs');
  value=await runCanonicalBinary(binary,b.args);
}else if(task.name==='canonical-audit'){
  const {detectCanonicalFault}=await import(campaign+'runtime/scripts/canonical-protocol.mjs');
  value=await detectCanonicalFault({...b,binary});
  if(b.taskId){
    assert.match(b.taskId,/^0x[0-9a-fA-F]{64}$/);
    await fs.mkdir('/transport/audits',{recursive:true});
    await fs.writeFile('/transport/audits/'+b.taskId+'.json',JSON.stringify({request:b,result:value}),{flag:'wx',mode:0o600});
  }
}else if(task.name==='audit-commit'){
  const {ethers}=createRequire('/app/fhe-pod/package.json')('ethers');
  const config=JSON.parse(await fs.readFile('/config/campaign.json','utf8'));
  const registry=JSON.parse(await fs.readFile('/transport/contracts/'+b.game.toLowerCase()+'.json','utf8'));
  const game=new ethers.Contract(b.game,registry.abi,new ethers.JsonRpcProvider(cfg.rpcUrl));
  assert.equal(b.auditorAddress.toLowerCase(),cfg.identities[cfg.node].toLowerCase());
  const {canonicalTrace}=await import(campaign+'runtime/scripts/canonical-protocol.mjs');
  const {publicTracePlan}=await import(campaign+'runtime/scripts/canonical-chain.mjs');
  const operatorTrace=await canonicalTrace(b.context,b.publicDir,b.operatorDir);
  const operatorLeaves=publicTracePlan(b.taskId,b.context,operatorTrace.manifest).leaves;
  let candidateLeaves,control=false;
  try{
    const own=JSON.parse(await fs.readFile('/transport/audits/'+b.taskId+'.json','utf8'));
    assert.equal(own.result.operatorRoot,operatorTrace.tree.root);
    assert.equal(b.supportsOperator,own.result.index===null);
    assert.equal(Number(b.index),own.result.index??0);
    const candidate=await canonicalTrace(own.request.context,own.request.publicDir,own.request.replayDir);
    candidateLeaves=publicTracePlan(b.taskId,own.request.context,candidate.manifest).leaves;
    assert.equal(candidate.tree.root,own.result.replayRoot);
  }catch(error){
    if(error.code!=='ENOENT')throw error;
    // The original campaign includes deliberately false agreement controls.
    // They are confined to the known faulty full-case tasks and never counted
    // as honest recomputation or rewarded by this adapter.
    assert.equal(cfg.allowAdversarialAgreementControls,true);
    assert.ok(allowsAdversarialAgreementControl(config,b.caseName));
    assert.equal(b.taskId,ethers.id(b.caseName+':fault'));
    assert.equal(b.supportsOperator,true);candidateLeaves=operatorLeaves;control=true;
  }
  const {prepareSealedBountyAudit}=await import(campaign+'runtime/scripts/canonical-bounty-client.mjs');
  value=await prepareSealedBountyAudit({game,taskId:b.taskId,auditorAddress:b.auditorAddress,
    operatorLeaves,candidateLeaves,index:Number(b.index),supportsOperator:b.supportsOperator});
  await fs.mkdir('/transport/audit-commitments',{recursive:true});
  await fs.writeFile('/transport/audit-commitments/'+b.taskId+'.json',JSON.stringify({game:b.game,
    commitment:value.commitment,adversarialAgreementControl:control}),{flag:'wx',mode:0o600});
}else if(task.name==='canonical-attest'){
  const {signingWorker}=await import(campaign+'runtime/scripts/canonical-game-driver.mjs');
  value=await signingWorker(localIdentity(b,cfg));
}else if(task.name==='normalize'){
  const {normalizeLocally}=await import('./normalization.mjs');
  value=await normalizeLocally(binary,b,'/transport/normalize-'+cfg.requestId);
}else if(['linear-aggregate','linear-proposed','linear-baseline'].includes(task.name)){
  const p=await import(campaign+'paired-linear.mjs');
  const inputs=JSON.parse(await fs.readFile(b.coordinates,'utf8')),vectors=p.groupedVectors(inputs);
  if(task.name==='linear-aggregate'){
    const L=createRequire('/app/BN254-Signatures/package.json')('/app/BN254-Signatures/scripts/mklhs-lib.js');
    const start=performance.now(),aggregate=p.aggregateVectors(vectors),gens=p.generators(aggregate.length);
    const commitment=L.g1ToContract(L.commit(aggregate,gens));
    value={aggregate:aggregate.map(String),commitment:commitment.map(String),aggregateDigest:L.coordsDigest(aggregate),ms:performance.now()-start};
    if(b.output)await fs.writeFile(b.output,Buffer.concat(aggregate.map(L.be32)),{flag:'wx'});
  }else{
    const signed=JSON.parse(await fs.readFile(b.admissions,'utf8'));
    const args={...signed,vectors,aggregate:b.aggregate.map(BigInt),generators:p.generators(signed.dimension)};
    value=task.name==='linear-proposed'?await p.verifyProposal(args):await p.verifyBaseline(args);
  }
}else throw Error('task requires its persistent participant adapter');
process.stdout.write(JSON.stringify(value,(_,v)=>typeof v==='bigint'?String(v):v));
