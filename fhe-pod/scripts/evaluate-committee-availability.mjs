// Local paired control-flow evaluation. Opaque handles and fixture signatures
// do not establish FHE correctness, independent auditing or production liveness.
// Solidity compilation stays in memory and never writes contracts/out.
import fs from 'node:fs/promises';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
import solc from 'solc';
import {ethers,traceLeafClaim} from './evm-lib.mjs';
import {canonicalDomain,CONTEXT_TYPES,RESULT_TYPES,FULL_TYPES} from './canonical-chain.mjs';
import {createProvider,signerFor,advanceTime,confirm,chainTimestamp,EXTERNAL_RPC_URL} from '../contracts/test/chain-harness.mjs';
import {deployCanonicalBountyStack,createBountyTask,prepareSealedBountyAudit,
  commitSealedBountyAudit,revealSealedBountyAudit,proveAndOpenBountyChallenge,
  discloseAndBisectBountyChallenge,bountyLeafClaims,settleBountyChallenge} from './canonical-bounty-client.mjs';

const pod=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const gas={gasLimit:5_000_000};
async function sourceHashes() {
  const files=(await fs.readdir(path.join(pod,'contracts/src'))).filter(n=>n.endsWith('.sol')).map(n=>'contracts/src/'+n);
  files.push('scripts/evaluate-committee-availability.mjs','scripts/canonical-bounty-client.mjs',
    'scripts/canonical-chain.mjs','scripts/evm-lib.mjs','contracts/test/chain-harness.mjs');
  return Object.fromEntries(await Promise.all(files.map(async file=>[file,
    createHash('sha256').update(await fs.readFile(path.join(pod,file))).digest('hex')])));
}
async function compileInMemory() {
  const sources={};
  for(const name of (await fs.readdir(path.join(pod,'contracts/src'))).filter(n=>n.endsWith('.sol')))
    sources[name]={content:await fs.readFile(path.join(pod,'contracts/src',name),'utf8')};
  const names={
    'VerifiableFHEDisputeGame.sol':'ObjectiveMicroVerifier',
    'BountyTraceAvailability.sol':'BountyTraceAvailability',
    'CanonicalLeafVerifier.sol':'CanonicalLeafVerifier',
    'CanonicalBountyFHEDisputeGame.sol':'CanonicalBountyFHEDisputeGame',
    'CanonicalExecutionBaseline.sol':'CanonicalExecutionBaseline',
  };
  const selection=Object.fromEntries(Object.entries(names).map(([file,name])=>[file,
    {[name]:['abi','evm.bytecode.object','evm.deployedBytecode.object']}]));
  const resolve=importPath=>{
    for(const base of ['contracts/src','','node_modules','node_modules/@fhevm/solidity',
      'node_modules/@fhevm/solidity/lib','node_modules/@fhevm/solidity/config',
      'node_modules/@fhevm/solidity/lib/cryptography']) {
      try{return {contents:readFileSync(path.resolve(pod,base,importPath),'utf8')};}catch{}
    }
    return {error:'Solidity import unavailable: '+importPath};
  };
  const output=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources,settings:{
    evmVersion:'paris',viaIR:true,optimizer:{enabled:true,runs:1},metadata:{bytecodeHash:'none'},
    outputSelection:selection}}),{import:resolve}));
  const errors=(output.errors??[]).filter(e=>e.severity==='error');
  if(errors.length)throw new Error(errors.map(e=>e.formattedMessage).join('\n'));
  return Object.fromEntries(Object.entries(names).map(([file,name])=>{
    const c=output.contracts[file][name],bytes=c.evm.deployedBytecode.object.length/2;
    assert.ok(bytes<=24576,'runtime exceeds EIP-170');
    return [name,{abi:c.abi,bytecode:'0x'+c.evm.bytecode.object,deployedBytecodeBytes:bytes}];
  }));
}
async function reject(action){await assert.rejects(async()=>{const tx=await action();if(tx?.wait)await tx.wait();},
  e=>e.code==='CALL_EXCEPTION'||e.code==='UNKNOWN_ERROR');}

export async function evaluateCommitteeAvailability({outputDir}) {
  if(EXTERNAL_RPC_URL)throw new Error('this evaluation only supports an isolated in-process EVM, unset VCFHE_TEST_RPC_URL');
  if(!outputDir||!path.isAbsolute(outputDir))throw new Error('an absolute, new output directory is required');
  await fs.mkdir(outputDir,{recursive:false});
  const before=await sourceHashes(),artifacts=await compileInMemory(),checks=[];
  const record=(name,detail)=>checks.push({name,status:'passed',detail});
  const provider=await createProvider({totalAccounts:10});provider.pollingInterval=10;
  const signers=await Promise.all(Array.from({length:10},(_,i)=>signerFor(provider,i)));
  const [requester,operator,...remaining]=signers,auditors=remaining.slice(0,3),relayer=remaining[3];
  const committee=Array.from({length:3},(_,i)=>new ethers.Wallet(ethers.id('availability-fixture-signer-'+i)));
  const profileDigest=ethers.id('local-opaque-availability-fixture');
  const stack=await deployCanonicalBountyStack({requester,committee:committee.map(x=>x.address),profileDigest,artifacts});
  await confirm(stack.game.connect(operator).registerOperator({value:ethers.parseEther('6')}));
  for(const a of auditors)await confirm(stack.game.connect(a).registerAuditor({value:ethers.parseEther('2')}));
  const baseline=await new ethers.ContractFactory(artifacts.CanonicalExecutionBaseline.abi,
    artifacts.CanonicalExecutionBaseline.bytecode,requester).deploy(stack.verifier.target);
  await baseline.waitForDeployment();
  const chainId=Number((await provider.getNetwork()).chainId),domain=canonicalDomain(chainId,stack.verifier.target);
  const past=async(taskId,phase)=>{const end=Number((await stack.game.getTaskDeadlines(taskId))[phase]);
    const now=await chainTimestamp(provider);if(now<=end)await advanceTime(provider,end-now+1);};
  async function makeTask(label,claimed){
    const leaves=[{opcode:6,lhs:1,rhs:2,claimed,lhsRef:{kind:'input',index:0},rhsRef:{kind:'input',index:1}}];
    const taskId=ethers.id(label),task=await createBountyTask({...stack,requester,operator,taskId,operatorLeaves:leaves});
    const contextDigest=ethers.id('context-'+label);
    const signatures=await Promise.all(committee.slice(0,2).map(w=>w.signTypedData(domain,CONTEXT_TYPES,{taskId,contextDigest})));
    await reject(()=>stack.verifier.registerContext(taskId,contextDigest,[],gas));
    await reject(()=>stack.verifier.registerContext(taskId,contextDigest,[signatures[0]],gas));
    await confirm(stack.verifier.registerContext(taskId,contextDigest,signatures));
    const [resultHash,traceRoot]=await stack.game.getTaskResultBinding(taskId);
    return {...task,leaves,contextDigest,resultHash,traceRoot};
  }
  async function openAudit(task,candidate,supportsOperator){
    const assigned=await stack.game.getAssignedAuditorsForLeaf(task.taskId,0);
    const auditor=auditors.find(x=>x.address.toLowerCase()===assigned[0].toLowerCase());
    const candidateLeaves=task.leaves.map(l=>({...l,claimed:candidate}));
    const audit=await prepareSealedBountyAudit({game:stack.game,taskId:task.taskId,auditorAddress:auditor.address,
      operatorLeaves:task.leaves,candidateLeaves,index:0,supportsOperator});
    await commitSealedBountyAudit(stack.game,auditor,audit);await past(task.taskId,0);
    await revealSealedBountyAudit(stack.game,relayer,audit);await past(task.taskId,1);
    return {auditor,audit};
  }

  const honest=await makeTask('honest-after-context',3);
  record('context-certification-needs-quorum',{threshold:2,rejectedSignerCounts:[0,1],acceptedSignerCount:2});
  await openAudit(honest,3,true);
  await reject(()=>baseline.accept(honest.taskId,honest.traceRoot,honest.resultHash,[],gas));
  record('baseline-zero-result-signatures',{contextCertified:true,resultSignatures:0,accepted:false});
  const fullDomain={name:'VCFHE-Full-Execution',version:'1',chainId,verifyingContract:baseline.target};
  const body={taskId:honest.taskId,contextDigest:honest.contextDigest,traceRoot:honest.traceRoot,resultHash:honest.resultHash};
  const sig1=await committee[0].signTypedData(fullDomain,FULL_TYPES,body);
  await reject(()=>baseline.accept(honest.taskId,honest.traceRoot,honest.resultHash,[sig1],gas));
  record('baseline-one-result-signature',{contextCertified:true,resultSignatures:1,accepted:false});
  await past(honest.taskId,2);await confirm(stack.game.finalizeUnchallenged(honest.taskId));
  assert.equal((await stack.game.getTaskStatus(honest.taskId)).decision,1n);
  record('optimistic-uncontested-after-context',{contextCertified:true,auditFixtureOpened:true,resultSignatures:0,accepted:true});
  const sig2=await committee[1].signTypedData(fullDomain,FULL_TYPES,body);
  await confirm(baseline.accept(honest.taskId,honest.traceRoot,honest.resultHash,[sig1,sig2]));
  assert.equal(await baseline.accepted(honest.taskId),true);
  record('baseline-quorum-restored',{resultSignatures:2,accepted:true});

  const challenged=await makeTask('challenged-during-committee-outage',4);
  const {auditor,audit}=await openAudit(challenged,3,false);
  await proveAndOpenBountyChallenge(stack.game,auditor,audit);
  await discloseAndBisectBountyChallenge({...stack,task:challenged,audit,challenger:auditor,relayer});
  const claims=bountyLeafClaims(audit);
  await confirm(stack.game.settleLeafViaAttestedDecision(...claims,false,false,'0x',gas));
  const balance=await stack.game.getParticipantStake(operator.address);
  await advanceTime(provider,100);
  await reject(()=>stack.game.timeoutDispute(challenged.taskId,gas));
  await reject(()=>stack.game.finalizeUnchallenged(challenged.taskId,gas));
  assert.equal(await stack.game.getParticipantStake(operator.address),balance);
  record('admitted-dispute-without-certificate',{finalizationBlocked:true,timeoutAttributionBlocked:true,operatorBalancePreserved:true});
  const resultHandle=traceLeafClaim({...challenged.leaves[0],claimed:3}).claimedHandle;
  const binding=await stack.game.leafDecisionBinding(challenged.taskId,0,challenged.leaves[0].opcode);
  const leafBody={profileDigest,contextDigest:challenged.contextDigest,leafBinding:ethers.keccak256(binding),resultHandle};
  const leafSignatures=await Promise.all(committee.slice(0,2).map(w=>w.signTypedData(domain,RESULT_TYPES,leafBody)));
  await reject(()=>settleBountyChallenge({game:stack.game,relayer,audit,resultHandle,signatures:[leafSignatures[0]]}));
  record('admitted-dispute-one-result-signature',{resultSignatures:1,settlementBlocked:true});
  await settleBountyChallenge({game:stack.game,relayer,audit,resultHandle,signatures:leafSignatures});
  assert.equal((await stack.game.getTaskStatus(challenged.taskId)).decision,2n);
  record('admitted-dispute-quorum-restored',{resultSignatures:2,operatorRejected:true});

  const uncovered=await makeTask('coverage-negative-control',4);
  await reject(()=>baseline.accept(uncovered.taskId,uncovered.traceRoot,uncovered.resultHash,[],gas));
  await past(uncovered.taskId,2);await confirm(stack.game.finalizeUnchallenged(uncovered.taskId));
  assert.equal((await stack.game.getTaskStatus(uncovered.taskId)).decision,1n);
  record('no-audit-negative-control',{operatorFixture:4,canonicalFixture:3,auditsSubmitted:0,
    optimisticGameAccepted:true,baselineAccepted:false,meaning:'Explicit honest-audit coverage condition, not an unexpected protocol defect'});
  const after=await sourceHashes();assert.deepEqual(after,before,'sources changed during the local evaluation');
  const report={schema:'committee-availability-local-v1',status:'passed',checks,
    classification:'local-EVM-control-flow-only',realFheExecutions:0,kmsReleases:0,externalChain:false,
    auditEvidence:'opaque-handle-and-signature-fixtures-not-independent-recomputation',
    runtimeBytes:Object.fromEntries(Object.entries(artifacts).map(([k,v])=>[k,v.deployedBytecodeBytes])),
    sourceHashes:before,sourceUnchanged:true,limitations:[
      'No timing, throughput, economic profitability, secure-parameter or independent-administration claim',
      'Context certification precedes the compared result-certificate outage',
      'An admitted dispute still requires a quorum and owner/KMS release conditions are not executed',
    ]};
  await fs.writeFile(path.join(outputDir,'committee-availability.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});
  return report;
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  if(process.argv.length===3&&process.argv[2]==='--help') {
    console.log('node scripts/evaluate-committee-availability.mjs --output-dir /absolute/new/directory\nLocal in-process EVM only. No real FHE, KMS or campaign.');
  } else if(process.argv.length===4&&process.argv[2]==='--output-dir') {
    const report=await evaluateCommitteeAvailability({outputDir:process.argv[3]});
    console.log(JSON.stringify({status:report.status,checks:report.checks.length,
      report:path.join(process.argv[3],'committee-availability.json'),classification:report.classification}));
  } else throw new Error('use --help or --output-dir with a new absolute directory');
}
