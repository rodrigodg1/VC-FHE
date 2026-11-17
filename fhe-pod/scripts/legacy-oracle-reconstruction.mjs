// Diagnostic of the deliberately retained legacy API, never a deployment mode.
// Real FHE predicates; local full-key KMS and local signature quorum simulation.
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { ethers, compileContracts, buildMerkleTree, boundCreateTaskArgs, sampleTaskParticipants } from './evm-lib.mjs';
import { createProvider, signerFor, advanceTime, WINDOW_SECONDS, PAST_WINDOW_SECONDS, onExternalChain } from '../contracts/test/chain-harness.mjs';
import { runCanonicalBinary, hashFile, hashJson } from './canonical-protocol.mjs';
import { OutputReleasePolicy } from './output-release-policy.mjs';

const binary=process.env.VCFHE_CIRCUIT_EXECUTOR,reportFile=process.argv[2];
if(!binary||!reportFile||onExternalChain)throw new Error('requires canonical binary, new report path and local test chain');
const workDir=await fs.mkdtemp(path.join(os.tmpdir(),'tops-legacy-oracle-'));
const report={status:'running',classification:'legacy-oracle-reconstruction',workDir,
  scope:'real FHE chosen predicates and legacy EVM opening; simulated full-key KMS and signer quorum',
  cases:[],legacyOpenings:0,repairedBlocked:0,repairedKmsCalls:0};
await fs.writeFile(reportFile,JSON.stringify(report),{flag:'wx'});
const save=()=>fs.writeFile(reportFile,JSON.stringify(report,null,2));
const types={PublicDecryptVerification:[{name:'ctHandles',type:'bytes32[]'},{name:'decryptedResult',type:'bytes'},{name:'extraData',type:'bytes'}]};
try {
  const provider=await createProvider({totalAccounts:12}),deployer=await signerFor(provider,0),operator=await signerFor(provider,1);
  const auditors=await Promise.all([2,3,4].map(i=>signerFor(provider,i)));
  const cores=Array.from({length:4},()=>ethers.Wallet.createRandom());
  const artifacts=await compileContracts();
  async function deploy(name,args=[]){const a=artifacts[name];const c=await new ethers.ContractFactory(a.abi,a.bytecode,deployer).deploy(...args);await c.waitForDeployment();return c;}
  const objective=await deploy('ObjectiveMicroVerifier');
  const game=await deploy('LegacyConfigurableDisputeGame',[objective.target,WINDOW_SECONDS,WINDOW_SECONDS,WINDOW_SECONDS,false]);
  const verifier=await deploy('ZamaKMSVerdictVerifier',['VCFHE-Legacy-Diagnostic','1',0,ethers.ZeroAddress,cores.map(w=>w.address),2]);
  await(await game.setKmsVerdictVerifier(verifier.target)).wait();
  await(await game.connect(operator).registerOperator({value:ethers.parseEther('2')})).wait();
  for(const a of auditors)await(await game.connect(a).registerAuditor({value:ethers.parseEther('1')})).wait();
  for(const i of [5,6,7])await(await game.connect(await signerFor(provider,i)).registerDecryptor({value:ethers.parseEther('1')})).wait();
  const domain={name:'VCFHE-Legacy-Diagnostic',version:'1',chainId:String((await provider.getNetwork()).chainId),verifyingContract:verifier.target};
  const repaired=new OutputReleasePolicy({domain:'diagnostic',ledgerFile:path.join(workDir,'repaired-ledger.json'),
    resolveFinalized:async()=>{throw new Error('an audit query must not reach finality resolution');},
    kms:{decryptAuthorized:async()=>{report.repairedKmsCalls++;throw new Error('forbidden');}}});
  const leaves=[{opcode:1,lhs:12,rhs:5,claimed:60},{opcode:2,lhs:60,rhs:2,claimed:15},
    {opcode:4,lhs:15,rhs:7,claimed:7},{opcode:5,lhs:7,rhs:1,claimed:1}];
  const tree=buildMerkleTree(leaves),abi=ethers.AbiCoder.defaultAbiCoder();
  for(let secret=1;secret<=5;secret++){
    const caseDir=path.join(workDir,`record-${secret}`);await fs.mkdir(caseDir);
    const program={version:'compliance-explicit-dag-v1',inputs:[{id:'rating',type:'uint64'}],
      instructions:[{index:0,opcode:'GT',lhs:{kind:'input',index:0},rhs:{kind:'constant',value:'3'}}],output:{kind:'output',index:0}};
    await fs.writeFile(path.join(caseDir,'program.json'),JSON.stringify(program));
    await fs.writeFile(path.join(caseDir,'values.json'),JSON.stringify([secret]));
    await runCanonicalBinary(binary,['setup',path.join(caseDir,'program.json'),path.join(caseDir,'values.json'),caseDir]);
    // The adversarial loop receives only encrypted inputs and query responses.
    // The secret remains in fixture setup and the final laboratory assertion.
    let low=1,high=5;const queries=[];
    while(low<high){
      const threshold=Math.floor((low+high)/2),q=queries.length;
      program.instructions[0].rhs.value=String(threshold);
      const publicDir=path.join(caseDir,'public'),traceDir=path.join(caseDir,`query-${q}`);
      await fs.writeFile(path.join(publicDir,'program.json'),JSON.stringify(program));
      const execution=await runCanonicalBinary(binary,['execute-canonical',publicDir,traceDir]);
      const handle=execution.terminalHandle;
      assert.equal(handle,await hashFile(path.join(traceDir,'result-0.ct')));
      const taskId=ethers.id(`legacy-record-${secret}-query-${q}`),podRoot=ethers.id(`pod-${taskId}`);
      await(await game.connect(operator).createTask(...boundCreateTaskArgs(taskId,tree,leaves,ethers.id(`ack-${taskId}`)))).wait();
      await sampleTaskParticipants(game.connect(operator),taskId);
      let auditor,leafIndex;
      for(const a of auditors)for(let i=0;i<leaves.length&&!auditor;i++)if(await game.isAuditorAssignedToLeaf(taskId,a.address,i)){auditor=a;leafIndex=i;}
      assert.ok(auditor);
      await(await game.connect(auditor).submitAudit(taskId,leafIndex,podRoot,handle)).wait();
      await advanceTime(provider,PAST_WINDOW_SECONDS);
      const opened=await runCanonicalBinary(binary,['release-output',path.join(caseDir,'owner/client-key.bin'),path.join(traceDir,'result-0.ct'),handle]);
      const plaintext=abi.encode(['uint256'],[BigInt(opened.value)]),extra=await game.verdictOpeningBinding(taskId,auditor.address);
      const signatures=await Promise.all(cores.slice(0,2).map(w=>w.signTypedData(domain,types,{ctHandles:[handle],decryptedResult:plaintext,extraData:extra})));
      const receipt=await(await game.openVerdictViaKMS(taskId,auditor.address,podRoot,plaintext,abi.encode(['bytes[]','bytes'],[signatures,extra]))).wait();
      const event=receipt.logs.map(l=>{try{return game.interface.parseLog(l);}catch{return null;}}).find(l=>l?.name==='VerdictOpened');
      assert.ok(event);const bit=Number(event.args.verdictSupportsOperator);
      if(bit)low=threshold+1;else high=threshold;
      report.legacyOpenings++;
      const forbidden={kind:'audit-verdict',domain:'diagnostic',taskId,outputDigest:handle};
      const signer=cores[3];await assert.rejects(repaired.release(forbidden,await signer.signMessage(ethers.getBytes(hashJson(forbidden)))));
      report.repairedBlocked++;
      queries.push({threshold,handle,openedBit:bit,transactionHash:receipt.hash});
    }
    assert.equal(low,secret);assert.ok(queries.length<=3);
    report.cases.push({expected:secret,reconstructed:low,queries});await save();
  }
  assert.equal(report.repairedKmsCalls,0);assert.equal(report.repairedBlocked,report.legacyOpenings);
  report.reconstructionCorrect=report.cases.filter(r=>r.expected===r.reconstructed).length;
  report.status='passed';console.log(`Legacy reconstruction ${report.reconstructionCorrect}/5; revised API blocked ${report.repairedBlocked} requests with zero KMS calls`);
}catch(e){report.status='failed';report.error=String(e.stack??e);throw e;}
finally{await save();}
