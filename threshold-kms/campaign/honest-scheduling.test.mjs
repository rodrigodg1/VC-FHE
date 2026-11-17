// Local control-flow regression only. The opaque byte files and fixture
// signatures below are not FHE computations, independent audits or KMS shares.
// Real driver methods and contracts enforce ordering, deadlines and certificates.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {createCanonicalGame, freshChainTimestamp} from '../../fhe-pod/scripts/canonical-game-driver.mjs';
import {CANONICAL_VERSION, hashJson} from '../../fhe-pod/scripts/canonical-protocol.mjs';
import {COMPLIANCE_CIRCUIT_VERSION} from '../../fhe-pod/scripts/compliance-circuit.mjs';
import {canonicalDomain, CONTEXT_TYPES, FULL_TYPES} from '../../fhe-pod/scripts/canonical-chain.mjs';
import {ethers} from '../../fhe-pod/scripts/evm-lib.mjs';
import {createProvider, signerFor, advanceTime, EXTERNAL_RPC_URL} from '../../fhe-pod/contracts/test/chain-harness.mjs';

if (EXTERNAL_RPC_URL) throw new Error('honest scheduling tests require an isolated in-process EVM');

async function opaqueFixture(workDir, owner) {
  const publicDir=path.join(workDir,'public'), operatorDir=path.join(workDir,'operator');
  await fs.mkdir(publicDir);await fs.mkdir(operatorDir);
  const instruction={index:0,opcode:'ADD',lhs:{kind:'input',index:0},rhs:{kind:'constant',value:'1'}};
  const program={version:COMPLIANCE_CIRCUIT_VERSION,inputs:[{id:'opaque-owner-record',type:'uint64'}],
    instructions:[instruction],output:{kind:'output',index:0}};
  const bytes={program:Buffer.from(JSON.stringify(program)),key:Buffer.from('opaque-key-fixture'),
    input:Buffer.from('opaque-input-fixture'),result:Buffer.from('opaque-output-fixture')};
  await Promise.all([
    fs.writeFile(path.join(publicDir,'program.json'),bytes.program),
    fs.writeFile(path.join(publicDir,'server-key.bin'),bytes.key),
    fs.writeFile(path.join(publicDir,'input-0.ct'),bytes.input),
    fs.writeFile(path.join(operatorDir,'result-0.ct'),bytes.result),
  ]);
  const profile={binaryDigest:ethers.id('unused-opaque-fixture-binary'),tfhe:'opaque-fixture',
    threads:1,fixedFFT:true,arch:'x86_64',os:'linux'};
  const input=ethers.keccak256(bytes.input),result=ethers.keccak256(bytes.result);
  const context={profile,programDigest:ethers.keccak256(bytes.program),keyDigest:ethers.keccak256(bytes.key),
    inputs:[{id:program.inputs[0].id,owner,protectedId:ethers.id('opaque-protected-record'),handle:input}]};
  const manifest={version:CANONICAL_VERSION,profile,programDigest:context.programDigest,
    serverKeyDigest:context.keyDigest,publicDecisionsReleased:0,inputs:[input],
    leaves:[{...instruction,lhsHandle:input,rhsHandle:ethers.toBeHex(1n,32),resultHandle:result}],
    terminalHandle:result,elapsedMs:0};
  await fs.writeFile(path.join(operatorDir,'manifest.json'),JSON.stringify(manifest));
  return {context,publicDir,operatorDir};
}

test('honest scheduling preserves real local-EVM phases and certificate checks with opaque fixtures',async t=>{
  const provider=await createProvider({totalAccounts:12});provider.pollingInterval=10;
  const signers=await Promise.all(Array.from({length:12},(_,i)=>signerFor(provider,i)));
  const workDir=await fs.mkdtemp(path.join(os.tmpdir(),'honest-scheduling-'));
  try {
    const fixture=await opaqueFixture(workDir,signers[8].address);
    const calls=[],waits=[];
    let stack;
    const workerRunner=async request=>{
      calls.push({mode:request.mode,taskId:request.taskId});
      const signer=new ethers.Wallet((await fs.readFile(request.identityFile,'utf8')).trim());
      const chainId=(await provider.getNetwork()).chainId;
      const contextDigest=hashJson(fixture.context);
      if(request.mode==='context') {
        const evidence={taskId:request.taskId,contextDigest};
        return {signer:signer.address,evidence,plaintextOpenings:0,
          signature:await signer.signTypedData(canonicalDomain(chainId,stack.verifier.target),CONTEXT_TYPES,evidence)};
      }
      assert.equal(request.mode,'full','this fixture must never stand in for leaf recomputation');
      const binding=await stack.game.getTaskResultBinding(request.taskId);
      const body={taskId:request.taskId,contextDigest,traceRoot:binding.operatorTraceRoot,resultHash:binding.resultHash};
      return {signer:signer.address,evidence:{index:null,replayMs:0,fixtureOnly:true},plaintextOpenings:0,
        signature:await signer.signTypedData({name:'VCFHE-Full-Execution',version:'1',chainId,
          verifyingContract:request.baseline},FULL_TYPES,body)};
    };
    stack=await createCanonicalGame({provider,signers,...fixture,workDir,binary:'unused-opaque-fixture',
      rpcUrl:'unused-local-fixture',nonlinearProtocol:'bounty-v2',windowSeconds:120,
      auditorFundingLeafCount:1,workerRunner,
      advanceSeconds:async(seconds,target)=>{
        waits.push({seconds,target});await advanceTime(provider,seconds);
      }});
    const makeTask=async label=>{
      const taskId=ethers.id(label);
      await stack.createTask(taskId,fixture.operatorDir);
      return taskId;
    };
    const finalized=async taskId=>{
      const status=await stack.game.getTaskStatus(taskId);
      assert.equal(status.status,3n);assert.equal(status.decision,1n);
      assert.equal(await stack.game.getOperatorReservation(taskId),0n);
    };

    await t.test('commit and reveal precede both baseline certificates and finalization',async()=>{
      const taskId=await makeTask('honest-schedule-order'),start=stack.txs.length;
      const deadlines=Array.from(await stack.game.getTaskDeadlines(taskId));
      let baseline,invocations=0;
      const result=await stack.acceptHonest(taskId,{duringFinalizationWait:async()=>{
        invocations++;
        const labels=stack.txs.slice(start).map(row=>row.label);
        assert.deepEqual(labels,['honestSubmitSealedAudit','honestRevealSealedAudit']);
        assert.ok(await freshChainTimestamp(provider)>Number(deadlines[0]));
        assert.ok(await freshChainTimestamp(provider)<=Number(deadlines[2]));
        await assert.rejects(stack.game.finalizeUnchallenged.staticCall(taskId),
          'the callback must not permit early finalization');
        baseline=await stack.fullExecutionBaseline(taskId);
        assert.equal(baseline.accepted,true);assert.equal(baseline.certificates.length,2);
      }});
      assert.equal(invocations,1);
      assert.deepEqual(stack.txs.slice(start).map(row=>row.label),[
        'honestSubmitSealedAudit','honestRevealSealedAudit','deploy:CanonicalExecutionBaseline',
        'acceptFullExecution','finalizeUnchallenged','honestClaimAuditBond']);
      assert.equal(calls.filter(c=>c.taskId===taskId&&c.mode==='full').length,2);
      assert.deepEqual(Array.from(await stack.game.getTaskDeadlines(taskId)),deadlines);
      assert.ok(result.finalizationWaitWork.elapsedMs>=0);
      assert.equal(result.finalizationWaitWork.challengeDeadline,Number(deadlines[2]));
      const timing=result.finalizationWaitWork;
      assert.equal(timing.commitDeadline,Number(deadlines[0]));
      assert.equal(timing.openDeadline,Number(deadlines[1]));
      assert.ok(timing.commitTimestamp<=timing.commitDeadline);
      assert.ok(timing.openTimestamp>timing.commitDeadline&&timing.openTimestamp<=timing.openDeadline);
      assert.ok(timing.startTimestamp>=timing.openTimestamp&&timing.endTimestamp>=timing.startTimestamp);
      await finalized(taskId);
    });

    await t.test('work crossing the challenge deadline neither extends it nor starts another wait',async()=>{
      const taskId=await makeTask('honest-schedule-overrun');
      const deadlines=Array.from(await stack.game.getTaskDeadlines(taskId));
      let afterCallbackWaits;
      const result=await stack.acceptHonest(taskId,{duringFinalizationWait:async()=>{
        const baseline=await stack.fullExecutionBaseline(taskId);
        assert.equal(baseline.certificates.length,2);assert.equal(baseline.accepted,true);
        const now=await freshChainTimestamp(provider);
        await advanceTime(provider,Number(deadlines[2])-now+7);
        afterCallbackWaits=waits.length;
      }});
      assert.equal(waits.length,afterCallbackWaits,'expired deadlines must not add another window');
      assert.deepEqual(Array.from(await stack.game.getTaskDeadlines(taskId)),deadlines);
      assert.ok(result.finalizationWaitWork.endTimestamp>Number(deadlines[2]));
      await finalized(taskId);
    });

    await t.test('omitting the callback retains the previous honest workflow',async()=>{
      const taskId=await makeTask('honest-schedule-no-hook'),start=stack.txs.length;
      const fullBefore=calls.filter(c=>c.mode==='full').length;
      const result=await stack.acceptHonest(taskId);
      assert.equal(result?.finalizationWaitWork,undefined);
      assert.deepEqual(stack.txs.slice(start).map(row=>row.label),[
        'honestSubmitSealedAudit','honestRevealSealedAudit','finalizeUnchallenged','honestClaimAuditBond']);
      assert.equal(calls.filter(c=>c.mode==='full').length,fullBefore);
      await finalized(taskId);
    });

    await t.test('a failed awaited callback does not finalize or release reserved collateral',async()=>{
      const taskId=await makeTask('honest-schedule-hook-failure'),start=stack.txs.length;
      await assert.rejects(stack.acceptHonest(taskId,{duringFinalizationWait:async()=>{
        assert.equal(stack.txs.at(-1).label,'honestRevealSealedAudit');
        await Promise.resolve();throw new Error('fixture baseline failed');
      }}),/fixture baseline failed/);
      assert.deepEqual(stack.txs.slice(start).map(row=>row.label),['honestSubmitSealedAudit','honestRevealSealedAudit']);
      assert.notEqual((await stack.game.getTaskStatus(taskId)).status,3n);
      assert.ok(await stack.game.getOperatorReservation(taskId)>0n);
    });
  } finally {
    provider.destroy();
    await fs.rm(workDir,{recursive:true,force:true});
  }
});
