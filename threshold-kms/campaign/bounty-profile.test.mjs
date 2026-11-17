import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {nonlinearProfile,nonlinearManifestProfile} from './nonlinear-profile.mjs';
import {receiptScope} from './measurement-scopes.mjs';
import {createCanonicalGame} from '../../fhe-pod/scripts/canonical-game-driver.mjs';
import {createProvider,signerFor} from '../../fhe-pod/contracts/test/chain-harness.mjs';
import {ethers} from '../../fhe-pod/scripts/evm-lib.mjs';
import {BOUNTY_TEST_ECONOMICS} from '../../fhe-pod/scripts/bounty-economics.mjs';

test('versioned manifests cannot silently select another nonlinear protocol',()=>{
 for(const name of ['canonical','bounty-v2']){
  const profile=nonlinearProfile(name);
  assert.deepEqual(nonlinearManifestProfile(profile.kind),profile);
 }
 assert.throws(()=>nonlinearProfile('latest'));
 assert.throws(()=>nonlinearManifestProfile('canonical-nonlinear-v2'));
 assert.deepEqual(nonlinearProfile().extraConstructorArgs,[]);
 assert.deepEqual(nonlinearProfile('bounty-v2').extraConstructorArgs,BOUNTY_TEST_ECONOMICS.extraConstructorArgs);
 assert.equal(nonlinearProfile('bounty-v2').economics.revision,'bounded-cost-v1');
});

test('shared campaign driver deploys bounty V2 with funded auditors and no opening committee',async()=>{
 const provider=await createProvider({totalAccounts:12});
 const signers=await Promise.all(Array.from({length:12},(_,i)=>signerFor(provider,i)));
 const workDir=await fs.mkdtemp(path.join(os.tmpdir(),'bounty-campaign-deployment-'));
 try{
  const stack=await createCanonicalGame({provider,signers,context:{profile:{fixture:true}},workDir,
   publicDir:workDir,binary:'unused-deployment-fixture',rpcUrl:'unused',advanceSeconds:async()=>{},
   nonlinearProtocol:'bounty-v2',auditorFundingLeafCount:512});
  const labels=stack.txs.map(r=>r.label);
  assert.ok(labels.includes('deploy:CanonicalBountyFHEDisputeGame'));
  assert.ok(labels.includes('deploy:BountyTraceAvailability'));
  assert.ok(!labels.includes('registerOpeningParticipant'));
  assert.equal(await stack.game.availabilityModule(),stack.availability.target);
  assert.equal(await stack.availability.RELAY_VERSION(),2n);
  assert.equal(await stack.game.OPERATOR_PENALTY_WEI(),BigInt(BOUNTY_TEST_ECONOMICS.operatorPenaltyWei));
  assert.equal(await stack.game.CHALLENGE_BOUNTY_WEI(),BigInt(BOUNTY_TEST_ECONOMICS.bountyWei));
  assert.equal(await stack.game.MAX_TRACE_LEAVES(),512n);
  assert.equal(await stack.game.ECONOMICS_VERSION(),1n);
  assert.equal(await stack.game.MAX_DISCLOSURE_FEE_WEI(),BigInt(BOUNTY_TEST_ECONOMICS.maxDisclosureFeeWei));
  assert.ok(await stack.game.getParticipantStake(signers[1].address)>=await stack.game.OPERATOR_PENALTY_WEI());
  assert.ok(labels.every(l=>receiptScope(l)));
  const required=await stack.game.DISPUTE_BOND_BASE_WEI()+9n*await stack.game.DISPUTE_BOND_PER_ROUND_WEI();
  for(const a of signers.slice(2,5))assert.ok(await stack.game.getParticipantStake(a.address)>=required);
 }finally{await fs.rm(workDir,{recursive:true});}
});
