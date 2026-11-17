import test from 'node:test';
import assert from 'node:assert/strict';
import {ethers,ownerTransaction,waitFile,cancelPending} from './common.mjs';

const tx={type:2,to:'0x0000000000000000000000000000000000001234',chainId:46853n,
  nonce:0,value:0n,data:'0x1234',gasLimit:100000n,maxFeePerGas:100n,maxPriorityFeePerGas:1n};
test('remote owner receives all getter-backed ethers Transaction fields',async()=>{
  const source=ethers.Transaction.from(tx),wire=await ownerTransaction(source);
  assert.equal(wire.chainId,'46853');assert.equal(wire.nonce,0);assert.equal(wire.data,'0x1234');
  assert.equal(ethers.Transaction.from(wire).unsignedHash,source.unsignedHash);
  const signed=await ethers.Wallet.createRandom().signTransaction(wire);
  assert.equal(ethers.Transaction.from(signed).unsignedHash,source.unsignedHash);
});
test('remote owner serializes promised plain transaction fields',async()=>{
  const wire=await ownerTransaction({...tx,chainId:Promise.resolve(46853n)});
  assert.equal(wire.chainId,'46853');assert.equal(wire.value,'0');
});
test('remote owner rejects missing chain context before RPC',async()=>{
  await assert.rejects(ownerTransaction({data:'0x'}),/explicit chain ID/);
});
test('shutdown cancels transport waits instead of replaying a release',async()=>{
  cancelPending('unit-test');await assert.rejects(waitFile('/unread-after-cancellation'),/campaign interrupted/);
});
