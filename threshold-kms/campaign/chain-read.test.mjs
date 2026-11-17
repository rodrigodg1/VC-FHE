import test from 'node:test';
import assert from 'node:assert/strict';
import {readLatestBlock,waitForChainSeconds,waitForChainTimestamp} from './chain-read.mjs';
const block=(n,t)=>({number:n,timestamp:t});
test('null latest reads recover without supplying a guessed or stale block',async()=>{
 let calls=0,time=0;const retries=[],wanted=block(10,100);
 assert.equal(await readLatestBlock(async()=>++calls<3?null:wanted,{now:()=>time,sleep:async ms=>{time+=ms;},onRetry:r=>retries.push(r)}),wanted);
 assert.equal(calls,3);assert.equal(retries.length,2);
});
test('permanent absence stops at the read-attempt bound',async()=>{
 let calls=0;await assert.rejects(readLatestBlock(async()=>{calls++;return null;},{maxAttempts:3,sleep:async()=>{}}),/bounded read retries/);
 assert.equal(calls,3);
});
test('hung read has a wall-clock limit and launches no additional request',async()=>{
 let calls=0;await assert.rejects(readLatestBlock(()=>{calls++;return new Promise(()=>{});},{timeoutMs:15}),/timed out/);
 assert.equal(calls,1);
});
test('RPC errors and malformed non-null blocks are not silently retried',async()=>{
 for(const response of [undefined,{},block(1,NaN),block(-1,100),block(1,-1)]){
  let calls=0;await assert.rejects(readLatestBlock(async()=>{calls++;return response;}),/malformed/);assert.equal(calls,1);
 }
 let calls=0;const fault=new Error('transport failure');
 await assert.rejects(readLatestBlock(async()=>{calls++;throw fault;}),e=>e===fault);assert.equal(calls,1);
});
test('read retry does not change the initial real-chain target or let equality finish early',async()=>{
 let time=0,index=0;const reads=[block(1,100),null,block(2,101),block(3,105),block(4,106)];
 const read=()=>readLatestBlock(async()=>reads[index++],{now:()=>time,sleep:async ms=>{time+=ms;}});
 const result=await waitForChainSeconds(read,5,{now:()=>time,sleep:async ms=>{time+=ms;}});
 assert.deepEqual(result,{startBlock:1,targetTimestamp:105,observedBlock:4,observedTimestamp:106});assert.equal(index,5);
});
test('stalled and regressed chains fail closed without extending a target',async()=>{
 let time=0;await assert.rejects(waitForChainSeconds(async()=>block(1,100),5,
  {stallTimeoutMs:2000,now:()=>time,sleep:async ms=>{time+=ms;}}),/stalled/);
 let calls=0;await assert.rejects(waitForChainSeconds(async()=>++calls===1?block(3,100):block(2,99),5),/regressed/);
});
test('invalid read and wait budgets are rejected',async()=>{
 for(const options of [{maxAttempts:0},{timeoutMs:0},{retryDelayMs:-1}])await assert.rejects(readLatestBlock(async()=>block(1,1),options),/invalid/);
 for(const seconds of [-1,NaN,1.2])await assert.rejects(waitForChainSeconds(async()=>block(1,1),seconds),/invalid/);
});
test('absolute wait does not slide its target when a block intervenes',async()=>{
 const blocks=[block(7,107),block(8,115),block(9,121)];let reads=0,time=0;
 const result=await waitForChainTimestamp(async()=>blocks[Math.min(reads++,blocks.length-1)],121,
  {pollMs:1,now:()=>time,sleep:async ms=>{time+=ms;}});
 assert.deepEqual(result,{startBlock:7,targetTimestamp:121,observedBlock:9,observedTimestamp:121});
 assert.equal(reads,3);
});
test('absolute wait returns at the exact phase boundary and validates its target',async()=>{
 const result=await waitForChainTimestamp(async()=>block(12,241),241);
 assert.deepEqual(result,{startBlock:12,targetTimestamp:241,observedBlock:12,observedTimestamp:241});
 for(const target of [-1,NaN,1.2])await assert.rejects(
  waitForChainTimestamp(async()=>block(1,1),target),/invalid absolute chain wait limits/);
});
