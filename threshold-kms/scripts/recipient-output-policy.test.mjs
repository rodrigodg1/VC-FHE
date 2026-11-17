// Policy component tests use a stub decoder/transport, not threshold-FHE evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createRequire} from 'node:module';
import {RecipientOutputPolicy,policyHash} from './recipient-output-policy.mjs';
const require = createRequire(new URL('../../BN254-Signatures/package.json',import.meta.url));
const {ethers} = require('ethers');
const owners = [1,2].map(n => new ethers.Wallet('0x'+String(n).padStart(64,'0')));
const recipient = new ethers.Wallet('0x'+'3'.padStart(64,'0'));
const sign = (wallet,body) => wallet.signMessage(ethers.getBytes(policyHash(body)));
async function fixture(t,{autoConsent=true}={}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(),'tops-recipient-policy-'));
  t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
  const file = path.join(directory,'ledger.json'), domain=ethers.id('policy-fixture');
  const records = owners.map((o,i)=>({kind:'kms-protected-record-v2',domain,id:ethers.id(`record-${i}`),owner:o.address,releaseLimit:1}));
  const consent = {kind:'kms-final-consent-v2',domain,slot:ethers.id('slot'),chainId:'31337',game:owners[0].address,
    contextDigest:ethers.id('context'),programDigest:ethers.id('program'),keyId:ethers.id('key'),keyEpoch:ethers.id('epoch'),
    keysetDigest:ethers.id('keyset'),mpcContext:ethers.id('mpc'),profileDigest:ethers.id('profile'),outputType:'uint16',recordIds:records.map(r=>r.id),recipients:[recipient.address]};
  const wire=Uint8Array.from([1,2,3]), expectedWire=Uint8Array.from(wire);
  const request = {kind:'kms-recipient-release-v2',domain,slot:consent.slot,consentId:policyHash(consent),
    ...Object.fromEntries(['chainId','game','contextDigest','programDigest','keyId','keyEpoch','profileDigest','keysetDigest','mpcContext'].map(k=>[k,consent[k]])),
    requestId:ethers.id('request'),taskId:ethers.id('task'),aggregateDigest:ethers.id('aggregate'),outputDigest:ethers.id('output'),
    outputType:'uint16',recipient:recipient.address,encKeyDigest:ethers.id('ephemeral-key'),kmsRequestDigest:ethers.keccak256(wire)};
  const state={calls:0,decoded:{...request,ciphertextCount:1},final:{...request,recordIds:consent.recordIds,
    recordOwners:Object.fromEntries(records.map(r=>[r.id,r.owner]))},response:Uint8Array.from([4,5]),fail:false};
  const options={ledgerFile:file,domain,inspectRequest:async()=>structuredClone(state.decoded),
    resolveFinalized:async()=>structuredClone(state.final),submitUserDecrypt:async bytes=>{
      state.calls++;
      const ledger=JSON.parse(fs.readFileSync(file,'utf8'));
      assert.equal(ledger.slots[request.slot].state,'reserved');
      for(const r of records)assert.equal(ledger.records[r.id].spent,1);
      assert.deepEqual(bytes,expectedWire);
      if(state.fail)throw Error('stub core unavailable');
      return state.response;
    }};
  const policy=new RecipientOutputPolicy(options);
  for(let i=0;i<records.length;i++)await policy.registerRecord(records[i],await sign(owners[i],records[i]));
  const signatures=Object.fromEntries(await Promise.all(owners.map(async o=>[o.address.toLowerCase(),await sign(o,consent)])));
  if(autoConsent)await policy.registerConsent(consent,signatures);
  return {file,options,policy,state,request,consent,records,signatures,wire,
    release:async(r=request,bytes=wire)=>policy.release(r,await sign(recipient,r),bytes)};
}

test('recipient response follows durable reservation; replay remains consumed after restart',async t=>{
  const f=await fixture(t);assert.deepEqual(await f.release(),f.state.response);assert.equal(f.state.calls,1);
  const restarted=new RecipientOutputPolicy(f.options);
  await assert.rejects(restarted.release(f.request,await sign(recipient,f.request),f.wire),/consumed/);
  assert.equal(f.state.calls,1);
});
test('all owners must authorize the output',async t=>{
  const f=await fixture(t,{autoConsent:false});delete f.signatures[owners[1].address.toLowerCase()];
  await assert.rejects(f.policy.registerConsent(f.consent,f.signatures));assert.equal(f.state.calls,0);
  await assert.rejects(f.release(),/consent/);
});
test('chosen wire bytes cannot replace the signed request',async t=>{
  const f=await fixture(t);await assert.rejects(f.release(f.request,Uint8Array.from([7])),/invalid recipient request/);assert.equal(f.state.calls,0);
});
for(const field of ['recipient','encKeyDigest','keyId','keyEpoch','outputDigest','aggregateDigest','taskId','programDigest','profileDigest','contextDigest','keysetDigest','mpcContext','slot','consentId']) {
  test(`wire substitution of ${field} rejects before contacting cores`,async t=>{
    const f=await fixture(t);f.state.decoded[field]=field==='recipient'?owners[0].address:ethers.id('substitution');
    await assert.rejects(f.release(),/wire request/);assert.equal(f.state.calls,0);
    assert.equal(f.policy.inspectLedger().records[f.records[0].id].spent,0);
  });
}
test('multiple ciphertexts/subtotals cannot share a terminal slot',async t=>{
  const f=await fixture(t);f.state.decoded.ciphertextCount=2;await assert.rejects(f.release(),/wire request/);assert.equal(f.state.calls,0);
});
test('caller-supplied acceptance cannot override a missing finalized conversion',async t=>{
  const f=await fixture(t);f.state.final=null;
  await assert.rejects(f.release({...f.request,accepted:true}),/unexpected policy fields/);
  await assert.rejects(f.release(),/finalized conversion/);assert.equal(f.state.calls,0);
});
test('a different conversion cannot replace the authenticated aggregate',async t=>{
  const f=await fixture(t);f.state.final.aggregateDigest=ethers.id('other aggregate');
  await assert.rejects(f.release(),/finalized conversion/);assert.equal(f.state.calls,0);
});
test('core failure burns the slot and cumulative record budget across tasks and key epochs',async t=>{
  const f=await fixture(t);f.state.fail=true;await assert.rejects(f.release(),/unavailable/);
  assert.equal(f.policy.inspectLedger().slots[f.request.slot].state,'reserved');
  const next={...f.consent,slot:ethers.id('next-slot'),keyEpoch:ethers.id('next-epoch')};
  const signatures=Object.fromEntries(await Promise.all(owners.map(async o=>[o.address.toLowerCase(),await sign(o,next)])));
  await f.policy.registerConsent(next,signatures);
  const request={...f.request,slot:next.slot,consentId:policyHash(next),keyEpoch:next.keyEpoch,taskId:ethers.id('next-task'),requestId:ethers.id('next-request')};
  f.state.decoded={...request,ciphertextCount:1};f.state.final={...f.state.final,...request};
  await assert.rejects(f.release(request),/budget exhausted/);assert.equal(f.state.calls,1);
});
test('plaintext-valued callback is not the recipient transport interface',async t=>{
  const f=await fixture(t);f.state.response={value:'42'};
  await assert.rejects(f.release(),/opaque recipient-encrypted/);assert.equal(f.state.calls,1);
  await assert.rejects(f.release(),/consumed/);
});
test('mutating the caller request during resolution cannot alter the reserved transport',async t=>{
  const f=await fixture(t);const gate=new RecipientOutputPolicy({...f.options,resolveFinalized:async()=>{
    f.request.outputDigest=ethers.id('changed after signature');f.wire[0]=99;return f.state.final;
  }});
  assert.deepEqual(await gate.release(f.request,await sign(recipient,f.request),f.wire),f.state.response);
  assert.equal(f.state.calls,1);
});
test('concurrent policy instances cannot spend the same slot twice',async t=>{
  const f=await fixture(t), other=new RecipientOutputPolicy(f.options), signature=await sign(recipient,f.request);
  const outcomes=await Promise.allSettled([f.policy.release(f.request,signature,f.wire),other.release(f.request,signature,f.wire)]);
  assert.equal(outcomes.filter(r=>r.status==='fulfilled').length,1);assert.equal(f.state.calls,1);
});
test('malformed persisted counters fail closed',async t=>{
  const f=await fixture(t), ledger=f.policy.inspectLedger();ledger.records[f.records[0].id].spent=null;
  fs.writeFileSync(f.file,JSON.stringify(ledger));await assert.rejects(f.release(),/durable record counter/);assert.equal(f.state.calls,0);
});
