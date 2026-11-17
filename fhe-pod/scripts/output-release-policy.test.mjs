import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ethers } from "ethers";
import { OutputReleasePolicy } from "./output-release-policy.mjs";
import { hashJson } from "./canonical-protocol.mjs";
const sign = (w, body) => w.signMessage(ethers.getBytes(hashJson(body)));
async function fixture({ limit = 1, failingKms = false } = {}) {
  const owner = ethers.Wallet.createRandom(), other = ethers.Wallet.createRandom(), recipient = ethers.Wallet.createRandom();
  const domain = "test-release-domain", recordIds = [ethers.id("record-a"), ethers.id("record-b")];
  let calls = 0, finalized = true, selectedIds = recordIds, resultValue = "0", selectedProgram = ethers.id("program");
  const ledgerFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "tops-policy-")), "ledger.json");
  const make = () => new OutputReleasePolicy({ ledgerFile, domain,
    resolveFinalized: async r => finalized ? { contextDigest: r.contextDigest, outputDigest: ethers.id("output"),
      programDigest: selectedProgram, outputType: "bool", recordIds: selectedIds,
      recordOwners: { [recordIds[0]]: owner.address.toLowerCase(), [recordIds[1]]: other.address.toLowerCase() } } : null,
    kms: { decryptAuthorized: async () => { calls++; if (failingKms) throw new Error("simulated quorum unavailable"); return { value: resultValue }; } } });
  const service = make();
  for (const [i, w] of [owner, other].entries()) {
    const record = { id: recordIds[i], owner: w.address, releaseLimit: limit };
    await service.registerProtectedRecord(record, await sign(w, { kind: "protected-record-v1", domain, ...record }));
  }
  const consent = { kind: "final-output-consent-v1", domain, slot: ethers.id("slot"),
    contextDigest: ethers.id("context"), programDigest: ethers.id("program"), keyEpoch: "epoch-1",
    game: ethers.Wallet.createRandom().address, chainId: "31337", recordIds,
    outputType: "bool", recipients: [recipient.address] };
  const approve = async c => service.registerConsent(c, Object.fromEntries(await Promise.all([owner, other].map(async w => [w.address.toLowerCase(), await sign(w, c)]))));
  const consentId = await approve(consent);
  const request = { kind: "final-output-release-v1", domain, requestId: ethers.id("request"),
    taskId: ethers.id("task"), slot: consent.slot, consentId, contextDigest: consent.contextDigest,
    keyEpoch: consent.keyEpoch, game: consent.game, chainId: consent.chainId,
    outputDigest: ethers.id("output"), recipient: recipient.address };
  return { service, make, consent, request, approve, recipient, owner, other, domain, recordIds,
    calls: () => calls, finalize: value => { finalized = value; }, select: value => { selectedIds = value; }, result: value => { resultValue = value; }, program: value => { selectedProgram = value; },
    release: async (r = request, s = service) => s.release(r, await sign(recipient, r)) };
}
test("only finalized owner-approved exact outputs reach the KMS", async () => {
  const f = await fixture(); f.finalize(false);
  await assert.rejects(f.release(), /finalized/); assert.equal(f.calls(), 0);
  f.finalize(true); assert.deepEqual(await f.release(), { value: "0" }); assert.equal(f.calls(), 1);
  await assert.rejects(f.release(undefined, f.make()), /consumed/); assert.equal(f.calls(), 1);
});
test("authorized adaptive outputs retain their ordinary inference power; forbidden leaf queries add none", async () => {
  // Policy-unit experiment: finality and the permitted Boolean computation are
  // mocked. Real encrypted compliance release is covered by the integration.
  let baselineCorrect=0, policyCorrect=0, forbiddenOpenings=0;
  for (let secret=1;secret<=5;secret++) {
    const f=await fixture({limit:3});let lo=1,hi=5,baselineLo=1,baselineHi=5,query=0;
    while(lo<hi) {
      const mid=Math.floor((lo+hi)/2),bit=secret>mid?1:0;
      const c={...f.consent,slot:ethers.id(`authorized-${secret}-${query}`),contextDigest:ethers.id(`approved-threshold-${mid}`),programDigest:ethers.id(`GT(input,${mid})`)};
      f.program(c.programDigest);
      const consentId=await f.approve(c);
      const r={...f.request,slot:c.slot,contextDigest:c.contextDigest,consentId,
        requestId:ethers.id(`request-${secret}-${query}`),taskId:ethers.id(`task-${secret}-${query}`)};
      const calls=f.calls();await assert.rejects(f.release({...r,kind:'leaf-equality'}));
      forbiddenOpenings+=f.calls()-calls;
      f.result(String(bit));const response=await f.release(r);
      if(response.value==='1')lo=mid+1;else hi=mid;
      const bmid=Math.floor((baselineLo+baselineHi)/2);
      if(secret>bmid)baselineLo=bmid+1;else baselineHi=bmid;
      query++;
    }
    assert.ok(query<=3);assert.equal(f.calls(),query);
    policyCorrect+=Number(lo===secret);baselineCorrect+=Number(baselineLo===secret);
  }
  assert.equal(policyCorrect,5);assert.equal(baselineCorrect,5);assert.equal(forbiddenOpenings,0);
});
test("verdicts, leaf predicates, output aliases and identity/context changes produce no KMS call", async () => {
  const f = await fixture();
  for (const change of [{ kind: "leaf-equality" }, { kind: "audit-verdict" },
    { outputDigest: ethers.id("derived-predicate") }, { contextDigest: ethers.id("context-2") },
    { keyEpoch: "epoch-2" }, { game: f.owner.address }, { chainId: "999" },
    { recipient: f.owner.address }, { consentId: ethers.id("another-policy") }]) {
    await assert.rejects(f.release({ ...f.request, ...change }));
  }
  assert.equal(f.calls(), 0);
});
test("overlap, fresh consent names and re-encryption/epoch changes cannot reset a record budget", async () => {
  const f = await fixture(); await f.release();
  const c = { ...f.consent, slot: ethers.id("new-slot"), contextDigest: ethers.id("reencryption"), keyEpoch: "epoch-2" };
  const consentId = await f.approve(c);
  await assert.rejects(f.release({ ...f.request, slot: c.slot, consentId, contextDigest: c.contextDigest,
    keyEpoch: c.keyEpoch, taskId: ethers.id("new-task"), requestId: ethers.id("new-request") }), /budget exhausted/);
  assert.equal(f.calls(), 1);
  const record = { id: f.recordIds[0], owner: f.owner.address, releaseLimit: 99 };
  await assert.rejects(f.service.registerProtectedRecord(record, await sign(f.owner,
    { kind: "protected-record-v1", domain: f.domain, ...record })), /already registered/);
});
test("every protected record owner must approve; requester consent cannot substitute", async () => {
  const f = await fixture(); const c = { ...f.consent, slot: ethers.id("unapproved") };
  await assert.rejects(f.service.registerConsent(c, { [f.owner.address.toLowerCase()]: await sign(f.owner, c) }));
  assert.equal(f.calls(), 0);
});
test("an approved overlapping subset consumes the original record's cumulative budget", async () => {
  const f = await fixture(); await f.release(); f.select([f.recordIds[0]]);
  const c = { ...f.consent, slot: ethers.id("overlapping-subset"), recordIds: [f.recordIds[0]] };
  const consentId = await f.approve(c);
  await assert.rejects(f.release({ ...f.request, slot: c.slot, consentId,
    taskId: ethers.id("subset-task"), requestId: ethers.id("subset-request") }), /budget exhausted/);
  assert.equal(f.calls(), 1);
});
test("failed KMS attempts retain their reservation across process restart", async () => {
  const f = await fixture({ failingKms: true });
  await assert.rejects(f.release(), /quorum unavailable/);
  await assert.rejects(f.release(undefined, f.make()), /consumed/);
  assert.equal(f.calls(), 1); assert.equal(f.service.inspectLedger().consumed[f.consent.slot].state, "reserved");
});
test("concurrent requests cannot double-spend the same output slot", async () => {
  const f = await fixture();
  const results = await Promise.allSettled([f.release(), f.release()]);
  assert.equal(results.filter(r => r.status === "fulfilled").length, 1); assert.equal(f.calls(), 1);
});
