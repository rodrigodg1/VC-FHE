import test from "node:test";
import assert from "node:assert/strict";
import { SimulatedOutputKms } from "./simulated-output-kms.mjs";
test("local KMS simulation admits an authorized response with one missing party", async () => {
  let calls=0;
  const kms=new SimulatedOutputKms({decryptExact:async()=>{calls++;return {value:"1"};},faults:{3:"missing"}});
  const result=await kms.decryptAuthorized({kind:"final-output-release-v1"});
  assert.equal(result.value,"1");assert.equal(calls,1);assert.equal(kms.auditLog()[0].approvals,3);
});
test("insufficient, duplicate, malformed or misbound simulated approvals never decrypt", async () => {
  for(const faults of [{2:"missing",3:"missing"},{1:"duplicate",2:"duplicate"},
    {1:"malformed",2:"malformed"},{1:"wrong-output",2:"wrong-output"}]) {
    let calls=0;const kms=new SimulatedOutputKms({decryptExact:async()=>{calls++;},faults});
    await assert.rejects(kms.decryptAuthorized({kind:"final-output-release-v1"}),/unavailable/);
    assert.equal(calls,0);
  }
});
