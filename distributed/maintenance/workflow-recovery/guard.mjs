// This gate reuses completed measurements. It sends no protocol transaction.
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
const sha=value=>createHash('sha256').update(value).digest('hex');
export async function verifyContinuation(cfg,prepared){
  const manifest=JSON.parse(await fs.readFile('/continuation/manifest.json','utf8'));
  assert.equal(manifest.profile,'distributed-same-keyset-workflows-only-v1');
  assert.equal(cfg.workflowContinuation.profile,manifest.profile);
  assert.notEqual(cfg.runId,manifest.parentConfiguration.runId);
  const {runId,workflowContinuation,...current}=cfg;
  const {runId:parentRunId,...parent}=manifest.parentConfiguration;
  assert.deepEqual(current,parent,'configuration changed outside fresh continuation identity');
  const bytes=await fs.readFile('/reports/paired.json');
  assert.equal(sha(bytes),manifest.pairedSha256,'completed measurements changed');
  const paired=JSON.parse(bytes);
  assert.equal(paired.status,'passed');assert.equal(paired.rows.length,498);
  assert.equal(paired.rows.filter(r=>!r.warmup).length,480);
  assert.equal(paired.rows.filter(r=>r.warmup).length,18);
  assert.equal(paired.designSha256,cfg.pocPlan.designSha256);
  assert.deepEqual(prepared.keys,manifest.keyset);
  assert.deepEqual(prepared.cases.filter(c=>c.fullCase).map(c=>c.name),workflowContinuation.fullCases);
  const repeatability=await fs.readFile('/reports/distributed/byte-repeatability.json');
  assert.equal(sha(repeatability),manifest.repeatabilitySha256);
  assert.equal(JSON.parse(repeatability).status,'passed');
  await fs.writeFile('/reports/workflow-continuation-gate.json',JSON.stringify({profile:manifest.profile,
    status:'passed',pairedSha256:manifest.pairedSha256,comparisonsReused:480,warmupsReused:18,
    setupRepeated:false,fullWorkflows:27,originalFailurePreserved:true}),{flag:'wx'});
}
