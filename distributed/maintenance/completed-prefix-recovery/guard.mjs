import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
const sha=b=>createHash('sha256').update(b).digest('hex');
export async function verifyContinuation(cfg,prepared){
 const m=JSON.parse(await fs.readFile('/continuation/manifest.json','utf8'));
 assert.equal(m.profile,'distributed-completed-prefix-continuation-v1');
 assert.equal(cfg.workflowContinuation.profile,m.profile);
 const {runId,workflowContinuation,...current}=cfg;
 const {runId:parentId,workflowContinuation:oldContinuation,...parent}=m.parentConfiguration;
 assert.deepEqual(current,parent);assert.notEqual(runId,parentId);
 assert.deepEqual(workflowContinuation.completedCases,m.completedCases);
 assert.deepEqual(workflowContinuation.fullCases,m.fullCases);
 assert.equal(m.completedCases.length,10);assert.equal(m.fullCases.length,17);
 assert.ok(m.fullCases.every(n=>!m.completedCases.includes(n)));
 assert.deepEqual(prepared.cases.map(c=>c.name),m.fullCases);
 assert.ok(prepared.cases.every(c=>c.fullCase&&c.half==='nonlinear'));
 assert.deepEqual(prepared.keys,m.keyset);
 const pairs=await fs.readFile('/reports/paired.json');assert.equal(sha(pairs),m.pairedSha256);
 const p=JSON.parse(pairs);assert.equal(p.status,'passed');assert.equal(p.rows.length,498);
 assert.equal(p.rows.filter(r=>!r.warmup).length,480);assert.equal(p.rows.filter(r=>r.warmup).length,18);
 assert.equal(p.designSha256,cfg.pocPlan.designSha256);
 assert.equal(sha(await fs.readFile('/reports/distributed/byte-repeatability.json')),m.repeatabilitySha256);
 assert.deepEqual(await fs.readdir('/exchange'),[],'Old recipient requests must never enter the continuation');
 const proof=await fs.readFile('/continuation/prefix-validation.json');
 assert.equal(sha(proof),m.prefixValidationSha256);
 assert.equal(JSON.parse(proof).status,'validated-completed-prefix-only');
 await fs.writeFile('/reports/workflow-continuation-gate.json',JSON.stringify({profile:m.profile,
  status:'passed',completedPreserved:10,pendingWorkflows:17,comparisonsReused:480,warmupsReused:18,
  sourcePrefixValidation:m.prefixValidationSha256,analysisComplete:false}),{flag:'wx'});
}
