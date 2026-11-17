import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {allowsAdversarialAgreementControl as allowed} from '../../../agreement-control-policy.mjs';
const diagnostic={smoke:true,readinessOnly:true,
 classification:'test-insecure-distributed-regional-release-diagnostic-not-evaluation',
 distributedDiagnosticProfile:'regional-output-release-v1',half:'nonlinear',parameters:'Test',records:50,repeats:1,
 windowSeconds:120,kmsRayonThreads:1,kmsTokioThreads:1,linearSizes:[],nonlinearWorkloads:['regional']};
const name='regional_qoe_compliance-0';
test('actual current guard reproduces the diagnostic rejection without FHE',()=>{
 const text=fs.readFileSync(new URL('./fixtures/original-negative-allowlist.js',import.meta.url),'utf8');
 assert.throws(()=>vm.runInNewContext(text,{config:diagnostic,b:{caseName:name},assert}));
});
test('regional controls require the complete admitted diagnostic profile',()=>{
 assert.equal(allowed(diagnostic,name),true);
 for(const field of ['smoke','readinessOnly','distributedDiagnosticProfile','classification','records','repeats','parameters','windowSeconds','kmsRayonThreads','kmsTokioThreads','linearSizes','nonlinearWorkloads']){
   const cfg=structuredClone(diagnostic);delete cfg[field];assert.equal(allowed(cfg,name),false,field);
 }
 for(const field of ['pocPlan','policyRefreshPlan','readinessDisputesOnly','keysetReuse'])assert.equal(allowed({...diagnostic,[field]:{}},name),false,field);
 assert.equal(allowed(diagnostic,'regulatory_qoe_compliance-0'),false);
});
test('existing complete and three-case smoke controls stay eligible',()=>{
 assert.equal(allowed({pocPlan:{jobs:[{name,fullCase:true,half:'nonlinear'}]}},name),true);
 for(const c of [name,'regulatory_qoe_compliance-0'])assert.equal(allowed({smoke:true,readinessOnly:true,classification:'test-insecure-distributed-smoke-not-evaluation'},c),true);
 assert.equal(allowed({},name),false);
});
test('worker still confines false controls to known fault tasks and positive opinions',()=>{
 const text=fs.readFileSync(new URL('../../../worker.mjs',import.meta.url),'utf8');
 assert.ok(text.includes('assert.equal(cfg.allowAdversarialAgreementControls,true)'));
 assert.ok(text.includes("assert.equal(b.taskId,ethers.id(b.caseName+':fault'))"));
 assert.ok(text.includes('assert.equal(b.supportsOperator,true)'));
 assert.ok(text.includes('adversarialAgreementControl:control'));
});
