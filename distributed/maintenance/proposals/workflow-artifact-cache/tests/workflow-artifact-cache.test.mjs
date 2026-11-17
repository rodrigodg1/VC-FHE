import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {existsSync} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {createRequire} from 'node:module';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {buildWorkflowArtifactCache,loadWorkflowArtifactCache} from '../workflow-artifact-cache.mjs';

const proposal=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
let distributed=proposal;
while(!existsSync(path.join(distributed,'deployment.py'))){
 const parent=path.dirname(distributed);assert.notEqual(parent,distributed,'distributed source directory not found');distributed=parent;
}
const original=await fs.readFile(path.join(distributed,'../threshold-kms/campaign/workflow-auth.mjs'),'utf8');
const hard=original.slice(original.indexOf('function hardErrors('),original.indexOf('export function compileCanonicalWorkflowArtifacts(){'));
const names=['GroupedLinearVerification','ObjectiveMicroVerifier','CanonicalBountyFHEDisputeGame',
 'BountyTraceAvailability','CanonicalFHEDisputeGame','AuthenticatedTraceAvailability','CanonicalLeafVerifier','ReleasePolicyRegistry'];
const cachePath='distributed/workflow-artifacts.json';
async function fixture(t){
 const root=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'vcfhe-workflow-cache-')));
 t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const put=async(n,s)=>{await fs.mkdir(path.dirname(path.join(root,n)),{recursive:true});await fs.writeFile(path.join(root,n),s);};
 for(const folder of ['BN254-Signatures','fhe-pod']){
  await put(folder+'/package.json','{}');await put(folder+'/package-lock.json','{}');
  await put(folder+'/node_modules/solc/package.json','{"name":"solc","main":"index.js"}');
  await put(folder+'/node_modules/solc/soljson.js','module.exports={fixture:true};');
  await put(folder+'/node_modules/solc/support.js',"module.exports=require('./nested/compiler-leaf.js');");
  await put(folder+'/node_modules/solc/nested/compiler-leaf.js','module.exports={fixture:true};');
  await put(folder+'/node_modules/solc/index.js',`require('./soljson.js');require('./support.js');module.exports={calls:0,version:()=>${JSON.stringify(folder)},compile(input,callbacks){this.calls++;require('node:fs').appendFileSync(__dirname+'/compile-calls.log','x');if(callbacks?.import){const result=callbacks.import('@fixture/dependency.sol');if(!result.contents)throw Error('fixture import missing');}const contracts={};for(const source of Object.keys(JSON.parse(input).sources)){contracts[source]={};for(const name of ${JSON.stringify(names)})contracts[source][name]={abi:[{type:'function',name:'marker',inputs:[],outputs:[]}],evm:{bytecode:{object:'6001600055'},deployedBytecode:{object:'6000'},immutableReferences:{}}};}return JSON.stringify({contracts});}};`);
 }
 for(const n of ['GroupedLinearVerification','OnChainReleasePolicy'])await put('threshold-kms/contracts/'+n+'.sol','contract '+n+' {}');
 await put('BN254-Signatures/contract/MKLHS-Verification.sol','contract MKLHS {}');
 for(const n of ['VerifiableFHEDisputeGame','CanonicalBountyFHEDisputeGame','BountyTraceAvailability','CanonicalFHEDisputeGame','AuthenticatedTraceAvailability','CanonicalLeafVerifier'])
  await put('fhe-pod/contracts/src/'+n+'.sol','contract '+n+' {}');
 await put('fhe-pod/node_modules/@fixture/dependency.sol','library Dependency {}');
 await put('threshold-kms/campaign/nonlinear-profile.mjs','export const fixture=true;');
 await put('distributed/workflow-artifact-cache.mjs',await fs.readFile(path.join(proposal,'workflow-artifact-cache.mjs')));
 const prefix=`import fs from 'node:fs/promises';import {readFileSync} from 'node:fs';import path from 'node:path';import {createRequire} from 'node:module';import {fileURLToPath} from 'node:url';const here=path.dirname(fileURLToPath(import.meta.url));const thresholdRoot=path.resolve(here,'..'),vcFheRoot=path.resolve(thresholdRoot,'..'),nonlinearProjectRoot=path.join(vcFheRoot,'fhe-pod'),nonlinearContractsDir=path.join(nonlinearProjectRoot,'contracts/src');const linearSolc=createRequire(path.join(vcFheRoot,'BN254-Signatures/package.json'))('solc'),nonlinearSolc=createRequire(path.join(vcFheRoot,'fhe-pod/package.json'))('solc');\n`;
 const cacheImport=`import {loadWorkflowArtifactCache} from ${JSON.stringify(pathToFileURL(path.join(root,'distributed/workflow-artifact-cache.mjs')).href)};`;
 const wrapper=`export function compileCanonicalWorkflowArtifacts(){return loadWorkflowArtifactCache({appRoot:vcFheRoot,compilerVersions:{linear:linearSolc.version(),nonlinear:nonlinearSolc.version()},resolveImport:resolveNonlinearSolidityImport});}`;
 await put('threshold-kms/campaign/workflow-auth.mjs',cacheImport+prefix+hard+wrapper+'\nexport {compileCanonicalWorkflowArtifactsOnce as compileWorkflowArtifactsForImageBuild,resolveNonlinearSolidityImport as resolveWorkflowCompilerImport};\n');
 const module=await import(pathToFileURL(path.join(root,'threshold-kms/campaign/workflow-auth.mjs')));
 const linear=createRequire(path.join(root,'BN254-Signatures/package.json'))('solc'),nonlinear=createRequire(path.join(root,'fhe-pod/package.json'))('solc');
 const options={appRoot:root,compilerVersions:{linear:linear.version(),nonlinear:nonlinear.version()},resolveImport:module.resolveWorkflowCompilerImport};
 return {root,put,module,linear,nonlinear,options,cache:path.join(root,cachePath)};
}

test('the exact original compiler function feeds a byte-for-byte equal cache, without runtime compilation',async t=>{
 const f=await fixture(t),report=await buildWorkflowArtifactCache(f.root);
 assert.equal(report.artifactCount,8);assert.equal(report.transitiveImportCount,1);
 assert.equal(report.freshProcessValidated,true);
 assert.equal(f.linear.calls,2);assert.equal(f.nonlinear.calls,1);
 assert.equal((await fs.readFile(path.join(f.root,'BN254-Signatures/node_modules/solc/compile-calls.log'))).length,2);
 assert.equal((await fs.readFile(path.join(f.root,'fhe-pod/node_modules/solc/compile-calls.log'))).length,1);
 const cached=await loadWorkflowArtifactCache(f.options);
 assert.equal(f.linear.calls,2);assert.equal(f.nonlinear.calls,1);
 assert.deepStrictEqual(cached,await f.module.compileWorkflowArtifactsForImageBuild());
 assert.ok(Object.isFrozen(cached));assert.ok(Object.isFrozen(cached.GroupedLinearVerification));
 const body=JSON.parse(await fs.readFile(f.cache));
 assert.ok(Object.keys(body.sourceFiles).some(n=>n.endsWith('/solc/soljson.js')));
 assert.ok(Object.keys(body.sourceFiles).some(n=>n.endsWith('/solc/index.js')));
 assert.ok(Object.keys(body.sourceFiles).some(n=>n.endsWith('/solc/nested/compiler-leaf.js')));
 assert.ok(body.sourceFiles['threshold-kms/campaign/workflow-auth.mjs']);
 assert.deepEqual(Object.keys(body.transitiveImports),['@fixture/dependency.sol']);
 assert.deepEqual(await fs.readFile(f.cache),await fs.readFile(path.join(f.root,'threshold-kms/campaign/build-evidence/workflow-artifacts.json')));
});
test('unrelated CommonJS modules loaded by a role do not change the compiler closure',async t=>{
 const f=await fixture(t),require=createRequire(path.join(f.root,'fhe-pod/package.json'));
 const before='fhe-pod/node_modules/unrelated-before-build.js';
 await f.put(before,'module.exports={unrelated:true};');require('./node_modules/unrelated-before-build.js');
 await buildWorkflowArtifactCache(f.root);
 const name='fhe-pod/node_modules/unrelated-role-module.js';
 await f.put(name,'module.exports={unrelated:true};');
 require('./node_modules/unrelated-role-module.js');
 const body=JSON.parse(await fs.readFile(f.cache));assert.equal(body.sourceFiles[name],undefined);assert.equal(body.sourceFiles[before],undefined);
 const value=await loadWorkflowArtifactCache(f.options);
 assert.equal(value.GroupedLinearVerification.contractName,'GroupedLinearVerification');
 assert.equal(f.linear.calls,2);assert.equal(f.nonlinear.calls,1);
});
test('changed or missing recursive compiler descendants still fail closed',async t=>{
 for(const change of ['mutation','missing'])await t.test(change,async t=>{
  const f=await fixture(t);await buildWorkflowArtifactCache(f.root);
  const leaf='fhe-pod/node_modules/solc/nested/compiler-leaf.js';
  if(change==='mutation')await f.put(leaf,'module.exports={changed:true};');
  else await fs.rm(path.join(f.root,leaf));
  await assert.rejects(loadWorkflowArtifactCache(f.options));
 });
});
test('missing cache fails closed and does not call a compiler',async t=>{
 const f=await fixture(t);await assert.rejects(loadWorkflowArtifactCache(f.options));
 assert.equal(f.linear.calls,0);assert.equal(f.nonlinear.calls,0);
});
test('modified Solidity, added sources and removed compiler dependencies are rejected',async t=>{
 for(const change of ['source','addition','compiler']){
  await t.test(change,async t=>{
   const f=await fixture(t);await buildWorkflowArtifactCache(f.root);
   if(change==='source')await f.put('threshold-kms/contracts/GroupedLinearVerification.sol','changed');
   if(change==='addition')await f.put('fhe-pod/contracts/src/Unexpected.sol','contract Unexpected {}');
   if(change==='compiler')await fs.rm(path.join(f.root,'BN254-Signatures/node_modules/solc/soljson.js'));
   await assert.rejects(loadWorkflowArtifactCache(f.options));
  });
 }
});
test('changed transitive import, lockfile and compiler version are rejected',async t=>{
 for(const change of ['import','lock','version']){
  await t.test(change,async t=>{
   const f=await fixture(t);await buildWorkflowArtifactCache(f.root);
   if(change==='import')await f.put('fhe-pod/node_modules/@fixture/dependency.sol','library Changed {}');
   if(change==='lock')await f.put('fhe-pod/package-lock.json','{"changed":true}');
   const options=change==='version'?{...f.options,compilerVersions:{linear:'stale',nonlinear:'stale'}}:f.options;
   await assert.rejects(loadWorkflowArtifactCache(options));
  });
 }
});
test('cache tampering, writable anchors, malformed JSON and missing seal fail closed',async t=>{
 for(const change of ['tamper','writable','malformed','seal']){
  await t.test(change,async t=>{
   const f=await fixture(t);await buildWorkflowArtifactCache(f.root);
   if(change==='seal')await fs.rm(f.cache+'.seal.json');
   else{
    await fs.chmod(f.cache,0o644);
    if(change==='tamper'){const c=JSON.parse(await fs.readFile(f.cache));c.artifacts.GroupedLinearVerification.bytecode='0x6001';await fs.writeFile(f.cache,JSON.stringify(c));}
    if(change==='malformed')await fs.writeFile(f.cache,'{');
    if(change!=='writable')await fs.chmod(f.cache,0o444);
   }
   await assert.rejects(loadWorkflowArtifactCache(f.options));
  });
 }
});
