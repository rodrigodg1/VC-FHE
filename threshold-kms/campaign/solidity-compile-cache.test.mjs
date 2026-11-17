import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {createRequire} from 'node:module';
import {createSolidityCompileCache} from './solidity-compile-cache.mjs';

const require=createRequire(new URL('../../BN254-Signatures/package.json',import.meta.url));
const solc=require('solc');
const input=()=>({language:'Solidity',sources:{'A.sol':{content:'pragma solidity ^0.8.20; contract A {}'}},
 settings:{optimizer:{enabled:false},evmVersion:'london',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}});
function fixture(){
 let calls=0,version='test-v1',result=JSON.stringify({contracts:{'A.sol':{A:{abi:[],evm:{bytecode:{object:'1234'}}}}}});
 const compiler={version:()=>version,compile:()=>{calls++;if(result instanceof Error)throw result;return result;}};
 return {compile:createSolidityCompileCache(compiler),get calls(){return calls;},
  version:value=>{version=value;},result:value=>{result=value;}};
}

test('identical source, settings and compiler version reuse one compilation',()=>{
 const f=fixture();assert.deepEqual(f.compile(input()),f.compile(input()));assert.equal(f.calls,1);
});

test('source, configuration and compiler version changes force compilation',()=>{
 const f=fixture(),source=input();f.compile(source);
 source.sources['A.sol'].content+='\n// changed source';f.compile(source);assert.equal(f.calls,2);
 source.settings.optimizer.enabled=true;f.compile(source);assert.equal(f.calls,3);
 f.version('test-v2');f.compile(source);assert.equal(f.calls,4);
});

test('mutating a returned ABI or bytecode cannot poison later deployments',()=>{
 const f=fixture(),first=f.compile(input());
 first.contracts['A.sol'].A.abi.push({type:'constructor'});
 first.contracts['A.sol'].A.evm.bytecode.object='ffff';
 const next=f.compile(input());assert.deepEqual(next.contracts['A.sol'].A.abi,[]);
 assert.equal(next.contracts['A.sol'].A.evm.bytecode.object,'1234');assert.equal(f.calls,1);
 next.contracts={};assert.ok(f.compile(input()).contracts['A.sol']);assert.equal(f.calls,1);
});

for(const [label,failure] of [['compiler exception',Error('compile failed')],['invalid JSON','not JSON'],
 ['Solidity error',JSON.stringify({errors:[{severity:'error',formattedMessage:'rejected source'}]})]]){
 test(`${label} is not cached and a retry recompiles`,()=>{
  const f=fixture();f.result(failure);assert.throws(()=>f.compile(input()));assert.throws(()=>f.compile(input()));
  assert.equal(f.calls,2);f.result(JSON.stringify({contracts:{}}));assert.deepEqual(f.compile(input()),{contracts:{}});
  assert.equal(f.calls,3);f.compile(input());assert.equal(f.calls,3);
 });
}

test('URL sources cannot introduce unkeyed import or filesystem dependencies',()=>{
 const f=fixture(),source=input();delete source.sources['A.sol'].content;source.sources['A.sol'].urls=['A.sol'];
 assert.throws(()=>f.compile(source),/inline source contents/);assert.equal(f.calls,0);
});

test('real production compiler produces exactly the fresh linear ABI and bytecode',async()=>{
 const sources={};
 for(const [name,url] of [
  ['GroupedLinearVerification.sol',new URL('../contracts/GroupedLinearVerification.sol',import.meta.url)],
  ['MKLHS-Verification.sol',new URL('../../BN254-Signatures/contract/MKLHS-Verification.sol',import.meta.url)]
 ])sources[name]={content:await fs.readFile(url,'utf8')};
 const source={...input(),sources};let calls=0;
 const cached=createSolidityCompileCache({version:()=>solc.version(),compile:encoded=>{calls++;return solc.compile(encoded);}});
 const fresh=JSON.parse(solc.compile(JSON.stringify(source)));
 assert.deepEqual((fresh.errors??[]).filter(error=>error.severity==='error'),[]);
 const first=cached(source),second=cached(structuredClone(source));
 assert.deepEqual(first,fresh);assert.deepEqual(second,fresh);assert.equal(calls,1);
 const expected=fresh.contracts['GroupedLinearVerification.sol'].GroupedLinearVerification;
 assert.ok(expected.evm.bytecode.object.length>0);assert.ok(expected.abi.length>0);
 assert.match(solc.version(),/^0\.8\.20\+/);
});

test('linear runner still rereads sources and deploys before unchanged admission timing',async()=>{
 const source=await fs.readFile(new URL('./linear.mjs',import.meta.url),'utf8');
 const body=source.slice(source.indexOf('export async function linear('));
 const reread=body.indexOf("content:await fs.readFile(file,'utf8')");
 const compile=body.indexOf('compileLinearContracts('),deploy=body.indexOf('new ethers.ContractFactory(');
 const timer=body.indexOf('const prepareStart=performance.now()');
 assert.ok(reread>=0&&compile>reread&&deploy>compile&&timer>deploy);
});
