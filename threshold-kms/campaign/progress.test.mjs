import assert from 'node:assert/strict';
import test from 'node:test';
import {createProgress} from './progress.mjs';

test('progress writes only public phase and count fields without touching stdout',()=>{
 const writes=[];const progress=createProgress('evaluation',{directory:'/reports',append:(...args)=>writes.push(args)});
 assert.equal(progress('full-case',{state:'done',caseName:'linear-acr-27-99',group:'full',current:15,total:15,
  values:[123],secret:'must-never-appear'}),true);
 assert.equal(writes[0][0],'/reports/progress-evaluation.jsonl');
 assert.deepEqual(JSON.parse(writes[0][1]),{version:1,phase:'full-case',state:'done',caseName:'linear-acr-27-99',
  group:'full',current:15,total:15});
});
test('invalid names, counts and control characters cannot become terminal output',()=>{
 const writes=[];const progress=createProgress('owner',{append:(...args)=>writes.push(args)});
 for(const options of [{caseName:'private\nvalue'},{current:3,total:2},{current:1,total:Infinity},{group:'secret'},
  {caseName:'x'.repeat(121)},{state:'\u001b[31m'}])assert.equal(progress('owner-encrypt',options),false);
 assert.equal(progress('bad\nphase'),false);assert.equal(writes.length,0);
});
test('unavailable progress log does not fail computation',()=>{
 const progress=createProgress('evaluation',{append:()=>{throw Error('read-only filesystem');}});
 assert.equal(progress('operator-execution'),false);
 assert.throws(()=>createProgress('private'),/unknown progress channel/);
});
