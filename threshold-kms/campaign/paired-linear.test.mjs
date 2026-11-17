import test from 'node:test';
import assert from 'node:assert/strict';
import {prepareLinearBenchmark,groupedVectors,aggregateVectors,generators,verifyProposal,verifyBaseline,benchmarkTag} from './paired-linear.mjs';
test('paired verifiers use one encrypted fixture and independent signature domains',()=>{
 const inputs=Array.from({length:10},(_,i)=>[String(i+1),String(2*i)]);
 const domain={caseName:'linear-test',keysetDigest:'0x'+'ab'.repeat(32),chainId:'46853'};
 const signed=prepareLinearBenchmark({inputs,...domain}),vectors=groupedVectors(inputs),aggregate=aggregateVectors(vectors);
 const args={...signed,vectors,aggregate,generators:generators(18)};
 assert.equal(signed.datasetTag,benchmarkTag(domain));
 assert.equal(verifyProposal(args).accepted,true);assert.equal(verifyBaseline(args).accepted,true);
 const bad={...args,aggregate:[aggregate[0]+1n,...aggregate.slice(1)]};
 assert.throws(()=>verifyProposal(bad));assert.throws(()=>verifyBaseline(bad));
 assert.throws(()=>verifyBaseline({...args,admissions:signed.admissions.map(a=>({...a,baselineSignature:a.signature}))}));
 assert.throws(()=>verifyProposal({...args,datasetTag:benchmarkTag({...domain,caseName:'another'})}));
});
