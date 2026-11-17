import test from 'node:test';
import assert from 'node:assert/strict';
import {measureLinearCommunication,experimentalCompactSumEncode,experimentalCompactSumDecode} from './linear-communication.mjs';

const MAX=(1n<<64n)-1n,FR=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
function fixture(n=5,width=8,op='SUM',value=MAX){
 const inputs=Array.from({length:n},()=>Array(width).fill(value)),sum=Array(width*9).fill(0n);
 for(let i=0;i<n;i++){
  const group=op==='SUM'?Math.floor(i/4):i===0?0:1+Math.floor((i-1)/4),sign=op==='SUB'&&i>0?-1n:1n;
  for(let j=0;j<width;j++)sum[group*width+j]+=sign*inputs[i][j];
 }
 const canonicalAggregate=Buffer.concat(sum.map(x=>Buffer.from(((x%FR+FR)%FR).toString(16).padStart(64,'0'),'hex')));
 return {inputs,canonicalAggregate,op,kmsWitnessBytes:123};
}

for(const [n,inputBytes,compactBytes] of [[10,164480,55512],[16,263168,74016],[27,444096,129528]]){
 test(`Test-profile byte counts use a reconstruction baseline and retain losing regimes at n=${n}`,()=>{
  const f=fixture(n,8*257),r=measureLinearCommunication(f);
  assert.equal(r.observed.canonicalAggregateBytes,592128);
  assert.equal(r.sizeModel.packedInputPayloadBytes,inputBytes);
  assert.equal(r.coldInputCache.baselineAdditionalAggregatePayloadBytes,0);
  assert.ok(r.coldInputCache.proposedReductionFraction<0);
  assert.equal(r.compactSum.encodedBytes,compactBytes);
  assert.equal(r.compactSum.coldInputCache.proposedReductionFraction,(inputBytes-compactBytes)/inputBytes);
  assert.equal(r.compactSum.roundTripCanonicalBytesEqual,true);
  assert.equal(r.networkTransferMeasured,false);
  assert.equal(r.cryptographicOrFheValidationPerformed,false);
  assert.equal(r.observed.kmsInputWitnessSerializedBytes,123);
  assert.equal(r.warmAuthenticatedInputAndAggregateCache.proposedAggregatePayloadBytes,0);
  assert.equal(r.warmAuthenticatedInputAndAggregateCache.baselineInputPayloadBytes,0);
 });
}

test('experimental SUM packing preserves carries above 64 bits and all public zero groups',()=>{
 const f=fixture(),args={inputCount:5,coordinateWidth:8};
 const packed=experimentalCompactSumEncode(f.canonicalAggregate,args);
 assert.equal(packed.length,2*8*9);
 assert.equal(BigInt('0x'+packed.subarray(0,9).toString('hex')),4n*MAX);
 assert.equal(BigInt('0x'+packed.subarray(8*9,9*9).toString('hex')),MAX);
 assert.deepEqual(experimentalCompactSumDecode(packed,args),f.canonicalAggregate);
});

test('one input and the 33-input limit have exact partial-group capacity',()=>{
 for(const n of [1,33]){
  const f=fixture(n),args={inputCount:n,coordinateWidth:8};
  const packed=experimentalCompactSumEncode(f.canonicalAggregate,args);
  assert.equal(packed.length,Math.ceil(n/4)*8*9);
  assert.deepEqual(experimentalCompactSumDecode(packed,args),f.canonicalAggregate);
 }
});

test('SUB canonical accounting does not claim that the SUM experiment supports negative groups',()=>{
 const f=fixture(6,8,'SUB'),r=measureLinearCommunication(f);
 assert.equal(r.operation,'SUB');assert.equal(r.compactSum.available,false);
 assert.match(r.compactSum.reason,/SUM, not SUB/);
 assert.throws(()=>experimentalCompactSumEncode(f.canonicalAggregate,{inputCount:6,coordinateWidth:8,op:'SUB'}),/SUM only/);
});

test('malformed input counts and grouped dimensions are rejected',()=>{
 const f=fixture();
 for(const inputs of [[],Array(34).fill(Array(8).fill(1n)),[[]],[[1n]],[[1n,2n],[1n]],null])
  assert.throws(()=>measureLinearCommunication({...f,inputs}));
 assert.throws(()=>experimentalCompactSumDecode(Buffer.alloc(0),{inputCount:0,coordinateWidth:8}),/input count/);
 assert.throws(()=>experimentalCompactSumDecode(Buffer.alloc(0),{inputCount:1,coordinateWidth:7}),/eight-block/);
 assert.throws(()=>measureLinearCommunication({...f,op:'MUL'}),/unsupported/);
});

test('coordinates must be exact uint64 integers',()=>{
 for(const invalid of [-1n,1n<<64n,1.5,Number.MAX_SAFE_INTEGER+1,'1e3','-1',{},null]){
  const f=fixture();f.inputs[0][0]=invalid;
  assert.throws(()=>measureLinearCommunication(f));
 }
 const f=fixture(1,8,'SUM',1n);f.inputs[0]=f.inputs[0].map(String);
 assert.equal(measureLinearCommunication(f).sizeModel.packedInputPayloadBytes,64);
});

test('truncated, oversized, noncanonical and inconsistent aggregate bytes are rejected',()=>{
 const f=fixture();
 for(const canonicalAggregate of [f.canonicalAggregate.subarray(1),Buffer.concat([f.canonicalAggregate,Buffer.alloc(32)])])
  assert.throws(()=>measureLinearCommunication({...f,canonicalAggregate}),/length/);
 const badField=Buffer.from(f.canonicalAggregate);Buffer.from(FR.toString(16).padStart(64,'0'),'hex').copy(badField);
 assert.throws(()=>measureLinearCommunication({...f,canonicalAggregate:badField}),/noncanonical/);
 const altered=Buffer.from(f.canonicalAggregate);altered[31]^=1;
 assert.throws(()=>measureLinearCommunication({...f,canonicalAggregate:altered}),/differ/);
 const unused=Buffer.from(f.canonicalAggregate);unused[unused.length-1]=1;
 assert.throws(()=>experimentalCompactSumEncode(unused,{inputCount:5,coordinateWidth:8}),/public group bound/);
});

test('compact decoder rejects extra/truncated data and values beyond actual group size',()=>{
 const f=fixture(),args={inputCount:5,coordinateWidth:8};
 const packed=experimentalCompactSumEncode(f.canonicalAggregate,args);
 for(const bytes of [packed.subarray(1),Buffer.concat([packed,Buffer.alloc(9)])])
  assert.throws(()=>experimentalCompactSumDecode(bytes,args),/length/);
 const tooLarge=Buffer.from(packed);tooLarge.fill(255,0,9);
 assert.throws(()=>experimentalCompactSumDecode(tooLarge,args),/public group bound/);
 const lastGroup=Buffer.from(packed);lastGroup[8*9]=1;
 assert.throws(()=>experimentalCompactSumDecode(lastGroup,args),/public group bound/);
});

test('measurement is JSON-safe, nonmutating and preserves absent witness information',()=>{
 const f=fixture(),before=f.canonicalAggregate.toString('hex'),original=f.inputs.map(v=>v.slice());
 const {kmsWitnessBytes,...withoutWitness}=f,r=measureLinearCommunication(withoutWitness);
 assert.equal(r.observed.kmsInputWitnessSerializedBytes,null);
 assert.equal(JSON.parse(JSON.stringify(r)).schema,'vcfhe-linear-communication-v1');
 assert.equal(f.canonicalAggregate.toString('hex'),before);assert.deepEqual(f.inputs,original);
 assert.throws(()=>measureLinearCommunication({...f,kmsWitnessBytes:-1}),/witness byte/);
 assert.match(r.scope,/KMS still needs/);
});
