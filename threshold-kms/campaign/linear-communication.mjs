// Byte accounting for the unchanged grouped linear workflow. This module does
// not send data, change the accepted encoding, validate FHE, or call the KMS.
// The nine-byte SUM representation is a diagnostic counterfactual only.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {constants as bufferConstants} from 'node:buffer';

export const LINEAR_COMMUNICATION_SCHEMA='vcfhe-linear-communication-v1';
const GROUPS=9, BLOCKS=8, MAX_INPUTS=33;
const U64_MAX=(1n<<64n)-1n;
const FR=21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function shape(inputCount,coordinateWidth,op){
 assert.ok(Number.isSafeInteger(inputCount)&&inputCount>=1&&inputCount<=MAX_INPUTS,'input count outside [1,33]');
 assert.ok(Number.isSafeInteger(coordinateWidth)&&coordinateWidth>0&&coordinateWidth%BLOCKS===0,'invalid eight-block coordinate width');
 assert.ok(coordinateWidth<=Math.floor(bufferConstants.MAX_LENGTH/(GROUPS*32)),'diagnostic buffer too large');
 assert.ok(op==='SUM'||op==='SUB','unsupported grouped operation');
 const layout=Array.from({length:inputCount},(_,i)=>op==='SUM'
  ?{group:Math.floor(i/4),sign:1n}:{group:i===0?0:1+Math.floor((i-1)/4),sign:i===0?1n:-1n});
 return {dimension:GROUPS*coordinateWidth,layout};
}
function integer(value){
 assert.ok(typeof value==='bigint'||(typeof value==='string'&&/^(0|[1-9][0-9]*)$/.test(value))||
  (typeof value==='number'&&Number.isSafeInteger(value)),'coordinate is not an exact integer');
 return BigInt(value);
}
function encode(values,bytes){
 const out=Buffer.alloc(values.length*bytes);
 values.forEach((value,i)=>{let v=value;
  assert.ok(v>=0n&&v<(1n<<BigInt(bytes*8)),'coordinate outside encoding range');
  for(let j=bytes-1;j>=0;j--){out[i*bytes+j]=Number(v&255n);v>>=8n;}
 });
 return out;
}
function decode(bytes,width){
 assert.ok(Buffer.isBuffer(bytes)||bytes instanceof Uint8Array,'byte array required');
 const data=Buffer.from(bytes);
 assert.equal(data.byteLength%width,0,'truncated coordinate');
 return Array.from({length:data.byteLength/width},(_,i)=>{
  let v=0n;for(let j=0;j<width;j++)v=(v<<8n)+BigInt(data[i*width+j]);return v;
 });
}
function canonicalWords(bytes,inputCount,coordinateWidth,op){
 const {dimension}=shape(inputCount,coordinateWidth,op);
 assert.equal(bytes.byteLength,dimension*32,'wrong canonical aggregate length');
 const words=decode(bytes,32);
 assert.ok(words.every(x=>x<FR),'noncanonical field coordinate');
 return words;
}

// Experimental serialization, never used as a production ciphertext or request.
// All groups are public. Each populated SUM group contains at most four uint64
// inputs, hence at most 66 bits per summed coordinate. Decompression restores
// the exact current 32-byte field encoding before any ordinary protocol checks.
export function experimentalCompactSumEncode(canonical,{inputCount,coordinateWidth,op='SUM'}){
 assert.equal(op,'SUM','experimental compact representation supports SUM only');
 const words=canonicalWords(canonical,inputCount,coordinateWidth,op),populated=Math.ceil(inputCount/4);
 for(let group=0;group<GROUPS;group++){
  const members=Math.max(0,Math.min(4,inputCount-group*4)),bound=BigInt(members)*U64_MAX;
  for(let j=0;j<coordinateWidth;j++)assert.ok(words[group*coordinateWidth+j]<=bound,'aggregate exceeds public group bound');
 }
 return encode(words.slice(0,populated*coordinateWidth),9);
}
export function experimentalCompactSumDecode(packed,{inputCount,coordinateWidth,op='SUM'}){
 assert.equal(op,'SUM','experimental compact representation supports SUM only');
 const {dimension}=shape(inputCount,coordinateWidth,op),populated=Math.ceil(inputCount/4);
 assert.equal(packed.byteLength,populated*coordinateWidth*9,'wrong experimental aggregate length');
 const words=decode(packed,9),canonical=encode([...words,...Array(dimension-words.length).fill(0n)],32);
 // Also rejects a value that fits in nine bytes but exceeds its group capacity.
 experimentalCompactSumEncode(canonical,{inputCount,coordinateWidth,op});
 return canonical;
}

export function measureLinearCommunication({inputs,canonicalAggregate,op,kmsWitnessBytes=null}){
 assert.ok(Array.isArray(inputs)&&inputs.length>0,'input vectors required');
 assert.ok(Array.isArray(inputs[0]),'input coordinate array required');
 const inputCount=inputs.length,coordinateWidth=inputs[0].length;
 const {dimension,layout}=shape(inputCount,coordinateWidth,op);
 const words=canonicalWords(canonicalAggregate,inputCount,coordinateWidth,op);
 const expected=Array(dimension).fill(0n);
 let packedInputBytes=0;
 inputs.forEach((vector,i)=>{
  assert.ok(Array.isArray(vector)&&vector.length===coordinateWidth,'inconsistent input width');
  const coordinates=vector.map(value=>{const v=integer(value);assert.ok(v>=0n&&v<=U64_MAX,'input outside uint64');return v;});
  packedInputBytes+=encode(coordinates,8).byteLength;
  coordinates.forEach((x,j)=>{expected[layout[i].group*coordinateWidth+j]+=layout[i].sign*x;});
 });
 expected.forEach((x,i)=>{expected[i]=(x%FR+FR)%FR;});
 assert.deepEqual(words,expected,'aggregate bytes differ from the declared grouped operation');
 assert.ok(kmsWitnessBytes===null||(Number.isSafeInteger(kmsWitnessBytes)&&kmsWitnessBytes>=0),'invalid witness byte count');
 const canonicalBytes=canonicalAggregate.byteLength;
 const scenario=proposedBytes=>({
  proposedAggregatePayloadBytes:proposedBytes,
  baselineInputPayloadBytes:packedInputBytes,
  baselineAdditionalAggregatePayloadBytes:0,
  proposedMinusBaselineBytes:proposedBytes-packedInputBytes,
  proposedReductionFraction:(packedInputBytes-proposedBytes)/packedInputBytes
 });
 let compactSum={available:false,reason:'Nine-byte diagnostic encoding is defined only for SUM, not SUB.'};
 if(op==='SUM'){
  const encoded=experimentalCompactSumEncode(canonicalAggregate,{inputCount,coordinateWidth,op});
  const restored=experimentalCompactSumDecode(encoded,{inputCount,coordinateWidth,op});
  assert.deepEqual(restored,Buffer.from(canonicalAggregate));
  compactSum={available:true,status:'hypothetical-transport-not-used-by-protocol',coordinateBytes:9,
   populatedGroups:Math.ceil(inputCount/4),encodedBytes:encoded.byteLength,roundTripCanonicalBytesEqual:true,
   coldInputCache:scenario(encoded.byteLength)};
 }
 return {
  schema:LINEAR_COMMUNICATION_SCHEMA,operation:op,inputCount,coordinateWidth,dimension,
  evidenceClass:'serialized-byte-accounting-not-network-measurement',networkTransferMeasured:false,
  cryptographicOrFheValidationPerformed:false,
  observed:{canonicalAggregateBytes:canonicalBytes,canonicalAggregateSha256:createHash('sha256').update(canonicalAggregate).digest('hex'),
   kmsInputWitnessSerializedBytes:kmsWitnessBytes},
  sizeModel:{inputCoordinateBytes:8,packedInputPayloadBytes:packedInputBytes,
   zeroGroupsReconstructedFromPublicLayout:true,baselineReconstructsAggregate:true,
   canonicalAggregateEncoding:'32-byte-big-endian-field-coordinates'},
  coldInputCache:{publicContext:'keys-and-generators-available-to-both',...scenario(canonicalBytes)},
  warmAuthenticatedInputAndAggregateCache:{proposedAggregatePayloadBytes:0,baselineInputPayloadBytes:0,
   baselineAdditionalAggregatePayloadBytes:0,condition:'Both may reuse authenticated inputs and the derived aggregate for the identical statement. This is not amortization over different computations.'},
  compactSum,
  excludedCommonOrSeparateBytes:[
   'Public and evaluation keys and public commitment generators',
   'Signatures, record identifiers, layout and execution metadata',
   'Blockchain reads, proofs, receipts and transaction calldata',
   'Owner consent, exact release approval and KMS response traffic',
   'Claimed output digests and final converted ciphertext',
   'All-input KMS witness transfer and replication, whose serialized size is recorded separately when supplied'
  ],
  scope:'Recipient ciphertext payload only. The baseline reconstructs the aggregate from inputs instead of receiving it twice. The current KMS still needs the original-input witness. No total communication, confidentiality, availability or speedup conclusion follows.'
 };
}
