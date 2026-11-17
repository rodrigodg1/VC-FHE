// Pure encrypted-vector verification components. No chain mutation, FHE secret
// key, plaintext, KMS call or release. Owner preparation is separately timed.
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createRequire} from 'node:module';
import {ethers} from './common.mjs';
import {ordinarySign,ordinaryVerify,ordinaryPublicKey,ORDINARY_BLS_PROFILE} from './ordinary-bls.mjs';
const require=createRequire(import.meta.url),L=require('../../BN254-Signatures/scripts/mklhs-lib.js');
const {bn254}=createRequire(new URL('../../BN254-Signatures/package.json',import.meta.url))('@noble/curves/bn254');
export function benchmarkTag({caseName,keysetDigest,chainId}){
 return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['string','uint256','bytes32','string'],
  ['VCFHE_OFFCHAIN_PAIRED_LINEAR_V1',chainId,keysetDigest,caseName]));
}
export function groupedVectors(inputs){
 assert.ok(inputs.length>0&&inputs.length<=33);const width=inputs[0].length;
 assert.ok(width>0&&inputs.every(v=>v.length===width));
 return inputs.map((coords,i)=>{const v=Array(9*width).fill(0n);coords.forEach((x,j)=>{
  x=BigInt(x);assert.ok(x>=0n&&x<2n**64n);v[Math.floor(i/4)*width+j]=x;
 });return v;});
}
export function aggregateVectors(vectors){
 const aggregate=Array(vectors[0].length).fill(0n);
 for(const v of vectors)for(let j=0;j<v.length;j++)aggregate[j]=L.mod(aggregate[j]+v[j],L.R);
 return aggregate;
}
export function prepareLinearBenchmark({inputs,...domain}){
 const vectors=groupedVectors(inputs),datasetTag=benchmarkTag(domain),n=vectors.length;
 const started=performance.now(),generators=L.commitGenerators(vectors[0].length),generatorsMs=performance.now()-started;
 const admissions=vectors.map((vector,index)=>{
  let t=performance.now();const {sk,pk}=L.keygen(()=>randomBytes(32)),keygenMs=performance.now()-t;
  t=performance.now();const c=L.commit(vector,generators),commitmentMs=performance.now()-t;
  t=performance.now();const sig=L.sign(sk,c,datasetTag,index,{pk,op:0,totalItems:n}),proposalSignMs=performance.now()-t;
  t=performance.now();const baselineSignature=ordinarySign(sk,{pk,datasetTag,index,op:0,totalItems:n,vector}),baselineSignMs=performance.now()-t;
  return {pk:L.g2ToContract(pk).map(String),commitment:L.g1ToContract(c).map(String),signature:L.g1ToContract(sig).map(String),
   baselineSignature,preparationTimings:{keygenMs,commitmentMs,proposalSignMs,baselineSignMs}};
 });
 return {profile:ORDINARY_BLS_PROFILE,datasetTag,dimension:vectors[0].length,generatorsMs,admissions};
}
export function verifyProposal({aggregate,admissions,datasetTag,generators}){
 const n=admissions.length;let expected=L.G1.ZERO;
 for(let i=0;i<n;i++){
  const a=admissions[i],pk=ordinaryPublicKey(a.pk);
  const [x,y]=a.commitment.map(BigInt),[sx,sy]=a.signature.map(BigInt);
  const c=L.G1.fromAffine({x,y}),sig=L.G1.fromAffine({x:sx,y:sy});c.assertValidity();sig.assertValidity();assert.ok(!sig.equals(L.G1.ZERO));
  assert.ok(bn254.fields.Fp12.eql(bn254.pairingBatch([{g1:sig.negate(),g2:L.G2.BASE},
   {g1:L.contextPoint(pk,datasetTag,i,0,n,c),g2:pk}]),bn254.fields.Fp12.ONE));
  expected=expected.add(c);
 }
 assert.ok(L.commit(aggregate,generators).equals(expected),'incorrect encrypted aggregate');
 return {accepted:true,verifiedSignatures:n,plaintextOpenings:0};
}
export function verifyBaseline({vectors,aggregate,admissions,datasetTag}){
 for(let i=0;i<admissions.length;i++)assert.ok(ordinaryVerify({pk:ordinaryPublicKey(admissions[i].pk),
  datasetTag,index:i,op:0,totalItems:admissions.length,vector:vectors[i]},admissions[i].baselineSignature));
 assert.deepEqual(aggregateVectors(vectors),aggregate);
 return {accepted:true,verifiedSignatures:admissions.length,plaintextOpenings:0};
}
export const generators=dimension=>L.commitGenerators(dimension);
