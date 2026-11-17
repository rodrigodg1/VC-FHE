// Reference baseline only: ordinary BLS authenticates the complete canonical
// encrypted vector, not the proposal's vector commitment. No decryption/key share.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const L=require('../../BN254-Signatures/scripts/mklhs-lib.js');
const {bn254}=createRequire(new URL('../../BN254-Signatures/package.json',import.meta.url))('@noble/curves/bn254');
export const ORDINARY_BLS_PROFILE='ordinary-bls-canonical-vector-v1';

export function ordinaryMessage({pk,datasetTag,index,op,totalItems,vector}){
 assert.match(datasetTag,/^0x[0-9a-fA-F]{64}$/);
 assert.ok(Number.isSafeInteger(totalItems)&&totalItems>0&&totalItems<=33);
 assert.ok(Number.isSafeInteger(index)&&index>=0&&index<totalItems);
 assert.equal(op,0,'this campaign admits SUM only');
 assert.ok(Array.isArray(vector)&&vector.length>0&&vector.length<2**32);
 pk.assertValidity();assert.ok(!pk.equals(L.G2.ZERO),'identity public key');
 const coordinates=vector.map(x=>{const v=BigInt(x);assert.ok(v>=0n&&v<L.R,'noncanonical field coordinate');return L.be32(v);});
 return Buffer.concat([Buffer.from('VCFHE_ORDINARY_BLS_VECTOR_V1_'),
  ...L.g2ToContract(pk).map(L.be32),Buffer.from(datasetTag.slice(2),'hex'),
  L.be32(BigInt(index)),L.be32(BigInt(op)),L.be32(BigInt(totalItems)),
  L.be32(BigInt(vector.length)),...coordinates]);
}

export function ordinarySign(sk,body){
 assert.ok(sk>0n&&sk<L.R);assert.ok(L.G2.BASE.multiply(sk).equals(body.pk));
 return L.g1ToContract(L.hashToG1(ordinaryMessage(body)).multiply(sk)).map(String);
}

export function ordinaryVerify(body,signature){
 assert.ok(Array.isArray(signature)&&signature.length===2);
 const [x,y]=signature.map(BigInt);assert.ok(x>=0n&&x<L.Q&&y>=0n&&y<L.Q);
 const sig=L.G1.fromAffine({x,y});sig.assertValidity();assert.ok(!sig.equals(L.G1.ZERO),'identity signature');
 return bn254.fields.Fp12.eql(bn254.pairingBatch([
  {g1:sig.negate(),g2:L.G2.BASE},
  {g1:L.hashToG1(ordinaryMessage(body)),g2:body.pk}
 ]),bn254.fields.Fp12.ONE);
}

export function ordinaryPublicKey(encoded){
 assert.ok(Array.isArray(encoded)&&encoded.length===4);
 const [x0,x1,y0,y1]=encoded.map(BigInt);
 assert.ok([x0,x1,y0,y1].every(x=>x>=0n&&x<L.Q),'noncanonical public key');
 const pk=L.G2.fromAffine({x:{c0:x0,c1:x1},y:{c0:y0,c1:y1}});
 pk.assertValidity();assert.ok(!pk.equals(L.G2.ZERO));return pk;
}
