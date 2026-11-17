import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {ordinaryMessage,ordinarySign,ordinaryVerify,ordinaryPublicKey} from './ordinary-bls.mjs';
const L=createRequire(import.meta.url)('../../BN254-Signatures/scripts/mklhs-lib.js');
const sk=123456789n,pk=L.G2.BASE.multiply(sk);
const body={pk,datasetTag:'0x'+'ab'.repeat(32),index:1,op:0,totalItems:3,vector:[1n,0n,5n,0n]};
test('ordinary baseline authenticates exact canonical vector bytes with owner/context binding',()=>{
 const signature=ordinarySign(sk,body);
 assert.equal(ordinaryVerify(body,signature),true);
 assert.ok(ordinaryPublicKey(L.g2ToContract(pk).map(String)).equals(pk));
 assert.deepEqual(ordinaryMessage({...body,vector:body.vector.map(String)}),ordinaryMessage(body));
 for(const patch of [{vector:[2n,0n,5n,0n]},{vector:[0n,1n,5n,0n]},
  {vector:[1n,0n,5n]},{vector:[1n,0n,5n,0n,0n]},{index:0},{totalItems:4},
  {datasetTag:'0x'+'cd'.repeat(32)},{pk:L.G2.BASE.multiply(sk+1n)}]){
  assert.equal(ordinaryVerify({...body,...patch},signature),false);
 }
});
test('proposal commitment signatures are not ordinary ciphertext signatures',()=>{
 const commitment=L.commit(body.vector,L.commitGenerators(body.vector.length));
 const proposal=L.sign(sk,commitment,body.datasetTag,body.index,{pk,op:0,totalItems:body.totalItems});
 assert.equal(ordinaryVerify(body,L.g1ToContract(proposal).map(String)),false);
});
test('invalid domains, coordinates and identity points fail closed',()=>{
 for(const patch of [{vector:[-1n]},{vector:[L.R]},{vector:[]},{index:-1},
  {index:3},{index:1.5},{totalItems:34},{op:1},{datasetTag:'0x00'},{pk:L.G2.ZERO}]){
  assert.throws(()=>ordinaryMessage({...body,...patch}));
 }
 assert.throws(()=>ordinarySign(sk+1n,body));
 assert.throws(()=>ordinaryVerify(body,['0','0']));
 assert.throws(()=>ordinaryVerify(body,[String(L.Q),'1']));
 assert.throws(()=>ordinaryPublicKey(['0','0','0','0']));
 assert.throws(()=>ordinaryPublicKey([String(L.Q),'0','0','0']));
});
