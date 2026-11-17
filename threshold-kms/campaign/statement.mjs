// Public statement derivation shared by the owner and verifier. Owners invoke
// this on their private, immutable preparation snapshot, never verifier files.
import assert from 'node:assert/strict';
import {ethers} from './common.mjs';
import {policyHash} from '../scripts/recipient-output-policy.mjs';
export function linearStatement({item,keys,inputs,binaryDigest,game,chainId}){
 const width=inputs[0].length;
 assert.equal(inputs.length,item.n);assert.ok(inputs.every(v=>v.length===width));
 const profile={...item.plan,dimension:9*width,lweSize:width/8,keyId:keys.keyId,keysetDigest:keys.keysetDigest,
  binaryDigest,tfhe:'1.6.1',threads:1,fixedFFT:true};
 const profileDigest=policyHash(profile),tag=ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
  ['string','uint256','address','bytes32','bytes32','bytes32','uint64','uint8'],
  ['VCFHE-LINEAR-GROUPED-V1',chainId,game,keys.keyEpoch,profileDigest,keys.keysetDigest,item.n,0]));
 const digest=v=>ethers.keccak256(ethers.concat(v.map(x=>ethers.zeroPadValue(ethers.toBeHex(BigInt(x)),32))));
 const context={profileDigest,keysetDigest:keys.keysetDigest,datasetTag:tag,
  records:item.recordIds.map((id,i)=>({id,owner:item.owners[i]})),ownerCiphertextDigests:inputs.map(digest)};
 return {profile,tag,context,contextDigest:policyHash(context),programDigest:policyHash(item.plan),profileDigest,outputType:'uint16'};
}
export function approveConsent(body,{cfg,keys,item,recipient,expected,game}){
 assert.equal(body.kind,'kms-final-consent-v2');assert.equal(body.domain,ethers.id(cfg.policyDomain));
 for(const k of ['keyId','keysetDigest','keyEpoch','mpcContext'])assert.equal(body[k],keys[k]);
 assert.equal(body.chainId,cfg.chainId);assert.equal(body.game,game);assert.ok(ethers.isAddress(game));
 assert.deepEqual([...body.recordIds].sort(),[...item.recordIds].sort());
 assert.deepEqual(body.recipients,[recipient]);
 for(const k of ['contextDigest','programDigest','profileDigest','outputType'])assert.equal(body[k],expected[k]);
 return true;
}
