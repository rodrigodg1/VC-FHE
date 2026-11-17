// Decode the actual pinned UserDecryptionRequest JSON representation. The Rust
// transport deserializes these exact bytes; caller-supplied metadata is insufficient.
import {createRequire} from 'node:module';
import assert from 'node:assert/strict';
import {nonlinearManifestProfile} from '../campaign/nonlinear-profile.mjs';
const require=createRequire(new URL('../../BN254-Signatures/package.json',import.meta.url));
const {ethers}=require('ethers');
const bytes=x=>{assert.ok(Array.isArray(x)&&x.every(n=>Number.isInteger(n)&&n>=0&&n<=255));return Uint8Array.from(x);};
const id=x=>{assert.match(x?.request_id,/^[0-9a-f]{64}$/);return '0x'+x.request_id;};
export const KMS_RELEASE_AUTHORIZATION_BASE_FIELDS=Object.freeze([
 'aggregateDigest','chainId','consentId','contextDigest','game','inputBindings','keyEpoch','keyId',
 'keysetDigest','kind','mpcContext','outputDigest','outputType','policy','policyDomain','policyVersion',
 'profileDigest','programDigest','programRoot','recipient','slot','taskId','workflowKind','workflowManifest'
].sort());
export function assertKmsReleaseAuthorizationSchema(value){
 assert.ok(value&&typeof value==='object'&&!Array.isArray(value),'invalid KMS release authorization');
 assert.ok(value.workflowKind===1||value.workflowKind===2,'invalid workflow kind');
 const expected=[...KMS_RELEASE_AUTHORIZATION_BASE_FIELDS];
 if(value.workflowKind===1)expected.push('linearWitnessDigest');
 assert.deepEqual(Object.keys(value).sort(),expected.sort(),'unexpected KMS release authorization field');
 return value;
}
export function inspectKmsRequest(wire) {
 const r=JSON.parse(Buffer.from(wire).toString('utf8'));
 assert.deepEqual(Object.keys(r).sort(),['request_id','typed_ciphertexts','key_id','client_address','enc_key','domain','extra_data','context_id','epoch_id'].sort());
 assert.equal(r.typed_ciphertexts.length,1);
 const ct=r.typed_ciphertexts[0],ciphertext=bytes(ct.ciphertext),digest=ethers.keccak256(ciphertext);
 assert.equal(ethers.hexlify(bytes(ct.external_handle)),digest);assert.equal(ct.ciphertext_format,1);
 const c=JSON.parse(Buffer.from(bytes(r.extra_data)).toString('utf8')),
  a=assertKmsReleaseAuthorizationSchema(c.authorization);
 assert.equal(a.kind,'kms-recipient-release-v3');assert.equal(a.policyVersion,3);
 for(const [field,wireField] of [['requestId','request_id'],['keyId','key_id'],['keyEpoch','epoch_id'],['mpcContext','context_id']]) {
  assert.equal('0x'+c[field],id(r[wireField]));
  if(field!=='requestId')assert.equal(a[field],id(r[wireField]));
 }
 assert.equal(c.outputDigest,digest);assert.equal(a.outputDigest,digest);
 assert.equal(c.outputType,ct.fhe_type);assert.equal(ct.fhe_type,a.outputType==='uint16'?3:5);
 assert.ok(['bool','uint16','uint64'].includes(a.outputType));
 assert.equal(c.recipient.toLowerCase(),r.client_address.toLowerCase());
 assert.equal(a.recipient.toLowerCase(),r.client_address.toLowerCase());
 assert.equal(r.domain.name,'VCFHE authorized output');assert.equal(r.domain.version,'1');assert.equal(r.domain.salt,null);
 assert.equal(r.domain.verifying_contract.toLowerCase(),a.game.toLowerCase());
 assert.equal(BigInt(ethers.hexlify(bytes(r.domain.chain_id))).toString(),a.chainId);
 assert.equal(BigInt(a.chainId)>0n,true);
 assert.ok(Array.isArray(a.inputBindings)&&a.inputBindings.length>0&&a.inputBindings.length<=128&&
  a.inputBindings.every(value=>ethers.isHexString(value,32)),'invalid input bindings');
 assert.equal(a.workflowManifest?.schema,'vcfhe-workflow-deployment-v1');
 if(a.workflowKind===1)assert.equal(a.workflowManifest?.kind,'grouped-linear');
 else nonlinearManifestProfile(a.workflowManifest?.kind);
 if(a.workflowKind===1)assert.equal(ethers.isHexString(a.linearWitnessDigest,32),true,'missing linear witness');
 else assert.equal(Object.hasOwn(a,'linearWitnessDigest'),false,'nonlinear request carried a linear witness');
 for(const field of ['policy','game','recipient'])assert.equal(ethers.isAddress(a[field]),true,`invalid ${field}`);
 for(const field of ['policyDomain','slot','consentId','taskId','contextDigest','programDigest','programRoot',
  'profileDigest','keysetDigest','keyId','keyEpoch','mpcContext','outputDigest','aggregateDigest'])
  assert.equal(ethers.isHexString(a[field],32),true,`invalid ${field}`);
 assert.ok(bytes(r.enc_key).length>0);
 return {...a,requestId:id(r.request_id),encKeyDigest:ethers.keccak256(bytes(r.enc_key)),ciphertextCount:1};
}
