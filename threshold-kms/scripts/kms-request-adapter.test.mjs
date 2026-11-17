import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {inspectKmsRequest} from './kms-request-adapter.mjs';

const {ethers}=createRequire(new URL('../../BN254-Signatures/package.json',import.meta.url))('ethers');
const word=n=>'0x'+n.repeat(64);
const address=n=>'0x'+n.repeat(40);

function request(kind='canonical-bounty-nonlinear-v2'){
 const linear=kind==='grouped-linear';
 const ciphertext=[1,2,3],digest=ethers.keccak256(Uint8Array.from(ciphertext));
 const authorization={aggregateDigest:word('a'),chainId:'46853',consentId:word('b'),
  contextDigest:word('c'),game:address('1'),inputBindings:[word('d')],keyEpoch:word('4'),
  keyId:word('3'),keysetDigest:word('e'),kind:'kms-recipient-release-v3',mpcContext:word('5'),
  outputDigest:digest,outputType:linear?'uint16':'bool',policy:address('2'),policyDomain:word('f'),
  policyVersion:3,profileDigest:word('6'),programDigest:word('7'),programRoot:word('8'),
  recipient:address('3'),slot:word('9'),taskId:word('0'),workflowKind:linear?1:2,
  workflowManifest:{schema:'vcfhe-workflow-deployment-v1',kind}};
 if(linear)authorization.linearWitnessDigest=word('1');
 const context={authorization,requestId:word('2').slice(2),keyId:authorization.keyId.slice(2),
  keyEpoch:authorization.keyEpoch.slice(2),mpcContext:authorization.mpcContext.slice(2),
  outputDigest:digest,outputType:linear?3:5,recipient:authorization.recipient};
 const id=value=>({request_id:value.slice(2)});
 const wire={request_id:id(word('2')),typed_ciphertexts:[{ciphertext,
  external_handle:Array.from(ethers.getBytes(digest)),ciphertext_format:1,fhe_type:context.outputType}],
  key_id:id(authorization.keyId),client_address:authorization.recipient,enc_key:[1,2,3],
  domain:{name:'VCFHE authorized output',version:'1',salt:null,verifying_contract:authorization.game,
   chain_id:Array.from(ethers.getBytes(ethers.toBeHex(46853,32)))},
  extra_data:[],context_id:id(authorization.mpcContext),epoch_id:id(authorization.keyEpoch)};
 return {wire,context};
}
function encode({wire,context}){
 return Buffer.from(JSON.stringify({...wire,extra_data:Array.from(Buffer.from(JSON.stringify(context)))}));
}

for(const kind of ['grouped-linear','canonical-nonlinear','canonical-bounty-nonlinear-v2']){
 test('exact request decoder accepts the explicitly versioned '+kind+' profile',()=>{
  const decoded=inspectKmsRequest(encode(request(kind)));
  assert.equal(decoded.workflowManifest.kind,kind);
  assert.equal(decoded.workflowKind,kind==='grouped-linear'?1:2);
  assert.equal(decoded.ciphertextCount,1);
 });
}
for(const kind of ['canonical-bounty-nonlinear-v3','canonical-nonlinear-v2','latest','grouped-linear-other',undefined]){
 test('request decoder rejects unknown nonlinear profile '+String(kind),()=>{
  const value=request();value.context.authorization.workflowManifest.kind=kind;
  assert.throws(()=>inspectKmsRequest(encode(value)),/unsupported nonlinear workflow manifest kind/);
 });
}
for(const [name,change] of [
 ['linear authorization with a nonlinear manifest',v=>{v.context.authorization.workflowKind=1;v.context.authorization.linearWitnessDigest=word('1');}],
 ['nonlinear authorization with a linear manifest',v=>{v.context.authorization.workflowManifest.kind='grouped-linear';}],
 ['extra authorization field',v=>{v.context.authorization.fallback=true;}],
 ['substituted ciphertext',v=>{v.wire.typed_ciphertexts[0].ciphertext[0]^=1;}],
 ['substituted output digest',v=>{v.context.authorization.outputDigest=word('1');}],
 ['substituted recipient',v=>{v.context.authorization.recipient=address('4');}],
 ['substituted key epoch',v=>{v.context.authorization.keyEpoch=word('1');}],
 ['substituted chain',v=>{v.context.authorization.chainId='46854';}],
 ['substituted game',v=>{v.context.authorization.game=address('4');}],
 ['missing input binding',v=>{v.context.authorization.inputBindings=[];}],
 ['nonlinear linear-conversion witness',v=>{v.context.authorization.linearWitnessDigest=word('1');}]
]){
 test('version support retains rejection of '+name,()=>{
  const value=request();change(value);assert.throws(()=>inspectKmsRequest(encode(value)));
 });
}
