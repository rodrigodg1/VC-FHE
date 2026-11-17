import test from 'node:test';
import assert from 'node:assert/strict';
import {kmsReleaseAuthorizationV3} from './onchain-policy.mjs';
import {assertKmsReleaseAuthorizationSchema} from '../scripts/kms-request-adapter.mjs';

const word=byte=>'0x'+byte.repeat(64);
const address=byte=>'0x'+byte.repeat(40);
const binding={chainId:'46853',game:address('1'),taskId:word('1'),contextDigest:word('2'),
 programDigest:word('3'),programRoot:word('4'),profileDigest:word('5'),keysetDigest:word('6'),
 keyId:word('7'),keyEpoch:word('8'),mpcContext:word('9'),inputBindings:[word('a'),word('b')],
 inputProtectedRecordIds:[word('c'),word('d')],
 workflowManifest:{schema:'vcfhe-workflow-deployment-v1',kind:'canonical-nonlinear'}};
const output={taskId:binding.taskId,aggregateDigest:word('e'),outputDigest:word('e'),outputType:'bool'};

test('KMS authorization keeps protected-record IDs on chain and emits the closed core schema',()=>{
 const authorization=kmsReleaseAuthorizationV3({policy:address('2'),policyDomain:word('f'),consentId:word('0'),
  binding,output,recipient:address('3'),workflowKind:2,slot:word('1')});
 assert.deepEqual(Object.keys(authorization).sort(),[
  'aggregateDigest','chainId','consentId','contextDigest','game','inputBindings','keyEpoch','keyId',
  'keysetDigest','kind','mpcContext','outputDigest','outputType','policy','policyDomain','policyVersion',
  'profileDigest','programDigest','programRoot','recipient','slot','taskId','workflowKind','workflowManifest'
 ].sort());
 assert.equal(Object.hasOwn(authorization,'inputProtectedRecordIds'),false);
 assert.equal(Object.hasOwn(authorization,'linearWitnessDigest'),false);
 assert.equal(assertKmsReleaseAuthorizationSchema(authorization),authorization);
 assert.throws(()=>assertKmsReleaseAuthorizationSchema({...authorization,
  inputProtectedRecordIds:binding.inputProtectedRecordIds}),/unexpected KMS release authorization field/);
});

test('linear KMS authorization includes only its content-addressed conversion witness',()=>{
 const linearBinding={...binding,linearWitnessDigest:word('f'),
  workflowManifest:{schema:'vcfhe-workflow-deployment-v1',kind:'grouped-linear'}};
 const authorization=kmsReleaseAuthorizationV3({policy:address('2'),policyDomain:word('f'),consentId:word('0'),
  binding:linearBinding,output:{...output,outputType:'uint16'},recipient:address('3'),workflowKind:1,slot:word('1')});
 assert.equal(authorization.linearWitnessDigest,linearBinding.linearWitnessDigest);
 assert.equal(Object.hasOwn(authorization,'inputProtectedRecordIds'),false);
 assert.equal(assertKmsReleaseAuthorizationSchema(authorization),authorization);
});

test('KMS authorization rejects an executed task outside the consented binding',()=>{
 assert.throws(()=>kmsReleaseAuthorizationV3({policy:address('2'),policyDomain:word('f'),consentId:word('0'),
  binding,output:{...output,taskId:word('2')},recipient:address('3'),workflowKind:2,slot:word('1')}),
 /executed task differs/);
});
