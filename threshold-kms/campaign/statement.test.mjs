import test from 'node:test';
import assert from 'node:assert/strict';
import {ethers} from './common.mjs';
import {linearStatement,approveConsent} from './statement.mjs';
const hash=ethers.id;
const address=n=>ethers.getAddress('0x'+n.toString(16).padStart(40,'0'));
const keys={keyId:hash('key'),keysetDigest:hash('set'),keyEpoch:hash('epoch'),mpcContext:hash('mpc')};
const cfg={chainId:'46853',policyDomain:'dataset-threshold-campaign-v1'};
const item={n:2,recordIds:[hash('a'),hash('b')],owners:[address(1),address(2)],plan:{op:'SUM',profile:'kms-grouped-radix-v1',bounds:[[1,5],[1,5]]}};
const args={item,keys,inputs:[Array(8).fill('1'),Array(8).fill('2')],binaryDigest:hash('binary'),game:address(3),chainId:cfg.chainId};
const statement=linearStatement(args),recipient=address(4);
const body={kind:'kms-final-consent-v2',domain:hash(cfg.policyDomain),...keys,...cfg,game:args.game,
 recordIds:item.recordIds,recipients:[recipient],contextDigest:statement.contextDigest,programDigest:statement.programDigest,
 profileDigest:statement.profileDigest,outputType:'uint16'};
delete body.policyDomain;
const check=b=>approveConsent(b,{cfg,keys,item,recipient,expected:statement,game:args.game});
test('owner derives the exact agreed public statement from its own inputs',()=>assert.ok(check(body)));
for(const field of ['contextDigest','programDigest','profileDigest','keyId','keyEpoch','keysetDigest','mpcContext'])
 test('owner refuses substituted '+field,()=>assert.throws(()=>check({...body,[field]:hash('substitution')})));
test('owner refuses chain, deployment, recipient, output type or record changes',()=>{
 for(const change of [{chainId:'31337'},{game:address(5)},{recipients:[address(6)]},{outputType:'uint64'},{recordIds:[item.recordIds[0]]}])
  assert.throws(()=>check({...body,...change}));
});
test('changing owner ciphertexts changes the consent context',()=>{
 const changed=structuredClone(args);changed.inputs[0][0]='99';
 assert.notEqual(linearStatement(changed).contextDigest,statement.contextDigest);
});
test('deployment-domain tag cannot be reused on another chain or contract',()=>{
 assert.notEqual(linearStatement({...args,chainId:'31337'}).tag,statement.tag);
 assert.notEqual(linearStatement({...args,game:address(8)}).tag,statement.tag);
});
