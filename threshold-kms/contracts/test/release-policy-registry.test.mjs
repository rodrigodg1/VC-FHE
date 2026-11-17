import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createRequire} from 'node:module';
import {assertExpectedWorkflow,bindExpectedWorkflow,computeConsentIdV3,computeReleaseDigestV3} from '../../campaign/onchain-policy.mjs';

const require = createRequire(new URL('../../package.json', import.meta.url));
const {ethers} = require('ethers');
const ganache = require('ganache');
const solc = require('solc');

const MNEMONIC = 'test test test test test test test test test test test junk';
const RELEASE_TYPES = {ReleaseRequest: [
  {name:'consentId',type:'bytes32'},
  {name:'requestId',type:'bytes32'},
  {name:'requestKey',type:'bytes32'},
  {name:'submitWireDigest',type:'bytes32'},
  {name:'resultQueryDigest',type:'bytes32'},
  {name:'finalOutputDigest',type:'bytes32'},
  {name:'aggregateDigest',type:'bytes32'},
  {name:'recipientEncryptionKeyDigest',type:'bytes32'},
  {name:'recipient',type:'address'}
]};

function compile(sources, names) {
  const input = {language:'Solidity', sources, settings:{optimizer:{enabled:true,runs:200},viaIR:true,
    evmVersion:'london',metadata:{bytecodeHash:'none',appendCBOR:false},
    outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.deployedBytecode.object']}}}};
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter(row => row.severity === 'error');
  assert.deepEqual(errors, [], errors.map(row => row.formattedMessage).join('\n'));
  return Object.fromEntries(names.map(([source, name]) => {
    const artifact = output.contracts[source][name];
    return [name, {abi:artifact.abi, bytecode:'0x'+artifact.evm.bytecode.object,
      runtimeBytes:artifact.evm.deployedBytecode.object.length/2}];
  }));
}

const policySource = fs.readFileSync(new URL('../OnChainReleasePolicy.sol', import.meta.url), 'utf8');
const mockSource = fs.readFileSync(new URL('./ReleasePolicyMocks.sol', import.meta.url), 'utf8');
const artifacts = compile({
  'OnChainReleasePolicy.sol':{content:policySource},
  'ReleasePolicyMocks.sol':{content:mockSource}
}, [
  ['OnChainReleasePolicy.sol','ReleasePolicyRegistry'],
  ['ReleasePolicyMocks.sol','MockGroupedLinear'],
  ['ReleasePolicyMocks.sol','MockNonlinearGame'],
  ['ReleasePolicyMocks.sol','MockAvailability'],
  ['ReleasePolicyMocks.sol','MockCanonicalVerifier']
]);

const groupedArtifacts = compile({
  'GroupedLinearVerification.sol':{content:fs.readFileSync(new URL('../GroupedLinearVerification.sol', import.meta.url),'utf8')},
  'MKLHS-Verification.sol':{content:fs.readFileSync(new URL('../../../BN254-Signatures/contract/MKLHS-Verification.sol', import.meta.url),'utf8')}
}, [['GroupedLinearVerification.sol','GroupedLinearVerification']]);

const id = label => ethers.id(label);
const wait = async promise => (await promise).wait();
const expectRevert = promise => assert.rejects(promise, /revert|CALL_EXCEPTION|missing revert data|could not coalesce/i);

async function chain(t) {
  const raw = ganache.provider({logging:{quiet:true}, chain:{chainId:31337, hardfork:'shanghai'},
    wallet:{mnemonic:MNEMONIC,totalAccounts:10}});
  t.after(async()=>{try{await raw.disconnect();}catch{}});
  const provider = new ethers.BrowserProvider(raw,undefined,{cacheTimeout:-1});
  const wallets = await Promise.all(Array.from({length:10},(_,i)=>provider.getSigner(i)));
  const signingKeys = Array.from({length:10},(_,i)=>ethers.HDNodeWallet.fromPhrase(
    MNEMONIC, undefined, `m/44'/60'/0'/0/${i}`));
  return {provider,wallets,signingKeys};
}

async function deploy(artifact, signer, args=[], overrides={}) {
  const contract = await new ethers.ContractFactory(artifact.abi,artifact.bytecode,signer).deploy(...args,overrides);
  await contract.waitForDeployment();
  return contract;
}

async function signRelease(f, request, signer=f.recipientKey) {
  return signer.signTypedData({name:'VCFHE-Onchain-Release-Policy',version:'3',chainId:31337,
    verifyingContract:f.policy.target},RELEASE_TYPES,request);
}

const INPUT_RECORD_TYPEHASH=id('FHE_POD_INPUT_RECORD_V1(address owner,bytes32 ciphertextHandle,bytes32 metadataHash)');
function canonicalInputRoot(taskId,inputProtectedRecordIds,inputBindings,ownersByRecord){
  assert.equal(inputProtectedRecordIds.length,inputBindings.length);
  const actual=inputBindings.length;
  let padded=1;while(padded<actual)padded*=2;
  const coder=ethers.AbiCoder.defaultAbiCoder(),level=[];
  for(let i=0;i<actual;i++){
    const owner=ownersByRecord.get(inputProtectedRecordIds[i].toLowerCase());
    assert.ok(owner);
    const metadata=ethers.keccak256(coder.encode(['bytes32','uint32','string'],[taskId,i,'record']));
    level.push(ethers.keccak256(coder.encode(['bytes32','address','bytes32','bytes32'],
      [INPUT_RECORD_TYPEHASH,owner,inputBindings[i],metadata])));
  }
  const paddingOwner=ownersByRecord.get(inputProtectedRecordIds[0].toLowerCase());
  for(let i=actual;i<padded;i++){
    const handle=ethers.solidityPackedKeccak256(['string','bytes32','uint32'],
      ['VCFHE_INPUT_TREE_PADDING',taskId,i]);
    const metadata=ethers.keccak256(coder.encode(['bytes32','uint32','string'],[taskId,i,'padding']));
    level.push(ethers.keccak256(coder.encode(['bytes32','address','bytes32','bytes32'],
      [INPUT_RECORD_TYPEHASH,paddingOwner,handle,metadata])));
  }
  for(let width=padded;width>1;width/=2){
    for(let i=0;i<width;i+=2)level[i/2]=ethers.solidityPackedKeccak256(
      ['bytes32','bytes32'],[level[i],level[i+1]]);
  }
  return {root:level[0],actual,padded};
}

async function baseFixture(t,{kind='linear',limit=2,initialSpent=0,approveConsent=true}={}) {
  const {provider,wallets,signingKeys} = await chain(t);
  const [deployer,ownerA,ownerB,recipient,relayerA,relayerB,attacker] = wallets;
  const policy = await deploy(artifacts.ReleasePolicyRegistry,deployer);
  assert.equal(await policy.POLICY_VERSION(),3n);
  assert.equal(ethers.getBytes(await policy.DOMAIN_SEPARATOR()).length,32);
  assert.ok(artifacts.ReleasePolicyRegistry.runtimeBytes < 24576);
  assert.equal(policy.interface.getFunction('isSubmitAuthorized').selector,'0x90fe045d');

  const owners=[ownerA,ownerB];
  const recordReferences=[id('protected-record-reference-a'),id('protected-record-reference-b')];
  const recordIds=await Promise.all(owners.map((owner,index)=>
    policy.deriveProtectedId(owner.address,recordReferences[index])));
  for(let i=0;i<2;i++) await wait(policy.connect(owners[i]).registerProtectedRecord(
    recordIds[i],owners[i].address,recordReferences[i],limit,initialSpent));

  const profileDigest=id('profile'),keysetDigest=id('keyset'),taskId=id(`task-${kind}`);
  const programDigest=id('program-digest'),programRoot=id('program-root');
  const inputBindings=[id('record-a-ciphertexts'),id('record-b-ciphertexts')];
  let workflow,availability,verifier,nonlinearAuthorization;
  const finalOutputDigest=id('final-output'),aggregateDigest=kind==='linear'?id('aggregate'):finalOutputDigest;
  if(kind==='linear'){
    workflow=await deploy(artifacts.MockGroupedLinear,deployer);
    await wait(workflow.configure(profileDigest,keysetDigest,2));
    for(let i=0;i<2;i++)await wait(workflow.setRecord(i,owners[i].address,recordIds[i],inputBindings[i]));
    await wait(workflow.setBoundResult(taskId,aggregateDigest,true));
  }else{
    workflow=await deploy(artifacts.MockNonlinearGame,deployer);
    availability=await deploy(artifacts.MockAvailability,deployer,[workflow.target]);
    verifier=await deploy(artifacts.MockCanonicalVerifier,deployer,[workflow.target]);
    await wait(workflow.setModules(availability.target,verifier.target));
  }

  const terms={domain:await policy.policyDomain(),chainId:31337,workflowKind:kind==='linear'?1:2,
    workflow:workflow.target,taskId,contextDigest:id('context'),programDigest,programRoot,
    profileDigest,keysetDigest,keyId:id('key-id'),keyEpoch:id('key-epoch'),mpcContext:id('mpc-context'),
    outputType:id(kind==='linear'?'uint16':'bool'),recipient:recipient.address,slot:id(`slot-${kind}`),
    protectedRecordIds:recordIds,inputProtectedRecordIds:kind==='linear'?[]:recordIds,inputBindings};
  const consentId=await policy.computeConsentId(terms);
  assert.equal(consentId,computeConsentIdV3(policy.target,terms));
  await wait(policy.connect(relayerA).createConsent(terms));
  if(approveConsent)for(const owner of owners)await wait(policy.connect(owner).approveConsent(consentId));

  const requestKey=id(`request-key-${kind}`);
  const request={consentId,requestId:id(`request-${kind}`),requestKey,
    submitWireDigest:id(`submit-wire-${kind}`),resultQueryDigest:requestKey,
    finalOutputDigest,aggregateDigest,recipientEncryptionKeyDigest:id('recipient-ephemeral-key'),
    recipient:recipient.address};
  assert.equal(computeReleaseDigestV3(request),await policy.releaseStructHash(request));

  if(kind==='nonlinear'){
    const traceRoot=id('trace-root'),leafCount=8,attestation=id('output-attestation');
    const typehash=await policy.OUTPUT_BINDING_V2_TYPEHASH();
    const resultHash=ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ['bytes32','bytes32','bytes32','uint32','bytes32','bytes32'],
      [typehash,taskId,traceRoot,leafCount,finalOutputDigest,attestation]));
    await wait(verifier.setProfileDigest(profileDigest));
    await wait(verifier.setContext(taskId,terms.contextDigest));
    await wait(availability.setCleared(true));
    const storedConsent=await policy.getConsent(consentId);
    nonlinearAuthorization={requester:deployer.address,operator:relayerA.address,
      traceRoot,resultHash,inputRoot:storedConsent.inputRoot,programRoot,provenanceRoot:id('provenance-root'),
      outputAttestationHash:attestation,inputCount:storedConsent.paddedInputCount,leafCount,
      deadline:9999999999n,consumed:true};
    await wait(availability.setTaskAuthorization(taskId,nonlinearAuthorization));
    await wait(workflow.setResultBinding(resultHash,traceRoot,leafCount));
    await wait(workflow.setStatus(3,1,false));
  }

  return {provider,wallets,deployer,owners,ownerA,ownerB,recipient,recipientKey:signingKeys[3],
    relayerA,relayerB,attacker,attackerKey:signingKeys[6],
    policy,workflow,availability,verifier,nonlinearAuthorization,
    recordReferences,recordIds,inputBindings,terms,consentId,request};
}

function kmsSubmitAuthorization(f,overrides={}){
  return {requestId:f.request.requestId,requestKey:f.request.requestKey,
    submitWireDigest:f.request.submitWireDigest,consentId:f.consentId,
    finalOutputDigest:f.request.finalOutputDigest,aggregateDigest:f.request.aggregateDigest,
    recipientEncryptionKeyDigest:f.request.recipientEncryptionKeyDigest,recipient:f.recipient.address,
    keyId:f.terms.keyId,keyEpoch:f.terms.keyEpoch,mpcContext:f.terms.mpcContext,
    outputType:f.terms.outputType,workflow:f.workflow.target,chainId:31337n,
    policyDomain:f.terms.domain,policy:f.policy.target,slot:f.terms.slot,
    workflowKind:f.terms.workflowKind,taskId:f.terms.taskId,contextDigest:f.terms.contextDigest,
    programDigest:f.terms.programDigest,programRoot:f.terms.programRoot,
    profileDigest:f.terms.profileDigest,keysetDigest:f.terms.keysetDigest,
    inputBindingsDigest:ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ['bytes32[]'],[f.terms.inputBindings])),...overrides};
}

async function propose(f,request=f.request,signer=f.recipientKey){
  const signature=await signRelease(f,request,signer);
  await wait(f.policy.connect(f.relayerA).proposeRelease(request,signature));
  return signature;
}

async function approveRelease(f,request=f.request,owners=f.owners){
  const releaseDigest=computeReleaseDigestV3(request);
  for(const owner of owners)await wait(f.policy.connect(owner).approveRelease(request.requestId,releaseDigest));
}

test('protected-record migration is owner asserted, bounded, and cannot be reset by re-registration',async t=>{
  const {wallets}=await chain(t),[deployer,owner,attacker]=wallets;
  const policy=await deploy(artifacts.ReleasePolicyRegistry,deployer);
  const reference=id('migration-record-reference');
  const record=await policy.deriveProtectedId(owner.address,reference);
  const expected=ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes32','uint256','address','address','bytes32'],
    [await policy.PROTECTED_RECORD_TYPEHASH(),31337,policy.target,owner.address,reference]));
  assert.equal(record,expected);
  const overspentReference=id('overspent-reference');
  const overspent=await policy.deriveProtectedId(owner.address,overspentReference);
  await expectRevert(wait(policy.connect(attacker).registerProtectedRecord(
    record,owner.address,reference,3,1)));
  await expectRevert(wait(policy.connect(owner).registerProtectedRecord(
    overspent,owner.address,overspentReference,2,3)));
  await wait(policy.connect(owner).registerProtectedRecord(record,owner.address,reference,3,1));
  const stored=await policy.protectedRecords(record);
  assert.equal(stored.owner,owner.address);assert.equal(stored.recordReference,reference);
  assert.equal(stored.releaseLimit,3n);assert.equal(stored.spent,1n);
  await expectRevert(wait(policy.connect(owner).registerProtectedRecord(
    record,owner.address,reference,9,0)));
});

test('stable record aliases and duplicate consent records are rejected',async t=>{
  const f=await baseFixture(t);
  await expectRevert(wait(f.policy.connect(f.attacker).registerProtectedRecord(
    f.recordIds[0],f.attacker.address,f.recordReferences[0],2,0)));
  assert.notEqual(
    await f.policy.deriveProtectedId(f.ownerA.address,f.recordReferences[0]),
    await f.policy.deriveProtectedId(f.ownerB.address,f.recordReferences[0]));
  const duplicate={...f.terms,slot:id('duplicate-slot'),protectedRecordIds:[f.recordIds[0],f.recordIds[0]],
    inputBindings:[id('first-binding'),id('second-binding')]};
  await expectRevert(wait(f.policy.connect(f.relayerA).createConsent(duplicate)));
  await expectRevert(wait(f.policy.createConsent({...f.terms,slot:id('linear-input-id-slot'),
    inputProtectedRecordIds:[f.recordIds[0]]})));
});

test('an authenticated workflow binding cannot be replaced before local consent derivation',()=>{
  const approved={};
  const first=ethers.getAddress('0x0000000000000000000000000000000000000011');
  const changed=ethers.getAddress('0x0000000000000000000000000000000000000022');
  assert.equal(bindExpectedWorkflow(approved,first),first);
  assert.equal(bindExpectedWorkflow(approved,first.toLowerCase()),first);
  assert.equal(assertExpectedWorkflow(approved,first),first);
  assert.throws(()=>assertExpectedWorkflow(approved,changed),/changed workflow contract/);
  assert.throws(()=>bindExpectedWorkflow(approved,changed),/changed workflow contract/);
  assert.equal(approved.game,first);
});

test('canonical nonlinear input roots match the explicit 50- and 100-input construction',async t=>{
  const f=await baseFixture(t,{kind:'nonlinear'});
  const ownersByRecord=new Map(f.recordIds.map((record,index)=>
    [record.toLowerCase(),f.owners[index].address]));
  for(const size of [50,100]){
    const inputProtectedRecordIds=Array.from({length:size},(_,i)=>f.recordIds[i%2]);
    const inputBindings=Array.from({length:size},(_,i)=>id(`root-${size}-handle-${i}`));
    const terms={...f.terms,taskId:id(`root-${size}-task`),slot:id(`root-${size}-slot`),
      inputProtectedRecordIds,inputBindings};
    const expected=canonicalInputRoot(terms.taskId,inputProtectedRecordIds,inputBindings,ownersByRecord);
    const consentId=await f.policy.computeConsentId(terms);
    await wait(f.policy.createConsent(terms));
    const stored=await f.policy.getConsent(consentId);
    assert.equal(stored.inputRoot,expected.root);
    assert.equal(stored.actualInputCount,BigInt(size));
    assert.equal(stored.paddedInputCount,BigInt(expected.padded));
    const last=await f.policy.getConsentInput(consentId,size-1);
    assert.equal(last.protectedId,inputProtectedRecordIds[size-1]);
    assert.equal(last.inputBinding,inputBindings[size-1]);
    assert.equal(last.owner,ownersByRecord.get(inputProtectedRecordIds[size-1].toLowerCase()));
    assert.equal((await f.policy.getConsentRecord(consentId,0)).inputBinding,ethers.ZeroHash);
  }
});

test('nonlinear consent rejects omitted owners and binds input order and every handle',async t=>{
  const f=await baseFixture(t,{kind:'nonlinear'});
  await expectRevert(wait(f.policy.createConsent({...f.terms,taskId:id('empty-input-task'),
    slot:id('empty-input-slot'),inputProtectedRecordIds:[],inputBindings:[]})));
  await expectRevert(wait(f.policy.createConsent({...f.terms,taskId:id('too-many-input-task'),
    slot:id('too-many-input-slot'),inputProtectedRecordIds:Array(129).fill(f.recordIds[0]),
    inputBindings:Array.from({length:129},(_,i)=>id(`too-many-${i}`))})));
  const omitted={...f.terms,taskId:id('omitted-task'),slot:id('omitted-slot'),
    inputProtectedRecordIds:[f.recordIds[0],f.recordIds[0]],
    inputBindings:[id('omitted-a'),id('omitted-b')]};
  await expectRevert(wait(f.policy.createConsent(omitted)));
  const unlisted={...f.terms,taskId:id('unlisted-task'),slot:id('unlisted-slot'),
    protectedRecordIds:[f.recordIds[0]],inputProtectedRecordIds:[f.recordIds[0],f.recordIds[1]],
    inputBindings:[id('unlisted-a'),id('unlisted-b')]};
  await expectRevert(wait(f.policy.createConsent(unlisted)));

  const taskId=id('ordered-input-task'),bindings=[id('ordered-a'),id('ordered-b'),id('ordered-c')];
  const variants=[
    {...f.terms,taskId,slot:id('ordered-slot'),
      inputProtectedRecordIds:[f.recordIds[0],f.recordIds[1],f.recordIds[0]],inputBindings:bindings},
    {...f.terms,taskId,slot:id('reordered-slot'),
      inputProtectedRecordIds:[f.recordIds[1],f.recordIds[0],f.recordIds[0]],
      inputBindings:[bindings[1],bindings[0],bindings[2]]},
    {...f.terms,taskId,slot:id('mutated-slot'),
      inputProtectedRecordIds:[f.recordIds[0],f.recordIds[1],f.recordIds[0]],
      inputBindings:[bindings[0],id('mutated-handle'),bindings[2]]}
  ];
  const roots=[];
  for(const terms of variants){
    const consentId=await f.policy.computeConsentId(terms);
    await wait(f.policy.createConsent(terms));
    roots.push((await f.policy.getConsent(consentId)).inputRoot);
  }
  assert.equal(new Set(roots).size,3);
});

test('pre-consent and every exact-release owner approval are both required',async t=>{
  const f=await baseFixture(t,{approveConsent:false});
  await wait(f.policy.connect(f.ownerA).approveConsent(f.consentId));
  const signature=await signRelease(f,f.request);
  await expectRevert(wait(f.policy.connect(f.relayerA).proposeRelease(f.request,signature)));
  await wait(f.policy.connect(f.ownerB).approveConsent(f.consentId));
  await wait(f.policy.connect(f.relayerA).proposeRelease(f.request,signature));
  const releaseDigest=computeReleaseDigestV3(f.request);
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)));
  await wait(f.policy.connect(f.ownerA).approveRelease(f.request.requestId,releaseDigest));
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)));
  await wait(f.policy.connect(f.ownerB).approveRelease(f.request.requestId,releaseDigest));
  await wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature));
});

test('exact approval rejects a release digest from a swapped RPC state',async t=>{
  const f=await baseFixture(t);await propose(f);
  const expected=computeReleaseDigestV3(f.request);
  const swapped=computeReleaseDigestV3({...f.request,finalOutputDigest:id('rpc-swapped-output')});
  assert.notEqual(swapped,expected);
  await expectRevert(wait(f.policy.connect(f.ownerA).approveRelease(f.request.requestId,swapped)));
  const before=await f.policy.getRelease(f.request.requestId);
  assert.equal(before.approvalCount,0n);
  assert.equal(await f.policy.releaseApprovedBy(f.request.requestId,f.ownerA.address),false);
  const receipt=await (await f.policy.connect(f.ownerA).approveRelease(f.request.requestId,expected)).wait();
  const event=receipt.logs.map(log=>{try{return f.policy.interface.parseLog(log);}catch{return null;}})
    .find(log=>log?.name==='ReleaseApproved');
  assert.ok(event);assert.equal(event.args.releaseDigest,expected);
  assert.equal(await f.policy.releaseApprovedBy(f.request.requestId,f.ownerA.address),true);
});

test('a relayer needs the recipient EIP-712 signature over the exact request',async t=>{
  const f=await baseFixture(t);
  const wrong=await signRelease(f,f.request,f.attackerKey);
  await expectRevert(wait(f.policy.connect(f.relayerA).proposeRelease(f.request,wrong)));
  const signature=await propose(f);await approveRelease(f);
  const changed={...f.request,finalOutputDigest:id('substituted-output')};
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(changed,signature)));
  await wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature));
});

test('linear reservation requires accepted binding and every owner-bound protected record',async t=>{
  const f=await baseFixture(t),signature=await propose(f);await approveRelease(f);
  await wait(f.workflow.setBoundResult(f.terms.taskId,f.request.aggregateDigest,false));
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)));
  await wait(f.workflow.setBoundResult(f.terms.taskId,f.request.aggregateDigest,true));
  await wait(f.workflow.setRecord(1,f.ownerB.address,f.recordIds[1],id('wrong-ciphertext-binding')));
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)));
  await wait(f.workflow.setRecord(1,f.ownerB.address,f.recordIds[1],f.inputBindings[1]));
  await wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature));
});

test('nonlinear reservation checks accepted finality, availability, context, and the V2 output formula',async t=>{
  const f=await baseFixture(t,{kind:'nonlinear'});
  const signature=await signRelease(f,f.request);
  await wait(f.workflow.setStatus(2,0,false));
  await expectRevert(wait(f.policy.connect(f.relayerA).proposeRelease(f.request,signature)));
  assert.equal((await f.policy.getRelease(f.request.requestId)).exists,false);
  await wait(f.workflow.setStatus(3,1,false));
  await wait(f.policy.connect(f.relayerA).proposeRelease(f.request,signature));
  await approveRelease(f);
  await wait(f.workflow.setStatus(2,0,false));
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)));
  await wait(f.workflow.setStatus(3,1,false));
  await wait(f.availability.setCleared(false));
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)));
  await wait(f.availability.setCleared(true));
  await wait(f.verifier.setContext(f.terms.taskId,id('wrong-context')));
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)));
  await wait(f.verifier.setContext(f.terms.taskId,f.terms.contextDigest));
  await wait(f.availability.setTaskAuthorization(f.terms.taskId,
    {...f.nonlinearAuthorization,programRoot:id('wrong-program-root')}));
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)));
  await wait(f.availability.setTaskAuthorization(f.terms.taskId,
    {...f.nonlinearAuthorization,inputRoot:id('wrong-input-root')}));
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)));
  await wait(f.availability.setTaskAuthorization(f.terms.taskId,
    {...f.nonlinearAuthorization,inputCount:f.nonlinearAuthorization.inputCount+1n}));
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)));
  await wait(f.availability.setTaskAuthorization(f.terms.taskId,
    {...f.nonlinearAuthorization,consumed:false}));
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)));
  await wait(f.availability.setTaskAuthorization(f.terms.taskId,f.nonlinearAuthorization));
  const old=await f.workflow.resultHash();await wait(f.workflow.setResultBinding(id('wrong-v2-result'),await f.workflow.operatorTraceRoot(),await f.workflow.leafCount()));
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)));
  await wait(f.workflow.setResultBinding(old,await f.workflow.operatorTraceRoot(),await f.workflow.leafCount()));
  await wait(f.workflow.setLegacyVerifiers(f.attacker.address,ethers.ZeroAddress));
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)));
  await wait(f.workflow.setLegacyVerifiers(ethers.ZeroAddress,f.attacker.address));
  await expectRevert(wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)));
  await wait(f.workflow.setLegacyVerifiers(ethers.ZeroAddress,ethers.ZeroAddress));
  await wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature));
});

for(const kind of ['linear','nonlinear']) test(`${kind} KMS submit authorization compares every field in the pinned static tuple`,async t=>{
  const f=await baseFixture(t,{kind}),signature=await propose(f);await approveRelease(f);
  const authorization=kmsSubmitAuthorization(f);
  assert.equal(await f.policy.isSubmitAuthorized(authorization),false);
  await wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature));
  assert.equal(await f.policy.isSubmitAuthorized(authorization),true);
  assert.equal(Object.keys(authorization).length,25);
  const addressFields=new Set(['recipient','workflow','policy']);
  const integerFields=new Set(['chainId','workflowKind']);
  for(const field of Object.keys(authorization)){
    const replacement=addressFields.has(field)?f.attacker.address:
      integerFields.has(field)?(field==='chainId'?1n:(kind==='linear'?2:1)):id(`changed-${field}`);
    assert.equal(await f.policy.isSubmitAuthorized({...authorization,[field]:replacement}),false,field);
  }
});

for(const kind of ['linear','nonlinear']) {
  test(`${kind} owner computation approvals do not transfer to changed consent terms`,async t=>{
    const f=await baseFixture(t,{kind});
    const variants={
      workflow:f.policy.target,taskId:id('other-task'),contextDigest:id('other-context'),
      programDigest:id('other-program'),programRoot:id('other-program-root'),
      profileDigest:id('other-profile'),keysetDigest:id('other-keyset'),keyId:id('other-key'),
      keyEpoch:id('other-epoch'),mpcContext:id('other-mpc'),outputType:id('other-output-type'),
      recipient:f.attacker.address,slot:id('other-slot'),
      inputBindings:[id('other-input'),f.inputBindings[1]]
    };
    for(const [field,value] of Object.entries(variants)){
      const terms={...f.terms,[field]:value};
      const consentId=await f.policy.computeConsentId(terms);
      assert.notEqual(consentId,f.consentId,field);
      await wait(f.policy.connect(f.attacker).createConsent(terms));
      assert.equal((await f.policy.getConsent(consentId)).approvalCount,0n,field);
      for(const owner of f.owners)assert.equal(await f.policy.consentApprovedBy(consentId,owner.address),false,field);
      const request={...f.request,consentId,recipient:terms.recipient};
      const signer=field==='recipient'?f.attackerKey:f.recipientKey;
      const signature=await signRelease(f,request,signer);
      await assert.rejects(f.policy.proposeRelease.staticCall(request,signature),
        error=>error.data===f.policy.interface.getError('ConsentNotApproved').selector,field);
    }
    await expectRevert(f.policy.connect(f.attacker).approveConsent.staticCall(f.consentId));
    assert.equal((await f.policy.getConsent(f.consentId)).approvalCount,2n);
  });

  test(`${kind} a new exact request needs new owner approvals and cannot reuse a consumed slot`,async t=>{
    const f=await baseFixture(t,{kind});
    const originalSignature=await propose(f);await approveRelease(f);
    const requestKey=id('new-request-key');
    const request={...f.request,requestId:id('new-request'),requestKey,resultQueryDigest:requestKey,
      submitWireDigest:id('new-submit-wire'),recipientEncryptionKeyDigest:id('new-recipient-key')};
    await assert.rejects(f.policy.proposeRelease.staticCall(request,originalSignature),
      error=>error.data===f.policy.interface.getError('InvalidRecipientSignature').selector);
    const signature=await propose(f,request);
    assert.equal((await f.policy.getRelease(request.requestId)).approvalCount,0n);
    await assert.rejects(f.policy.reserveRelease.staticCall(request,signature),
      error=>error.data===f.policy.interface.getError('ReleaseNotApproved').selector);
    await expectRevert(f.policy.connect(f.attacker).approveRelease.staticCall(
      request.requestId,computeReleaseDigestV3(request)));
    await approveRelease(f,request,[f.ownerA]);
    await assert.rejects(f.policy.reserveRelease.staticCall(request,signature),
      error=>error.data===f.policy.interface.getError('ReleaseNotApproved').selector);
    await approveRelease(f,request,[f.ownerB]);
    await wait(f.policy.connect(f.attacker).reserveRelease(request,signature));
    assert.equal((await f.policy.getRelease(request.requestId)).recipient,f.recipient.address);
    assert.equal(await f.policy.requestBySlot(f.terms.slot),request.requestId);
    await assert.rejects(f.policy.reserveRelease.staticCall(f.request,originalSignature),
      error=>error.data===f.policy.interface.getError('SlotAlreadyUsed').selector);
    for(const record of f.recordIds)assert.equal((await f.policy.protectedRecords(record)).spent,1n);
  });

  test(`${kind} recipient signatures cannot be reused from another chain or policy`,async t=>{
    const f=await baseFixture(t,{kind});
    const otherPolicy=await deploy(artifacts.ReleasePolicyRegistry,f.deployer);
    const domain={name:'VCFHE-Onchain-Release-Policy',version:'3',chainId:31337,
      verifyingContract:f.policy.target};
    for(const changed of [{...domain,chainId:1},{...domain,verifyingContract:otherPolicy.target}]){
      const signature=await f.recipientKey.signTypedData(changed,RELEASE_TYPES,f.request);
      await assert.rejects(f.policy.proposeRelease.staticCall(f.request,signature),
        error=>error.data===f.policy.interface.getError('InvalidRecipientSignature').selector);
    }
    assert.notEqual(await otherPolicy.computeConsentId({...f.terms,domain:await otherPolicy.policyDomain()}),f.consentId);
    assert.equal((await otherPolicy.getConsent(f.consentId)).exists,false);
    const signature=await propose(f);await approveRelease(f);
    await wait(f.policy.connect(f.relayerB).reserveRelease(f.request,signature));
  });
}

test('the result query is exact, request-key equality is mandatory, and failed KMS work cannot refund budgets',async t=>{
  const f=await baseFixture(t,{limit:1});
  const unequal={...f.request,requestId:id('unequal-request'),resultQueryDigest:id('unequal-query')};
  await expectRevert(wait(f.policy.proposeRelease(unequal,await signRelease(f,unequal))));
  const signature=await propose(f);await approveRelease(f);
  assert.equal(await f.policy.isResultAuthorized(
    f.request.requestId,f.request.requestKey,f.request.resultQueryDigest),false);
  await wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature));
  assert.equal(await f.policy.isResultAuthorized(
    f.request.requestId,f.request.requestKey,f.request.resultQueryDigest),true);
  assert.equal(await f.policy.isResultAuthorized(
    id('wrong-request'),f.request.requestKey,f.request.resultQueryDigest),false);
  assert.equal(await f.policy.isResultAuthorized(
    f.request.requestId,id('wrong-key'),f.request.resultQueryDigest),false);
  assert.equal(await f.policy.isResultAuthorized(
    f.request.requestId,f.request.requestKey,id('wrong-result-query')),false);
  await expectRevert(wait(f.policy.connect(f.relayerB).reserveRelease(f.request,signature)));
  for(const record of f.recordIds)assert.equal((await f.policy.protectedRecords(record)).spent,1n);

  const terms={...f.terms,taskId:id('second-task'),slot:id('second-slot')};
  await wait(f.workflow.setBoundResult(terms.taskId,id('second-aggregate'),true));
  const consentId=await f.policy.computeConsentId(terms);await wait(f.policy.createConsent(terms));
  for(const owner of f.owners)await wait(f.policy.connect(owner).approveConsent(consentId));
  const secondKey=id('second-request-key');
  const request={...f.request,consentId,requestId:id('second-request'),requestKey:secondKey,
    submitWireDigest:id('second-submit'),resultQueryDigest:secondKey,finalOutputDigest:id('second-output'),
    aggregateDigest:id('second-aggregate')};
  const signature2=await signRelease(f,request);await wait(f.policy.proposeRelease(request,signature2));
  await approveRelease(f,request);
  await expectRevert(wait(f.policy.reserveRelease(request,signature2)));
  assert.equal(await f.policy.isResultAuthorized(request.requestId,request.requestKey,request.resultQueryDigest),false);
});

test('concurrent relayers cannot reserve the same request twice',async t=>{
  const f=await baseFixture(t),signature=await propose(f);await approveRelease(f);
  const outcomes=await Promise.allSettled([
    wait(f.policy.connect(f.relayerA).reserveRelease(f.request,signature)),
    wait(f.policy.connect(f.relayerB).reserveRelease(f.request,signature))
  ]);
  assert.equal(outcomes.filter(row=>row.status==='fulfilled').length,1);
  assert.equal((await f.policy.protectedRecords(f.recordIds[0])).spent,1n);
});

test('GroupedLinearVerification exposes immutable owner-bound protected-record bindings',async t=>{
  const {wallets}=await chain(t),[deployer,ownerA,ownerB,attacker]=wallets;
  const grouped=await deploy(groupedArtifacts.GroupedLinearVerification,deployer,
    [2,0,id('epoch'),id('profile'),id('keyset'),[ownerA.address,ownerB.address]],{value:ethers.parseEther('1')});
  const protectedId=id('grouped-record-a'),ciphertext=id('grouped-ciphertext-a');
  await expectRevert(wait(grouped.connect(attacker).bindProtectedRecord(0,protectedId,ciphertext)));
  await wait(grouped.connect(ownerA).bindProtectedRecord(0,protectedId,ciphertext));
  assert.deepEqual(Array.from(await grouped.getProtectedRecordBinding(0)),[protectedId,ciphertext,true]);
  await expectRevert(wait(grouped.connect(ownerA).bindProtectedRecord(0,protectedId,id('reencrypted'))));
  await expectRevert(wait(grouped.connect(ownerB).bindProtectedRecord(1,protectedId,id('alias'))));
});
