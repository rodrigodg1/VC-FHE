import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {Readable} from 'node:stream';
import {fileURLToPath} from 'node:url';
import {
 compileCanonicalWorkflowArtifacts,
 readBoundedStdin,
 requireWorkflowObservationQuorum,
 WORKFLOW_AUTH_CLI_DEADLINE_MS,
 WORKFLOW_AUTH_CLI_MAX_STDIN_BYTES,
 validateCanonicalNonlinearWiring,
 validateDirectDeploymentObservation,
 validatePolicyConsent,
 validateWorkflowAuthCliRequest,
 validateWorkflowRpcUrls,
 verifyCanonicalWorkflowDeployment
} from './workflow-auth.mjs';

const here=path.dirname(fileURLToPath(import.meta.url));
const require=createRequire(path.resolve(here,'../../BN254-Signatures/package.json'));
const {ethers}=require('ethers');
const hash=value=>'0x'+BigInt(value).toString(16).padStart(64,'0');
const addresses=Array.from({length:12},(_,index)=>ethers.getAddress('0x'+(index+1).toString(16).padStart(40,'0')));
const urls=Array.from({length:4},(_,index)=>`http://node${index+1}:8545`);

function authorization(overrides={}){
 return{consentId:hash(1),policyDomain:hash(2),taskId:hash(3),contextDigest:hash(4),programDigest:hash(5),
  programRoot:hash(6),profileDigest:hash(7),keysetDigest:hash(8),keyId:hash(9),keyEpoch:hash(10),
  mpcContext:hash(11),outputType:hash(12),slot:hash(13),inputBindingsDigest:hash(14),
  finalOutputDigest:hash(15),aggregateDigest:hash(15),policy:addresses[0],workflow:addresses[1],
  recipient:addresses[2],chainId:46853,workflowKind:2,...overrides};
}

test('canonical workflow artifacts use the two production compiler profiles',async()=>{
 const artifacts=await compileCanonicalWorkflowArtifacts();
 assert.deepEqual([...artifacts.NonlinearSourceNames].sort(),[
  'AuthenticatedTraceAvailability.sol','BountyTraceAvailability.sol','CanonicalBountyFHEDisputeGame.sol','CanonicalExecutionBaseline.sol','CanonicalFHEDisputeGame.sol','CanonicalLeafVerifier.sol',
  'FhevmObjectiveMicroVerifier.sol','LegacyConfigurableDisputeGame.sol','LocalFhevmRuntime.sol','TraceAvailability.sol','UniformParticipantSampler.sol',
  'VerifiableFHEDisputeGame.sol','ZamaKMSVerdictVerifier.sol'
 ]);
 assert.match(artifacts.GroupedLinearVerification.compilerVersion,/^0\.8\.20\+/);
 assert.equal(artifacts.GroupedLinearVerification.settings.optimizer.enabled,false);
 assert.equal(artifacts.GroupedLinearVerification.settings.evmVersion,'london');
 for(const name of ['ObjectiveMicroVerifier','CanonicalFHEDisputeGame','AuthenticatedTraceAvailability','CanonicalLeafVerifier','CanonicalBountyFHEDisputeGame','BountyTraceAvailability']){
  assert.match(artifacts[name].compilerVersion,/^0\.8\.24\+/);
  assert.equal(artifacts[name].settings.evmVersion,'paris');
  assert.equal(artifacts[name].settings.viaIR,true);
  assert.deepEqual(artifacts[name].settings.optimizer,{enabled:true,runs:1});
  assert.ok(artifacts[name].bytecode.length>100&&artifacts[name].deployedBytecode.length>10);
 }
});

function deploymentFixture(){
 const artifact={abi:[{type:'constructor',inputs:[{name:'value',type:'uint256'}],stateMutability:'nonpayable'}],
  bytecode:'0x6001',deployedBytecode:'0x6002',immutableReferences:{}};
 const from=addresses[3],nonce='0x5',address=ethers.getCreateAddress({from,nonce:5}),transactionHash=hash(100),
  args=[7],input=ethers.concat([artifact.bytecode,new ethers.Interface(artifact.abi).encodeDeploy(args)]),
  blockNumber='0xa',blockHash=hash(101);
 return{artifact,address,transactionHash,args,expectedChainId:46853,viewNumber:12,expectedValue:0n,
  tx:{hash:transactionHash,to:null,input,blockNumber,blockHash,chainId:ethers.toQuantity(46853),from,nonce,value:'0x0'},
  receipt:{transactionHash,status:'0x1',blockNumber,blockHash,contractAddress:address,from,to:null},
  includedBlock:{number:blockNumber,hash:blockHash},code:artifact.deployedBytecode};
}

test('direct deployment validation binds creation bytecode, constructor, receipt and runtime',()=>{
 const fixture=deploymentFixture(),result=validateDirectDeploymentObservation(fixture);
 assert.equal(result.address,fixture.address);
 assert.equal(result.deploymentBlock,10);
 for(const [name,change,pattern] of [
  ['creation bytecode',value=>{value.tx.input='0x6003';},/bytecode or constructor/],
  ['constructor',value=>{value.args=[8];},/bytecode or constructor/],
  ['receipt',value=>{value.receipt.status='0x0';},/deployment failed/],
  ['contract address',value=>{value.receipt.contractAddress=addresses[8];},/address changed/],
  ['runtime',value=>{value.code='0x6003';},/runtime differs/]
 ]){
  const altered=structuredClone(fixture);change(altered);
  assert.throws(()=>validateDirectDeploymentObservation(altered),pattern,name);
 }
});

test('nonlinear wiring accepts only the exact canonical modules and windows',()=>{
 const auth=authorization(),manifest={game:addresses[1],availability:addresses[4],verifier:addresses[5],
  objective:addresses[6],canonicalSigners:[addresses[7],addresses[8],addresses[9]]};
 const state={secure:true,objective:manifest.objective,availabilityAddress:manifest.availability,
  verifierAddress:manifest.verifier,fhevm:ethers.ZeroAddress,kms:ethers.ZeroAddress,
  commitWindow:'120',openWindow:'120',challengeWindow:'120',disclosureWindow:'120',
 availabilityGame:manifest.game,verifierGame:manifest.game,profile:auth.profileDigest,threshold:'2',
  signerChecks:[true,true,true],context:auth.contextDigest,
  domainSeparator:ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
   ['bytes32','bytes32','bytes32','uint256','address'],[ethers.id('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
    ethers.id('VCFHE-Canonical-Execution'),ethers.id('1'),auth.chainId,manifest.verifier]))};
 assert.equal(validateCanonicalNonlinearWiring({state,authorization:auth,manifest,expectedWindowSeconds:120}),true);
 assert.throws(()=>validateCanonicalNonlinearWiring({state:{...state,availabilityAddress:addresses[10]},
  authorization:auth,manifest,expectedWindowSeconds:120}),/availability module changed/);
 assert.throws(()=>validateCanonicalNonlinearWiring({state:{...state,signerChecks:[true,true,false]},
  authorization:auth,manifest,expectedWindowSeconds:120}),/signer set changed/);
 assert.throws(()=>validateCanonicalNonlinearWiring({state:{...state,commitWindow:'121'},
  authorization:auth,manifest,expectedWindowSeconds:120}),/window changed/);
});

test('workflow observation quorum tolerates one fault and rejects a two-two split',()=>{
 const canonical={blockNumber:50,blockHash:hash(50),workflow:addresses[1]},forged={...canonical,workflow:addresses[2]};
 const accepted=requireWorkflowObservationQuorum([
  {index:0,value:canonical},{index:1,value:structuredClone(canonical)},
  {index:2,value:structuredClone(canonical)},{index:3,value:forged}
 ]);
 assert.deepEqual(accepted.supporters,[0,1,2]);
 assert.throws(()=>requireWorkflowObservationQuorum([
  {index:0,value:canonical},{index:1,value:canonical},{index:2,value:forged},{index:3,value:forged}
 ]),/fewer than three/);
 assert.throws(()=>requireWorkflowObservationQuorum([{index:0,value:canonical},{index:1,value:canonical}]),/fewer than three/);
});

test('policy consent domain is compared with the canonical policy domain',()=>{
 const auth={...authorization(),chainId:46853n};
 const consent={exists:true,domain:auth.policyDomain,chainId:auth.chainId,workflowKind:auth.workflowKind,
  approvalCount:2n,requiredOwnerCount:2n};
 for(const field of ['workflow','taskId','contextDigest','programDigest','programRoot','profileDigest','keysetDigest',
  'keyId','keyEpoch','mpcContext','outputType','recipient','slot','inputBindingsDigest'])consent[field]=auth[field];
 assert.equal(auth.domain,undefined);
 assert.doesNotThrow(()=>validatePolicyConsent(consent,auth));
 assert.throws(()=>validatePolicyConsent({...consent,domain:hash(99)},auth),/consent domain changed/);
});

test('RPC endpoint and manifest schemas are strict, and every RPC call is bounded',async()=>{
 assert.deepEqual(validateWorkflowRpcUrls(urls),urls);
 assert.throws(()=>validateWorkflowRpcUrls(urls.slice(0,3)),/exactly four/);
 assert.throws(()=>validateWorkflowRpcUrls([urls[0],urls[1],urls[2],urls[2]]),/distinct/);
 const auth=authorization({workflowKind:1,aggregateDigest:hash(16)});
 const base={schema:'vcfhe-workflow-deployment-v1',kind:'grouped-linear',workflow:auth.workflow,
  deployments:{workflow:hash(20)}};
 await assert.rejects(verifyCanonicalWorkflowDeployment({authorization:auth,workflowManifest:{...base,unexpected:true},
  rpcUrls:urls,blockNumber:10,blockHash:hash(30),expectedWindowSeconds:120}),/unexpected grouped-linear/);
 class HungRpc{send(){return new Promise(()=>{});}destroy(){}}
 const started=Date.now();
 await assert.rejects(verifyCanonicalWorkflowDeployment({authorization:auth,workflowManifest:base,rpcUrls:urls,
  blockNumber:10,blockHash:hash(30),expectedWindowSeconds:120,timeoutMs:20,providerFactory:()=>new HungRpc()}),
  /fewer than three/);
 assert.ok(Date.now()-started<1000,'per-call timeout did not bound unavailable validator RPCs');
});

test('CLI accepts only the documented JSON API fields and fails without stdout evidence',()=>{
 assert.equal(WORKFLOW_AUTH_CLI_DEADLINE_MS,120_000);
 const auth=authorization({workflowKind:1,aggregateDigest:hash(16)}),request={authorization:auth,
  workflowManifest:{schema:'vcfhe-workflow-deployment-v1',kind:'grouped-linear',workflow:auth.workflow,
   deployments:{workflow:hash(20)}},rpcUrls:urls,blockNumber:10,blockHash:hash(30),expectedWindowSeconds:120,
  timeoutMs:5000};
 assert.equal(validateWorkflowAuthCliRequest(request),request);
 assert.throws(()=>validateWorkflowAuthCliRequest({...request,sourcePath:'untrusted.sol'}),/unsupported field/);
 const file=path.join(here,'workflow-auth.mjs'),failed=spawnSync(process.execPath,[file],{
  input:JSON.stringify({...request,executable:'/tmp/attacker'}),encoding:'utf8',timeout:30_000});
 assert.notEqual(failed.status,0);
 assert.equal(failed.stdout,'');
 assert.match(failed.stderr,/unsupported field/);
});

test('CLI rejects oversized input before parsing or starting a worker',async()=>{
 assert.equal(await readBoundedStdin(Readable.from([Buffer.from('{}')])),'{}');
 await assert.rejects(readBoundedStdin(Readable.from([
  Buffer.alloc(WORKFLOW_AUTH_CLI_MAX_STDIN_BYTES),Buffer.from('x')
 ])),/exceeds its byte limit/);
});
