import assert from 'node:assert/strict';
import {nonlinearManifestProfile} from './nonlinear-profile.mjs';
import fs from 'node:fs/promises';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {Worker,isMainThread,parentPort,workerData} from 'node:worker_threads';

const here=path.dirname(fileURLToPath(import.meta.url));
const thresholdRoot=path.resolve(here,'..');
const vcFheRoot=path.resolve(thresholdRoot,'..');
const nonlinearProjectRoot=path.join(vcFheRoot,'fhe-pod');
const nonlinearContractsDir=path.join(nonlinearProjectRoot,'contracts','src');
const linearRequire=createRequire(path.join(vcFheRoot,'BN254-Signatures','package.json'));
const nonlinearRequire=createRequire(path.join(vcFheRoot,'fhe-pod','package.json'));
const {ethers}=linearRequire('ethers');
const linearSolc=linearRequire('solc');
const nonlinearSolc=nonlinearRequire('solc');

export const WORKFLOW_RPC_COUNT=4;
export const WORKFLOW_RPC_QUORUM=3;
export const WORKFLOW_AUTH_CLI_DEADLINE_MS=120_000;
export const WORKFLOW_AUTH_CLI_MAX_STDIN_BYTES=1024*1024;
const ZERO_ADDRESS=ethers.ZeroAddress.toLowerCase();
const INPUT_RECORD_TYPEHASH=ethers.id(
 'FHE_POD_INPUT_RECORD_V1(address owner,bytes32 ciphertextHandle,bytes32 metadataHash)');
const OUTPUT_BINDING_V2_TYPEHASH=ethers.id(
 'FHE_POD_OUTPUT_BINDING_V2(bytes32 taskId,bytes32 operatorTraceRoot,uint32 leafCount,bytes32 terminalOutputHandle,bytes32 outputAttestationHash)');
const EIP712_DOMAIN_TYPEHASH=ethers.id('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)');
const coder=ethers.AbiCoder.defaultAbiCoder();

let compiledPromise;

function hardErrors(output){
 return(output.errors??[]).filter(entry=>entry.severity==='error');
}

function resolveNonlinearSolidityImport(importPath){
 const nodeModulesDir=path.join(nonlinearProjectRoot,'node_modules');
 const fhevmSolidityDir=path.join(nodeModulesDir,'@fhevm','solidity');
 const candidates=[];
 if(importPath.startsWith('@'))candidates.push(path.join(nodeModulesDir,importPath));
 for(const base of [nonlinearContractsDir,nonlinearProjectRoot,nodeModulesDir,fhevmSolidityDir,
  path.join(fhevmSolidityDir,'lib'),path.join(fhevmSolidityDir,'config'),
  path.join(fhevmSolidityDir,'lib','cryptography')])candidates.push(path.resolve(base,importPath));
 for(const candidate of candidates){
  try{return{contents:readFileSync(candidate,'utf8')}}catch{}
 }
 return{error:`Solidity import not found: ${importPath}`};
}

function artifact(output,sourceName,contractName,compilerVersion,settings){
 const value=output.contracts?.[sourceName]?.[contractName];
 if(!value?.evm?.bytecode?.object||!value?.evm?.deployedBytecode?.object)
  throw Error(`missing ${contractName} compiler artifact`);
 return Object.freeze({sourceName,contractName,compilerVersion,settings,
  abi:value.abi,bytecode:'0x'+value.evm.bytecode.object,
  deployedBytecode:'0x'+value.evm.deployedBytecode.object,
  immutableReferences:value.evm.deployedBytecode.immutableReferences??{}});
}

async function compileCanonicalWorkflowArtifactsOnce(){
 const linearSettings={optimizer:{enabled:false},evmVersion:'london',
  outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.deployedBytecode.object',
   'evm.deployedBytecode.immutableReferences']}}};
 const linearSources={};
 for(const [name,file] of [
  ['GroupedLinearVerification.sol',path.join(thresholdRoot,'contracts','GroupedLinearVerification.sol')],
  ['MKLHS-Verification.sol',path.join(vcFheRoot,'BN254-Signatures','contract','MKLHS-Verification.sol')]
 ])linearSources[name]={content:await fs.readFile(file,'utf8')};
 const linearOutput=JSON.parse(linearSolc.compile(JSON.stringify({language:'Solidity',sources:linearSources,
  settings:linearSettings})));
 const linearErrors=hardErrors(linearOutput);
 if(linearErrors.length)throw Error(linearErrors.map(entry=>entry.formattedMessage).join('\n'));

 const nonlinearSettings={evmVersion:'paris',viaIR:true,optimizer:{enabled:true,runs:1},
  metadata:{bytecodeHash:'none'},outputSelection:{'*':{'*':['abi','evm.bytecode.object',
   'evm.deployedBytecode.object','evm.deployedBytecode.immutableReferences']}}};
 const nonlinearSources={};
 const nonlinearEntries=await fs.readdir(nonlinearContractsDir,{withFileTypes:true});
 for(const entry of nonlinearEntries){
  if(entry.isFile()&&entry.name.endsWith('.sol'))
   nonlinearSources[entry.name]={content:await fs.readFile(path.join(nonlinearContractsDir,entry.name),'utf8')};
 }
 const nonlinearOutput=JSON.parse(nonlinearSolc.compile(JSON.stringify({language:'Solidity',
  sources:nonlinearSources,settings:nonlinearSettings}),{import:resolveNonlinearSolidityImport}));
 const nonlinearErrors=hardErrors(nonlinearOutput);
 if(nonlinearErrors.length)throw Error(nonlinearErrors.map(entry=>entry.formattedMessage).join('\n'));

 const policySettings={optimizer:{enabled:true,runs:200},viaIR:true,evmVersion:'london',
  metadata:{bytecodeHash:'none',appendCBOR:false},outputSelection:{'*':{'*':['abi','evm.bytecode.object',
   'evm.deployedBytecode.object','evm.deployedBytecode.immutableReferences']}}};
 const policySourceName='OnChainReleasePolicy.sol';
 const policySource=await fs.readFile(path.join(thresholdRoot,'contracts',policySourceName),'utf8');
 const policyOutput=JSON.parse(linearSolc.compile(JSON.stringify({language:'Solidity',
  sources:{[policySourceName]:{content:policySource}},settings:policySettings})));
 const policyErrors=hardErrors(policyOutput);
 if(policyErrors.length)throw Error(policyErrors.map(entry=>entry.formattedMessage).join('\n'));

 return Object.freeze({
  GroupedLinearVerification:artifact(linearOutput,'GroupedLinearVerification.sol','GroupedLinearVerification',
   linearSolc.version(),linearSettings),
  ObjectiveMicroVerifier:artifact(nonlinearOutput,'VerifiableFHEDisputeGame.sol','ObjectiveMicroVerifier',
   nonlinearSolc.version(),nonlinearSettings),
  CanonicalBountyFHEDisputeGame:artifact(nonlinearOutput,'CanonicalBountyFHEDisputeGame.sol','CanonicalBountyFHEDisputeGame',
   nonlinearSolc.version(),nonlinearSettings),
  BountyTraceAvailability:artifact(nonlinearOutput,'BountyTraceAvailability.sol','BountyTraceAvailability',
   nonlinearSolc.version(),nonlinearSettings),
  CanonicalFHEDisputeGame:artifact(nonlinearOutput,'CanonicalFHEDisputeGame.sol','CanonicalFHEDisputeGame',
   nonlinearSolc.version(),nonlinearSettings),
  AuthenticatedTraceAvailability:artifact(nonlinearOutput,'AuthenticatedTraceAvailability.sol','AuthenticatedTraceAvailability',
   nonlinearSolc.version(),nonlinearSettings),
 CanonicalLeafVerifier:artifact(nonlinearOutput,'CanonicalLeafVerifier.sol','CanonicalLeafVerifier',
   nonlinearSolc.version(),nonlinearSettings),
  ReleasePolicyRegistry:artifact(policyOutput,policySourceName,'ReleasePolicyRegistry',linearSolc.version(),policySettings),
  NonlinearSourceNames:Object.freeze(Object.keys(nonlinearSources))
 });
}

export function compileCanonicalWorkflowArtifacts(){
 if(!compiledPromise)compiledPromise=compileCanonicalWorkflowArtifactsOnce().catch(error=>{
  compiledPromise=undefined;throw error;
 });
 return compiledPromise;
}

const lower=value=>String(value).toLowerCase();
const quantity=value=>Number(BigInt(value));
const asBigInt=value=>BigInt(value);
const isBytes32=value=>ethers.isHexString(value,32);
const same=(actual,expected,label)=>assert.equal(lower(actual),lower(expected),label);

function endpointKey(value){
 const url=new URL(value);
 if(!['http:','https:'].includes(url.protocol)||url.username||url.password||url.hash||url.search||url.pathname!=='/')
  throw Error('invalid workflow validator RPC URL');
 url.hostname=url.hostname.toLowerCase();
 if((url.protocol==='http:'&&url.port==='80')||(url.protocol==='https:'&&url.port==='443'))url.port='';
 return url.origin;
}

export function validateWorkflowRpcUrls(values){
 if(!Array.isArray(values)||values.length!==WORKFLOW_RPC_COUNT)
  throw Error('workflow authentication requires exactly four validator RPC URLs');
 const normalized=values.map(endpointKey);
 if(new Set(normalized).size!==WORKFLOW_RPC_COUNT)
  throw Error('workflow validator RPC URLs must be distinct');
 return normalized;
}

function canonical(value){
 if(typeof value==='bigint')return ['bigint',value.toString()];
 if(value instanceof Uint8Array)return ['bytes',Buffer.from(value).toString('hex')];
 if(Array.isArray(value))return value.map(canonical);
 if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])]));
 if(value===undefined)throw Error('workflow observation contains undefined');
 return value;
}

const observationKey=value=>JSON.stringify(canonical(value));

export function requireWorkflowObservationQuorum(rows){
 const groups=new Map();
 rows.forEach(({index,value})=>{
  let key;try{key=observationKey(value);}catch{return;}
  const group=groups.get(key)??{value,indexes:[]};group.indexes.push(index);groups.set(key,group);
 });
 const winners=[...groups.values()].filter(group=>group.indexes.length>=WORKFLOW_RPC_QUORUM);
 if(winners.length!==1)throw Error('workflow authentication: fewer than three validator RPCs returned the same verified observation');
 return Object.freeze({observation:winners[0].value,supporters:Object.freeze([...winners[0].indexes])});
}

function runtimeWithoutImmutables(code,references){
 assert.ok(ethers.isHexString(code),'invalid runtime bytecode');
 const bytes=Buffer.from(code.slice(2),'hex');
 for(const locations of Object.values(references??{}))for(const {start,length} of locations){
  assert.ok(Number.isSafeInteger(start)&&Number.isSafeInteger(length)&&length>0&&start+length<=bytes.length,
   'invalid compiler immutable reference');
  bytes.fill(0,start,start+length);
 }
 return '0x'+bytes.toString('hex');
}

export function validateDirectDeploymentObservation({artifact,address,transactionHash,args,expectedChainId,
 viewNumber,tx,receipt,includedBlock,code,expectedValue=0n}){
 assert.ok(ethers.isAddress(address)&&isBytes32(transactionHash),'invalid workflow deployment reference');
 assert.ok(tx&&receipt&&includedBlock,'workflow deployment evidence is incomplete');
 same(tx.hash,transactionHash,'workflow deployment transaction changed');
 same(receipt.transactionHash??receipt.hash,transactionHash,'workflow deployment receipt changed');
 assert.equal(tx.to??null,null,'workflow deployment transaction has a recipient');
 assert.equal(receipt.to??null,null,'workflow deployment receipt has a recipient');
 assert.equal(quantity(receipt.status),1,'workflow deployment failed');
 assert.equal(asBigInt(tx.chainId),asBigInt(expectedChainId),'workflow deployment is on another chain');
 assert.equal(asBigInt(tx.value??0),asBigInt(expectedValue),'workflow deployment value changed');
 const txBlock=quantity(tx.blockNumber),receiptBlock=quantity(receipt.blockNumber);
 assert.ok(txBlock<=viewNumber,'workflow deployment is outside the pinned view');
 assert.equal(receiptBlock,txBlock,'workflow deployment transaction/receipt block differs');
 same(tx.blockHash,receipt.blockHash,'workflow deployment transaction/receipt hash differs');
 assert.equal(quantity(includedBlock.number),txBlock,'workflow deployment block unavailable');
 same(includedBlock.hash,tx.blockHash,'workflow deployment block changed');
 same(receipt.contractAddress,address,'workflow deployment address changed');
 same(receipt.from,tx.from,'workflow deployment sender changed');
 const expectedAddress=ethers.getCreateAddress({from:tx.from,nonce:asBigInt(tx.nonce)});
 same(expectedAddress,address,'workflow deployment address is not the direct CREATE result');
 const constructorData=new ethers.Interface(artifact.abi).encodeDeploy(args);
 same(tx.input??tx.data,ethers.concat([artifact.bytecode,constructorData]),
  'workflow deployment bytecode or constructor changed');
 assert.notEqual(code,'0x','workflow runtime code unavailable');
 same(runtimeWithoutImmutables(code,artifact.immutableReferences),
  runtimeWithoutImmutables(artifact.deployedBytecode,artifact.immutableReferences),
  'workflow runtime differs from the canonical local source');
 return Object.freeze({address:ethers.getAddress(address),transactionHash:lower(transactionHash),
  deployer:ethers.getAddress(tx.from),deploymentBlock:txBlock,deploymentBlockHash:lower(tx.blockHash),
  runtimeCodeHash:ethers.keccak256(code)});
}

function workflowKind(value){
 if(value===1||value===1n||value==='1'||value==='linear'||value==='GroupedLinear')return 1;
 if(value===2||value===2n||value==='2'||value==='nonlinear'||value==='CanonicalNonlinear')return 2;
 throw Error('unsupported workflow kind');
}

function requireAuthorization(value){
 assert.ok(value&&typeof value==='object','workflow authorization is required');
 for(const field of ['consentId','policyDomain','taskId','contextDigest','programDigest','programRoot','profileDigest',
  'keysetDigest','keyId','keyEpoch','mpcContext','outputType','slot','inputBindingsDigest','finalOutputDigest','aggregateDigest'])
  assert.ok(isBytes32(value[field]),`invalid workflow authorization ${field}`);
 for(const field of ['policy','workflow','recipient'])assert.ok(ethers.isAddress(value[field]),`invalid workflow authorization ${field}`);
 assert.ok(value.chainId!==undefined,'workflow authorization chainId is required');
 return Object.freeze({...value,workflowKind:workflowKind(value.workflowKind),chainId:asBigInt(value.chainId),
  policy:ethers.getAddress(value.policy),workflow:ethers.getAddress(value.workflow),recipient:ethers.getAddress(value.recipient)});
}

function requireManifest(manifest,authorization){
 assert.ok(manifest&&typeof manifest==='object','workflow deployment manifest is required');
 assert.equal(manifest.schema,'vcfhe-workflow-deployment-v1','unsupported workflow deployment manifest schema');
 if(authorization.workflowKind===1){
  assert.equal(manifest.kind,'grouped-linear','workflow deployment manifest kind changed');
  assert.deepEqual(Object.keys(manifest).sort(),['deployments','kind','schema','workflow'],
   'unexpected grouped-linear workflow manifest field');
  assert.deepEqual(Object.keys(manifest.deployments??{}).sort(),['workflow'],
   'unexpected grouped-linear deployment field');
  const address=manifest.workflow,transactionHash=manifest.deployments.workflow;
  same(address,authorization.workflow,'linear workflow manifest address changed');
  assert.ok(isBytes32(transactionHash),'invalid linear workflow deployment transaction');
  return Object.freeze({kind:1,workflow:ethers.getAddress(address),deployments:{workflow:transactionHash}});
 }
 const profile=nonlinearManifestProfile(manifest.kind);
 assert.deepEqual(Object.keys(manifest).sort(),
  ['availability','canonicalSigners','deployments','game','kind','objective','schema','verifier'],
  'unexpected canonical-nonlinear workflow manifest field');
 assert.deepEqual(Object.keys(manifest.deployments??{}).sort(),['availability','game','objective','verifier'],
  'unexpected canonical-nonlinear deployment field');
 for(const field of ['game','availability','verifier','objective'])assert.ok(ethers.isAddress(manifest[field]),`invalid nonlinear ${field}`);
 same(manifest.game,authorization.workflow,'nonlinear workflow manifest address changed');
 assert.equal(new Set(['game','availability','verifier','objective'].map(field=>lower(manifest[field]))).size,4,
  'nonlinear workflow contracts must be distinct');
 assert.ok(Array.isArray(manifest.canonicalSigners)&&manifest.canonicalSigners.length===3&&
  manifest.canonicalSigners.every(ethers.isAddress),'nonlinear workflow requires three canonical signers');
 assert.equal(new Set(manifest.canonicalSigners.map(lower)).size,3,'duplicate canonical signer');
 const deployments={};
 for(const field of ['game','availability','verifier','objective']){
  deployments[field]=manifest.deployments?.[field];
  assert.ok(isBytes32(deployments[field]),`invalid nonlinear ${field} deployment transaction`);
 }
 return Object.freeze({kind:2,profile,...Object.fromEntries(['game','availability','verifier','objective'].map(field=>
  [field,ethers.getAddress(manifest[field])])),canonicalSigners:manifest.canonicalSigners.map(ethers.getAddress),deployments});
}

function decodeValue(param,value){
 if(param.baseType==='array')return Array.from(value,item=>decodeValue(param.arrayChildren,item));
 if(param.baseType==='tuple')return Object.fromEntries(param.components.map((component,index)=>
  [component.name||String(index),decodeValue(component,value[index])]));
 if(param.type.startsWith('uint')||param.type.startsWith('int'))return BigInt(value).toString();
 if(param.type==='address')return lower(value);
 if(param.type.startsWith('bytes'))return lower(value);
 return value;
}

function decodeCall(iface,name,data){
 const fragment=iface.getFunction(name),decoded=iface.decodeFunctionResult(fragment,data);
 if(fragment.outputs.length===1)return decodeValue(fragment.outputs[0],decoded[0]);
 return Object.fromEntries(fragment.outputs.map((output,index)=>[output.name||String(index),decodeValue(output,decoded[index])]));
}

function blockIdentity(block,number,hash){
 assert.ok(block,'validator lacks pinned workflow block');
 assert.equal(quantity(block.number),number,'validator returned another workflow block number');
 same(block.hash,hash,'validator returned another workflow block hash');
 return {number,hash:lower(block.hash)};
}

function timeout(promise,timeoutMs,label){
 let timer;
 return Promise.race([Promise.resolve(promise),new Promise((_,reject)=>{
  timer=setTimeout(()=>reject(Error(`${label} timed out`)),timeoutMs);
 })]).finally(()=>clearTimeout(timer));
}

function makeRpc(provider,timeoutMs,index){
 return(method,params)=>timeout(provider.send(method,params),timeoutMs,`validator ${index+1} ${method}`);
}

async function contractCall(rpc,iface,address,name,args,blockTag){
 const data=iface.encodeFunctionData(name,args);
 return decodeCall(iface,name,await rpc('eth_call',[{to:address,data},blockTag]));
}

async function deploymentEvidence(rpc,entry,blockTag){
 const [tx,receipt,code]=await Promise.all([
  rpc('eth_getTransactionByHash',[entry.transactionHash]),
  rpc('eth_getTransactionReceipt',[entry.transactionHash]),
  rpc('eth_getCode',[entry.address,blockTag])
 ]);
 const includedBlock=receipt?.blockNumber==null?null:await rpc('eth_getBlockByNumber',[receipt.blockNumber,false]);
 return{tx,receipt,includedBlock,code};
}

function inputRecord(owner,handle,taskId,index,kind){
 const metadataHash=ethers.keccak256(coder.encode(['bytes32','uint32','string'],[taskId,index,kind]));
 return ethers.keccak256(coder.encode(['bytes32','address','bytes32','bytes32'],
  [INPUT_RECORD_TYPEHASH,owner,handle,metadataHash]));
}

function nonlinearInputRoot(inputs,taskId,paddedCount){
 assert.ok(inputs.length>0&&Number.isSafeInteger(paddedCount)&&paddedCount>=inputs.length&&
  (paddedCount&(paddedCount-1))===0,'invalid canonical input-tree shape');
 const level=Array.from({length:paddedCount},(_,index)=>{
  if(index<inputs.length)return inputRecord(inputs[index].owner,inputs[index].inputBinding,taskId,index,'record');
  const paddingHandle=ethers.keccak256(ethers.solidityPacked(['string','bytes32','uint32'],
   ['VCFHE_INPUT_TREE_PADDING',taskId,index]));
  return inputRecord(inputs[0].owner,paddingHandle,taskId,index,'padding');
 });
 for(let width=paddedCount;width>1;width>>=1)for(let i=0;i<width;i+=2)
  level[i>>1]=ethers.keccak256(ethers.concat([level[i],level[i+1]]));
 return level[0];
}

export function validateCanonicalNonlinearWiring({state,authorization,manifest,expectedWindowSeconds}){
 assert.equal(state.secure,true,'nonlinear workflow is not in secure trace mode');
 same(state.objective,manifest.objective,'nonlinear objective verifier changed');
 same(state.availabilityAddress,manifest.availability,'nonlinear availability module changed');
 same(state.verifierAddress,manifest.verifier,'nonlinear canonical verifier changed');
 same(state.fhevm,ZERO_ADDRESS,'nonlinear FHEVM backend must be absent');
 same(state.kms,ZERO_ADDRESS,'nonlinear KMS verdict backend must be absent');
 for(const value of [state.commitWindow,state.openWindow,state.challengeWindow,state.disclosureWindow])
  assert.equal(Number(value),expectedWindowSeconds,'nonlinear workflow window changed');
 same(state.availabilityGame,manifest.game,'nonlinear availability game changed');
 same(state.verifierGame,manifest.game,'nonlinear canonical verifier game changed');
 same(state.profile,authorization.profileDigest,'nonlinear canonical profile changed');
 assert.equal(Number(state.threshold),2,'nonlinear canonical threshold changed');
 assert.ok(state.signerChecks.every(Boolean),'nonlinear canonical signer set changed');
 same(state.context,authorization.contextDigest,'nonlinear canonical context changed');
 const expectedDomain=ethers.keccak256(coder.encode(['bytes32','bytes32','bytes32','uint256','address'],
  [EIP712_DOMAIN_TYPEHASH,ethers.id('VCFHE-Canonical-Execution'),ethers.id('1'),authorization.chainId,manifest.verifier]));
 same(state.domainSeparator,expectedDomain,'nonlinear canonical signature domain changed');
 return true;
}

export function validatePolicyConsent(consent,authorization){
 assert.equal(consent.exists,true,'release-policy consent does not exist');
 same(consent.domain,authorization.policyDomain,'release-policy consent domain changed');
 const comparisons=['workflow','taskId','contextDigest','programDigest','programRoot','profileDigest','keysetDigest',
  'keyId','keyEpoch','mpcContext','outputType','recipient','slot','inputBindingsDigest'];
 for(const field of comparisons)same(consent[field],authorization[field],`release-policy consent ${field} changed`);
 assert.equal(asBigInt(consent.chainId),authorization.chainId,'release-policy consent chain changed');
 assert.equal(Number(consent.workflowKind),authorization.workflowKind,'release-policy consent workflow kind changed');
 assert.equal(consent.approvalCount,consent.requiredOwnerCount,'release-policy computation consent is incomplete');
}

async function readPolicy(rpc,artifact,authorization,blockTag){
 const iface=new ethers.Interface(artifact.abi);
 const [code,version,deploymentChainId,policyDomain,domainSeparator,consent]=await Promise.all([
  rpc('eth_getCode',[authorization.policy,blockTag]),
  contractCall(rpc,iface,authorization.policy,'POLICY_VERSION',[],blockTag),
  contractCall(rpc,iface,authorization.policy,'deploymentChainId',[],blockTag),
  contractCall(rpc,iface,authorization.policy,'policyDomain',[],blockTag),
  contractCall(rpc,iface,authorization.policy,'DOMAIN_SEPARATOR',[],blockTag),
  contractCall(rpc,iface,authorization.policy,'getConsent',[authorization.consentId],blockTag)
 ]);
 assert.notEqual(code,'0x','release-policy runtime unavailable');
 same(runtimeWithoutImmutables(code,artifact.immutableReferences),
  runtimeWithoutImmutables(artifact.deployedBytecode,artifact.immutableReferences),
  'release-policy runtime differs from the canonical local source');
 assert.equal(version,'3','release-policy version changed');
 assert.equal(asBigInt(deploymentChainId),authorization.chainId,'release-policy chain changed');
 same(policyDomain,authorization.policyDomain,'release-policy domain changed');
 const expectedPolicyDomain=ethers.keccak256(coder.encode(['string','uint256','address'],
  ['VCFHE_RELEASE_POLICY_DOMAIN_V3',authorization.chainId,authorization.policy]));
 same(policyDomain,expectedPolicyDomain,'release-policy immutable domain is not canonical');
 const expectedDomainSeparator=ethers.keccak256(coder.encode(['bytes32','bytes32','bytes32','uint256','address'],
  [EIP712_DOMAIN_TYPEHASH,ethers.id('VCFHE-Onchain-Release-Policy'),ethers.id('3'),authorization.chainId,
   authorization.policy]));
 same(domainSeparator,expectedDomainSeparator,'release-policy signature domain changed');
 validatePolicyConsent(consent,authorization);
 const recordCount=Number(consent.recordCount),actualInputCount=Number(consent.actualInputCount),
  paddedInputCount=Number(consent.paddedInputCount);
 assert.ok(Number.isSafeInteger(recordCount)&&recordCount>0&&recordCount<=64,'invalid protected-record count');
 assert.ok(Number.isSafeInteger(actualInputCount)&&actualInputCount>=0&&actualInputCount<=128,'invalid consent input count');
 const records=await Promise.all(Array.from({length:recordCount},(_,index)=>
  contractCall(rpc,iface,authorization.policy,'getConsentRecord',[authorization.consentId,index],blockTag)));
 const inputs=authorization.workflowKind===2?await Promise.all(Array.from({length:actualInputCount},(_,index)=>
  contractCall(rpc,iface,authorization.policy,'getConsentInput',[authorization.consentId,index],blockTag))):[];
 assert.equal(new Set(records.map(row=>lower(row.protectedId))).size,records.length,'duplicate protected record in consent');
 const bindings=(authorization.workflowKind===1?records:inputs).map(row=>row.inputBinding);
 same(ethers.keccak256(coder.encode(['bytes32[]'],[bindings])),authorization.inputBindingsDigest,
  'policy-derived input binding digest differs from the KMS authorization');
 return{codeHash:ethers.keccak256(code),consent,records,inputs,recordCount,actualInputCount,paddedInputCount};
}

async function readLinearState(rpc,artifact,authorization,policy,manifest,blockTag,expectedChainId){
 const iface=new ethers.Interface(artifact.abi),address=manifest.workflow;
 const calls=(name,args=[])=>contractCall(rpc,iface,address,name,args,blockTag);
 const [profile,keyset,totalItems,admittedCount,operation,datasetRef,scale,datasetTag,owner,boundResult]=await Promise.all([
  calls('profileDigest'),calls('keysetDigest'),calls('totalItems'),calls('admittedCount'),calls('allowedOperation'),
  calls('datasetRef'),calls('scale'),calls('datasetTag'),calls('owner'),calls('getBoundResult',[authorization.taskId])
 ]);
 same(profile,authorization.profileDigest,'linear profile changed');
 same(keyset,authorization.keysetDigest,'linear keyset changed');
 assert.equal(Number(totalItems),policy.recordCount,'linear protected-record count changed');
 assert.equal(Number(admittedCount),policy.recordCount,'linear owner admissions are incomplete');
 assert.equal(Number(operation),0,'canonical grouped-linear operation must be SUM');
 assert.equal(datasetRef,'kms-grouped-radix-v1','linear dataset profile changed');
 assert.equal(scale,'1','linear scale changed');
 const expectedTag=ethers.keccak256(coder.encode(['string','uint256','address','bytes32','bytes32','bytes32','uint64','uint8'],
  ['VCFHE-LINEAR-GROUPED-V1',expectedChainId,address,authorization.keyEpoch,authorization.profileDigest,
   authorization.keysetDigest,policy.recordCount,0]));
 same(datasetTag,expectedTag,'linear dataset tag changed');
 assert.equal(boundResult.accepted,true,'linear task was not accepted');
 same(boundResult.outputDigest,authorization.aggregateDigest,'linear aggregate digest changed');
 assert.ok(BigInt(boundResult.outputCommitment[0])!==0n||BigInt(boundResult.outputCommitment[1])!==0n,
  'linear output commitment is empty');
 const recordState=await Promise.all(policy.records.map(async(row,index)=>{
  const [recordOwner,binding]=await Promise.all([calls('recordOwner',[index]),calls('getProtectedRecordBinding',[index])]);
  same(recordOwner,row.owner,`linear record ${index} owner changed`);
  assert.equal(binding.bound,true,`linear record ${index} is not bound`);
  same(binding.protectedId,row.protectedId,`linear record ${index} protected id changed`);
  same(binding.ciphertextDigest,row.inputBinding,`linear record ${index} ciphertext changed`);
  return{protectedId:lower(binding.protectedId),owner:lower(recordOwner),inputBinding:lower(binding.ciphertextDigest)};
 }));
 return{profile:lower(profile),keyset:lower(keyset),owner:lower(owner),datasetTag:lower(datasetTag),
  task:{accepted:true,aggregateDigest:lower(boundResult.outputDigest),operator:lower(boundResult.operator)},records:recordState};
}

async function readNonlinearState(rpc,artifacts,authorization,policy,manifest,blockTag,expectedWindowSeconds){
 const gameIface=new ethers.Interface(artifacts[manifest.profile.game].abi),
  availabilityIface=new ethers.Interface(artifacts[manifest.profile.availability].abi),
  verifierIface=new ethers.Interface(artifacts.CanonicalLeafVerifier.abi);
 const game=(name,args=[])=>contractCall(rpc,gameIface,manifest.game,name,args,blockTag);
 const availability=(name,args=[])=>contractCall(rpc,availabilityIface,manifest.availability,name,args,blockTag);
 const verifier=(name,args=[])=>contractCall(rpc,verifierIface,manifest.verifier,name,args,blockTag);
 const [secure,objective,availabilityAddress,verifierAddress,fhevm,kms,commitWindow,openWindow,challengeWindow,
  availabilityGame,disclosureWindow,verifierGame,profile,threshold,signerChecks,context,domainSeparator,status,binding,
  taskAuthorization,cleared]=
  await Promise.all([game('secureTraceMode'),game('objectiveVerifier'),game('availabilityModule'),
   game('leafDecisionVerifier'),game('fhevmVerifier'),game('kmsVerdictVerifier'),game('COMMIT_WINDOW_SECONDS'),
   game('OPEN_WINDOW_SECONDS'),game('CHALLENGE_WINDOW_SECONDS'),availability('game'),availability('disclosureWindowSeconds'),
   verifier('game'),verifier('profileDigest'),verifier('threshold'),
   Promise.all(manifest.canonicalSigners.map(address=>verifier('isSigner',[address]))),verifier('contexts',[authorization.taskId]),
   verifier('domainSeparator'),
   game('getTaskStatus',[authorization.taskId]),game('getTaskResultBinding',[authorization.taskId]),
   availability('getTaskAuthorization',[authorization.taskId]),availability('isCleared',[authorization.taskId])]);
 validateCanonicalNonlinearWiring({state:{secure,objective,availabilityAddress,verifierAddress,fhevm,kms,commitWindow,
  openWindow,challengeWindow,disclosureWindow,availabilityGame,verifierGame,profile,threshold,signerChecks,context,
  domainSeparator},
  authorization,manifest,expectedWindowSeconds});
 assert.equal(Number(status.status),3,'nonlinear task is not finalized');
 assert.equal(Number(status.decision),1,'nonlinear task is not accepted');
 assert.equal(status.challengeTriggered,false,'nonlinear task was challenged');
 assert.equal(taskAuthorization.consumed,true,'nonlinear task authorization is not consumed');
 assert.equal(cleared,true,'nonlinear availability is not cleared');
 same(taskAuthorization.resultHash,binding.resultHash,'nonlinear authorization result hash changed');
 same(taskAuthorization.traceRoot,binding.operatorTraceRoot,'nonlinear authorization trace root changed');
 same(taskAuthorization.programRoot,authorization.programRoot,'nonlinear program root changed');
 same(taskAuthorization.inputRoot,policy.consent.inputRoot,'nonlinear policy/task input root changed');
 assert.equal(Number(taskAuthorization.inputCount),policy.paddedInputCount,'nonlinear padded input count changed');
 assert.equal(Number(taskAuthorization.leafCount),Number(binding.leafCount),'nonlinear leaf count changed');
 assert.notEqual(taskAuthorization.provenanceRoot,ethers.ZeroHash,'nonlinear provenance root is empty');
 assert.notEqual(taskAuthorization.outputAttestationHash,ethers.ZeroHash,'nonlinear output attestation is empty');
 same(authorization.aggregateDigest,authorization.finalOutputDigest,'nonlinear aggregate/output digest changed');
 const expectedResult=ethers.keccak256(coder.encode(['bytes32','bytes32','bytes32','uint32','bytes32','bytes32'],
  [OUTPUT_BINDING_V2_TYPEHASH,authorization.taskId,binding.operatorTraceRoot,Number(binding.leafCount),
   authorization.finalOutputDigest,taskAuthorization.outputAttestationHash]));
 same(binding.resultHash,expectedResult,'nonlinear final output is not bound to the accepted task');
 const expectedRoot=nonlinearInputRoot(policy.inputs,authorization.taskId,policy.paddedInputCount);
 same(expectedRoot,policy.consent.inputRoot,'nonlinear policy input root differs from its records');
 const registrations=await Promise.all(policy.inputs.map(async(row,index)=>{
  const recordHash=inputRecord(row.owner,row.inputBinding,authorization.taskId,index,'record');
  const [registered,handle,registeredOwner]=await Promise.all([
   availability('registeredInputRecords',[recordHash]),availability('registeredInputHandles',[recordHash]),
   availability('registeredInputOwners',[recordHash])]);
  assert.equal(registered,true,`nonlinear input ${index} is not owner-registered`);
  same(handle,row.inputBinding,`nonlinear input ${index} ciphertext changed`);
  same(registeredOwner,row.owner,`nonlinear input ${index} owner changed`);
  return{protectedId:lower(row.protectedId),owner:lower(row.owner),inputBinding:lower(row.inputBinding),recordHash:lower(recordHash)};
 }));
 return{profile:lower(profile),task:{status:Number(status.status),decision:Number(status.decision),
  operator:lower(status.operator),resultHash:lower(binding.resultHash),traceRoot:lower(binding.operatorTraceRoot),
  leafCount:Number(binding.leafCount)},authorization:{requester:lower(taskAuthorization.requester),
  operator:lower(taskAuthorization.operator),inputRoot:lower(taskAuthorization.inputRoot),
  programRoot:lower(taskAuthorization.programRoot),provenanceRoot:lower(taskAuthorization.provenanceRoot)},
  inputs:registrations};
}

async function observeEndpoint({provider,index,authorization,manifest,artifacts,blockNumber,blockHash,expectedWindowSeconds,timeoutMs}){
 const rpc=makeRpc(provider,timeoutMs,index),blockTag=ethers.toQuantity(blockNumber);
 assert.equal(asBigInt(await rpc('eth_chainId',[])),authorization.chainId,`validator ${index+1} chain changed`);
 blockIdentity(await rpc('eth_getBlockByNumber',[blockTag,false]),blockNumber,blockHash);
 const policy=await readPolicy(rpc,artifacts.ReleasePolicyRegistry,authorization,blockTag);
 const entries=authorization.workflowKind===1?[{
  name:'workflow',artifact:artifacts.GroupedLinearVerification,address:manifest.workflow,
  transactionHash:manifest.deployments.workflow,
  args:[policy.recordCount,0,authorization.keyEpoch,authorization.profileDigest,authorization.keysetDigest,
   policy.records.map(row=>row.owner)],expectedValue:ethers.parseEther('1')
 }]:[
  {name:'objective',artifact:artifacts.ObjectiveMicroVerifier,address:manifest.objective,
   transactionHash:manifest.deployments.objective,args:[]},
  {name:'game',artifact:artifacts[manifest.profile.game],address:manifest.game,
   transactionHash:manifest.deployments.game,args:[manifest.objective,expectedWindowSeconds,expectedWindowSeconds,
    expectedWindowSeconds,manifest.availability,manifest.verifier,...manifest.profile.extraConstructorArgs]},
  {name:'availability',artifact:artifacts[manifest.profile.availability],address:manifest.availability,
   transactionHash:manifest.deployments.availability,args:[manifest.game,expectedWindowSeconds]},
  {name:'verifier',artifact:artifacts.CanonicalLeafVerifier,address:manifest.verifier,
   transactionHash:manifest.deployments.verifier,args:[manifest.game,authorization.profileDigest,manifest.canonicalSigners,2]}
 ];
 const deployments=[];
 for(const entry of entries){
  const evidence=await deploymentEvidence(rpc,entry,blockTag);
  deployments.push({name:entry.name,...validateDirectDeploymentObservation({...entry,expectedChainId:authorization.chainId,
   viewNumber:blockNumber,...evidence})});
 }
 if(authorization.workflowKind===2)
  assert.equal(new Set(deployments.map(row=>lower(row.deployer))).size,1,'nonlinear workflow contracts have different deployers');
 const state=authorization.workflowKind===1?
  await readLinearState(rpc,artifacts.GroupedLinearVerification,authorization,policy,manifest,blockTag,authorization.chainId):
  await readNonlinearState(rpc,artifacts,authorization,policy,manifest,blockTag,expectedWindowSeconds);
 if(authorization.workflowKind===1)same(state.owner,deployments[0].deployer,'linear workflow owner differs from its deployer');
 blockIdentity(await rpc('eth_getBlockByNumber',[blockTag,false]),blockNumber,blockHash);
 return{chainId:authorization.chainId.toString(),blockNumber,blockHash:lower(blockHash),
  policy:{address:lower(authorization.policy),codeHash:policy.codeHash,consentId:lower(authorization.consentId),
   recordCount:policy.recordCount,actualInputCount:policy.actualInputCount,paddedInputCount:policy.paddedInputCount,
   inputRoot:lower(policy.consent.inputRoot),inputBindingsDigest:lower(policy.consent.inputBindingsDigest)},
  deployments,state};
}

export async function verifyCanonicalWorkflowDeployment({authorization:inputAuthorization,workflowManifest:inputManifest,
 rpcUrls,blockNumber,blockHash,expectedWindowSeconds,timeoutMs=5000,providerFactory}){
 const authorization=requireAuthorization(inputAuthorization),manifest=requireManifest(inputManifest,authorization);
 assert.ok(Number.isSafeInteger(blockNumber)&&blockNumber>=0,'invalid workflow authentication block number');
 assert.ok(isBytes32(blockHash),'invalid workflow authentication block hash');
 assert.ok(Number.isSafeInteger(expectedWindowSeconds)&&expectedWindowSeconds>0,'invalid expected workflow window');
 assert.ok(Number.isFinite(timeoutMs)&&timeoutMs>0,'invalid workflow RPC timeout');
 const urls=validateWorkflowRpcUrls(rpcUrls),artifacts=await compileCanonicalWorkflowArtifacts();
 const makeProvider=providerFactory??(url=>new ethers.JsonRpcProvider(url,undefined,{cacheTimeout:-1,pollingInterval:250}));
 const providers=urls.map((url,index)=>makeProvider(url,index));
 const settled=await Promise.allSettled(providers.map((provider,index)=>observeEndpoint({provider,index,authorization,
  manifest,artifacts,blockNumber,blockHash,expectedWindowSeconds,timeoutMs})));
 const rows=settled.flatMap((row,index)=>row.status==='fulfilled'?[{index,value:row.value}]:[]);
 try{
  const result=requireWorkflowObservationQuorum(rows);
  return Object.freeze({...result,failures:Object.freeze(settled.flatMap((row,index)=>row.status==='rejected'?
   [{index,message:String(row.reason?.message??row.reason)}]:[]))});
 }finally{
  for(const provider of providers)if(typeof provider.destroy==='function')provider.destroy();
 }
}

export function validateWorkflowAuthCliRequest(value){
 assert.ok(value&&typeof value==='object'&&!Array.isArray(value),'workflow-auth CLI expects one JSON object');
 const keys=Object.keys(value).sort(),required=['authorization','blockHash','blockNumber','expectedWindowSeconds','rpcUrls',
  'workflowManifest'],allowed=[...required,'timeoutMs'].sort();
 assert.ok(required.every(key=>keys.includes(key)),'workflow-auth CLI request is missing a required field');
 assert.ok(keys.every(key=>allowed.includes(key)),'workflow-auth CLI request contains an unsupported field');
 return value;
}

export async function runWorkflowAuthCli(value){
 const request=validateWorkflowAuthCliRequest(value),result=await verifyCanonicalWorkflowDeployment(request);
 const observation=result.observation;
 return Object.freeze({schema:'vcfhe-workflow-auth-result-v1',chainId:observation.chainId,
  blockNumber:observation.blockNumber,blockHash:observation.blockHash,consentId:observation.policy.consentId,
  policyCodeHash:observation.policy.codeHash,supportingValidators:result.supporters.map(index=>index+1),
  workflowRuntimeCodeHashes:Object.fromEntries(observation.deployments.map(row=>[row.name,row.runtimeCodeHash])),
  observationDigest:ethers.keccak256(ethers.toUtf8Bytes(observationKey(observation)))});
}

export async function readBoundedStdin(stream=process.stdin,maxBytes=WORKFLOW_AUTH_CLI_MAX_STDIN_BYTES){
 assert.ok(Number.isSafeInteger(maxBytes)&&maxBytes>0,'invalid workflow-auth stdin limit');
 const chunks=[];let size=0;
 for await(const chunk of stream){
  const bytes=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk);
  size+=bytes.length;
  assert.ok(size<=maxBytes,'workflow-auth CLI input exceeds its byte limit');
  chunks.push(bytes);
 }
 return Buffer.concat(chunks,size).toString('utf8');
}

async function supervisedMain(){
 const request=validateWorkflowAuthCliRequest(JSON.parse(await readBoundedStdin()));
 const worker=new Worker(fileURLToPath(import.meta.url),{workerData:{workflowAuthWorker:1,request}});
 const result=await new Promise((resolve,reject)=>{
  let settled=false;
  const timer=setTimeout(()=>{
   if(settled)return;settled=true;
   void worker.terminate();
   reject(Error(`workflow-auth CLI exceeded ${WORKFLOW_AUTH_CLI_DEADLINE_MS} ms`));
  },WORKFLOW_AUTH_CLI_DEADLINE_MS);
  worker.once('message',message=>{
   if(settled)return;settled=true;clearTimeout(timer);
   void worker.terminate();
   if(!message?.ok)return reject(Error(message?.error??'workflow-auth worker failed'));
   resolve(message.result);
  });
  worker.once('error',error=>{if(settled)return;settled=true;clearTimeout(timer);reject(error);});
  worker.once('exit',code=>{if(settled)return;settled=true;clearTimeout(timer);
   reject(Error(`workflow-auth worker exited before returning evidence (code ${code})`));});
 });
 assert.equal(result.schema,'vcfhe-workflow-auth-result-v1','workflow-auth worker returned an invalid result');
 process.stdout.write(JSON.stringify(result)+'\n');
}

if(!isMainThread&&workerData?.workflowAuthWorker===1){
 runWorkflowAuthCli(workerData.request).then(result=>parentPort.postMessage({ok:true,result}),error=>
  parentPort.postMessage({ok:false,error:String(error?.message??error)}));
}else if(isMainThread&&process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 supervisedMain().catch(error=>{
  process.stderr.write(`workflow authentication failed: ${error?.message??error}\n`);
  process.exitCode=1;
 });
}
