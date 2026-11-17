import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';

const require=createRequire(new URL('../../BN254-Signatures/package.json',import.meta.url));
export const {ethers}=require('ethers');
const solc=require('solc');
const here=path.dirname(fileURLToPath(import.meta.url));
export const POLICY_VERSION=3n;
export const CONSENT_TYPEHASH=ethers.id(
 'ReleaseConsent(uint256 policyVersion,address policy,bytes32 domain,uint256 chainId,bytes32 executionDigest,bytes32 keyDigest,bytes32 outputType,address recipient,bytes32 slot,bytes32 protectedRecordsDigest,bytes32 inputProtectedRecordsDigest,bytes32 inputBindingsDigest)');
export const RELEASE_TYPEHASH=ethers.id(
 'ReleaseRequest(bytes32 consentId,bytes32 requestId,bytes32 requestKey,bytes32 submitWireDigest,bytes32 resultQueryDigest,bytes32 finalOutputDigest,bytes32 aggregateDigest,bytes32 recipientEncryptionKeyDigest,address recipient)');

export const RELEASE_TYPES={ReleaseRequest:[
 {name:'consentId',type:'bytes32'},
 {name:'requestId',type:'bytes32'},
 {name:'requestKey',type:'bytes32'},
 {name:'submitWireDigest',type:'bytes32'},
 {name:'resultQueryDigest',type:'bytes32'},
 {name:'finalOutputDigest',type:'bytes32'},
 {name:'aggregateDigest',type:'bytes32'},
 {name:'recipientEncryptionKeyDigest',type:'bytes32'},
 {name:'recipient',type:'address'},
]};

let compiled;
export async function compileReleasePolicy(){
 if(compiled)return compiled;
 const source=await fs.readFile(path.join(here,'../contracts/OnChainReleasePolicy.sol'),'utf8');
 const result=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'OnChainReleasePolicy.sol':{content:source}},
  settings:{optimizer:{enabled:true,runs:200},viaIR:true,evmVersion:'london',metadata:{bytecodeHash:'none',appendCBOR:false},
   outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.deployedBytecode.object']}}}})));
 const errors=(result.errors||[]).filter(error=>error.severity==='error');
 if(errors.length)throw Error(errors.map(error=>error.formattedMessage).join('\n'));
 const contract=result.contracts?.['OnChainReleasePolicy.sol']?.ReleasePolicyRegistry;
 if(!contract?.evm?.bytecode?.object)throw Error('ReleasePolicyRegistry did not compile');
 compiled={abi:contract.abi,bytecode:'0x'+contract.evm.bytecode.object,
  deployedBytecode:'0x'+contract.evm.deployedBytecode.object};
 return compiled;
}

export const releaseDomain=(chainId,verifyingContract)=>({
 name:'VCFHE-Onchain-Release-Policy',version:'3',chainId:BigInt(chainId),verifyingContract
});

export async function loadReleasePolicy(provider,configPath='/config/release-policy.json'){
 const config=JSON.parse(await fs.readFile(configPath,'utf8'));
 if(String((await provider.getNetwork()).chainId)!==String(config.chainId)||!ethers.isAddress(config.address))
  throw Error('release-policy chain/address mismatch');
 const code=await provider.getCode(config.address);
 if(code==='0x'||ethers.keccak256(code)!==config.runtimeCodeHash)throw Error('release-policy runtime mismatch');
 const {abi}=await compileReleasePolicy(),contract=new ethers.Contract(config.address,abi,provider);
 if(Number(await contract.POLICY_VERSION())!==3||String(await contract.deploymentChainId())!==String(config.chainId))
  throw Error('release-policy version mismatch');
 if((await contract.policyDomain())!==config.policyDomain||(await contract.DOMAIN_SEPARATOR())!==config.domainSeparator)
  throw Error('release-policy domain mismatch');
 const domain=await contract.DOMAIN_SEPARATOR();
 if(domain===ethers.ZeroHash)throw Error('release-policy domain unavailable');
 return {config,abi,contract,domain};
}

export const outputTypeDigest=outputType=>{
 if(!['bool','uint16','uint64'].includes(outputType))throw Error('unsupported policy output type');
 return ethers.id(`VCFHE_OUTPUT_TYPE_V1:${outputType}`);
};

export function computeConsentIdV3(policy,terms){
 const coder=ethers.AbiCoder.defaultAbiCoder();
 const executionDigest=ethers.keccak256(coder.encode(
  ['uint8','address','bytes32','bytes32','bytes32','bytes32','bytes32','bytes32'],
  [terms.workflowKind,terms.workflow,terms.taskId,terms.contextDigest,terms.programDigest,
   terms.programRoot,terms.profileDigest,terms.keysetDigest]));
 const keyDigest=ethers.keccak256(coder.encode(
  ['bytes32','bytes32','bytes32'],[terms.keyId,terms.keyEpoch,terms.mpcContext]));
 return ethers.keccak256(coder.encode(
  ['bytes32','uint256','address','bytes32','uint256','bytes32','bytes32','bytes32','address','bytes32',
   'bytes32','bytes32','bytes32'],
  [CONSENT_TYPEHASH,POLICY_VERSION,policy,terms.domain,terms.chainId,executionDigest,keyDigest,
   terms.outputType,terms.recipient,terms.slot,
   ethers.keccak256(coder.encode(['bytes32[]'],[terms.protectedRecordIds])),
   ethers.keccak256(coder.encode(['bytes32[]'],[terms.inputProtectedRecordIds])),
   ethers.keccak256(coder.encode(['bytes32[]'],[terms.inputBindings]))]));
}

export function computeReleaseDigestV3(request){
 return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
  ['bytes32','bytes32','bytes32','bytes32','bytes32','bytes32','bytes32','bytes32','bytes32','address'],
  [RELEASE_TYPEHASH,request.consentId,request.requestId,request.requestKey,request.submitWireDigest,
   request.resultQueryDigest,request.finalOutputDigest,request.aggregateDigest,
   request.recipientEncryptionKeyDigest,request.recipient]));
}

export function bindExpectedWorkflow(approved,workflow){
 if(!approved||!ethers.isAddress(workflow))throw Error('invalid workflow binding');
 const normalized=ethers.getAddress(workflow);
 if(approved.game&&ethers.getAddress(approved.game)!==normalized)throw Error('changed workflow contract');
 approved.game=normalized;
 return normalized;
}

export function assertExpectedWorkflow(approved,workflow){
 if(!approved?.game||!ethers.isAddress(workflow)||ethers.getAddress(approved.game)!==ethers.getAddress(workflow))
  throw Error('changed workflow contract');
 return ethers.getAddress(approved.game);
}

export const PROTECTED_RECORD_TYPEHASH=ethers.id(
 'VCFHE_PROTECTED_RECORD_V2(uint256 chainId,address registry,address owner,bytes32 recordReference)');
export function ownerBoundProtectedId(chainId,registry,owner,recordReference){
 if(!ethers.isAddress(registry)||!ethers.isAddress(owner)||!ethers.isHexString(recordReference,32))
  throw Error('invalid protected-record identity');
 return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
  ['bytes32','uint256','address','address','bytes32'],
  [PROTECTED_RECORD_TYPEHASH,BigInt(chainId),registry,owner,recordReference]));
}

const PROGRAM_LEAF_TYPEHASH=ethers.id('FHE_POD_PROGRAM_LEAF_V1(bytes32 taskId,uint32 leafIndex,uint8 opcode,uint8 lhsSourceKind,uint32 lhsSourceIndex,uint8 rhsSourceKind,uint32 rhsSourceIndex,uint256 lhsConstant,uint256 rhsConstant)');
const SOURCE={input:0,output:1,constant:2};
const OPCODES=Object.freeze({MUL:1,SHR:2,CAST_U8:3,MIN:4,BITAND:5,ADD:6,SUB:7,DIV:8,MOD:9,EQ:10,LT:11,GT:12,BITOR:13,BITXOR:14,ADD_CHAIN:15});
const ref=(value,before)=>{
 if(!Object.hasOwn(SOURCE,value?.kind))throw Error('invalid program source');
 if(value.kind==='constant')return {kind:SOURCE.constant,index:0,constant:BigInt(value.value)};
 if(!Number.isSafeInteger(value.index)||value.index<0||(value.kind==='output'&&value.index>=before))throw Error('invalid program reference');
 return {kind:SOURCE[value.kind],index:value.index,constant:0n};
};
export function canonicalProgramRoot(taskId,program){
 if(!Array.isArray(program?.instructions)||!program.instructions.length||
    (program.instructions.length&(program.instructions.length-1))!==0)throw Error('program must have a power-of-two instruction count');
 let level=program.instructions.map((instruction,index)=>{
  if(instruction.index!==index||!Object.hasOwn(OPCODES,instruction.opcode))throw Error('invalid canonical instruction');
  const lhs=ref(instruction.lhs,index),rhs=ref(instruction.rhs,index);
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
   ['bytes32','bytes32','uint32','uint8','uint8','uint32','uint8','uint32','uint256','uint256'],
   [PROGRAM_LEAF_TYPEHASH,taskId,index,OPCODES[instruction.opcode],lhs.kind,lhs.index,rhs.kind,rhs.index,lhs.constant,rhs.constant]));
 });
 while(level.length>1){const next=[];for(let i=0;i<level.length;i+=2)next.push(ethers.solidityPackedKeccak256(['bytes32','bytes32'],[level[i],level[i+1]]));level=next;}
 return level[0];
}

export function nonlinearInputTerms(context){
 if(!Array.isArray(context?.inputs)||!context.inputs.length||context.inputs.length>128)
  throw Error('invalid canonical input list');
 const inputProtectedRecordIds=[],inputBindings=[];
 for(const input of context.inputs){
  if(!ethers.isHexString(input.protectedId,32)||!ethers.isHexString(input.handle,32)||!ethers.isAddress(input.owner))
   throw Error('invalid canonical protected input');
  inputProtectedRecordIds.push(input.protectedId);inputBindings.push(input.handle);
 }
 return {inputProtectedRecordIds,inputBindings};
}

export const INPUT_RECORD_TYPEHASH=ethers.id(
 'FHE_POD_INPUT_RECORD_V1(address owner,bytes32 ciphertextHandle,bytes32 metadataHash)');
export function canonicalConsentInputRoot(taskId,inputProtectedRecordIds,inputBindings,ownerForRecord){
 if(!ethers.isHexString(taskId,32)||inputProtectedRecordIds.length!==inputBindings.length||
    !inputBindings.length||inputBindings.length>128)throw Error('invalid canonical consent inputs');
 const coder=ethers.AbiCoder.defaultAbiCoder(),leaves=inputBindings.map((handle,index)=>{
  const owner=ownerForRecord(inputProtectedRecordIds[index]);
  if(!ethers.isAddress(owner)||!ethers.isHexString(handle,32))throw Error('invalid canonical consent input');
  const metadata=ethers.keccak256(coder.encode(['bytes32','uint32','string'],[taskId,index,'record']));
  return ethers.keccak256(coder.encode(['bytes32','address','bytes32','bytes32'],[INPUT_RECORD_TYPEHASH,owner,handle,metadata]));
 });
 let padded=1;while(padded<leaves.length)padded*=2;
 const paddingOwner=ownerForRecord(inputProtectedRecordIds[0]);
 for(let index=leaves.length;index<padded;index++){
  const handle=ethers.solidityPackedKeccak256(['string','bytes32','uint32'],['VCFHE_INPUT_TREE_PADDING',taskId,index]);
  const metadata=ethers.keccak256(coder.encode(['bytes32','uint32','string'],[taskId,index,'padding']));
  leaves.push(ethers.keccak256(coder.encode(['bytes32','address','bytes32','bytes32'],
   [INPUT_RECORD_TYPEHASH,paddingOwner,handle,metadata])));
 }
 let level=leaves;
 while(level.length>1){const next=[];for(let i=0;i<level.length;i+=2)
  next.push(ethers.solidityPackedKeccak256(['bytes32','bytes32'],[level[i],level[i+1]]));level=next;}
 return {inputRoot:level[0],actualInputCount:inputBindings.length,paddedInputCount:padded};
}

export function releaseRequestFromWire({consentId,decoded,wire,getWire}){
 const get=ethers.getBytes(getWire),submit=ethers.getBytes(wire);
 if(decoded.consentId!==consentId)throw Error('wire consent mismatch');
 const requestKey=ethers.keccak256(get),resultQueryDigest=ethers.keccak256(get);
 if(requestKey!==resultQueryDigest)throw Error('request-key/result-query mismatch');
 return {consentId,requestId:decoded.requestId,requestKey,
  submitWireDigest:ethers.keccak256(submit),resultQueryDigest,
  finalOutputDigest:decoded.outputDigest,aggregateDigest:decoded.aggregateDigest,
  recipientEncryptionKeyDigest:decoded.encKeyDigest,recipient:decoded.recipient};
}

export function kmsReleaseAuthorizationV3({policy,policyDomain,consentId,binding,output,recipient,
 workflowKind,slot}){
 if(output?.taskId!==binding?.taskId)throw Error('executed task differs from the consented task');
 const authorization={kind:'kms-recipient-release-v3',policyVersion:3,policy,policyDomain,slot,consentId,
  chainId:binding.chainId,game:binding.game,workflowKind,taskId:binding.taskId,
  contextDigest:binding.contextDigest,programDigest:binding.programDigest,programRoot:binding.programRoot,
  profileDigest:binding.profileDigest,keysetDigest:binding.keysetDigest,keyId:binding.keyId,
  keyEpoch:binding.keyEpoch,mpcContext:binding.mpcContext,aggregateDigest:output.aggregateDigest,
  outputDigest:output.outputDigest,outputType:output.outputType,recipient,
  inputBindings:binding.inputBindings,workflowManifest:binding.workflowManifest};
 if(workflowKind===1)authorization.linearWitnessDigest=binding.linearWitnessDigest;
 return authorization;
}

export function kmsSubmitAuthorization(decoded,releaseRequest){
 const inputBindings=decoded.inputBindings;
 if(!Array.isArray(inputBindings)||!inputBindings.length||
    !inputBindings.every(value=>ethers.isHexString(value,32)))throw Error('invalid inputBindings');
 const authorization={
  requestId:releaseRequest.requestId,requestKey:releaseRequest.requestKey,
  submitWireDigest:releaseRequest.submitWireDigest,consentId:releaseRequest.consentId,
  finalOutputDigest:releaseRequest.finalOutputDigest,aggregateDigest:releaseRequest.aggregateDigest,
  recipientEncryptionKeyDigest:releaseRequest.recipientEncryptionKeyDigest,recipient:releaseRequest.recipient,
  keyId:decoded.keyId,keyEpoch:decoded.keyEpoch,mpcContext:decoded.mpcContext,
  outputType:outputTypeDigest(decoded.outputType),workflow:decoded.game,chainId:BigInt(decoded.chainId),
  policyDomain:decoded.policyDomain,policy:decoded.policy,slot:decoded.slot,
  workflowKind:Number(decoded.workflowKind),taskId:decoded.taskId,contextDigest:decoded.contextDigest,
  programDigest:decoded.programDigest,programRoot:decoded.programRoot,profileDigest:decoded.profileDigest,
  keysetDigest:decoded.keysetDigest,
  inputBindingsDigest:ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
   ['bytes32[]'],[inputBindings]))
 };
 for(const [name,value] of Object.entries(authorization)){
  if(['recipient','workflow','policy'].includes(name)){if(!ethers.isAddress(value))throw Error(`invalid ${name}`);}
  else if(['chainId','workflowKind'].includes(name)){if(BigInt(value)<0n)throw Error(`invalid ${name}`);}
  else if(!ethers.isHexString(value,32))throw Error(`invalid ${name}`);
 }
 return authorization;
}

export async function signReleaseRequest(wallet,chainId,policyAddress,request){
 return wallet.signTypedData(releaseDomain(chainId,policyAddress),RELEASE_TYPES,request);
}
