// Deploy the adminless release-policy registry once, or verify the exact
// persisted deployment. A first deployment either binds an owner-attested
// legacy snapshot or records an explicit new lineage. It never silently
// replaces an address, counter lineage, chain or runtime.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';

const appRoot=process.env.VCFHE_APP_ROOT??'/app';
const require=createRequire(path.join(appRoot,'BN254-Signatures/package.json'));
const {ethers}=require('ethers'),solc=require('solc');
const sourceName='OnChainReleasePolicy.sol';
const sourceFile=path.join(appRoot,'threshold-kms/contracts',sourceName);
const stateFile=path.join(process.env.VCFHE_POLICY_STATE_DIR??'/policy-state','deployment.json');
const runFile=path.join(process.env.VCFHE_POLICY_CONFIG_DIR??'/config','release-policy.json');
const rpc=process.env.VCFHE_POLICY_RPC_URL;
const expectedChain=BigInt(process.env.VCFHE_EXPECTED_CHAIN_ID??'46853');
const expectedVersion=BigInt(process.env.VCFHE_POLICY_VERSION??'3');
const allowNewLineage=process.env.VCFHE_ALLOW_NEW_POLICY_LINEAGE==='1';
const requireExistingPolicy=process.env.VCFHE_REQUIRE_EXISTING_POLICY==='1';
if(!rpc)throw Error('VCFHE_POLICY_RPC_URL is required');
if(requireExistingPolicy&&allowNewLineage)throw Error('existing-policy verification cannot create a new lineage');

const sha256=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function atomic(file,value){
  const temporary=file+'.'+crypto.randomUUID()+'.pending';
  const fd=fs.openSync(temporary,'wx',0o600);
  try{fs.writeFileSync(fd,JSON.stringify(value,null,2)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  fs.renameSync(temporary,file);
  const directory=fs.openSync(path.dirname(file),'r');
  try{fs.fsyncSync(directory);}catch(error){if(!['EINVAL','EPERM'].includes(error.code))throw error;}finally{fs.closeSync(directory);}
}
function importSource(name){
  const roots=['threshold-kms/contracts','BN254-Signatures/contract','fhe-pod/contracts/src'].map(value=>path.join(appRoot,value));
  for(const root of roots){const candidate=path.join(root,name);if(fs.existsSync(candidate))return{contents:fs.readFileSync(candidate,'utf8')};}
  return{error:'missing Solidity import: '+name};
}
function compile(){
  const source=fs.readFileSync(sourceFile,'utf8');
  const input={language:'Solidity',sources:{[sourceName]:{content:source}},settings:{
    optimizer:{enabled:true,runs:200},viaIR:true,evmVersion:'london',metadata:{bytecodeHash:'none',appendCBOR:false},
    outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.deployedBytecode.object','evm.deployedBytecode.immutableReferences']}}
  }};
  const result=JSON.parse(solc.compile(JSON.stringify(input),{import:importSource}));
  const errors=(result.errors??[]).filter(e=>e.severity==='error');
  if(errors.length)throw Error(errors.map(e=>e.formattedMessage).join('\n'));
  const artifact=result.contracts?.[sourceName]?.ReleasePolicyRegistry;
  if(!artifact?.evm?.bytecode?.object)throw Error('ReleasePolicyRegistry artifact missing');
  const constructor=artifact.abi.find(item=>item.type==='constructor');
  if(constructor?.inputs?.length)throw Error('ReleasePolicyRegistry must have a no-argument constructor');
  return{artifact,sourceSha256:sha256(Buffer.from(source)),compilerVersion:solc.version()};
}
function normalizedRuntime(code,references){
  if(!ethers.isHexString(code))throw Error('invalid runtime bytecode');
  const bytes=Buffer.from(code.slice(2),'hex');
  for(const locations of Object.values(references??{}))for(const {start,length} of locations){
    if(start<0||length<1||start+length>bytes.length)throw Error('invalid immutable reference');
    bytes.fill(0,start,start+length);
  }
  return '0x'+bytes.toString('hex');
}
function legacyInput(persisted){
  const file=process.env.VCFHE_LEGACY_LEDGER??'/migration/ledger.json';
  if(requireExistingPolicy&&fs.existsSync(file))
    throw Error('existing-policy verification cannot import or recheck a legacy migration ledger');
  if(!fs.existsSync(file)){
    if(persisted?.legacyMigrationInput&&Array.isArray(persisted.legacyRecords))
      return{descriptor:persisted.legacyMigrationInput,records:persisted.legacyRecords};
    if(!allowNewLineage)throw Error('legacy ledger required for cumulative-policy migration');
    const ownersFile=path.join(path.dirname(runFile),'owners.json');
    if(!fs.existsSync(ownersFile))throw Error('owner identities unavailable for new policy lineage');
    const ownersBytes=fs.readFileSync(ownersFile),owners=JSON.parse(ownersBytes);
    if(!Array.isArray(owners)||owners.length!==4||owners.some(owner=>!ethers.isAddress(owner))||
       new Set(owners.map(owner=>owner.toLowerCase())).size!==owners.length)throw Error('invalid new-lineage owners');
    return{descriptor:{role:'explicit-new-policy-lineage',version:1,ownersSha256:sha256(ownersBytes),recordCount:0},records:[]};
  }
  const bytes=fs.readFileSync(file),value=JSON.parse(bytes);
  if(value.version!==2||!value.records||typeof value.records!=='object'||Array.isArray(value.records))
    throw Error('legacy migration ledger has no valid version/records');
  const records=Object.entries(value.records).map(([recordReference,record])=>{
    if(!ethers.isHexString(recordReference,32)||!ethers.isAddress(record?.owner)||
       !Number.isSafeInteger(record.limit)||record.limit<1||!Number.isSafeInteger(record.spent)||
       record.spent<0||record.spent>record.limit)throw Error('invalid legacy protected-record counter');
    return{recordReference,owner:ethers.getAddress(record.owner),releaseLimit:record.limit,initialSpent:record.spent};
  }).sort((a,b)=>a.recordReference.localeCompare(b.recordReference));
  const ownersFile=path.join(path.dirname(runFile),'owners.json');
  if(!fs.existsSync(ownersFile))throw Error('owner identities unavailable for legacy migration');
  const ownerSet=new Set(JSON.parse(fs.readFileSync(ownersFile,'utf8')).map(owner=>ethers.getAddress(owner)));
  if(records.some(record=>!ownerSet.has(record.owner)))throw Error('legacy record owner has no retained signing identity');
  return{descriptor:{role:'owner-attested-migration-input',version:value.version,sha256:sha256(bytes),
    ownersSha256:sha256(fs.readFileSync(ownersFile)),recordCount:records.length},records};
}
async function waitForChain(provider){
  const deadline=Date.now()+120000;
  while(true){
    try{return await provider.getNetwork();}
    catch(error){if(Date.now()>deadline)throw error;await new Promise(resolve=>setTimeout(resolve,1000));}
  }
}

fs.mkdirSync(path.dirname(stateFile),{recursive:true,mode:0o700});
const {artifact,sourceSha256,compilerVersion}=compile();
const references=artifact.evm.deployedBytecode.immutableReferences;
const expectedNormalized=normalizedRuntime('0x'+artifact.evm.deployedBytecode.object,references);
const persistedInput=fs.existsSync(stateFile)?JSON.parse(fs.readFileSync(stateFile,'utf8')):null;
const ownersFile=path.join(path.dirname(runFile),'owners.json');
let ownersSha256=null;
if(requireExistingPolicy){
  if(!persistedInput||persistedInput.schema!=='vcfhe-release-policy-deployment-v3'||persistedInput.status!=='deployed')
    throw Error('V3 policy refresh requires an already deployed policy');
  if(!fs.existsSync(ownersFile))throw Error('owner identities unavailable for existing-policy verification');
  const ownersBytes=fs.readFileSync(ownersFile),owners=JSON.parse(ownersBytes);
  if(!Array.isArray(owners)||owners.length!==4||owners.some(owner=>!ethers.isAddress(owner))||
     new Set(owners.map(owner=>owner.toLowerCase())).size!==owners.length)
    throw Error('invalid owner identities for existing-policy verification');
  ownersSha256=sha256(ownersBytes);
  if(persistedInput.legacyMigrationInput?.ownersSha256!==ownersSha256)
    throw Error('owner identity set changed from the deployed policy lineage');
}
const legacy=legacyInput(persistedInput);
const provider=new ethers.JsonRpcProvider(rpc,undefined,{cacheTimeout:-1,pollingInterval:250});
try{
  const network=await waitForChain(provider),chainId=BigInt(network.chainId);
  if(chainId!==expectedChain)throw Error(`release-policy chain mismatch: ${chainId} != ${expectedChain}`);
  const genesis=await provider.getBlock(0);
  if(!genesis?.hash)throw Error('release-policy genesis block unavailable');
  const genesisBlockHash=genesis.hash;
  let persisted=persistedInput;
  let address,transactionHash=null,deploymentBlock=null,deploymentBlockHash=null;
  if(persisted){
    if(String(persisted.chainId)!==String(chainId)||!ethers.isAddress(persisted.address))
      throw Error('persisted release-policy chain/address mismatch; refusing redeployment');
    if(!['pending','deployed'].includes(persisted.status))
      throw Error('invalid persisted release-policy deployment status');
    if(persisted.sourceSha256!==sourceSha256||persisted.compilerVersion!==compilerVersion||
       BigInt(persisted.policyVersion)!==expectedVersion)
      throw Error('persisted release-policy source/compiler/version mismatch');
    if(persisted.status==='deployed'&&(!persisted.genesisBlockHash||!persisted.deploymentBlockHash||
       !persisted.transactionHash||persisted.deploymentBlock==null))
      throw Error('persisted release-policy lacks V3 chain-lineage anchors');
    if(persisted.genesisBlockHash&&persisted.genesisBlockHash!==genesisBlockHash)
      throw Error('persisted release-policy genesis changed; refusing rollback or redeployment');
    if(persisted.lastVerifiedBlockNumber!=null){
      const checkpoint=await provider.getBlock(Number(persisted.lastVerifiedBlockNumber));
      if(!checkpoint?.hash||checkpoint.hash!==persisted.lastVerifiedBlockHash)
        throw Error('persisted release-policy checkpoint is absent or changed');
    }
    address=ethers.getAddress(persisted.address);
    let code=await provider.getCode(address);
    if(code==='0x'){
      if(persisted.status!=='pending'||!persisted.transactionHash)
        throw Error('persisted release-policy address has no code; refusing redeployment');
      let receipt=await provider.getTransactionReceipt(persisted.transactionHash);
      if(!receipt){
        const transaction=await provider.getTransaction(persisted.transactionHash);
        if(!transaction)throw Error('pending release-policy transaction was dropped; refusing redeployment');
        receipt=await transaction.wait(1,120000);
      }
      if(!receipt||receipt.status!==1)throw Error('pending release-policy deployment failed');
      deploymentBlock=receipt.blockNumber;deploymentBlockHash=receipt.blockHash;code=await provider.getCode(address);
    }
    const runtimeCodeHash=ethers.keccak256(code);
    if(persisted.status==='deployed'&&runtimeCodeHash!==persisted.runtimeCodeHash)
      throw Error('persisted release-policy runtime code changed; refusing redeployment');
    if(normalizedRuntime(code,references)!==expectedNormalized)
      throw Error('persisted release-policy runtime does not match the compiled registry');
    if(JSON.stringify(persisted.legacyMigrationInput??null)!==JSON.stringify(legacy.descriptor))
      throw Error('legacy migration input changed after release-policy deployment');
    if(JSON.stringify(persisted.legacyRecords??[])!==JSON.stringify(legacy.records))
      throw Error('legacy migration records changed after release-policy deployment');
    transactionHash=persisted.transactionHash??null;
    deploymentBlock=deploymentBlock??persisted.deploymentBlock??null;
    deploymentBlockHash=deploymentBlockHash??persisted.deploymentBlockHash??null;
    const receipt=await provider.getTransactionReceipt(transactionHash);
    if(persisted.status==='pending'&&receipt){
      deploymentBlock=receipt.blockNumber;
      deploymentBlockHash=receipt.blockHash;
    }
    if(!receipt||receipt.status!==1||receipt.blockNumber!==Number(deploymentBlock)||
       receipt.blockHash!==deploymentBlockHash||ethers.getAddress(receipt.contractAddress)!==address)
      throw Error('persisted release-policy deployment receipt changed or disappeared');
    const deploymentHeader=await provider.getBlock(Number(deploymentBlock));
    if(!deploymentHeader?.hash||deploymentHeader.hash!==deploymentBlockHash)
      throw Error('persisted release-policy deployment block changed or disappeared');
  }else{
    const mnemonic=process.env.VCFHE_MNEMONIC??'test test test test test test test test test test test junk';
    const wallet=ethers.HDNodeWallet.fromPhrase(mnemonic).connect(provider);
    const nonce=await provider.getTransactionCount(wallet.address,'pending');
    address=ethers.getCreateAddress({from:wallet.address,nonce});
    persisted={schema:'vcfhe-release-policy-deployment-v3',status:'pending',chainId:String(chainId),
      address,runtimeCodeHash:null,policyVersion:String(expectedVersion),domainSeparator:null,
      transactionHash:null,deploymentBlock:null,deploymentBlockHash:null,genesisBlockHash,
      lastVerifiedBlockNumber:null,lastVerifiedBlockHash:null,deployer:wallet.address,sourceSha256,compilerVersion,
      legacyMigrationInput:legacy.descriptor,legacyRecords:legacy.records};
    atomic(stateFile,persisted);
    const factory=new ethers.ContractFactory(artifact.abi,'0x'+artifact.evm.bytecode.object,wallet);
    const request=await factory.getDeployTransaction();
    const transaction=await wallet.sendTransaction({...request,nonce});transactionHash=transaction.hash;
    persisted={...persisted,transactionHash};atomic(stateFile,persisted);
    const receipt=await transaction.wait();
    deploymentBlock=receipt?.blockNumber??null;deploymentBlockHash=receipt?.blockHash??null;
    if(!receipt||receipt.status!==1||ethers.getAddress(receipt.contractAddress)!==ethers.getAddress(address))
      throw Error('release-policy deployment failed');
  }
  const code=await provider.getCode(address);
  if(code==='0x'||normalizedRuntime(code,references)!==expectedNormalized)
    throw Error('deployed release-policy runtime mismatch');
  const registry=new ethers.Contract(address,artifact.abi,provider);
  const policyVersion=BigInt(await registry.POLICY_VERSION());
  if(policyVersion!==expectedVersion)throw Error(`release-policy version mismatch: ${policyVersion} != ${expectedVersion}`);
  if(BigInt(await registry.deploymentChainId())!==chainId)throw Error('release-policy embedded chain mismatch');
  const policyDomain=await registry.policyDomain();
  if(!ethers.isHexString(policyDomain,32)||policyDomain===ethers.ZeroHash)throw Error('invalid release-policy domain');
  const domainSeparator=await registry.DOMAIN_SEPARATOR();
  if(!ethers.isHexString(domainSeparator,32)||domainSeparator===ethers.ZeroHash)throw Error('invalid release-policy domain separator');
  const expectedDomainSeparator=ethers.TypedDataEncoder.hashDomain({name:'VCFHE-Onchain-Release-Policy',
    version:'3',chainId,verifyingContract:address});
  if(domainSeparator!==expectedDomainSeparator)throw Error('release-policy EIP-712 domain mismatch');
  const runtimeCodeHash=ethers.keccak256(code);
  const checkpoint=await provider.getBlock('latest');
  if(!checkpoint?.hash)throw Error('release-policy checkpoint block unavailable');
  persisted={schema:'vcfhe-release-policy-deployment-v3',status:'deployed',chainId:String(chainId),
    address:ethers.getAddress(address),runtimeCodeHash,normalizedRuntimeCodeHash:ethers.keccak256(expectedNormalized),
    policyVersion:String(policyVersion),policyDomain,domainSeparator,transactionHash,deploymentBlock,deploymentBlockHash,
    genesisBlockHash,lastVerifiedBlockNumber:checkpoint.number,lastVerifiedBlockHash:checkpoint.hash,
    deployer:persisted?.deployer??null,sourceSha256,compilerVersion,
    legacyMigrationInput:legacy.descriptor,legacyRecords:legacy.records};
  atomic(stateFile,persisted);
  ownersSha256=ownersSha256??persisted.legacyMigrationInput?.ownersSha256??null;
  if(!ownersSha256)throw Error('release-policy deployment has no owner identity binding');
  atomic(runFile,{schema:'vcfhe-release-policy-config-v3',chainId:persisted.chainId,address:persisted.address,
    runtimeCodeHash:persisted.runtimeCodeHash,normalizedRuntimeCodeHash:persisted.normalizedRuntimeCodeHash,
    policyVersion:persisted.policyVersion,policyDomain:persisted.policyDomain,domainSeparator:persisted.domainSeparator,
    deploymentTransaction:persisted.transactionHash,deploymentBlock:persisted.deploymentBlock,
    deploymentBlockHash:persisted.deploymentBlockHash,genesisBlockHash:persisted.genesisBlockHash,
    lastVerifiedBlockNumber:persisted.lastVerifiedBlockNumber,lastVerifiedBlockHash:persisted.lastVerifiedBlockHash,
    sourceSha256:persisted.sourceSha256,compilerVersion:persisted.compilerVersion,
    ownersSha256,legacyMigrationInput:persisted.legacyMigrationInput,legacyRecords:persisted.legacyRecords});
  console.log(JSON.stringify({status:'verified',chainId:persisted.chainId,address:persisted.address,
    runtimeCodeHash:persisted.runtimeCodeHash,policyVersion:persisted.policyVersion}));
}finally{provider.destroy();}
