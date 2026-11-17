import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {ethers,json,ownerRpc} from './common.mjs';
import {policyHash} from '../scripts/recipient-output-policy.mjs';
import {runPublicWorker} from './public-worker.mjs';
import {ordinaryVerify,ordinaryPublicKey,ORDINARY_BLS_PROFILE} from './ordinary-bls.mjs';
import {measureLinearCommunication} from './linear-communication.mjs';
import {createSolidityCompileCache} from './solidity-compile-cache.mjs';
const require=createRequire('/app/BN254-Signatures/package.json');
const solc=require('solc'),L=require('/app/BN254-Signatures/scripts/mklhs-lib.js');
const compileLinearContracts=createSolidityCompileCache(solc);
async function writeContentAddressedWitness(bytes,digest){
 const target='/release-evidence/'+digest.slice(2)+'.json';
 try{await fs.writeFile(target,bytes,{flag:'wx',mode:0o600});}
 catch(error){
  if(error.code!=='EEXIST')throw error;
  assert.deepEqual(await fs.readFile(target),bytes,'content-addressed linear witness changed');
 }
 return target;
}
export async function linear({item,keys,admin,operator,ownerSigners,receipt,progress=()=>{}}){
 const dir=`/fixtures/${item.name}`,binary='/usr/local/bin/kms-campaign';
 const inputs=(await json(dir+'/coordinates.json')).map(a=>a.map(BigInt));
 const width=inputs[0].length,dimension=9*width,n=inputs.length;
 assert.equal(n,item.n);assert.ok(n>=1&&n<=33&&width>0&&width%8===0&&inputs.every(a=>a.length===width));
 const profile={...item.plan,dimension,lweSize:width/8,keyId:keys.keyId,keysetDigest:keys.keysetDigest,
  binaryDigest:ethers.keccak256(await fs.readFile(binary)),tfhe:'1.6.1',threads:1,fixedFFT:true};
 const profileDigest=policyHash(profile),sources={};
 for(const [name,file] of [['GroupedLinearVerification.sol','/app/threshold-kms/contracts/GroupedLinearVerification.sol'],
   ['MKLHS-Verification.sol','/app/BN254-Signatures/contract/MKLHS-Verification.sol']])sources[name]={content:await fs.readFile(file,'utf8')};
 const built=compileLinearContracts({language:'Solidity',sources,settings:{optimizer:{enabled:false},evmVersion:'london',
  outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}});
 assert.deepEqual((built.errors||[]).filter(e=>e.severity==='error'),[]);
 const a=built.contracts['GroupedLinearVerification.sol'].GroupedLinearVerification;
 const contract=await new ethers.ContractFactory(a.abi,a.evm.bytecode.object,admin).deploy(n,0,keys.keyEpoch,profileDigest,keys.keysetDigest,item.owners,{value:ethers.parseEther('1')});
 const deploymentReceipt=await receipt('linear-deploy',contract.deploymentTransaction());const tag=await contract.datasetTag();
 const records=item.recordIds.map((id,i)=>({id,owner:item.owners[i]})),gens=L.commitGenerators(dimension),vectors=[],admissions=[];
 progress('linear-admission');
 const prepareStart=performance.now();
 for(let i=0;i<n;i++){
  const owner=ownerSigners.find(s=>s.address===item.owners[i]);assert.ok(owner);
  const v=Array(dimension).fill(0n);inputs[i].forEach((x,j)=>{assert.ok(x>=0n&&x<(1n<<64n));v[Math.floor(i/4)*width+j]=x;});vectors.push(v);
  const signed=await ownerRpc({action:'bls',caseName:item.name,index:owner.index,input:i,datasetTag:tag,game:contract.target});admissions.push(signed);
  await receipt('owner-key',await contract.connect(owner).registerOwnerKey(i,signed.pk));
  await receipt('owner-admission',await contract.connect(owner).admitRecord(i,signed.commitment,signed.signature));
  await receipt('protected-record-binding',await contract.connect(owner).bindProtectedRecord(i,item.recordIds[i],L.coordsDigest(inputs[i])));
 }
 const ownerAdmissionMs=performance.now()-prepareStart;
 const context={profileDigest,keysetDigest:keys.keysetDigest,datasetTag:tag,records,ownerCiphertextDigests:inputs.map(L.coordsDigest)};
 const programDigest=policyHash(item.plan);
 const witnessBytes=Buffer.from(JSON.stringify({schema:'vcfhe-linear-release-witness-v1',
  inputPreparationAssumption:'honest-owner-preparation-required',plan:item.plan,
  vectors:inputs.map((coordinates,index)=>({coordsDigest:context.ownerCiphertextDigests[index],
   coordinates:coordinates.map(String)}))}));
 const linearWitnessDigest=ethers.keccak256(witnessBytes);
 await writeContentAddressedWitness(witnessBytes,linearWitnessDigest);
 const taskId=ethers.id(`${item.name}:${contract.target}`);
 const binding={chainId:String((await admin.provider.getNetwork()).chainId),game:contract.target,contextDigest:policyHash(context),
  taskId,programDigest,programRoot:programDigest,inputBindings:context.ownerCiphertextDigests,
  keyId:keys.keyId,keyEpoch:keys.keyEpoch,profileDigest,keysetDigest:keys.keysetDigest,mpcContext:keys.mpcContext,
  linearWitnessDigest,
  workflowManifest:{schema:'vcfhe-workflow-deployment-v1',kind:'grouped-linear',workflow:contract.target,
   deployments:{workflow:deploymentReceipt.hash}}};
 const outputFile=dir+'/output.bin',aggregateFile=dir+'/aggregate.bin';let aggregateDigest;
 const metrics={ownerAdmissionMs,dimension,aggregateBytes:dimension*32,baselineProfile:ORDINARY_BLS_PROFILE,
  ownerCryptographicPreparation:Object.fromEntries(['keygenMs','commitmentMs','proposalSignMs','baselineSignMs'].map(k=>
   [k,admissions.reduce((sum,a)=>sum+a.preparationTimings[k],0)]))};
 const normalize=async out=>runPublicWorker(binary,{action:'normalize',evaluationKey:'/keyset/evaluation-key.bin',plan:item.plan,
  aggregate:aggregateFile,aggregateDigest,output:out},dir);
 const execute=async()=>{
  progress('operator-execution');
  let start=performance.now();const aggregate=Array(dimension).fill(0n);
  for(const v of vectors)for(let j=0;j<dimension;j++)aggregate[j]=L.mod(aggregate[j]+v[j],L.R);
  const commitment=L.commit(aggregate,gens);aggregateDigest=L.coordsDigest(aggregate);metrics.aggregateMs=performance.now()-start;
  // Matched full-reaggregation baseline consumes these same encrypted vectors.
  start=performance.now();const baseline=Array(dimension).fill(0n);
  for(let i=0;i<n;i++){
   // Independent ordinary signatures cover canonical ciphertext bytes directly.
   // Do not reuse proposal signatures or charge its commitments to this baseline.
   assert.equal(admissions[i].baselineProfile,ORDINARY_BLS_PROFILE);
   const pk=ordinaryPublicKey(admissions[i].pk);
   assert.ok(ordinaryVerify({pk,datasetTag:tag,index:i,op:0,totalItems:n,vector:vectors[i]},admissions[i].baselineSignature));
   for(let j=0;j<dimension;j++)baseline[j]=L.mod(baseline[j]+vectors[i][j],L.R);
  }
  assert.deepEqual(baseline,aggregate);metrics.fullReaggregationMs=performance.now()-start;
  await receipt('operator-stake',await contract.connect(operator).depositStake({value:ethers.parseEther('1')}));
  await receipt('register-task',await contract.registerTask(taskId,operator.address));
  await receipt('bound-result',await contract.connect(operator).submitResultBound(taskId,aggregateDigest,L.g1ToContract(commitment)));
  await fs.writeFile(aggregateFile,Buffer.concat(aggregate.map(L.be32)),{flag:'wx'});
  start=performance.now();await normalize(outputFile);metrics.publicConversionMs=performance.now()-start;
  return {taskId,aggregateDigest,outputDigest:ethers.keccak256(await fs.readFile(outputFile)),outputType:'uint16'};
 };
 const resolve=async request=>{
  if(request.taskId!==taskId||request.game!==contract.target)return null;
  const result=await contract.getBoundResult(taskId);
  if(!result.accepted||result.outputDigest!==aggregateDigest||await contract.profileDigest()!==profileDigest||
     await contract.keysetDigest()!==keys.keysetDigest||Number(await contract.admittedCount())!==n)return null;
  assert.equal(await contract.datasetTag(),tag);
  for(let i=0;i<n;i++){
   assert.equal((await contract.recordOwner(i)).toLowerCase(),item.owners[i].toLowerCase());
   assert.deepEqual(Array.from(await contract.getOwnerKey(i)).map(String),admissions[i].pk);
  }
  assert.equal(ethers.keccak256(await fs.readFile(binary)),profile.binaryDigest);
  for(const [file,digest] of [['encryption-key.bin',keys.keyDescriptor.encryptionKeyDigest],['evaluation-key.bin',keys.keyDescriptor.evaluationKeyDigest]])
   assert.equal(ethers.keccak256(await fs.readFile('/keyset/'+file)),digest);
  const bytes=await fs.readFile(aggregateFile);assert.equal(bytes.length,dimension*32);assert.equal(ethers.keccak256(bytes),result.outputDigest);
  const coords=Array.from({length:dimension},(_,i)=>BigInt('0x'+bytes.subarray(i*32,(i+1)*32).toString('hex')));
  assert.ok(coords.every(v=>v<L.R));assert.deepEqual(L.g1ToContract(L.commit(coords,gens)).map(BigInt),Array.from(result.outputCommitment));
  const start=performance.now(),verified=dir+'/verified-'+Date.now()+'.bin';await normalize(verified);
  const digest=ethers.keccak256(await fs.readFile(verified));assert.equal(ethers.keccak256(await fs.readFile(outputFile)),digest);
  metrics.relayerVerificationMs=performance.now()-start;
  return {...binding,taskId,aggregateDigest,outputDigest:digest,outputType:'uint16',recordIds:item.recordIds,
    recordOwners:Object.fromEntries(records.map(r=>[r.id,r.owner]))};
 };
 // Called after workflow timers stop. This only records byte accounting for
 // the existing files. The experimental packing never changes their contents.
 const collectCommunication=async()=>{
  metrics.communication=measureLinearCommunication({inputs,op:item.plan.op,
   canonicalAggregate:await fs.readFile(aggregateFile),kmsWitnessBytes:witnessBytes.byteLength});
 };
 return {binding,execute,resolve,collectCommunication,metrics,outputFile,outputType:'uint16'};
}
