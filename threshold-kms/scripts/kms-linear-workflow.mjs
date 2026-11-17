import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {randomBytes,randomUUID} from 'node:crypto';
import {runPublicWorker} from './kms-public-worker.mjs';
import {policyHash} from './recipient-output-policy.mjs';
const base=path.resolve(path.dirname(new URL(import.meta.url).pathname),'../../BN254-Signatures');
const require=createRequire(path.join(base,'package.json'));
const {ethers}=require('ethers'),solc=require('solc'),L=require(path.join(base,'scripts/mklhs-lib.js'));
let compiled;
async function artifact(){
 if(compiled)return compiled;
 const source=await fs.readFile(new URL('../contracts/GroupedLinearVerification.sol',import.meta.url),'utf8');
 const inherited=await fs.readFile(path.join(base,'contract/MKLHS-Verification.sol'),'utf8');
 const built=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'GroupedLinearVerification.sol':{content:source},'MKLHS-Verification.sol':{content:inherited}},
  settings:{optimizer:{enabled:false},evmVersion:'london',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
 assert.deepEqual((built.errors||[]).filter(e=>e.severity==='error'),[]);
 return compiled=built.contracts['GroupedLinearVerification.sol'].GroupedLinearVerification;
}
export async function linearWorkflow({cfg,signers,name,op,values,bounds}) {
 const dir=path.join(cfg.root,name);await fs.mkdir(dir);
 const plan={profile:'kms-grouped-radix-v1',op,bounds};
 await runPublicWorker(cfg.workerBinary,{action:'prepare',evaluationKey:cfg.evaluationKey,publicKey:cfg.publicKey,plan,values},dir);
 // Owner encryption and normalization precede the signatures. No aggregate or
 // final conversion exists when the workflow returns for owner consent.
 const inputs=JSON.parse(await fs.readFile(path.join(dir,'coordinates.json'),'utf8')).map(a=>a.map(BigInt));
 const n=inputs.length,width=inputs[0].length,d=9*width,operation=op==='SUM'?0:1;
 assert.ok(n>=1&&n<=33&&width%8===0&&inputs.every(a=>a.length===width));
 const profile={...plan,dimension:d,lweSize:width/8,keyId:cfg.keyId,keysetDigest:cfg.keysetDigest,
  binaryDigest:ethers.keccak256(await fs.readFile(cfg.workerBinary)),tfhe:'1.6.1',threads:1,fixedFFT:true};
 const profileDigest=policyHash(profile),a=await artifact(),[admin,operator,...available]=signers;
 const owners=inputs.map((_,i)=>available[i%available.length]);
 const contract=await new ethers.ContractFactory(a.abi,a.evm.bytecode.object,admin)
  .deploy(n,operation,cfg.keyEpoch,profileDigest,cfg.keysetDigest,owners.map(o=>o.address),{value:ethers.parseEther('1')});
 await contract.waitForDeployment();
 const tag=await contract.datasetTag(),gens=L.commitGenerators(d),weights=L.weightsFor(operation,n),vectors=[];
 const records=owners.map((owner,i)=>({id:ethers.id(`${name}:stable-record:${i}`),owner:owner.address}));
 for(let i=0;i<n;i++){
  const g=operation===0?Math.floor(i/4):(i===0?0:1+Math.floor((i-1)/4));
  const v=Array(d).fill(0n);for(let j=0;j<width;j++){assert.ok(inputs[i][j]>=0n&&inputs[i][j]<(1n<<64n));v[g*width+j]=inputs[i][j];}
  vectors.push(v);const p=L.commit(v,gens),{sk,pk}=L.keygen(()=>randomBytes(32));
  const signature=L.sign(sk,p,tag,i,{pk,op:operation,totalItems:n});
  await(await contract.connect(owners[i]).registerOwnerKey(i,L.g2ToContract(pk))).wait();
  await(await contract.admitRecord(i,L.g1ToContract(p),L.g1ToContract(signature))).wait();
 }
 const context={profileDigest,keysetDigest:cfg.keysetDigest,datasetTag:tag,records,ownerCiphertextDigests:inputs.map(L.coordsDigest)};
 const binding={chainId:String((await admin.provider.getNetwork()).chainId),game:contract.target,
  contextDigest:policyHash(context),programDigest:policyHash(plan),keyId:cfg.keyId,keyEpoch:cfg.keyEpoch,
  profileDigest,keysetDigest:cfg.keysetDigest,mpcContext:cfg.mpcContext};
 const taskId=ethers.id(`${name}:task:${contract.target}`),aggregateFile=path.join(dir,'aggregate.bin'),outputFile=path.join(dir,'output.bin');
 let aggregateDigest;
 const checkProfile=async()=>{
  assert.equal(ethers.keccak256(await fs.readFile(cfg.workerBinary)),profile.binaryDigest);
  assert.equal(ethers.keccak256(await fs.readFile(cfg.publicKey)),cfg.keyDescriptor.encryptionKeyDigest);
  assert.equal(ethers.keccak256(await fs.readFile(cfg.evaluationKey)),cfg.keyDescriptor.evaluationKeyDigest);
 };
 const execute=async()=>{
  await checkProfile();
  const aggregate=Array(d).fill(0n);
  for(let i=0;i<n;i++)for(let j=0;j<d;j++)aggregate[j]=L.mod(aggregate[j]+weights[i]*vectors[i][j],L.R);
  const commitment=L.commit(aggregate,gens);aggregateDigest=L.coordsDigest(aggregate);
  await(await contract.connect(operator).depositStake({value:ethers.parseEther('1')})).wait();
  await(await contract.registerTask(taskId,operator.address)).wait();
  const changed=[...aggregate];changed[0]=(changed[0]+1n)%L.R;
  await assert.rejects(contract.connect(operator).submitResultBound.staticCall(taskId,L.coordsDigest(changed),L.g1ToContract(L.commit(changed,gens))));
  await(await contract.connect(operator).submitResultBound(taskId,aggregateDigest,L.g1ToContract(commitment))).wait();
  await fs.writeFile(aggregateFile,Buffer.concat(aggregate.map(L.be32)),{flag:'wx'});
  await runPublicWorker(cfg.workerBinary,{action:'normalize',evaluationKey:cfg.evaluationKey,plan,aggregate:aggregateFile,aggregateDigest,output:outputFile},dir);
  return {taskId,aggregateDigest,outputDigest:ethers.keccak256(await fs.readFile(outputFile)),outputType:'uint16'};
 };
 const resolve=async request=>{
  await checkProfile();
  if(request.taskId!==taskId||request.game!==contract.target)return null;
  const result=await contract.getBoundResult(taskId);
  if(!result.accepted||result.outputDigest!==aggregateDigest||await contract.profileDigest()!==profileDigest||await contract.keysetDigest()!==cfg.keysetDigest||Number(await contract.admittedCount())!==n)return null;
  const bytes=await fs.readFile(aggregateFile);assert.equal(bytes.length,d*32);assert.equal(ethers.keccak256(bytes),result.outputDigest);
  const coords=Array.from({length:d},(_,i)=>BigInt('0x'+bytes.subarray(i*32,(i+1)*32).toString('hex')));
  assert.ok(coords.every(v=>v<L.R));
  assert.deepEqual(L.g1ToContract(L.commit(coords,gens)).map(BigInt),Array.from(result.outputCommitment));
  for(let i=0;i<n;i++)assert.equal((await contract.recordOwner(i)).toLowerCase(),records[i].owner.toLowerCase());
  // Recompute the specified conversion from delivered, authenticated A, never
  // trust the operator's normalized output or the request's output digest.
  const converted=path.join(dir,`gateway-conversion-${randomUUID()}.bin`);
  await runPublicWorker(cfg.workerBinary,{action:'normalize',evaluationKey:cfg.evaluationKey,plan,aggregate:aggregateFile,aggregateDigest,output:converted},dir);
  const digest=ethers.keccak256(await fs.readFile(converted));
  assert.equal(ethers.keccak256(await fs.readFile(outputFile)),digest);
  return {...binding,taskId,aggregateDigest,outputDigest:digest,outputType:'uint16',recordIds:records.map(r=>r.id),recordOwners:Object.fromEntries(records.map(r=>[r.id,r.owner]))};
 };
 return {name,dir,binding,records,owners,execute,resolve,outputFile,inputFile:path.join(dir,'input-0.bin'),outputType:'uint16',
  expected:values.reduce((a,v,i)=>a+(operation===1&&i>0?-v:v),0),evidence:{profile,profileDigest,records:n,dimension:d,aggregateBytes:d*32,context,taskId,contract:contract.target}};
}
