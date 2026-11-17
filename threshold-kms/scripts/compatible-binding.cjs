// Real owner BLS admissions, EVM accumulator and public conversion of genuine KMS-key ciphertexts.
// A component integration, never a replacement for the sealed evaluation measurements.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {createRequire}=require('node:module');
const {spawnSync}=require('node:child_process'),{randomBytes}=require('node:crypto');
const base=path.resolve(__dirname,'../../BN254-Signatures');
const dependency=createRequire(path.join(base,'package.json'));
const hre=dependency('hardhat'),{ethers}=hre,solc=dependency('solc');
const L=require(path.join(base,'scripts/mklhs-lib.js'));
async function main(){
 const cfg=JSON.parse(fs.readFileSync(process.argv[2],'utf8')),dir=cfg.directory,plan=cfg.plan;
 assert.equal(plan.profile,'kms-grouped-radix-v1');assert.ok(['SUM','SUB'].includes(plan.op));
 const inputs=JSON.parse(fs.readFileSync(path.join(dir,'coordinates.json'),'utf8')).map(row=>row.map(BigInt));
 const n=inputs.length;assert.ok(n>0&&n<=33);assert.equal(plan.bounds.length,n);
 const width=inputs[0].length;assert.equal(width%8,0);assert.ok(inputs.every(a=>a.length===width));
 const d=9*width,op=plan.op==='SUM'?0:1;
 const profile={...plan,dimension:d,lweSize:width/8,keyId:cfg.keyId};
 const profileDigest=ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(profile)));
 const source=fs.readFileSync(path.resolve(__dirname,'../contracts/GroupedLinearVerification.sol'),'utf8');
 const inherited=fs.readFileSync(path.join(base,'contract/MKLHS-Verification.sol'),'utf8');
 const built=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources:{'GroupedLinearVerification.sol':{content:source},'MKLHS-Verification.sol':{content:inherited}},
  settings:{optimizer:{enabled:false},evmVersion:'london',outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}})));
 const errors=(built.errors||[]).filter(e=>e.severity==='error');assert.equal(errors.length,0,JSON.stringify(errors));
 const artifact=built.contracts['GroupedLinearVerification.sol'].GroupedLinearVerification;
 const [admin,operator,...available]=await ethers.getSigners(),owners=inputs.map((_,i)=>available[i%available.length]);
 const contract=await new ethers.ContractFactory(artifact.abi,artifact.evm.bytecode.object,admin)
  .deploy(n,op,ethers.id(cfg.keyId),profileDigest,cfg.keysetDigest,owners.map(w=>w.address),{value:ethers.parseEther('1')});
 await contract.waitForDeployment();
 const tag=await contract.datasetTag(),gens=L.commitGenerators(d),weights=L.weightsFor(op,n);
 const positiveGroups=Math.ceil((op===0?n:1)/4),vectors=[];
 const admission=[];
 for(let i=0;i<n;i++){
  const g=op===0?Math.floor(i/4):(i===0?0:positiveGroups+Math.floor((i-1)/4));
  const vector=Array(d).fill(0n);for(let j=0;j<width;j++){assert.ok(inputs[i][j]>=0n&&inputs[i][j]<(1n<<64n));vector[g*width+j]=inputs[i][j];}
  vectors.push(vector);const commitment=L.commit(vector,gens),{sk,pk}=L.keygen(()=>randomBytes(32));
  const signature=L.sign(sk,commitment,tag,i,{pk,op,totalItems:n});
  await(await contract.connect(owners[i]).registerOwnerKey(i,L.g2ToContract(pk))).wait();
  const receipt=await(await contract.admitRecord(i,L.g1ToContract(commitment),L.g1ToContract(signature))).wait();
  admission.push({index:i,transaction:receipt.hash});
 }
 const aggregate=Array(d).fill(0n);for(let i=0;i<n;i++)for(let j=0;j<d;j++)aggregate[j]=L.mod(aggregate[j]+weights[i]*vectors[i][j],L.R);
 const commitment=L.commit(aggregate,gens),digest=L.coordsDigest(aggregate);
 const task=ethers.id(`grouped:${contract.target}`);
 await(await contract.connect(operator).depositStake({value:ethers.parseEther('1')})).wait();
 await(await contract.registerTask(task,operator.address)).wait();
 const changed=[...aggregate];changed[0]=(changed[0]+1n)%L.R;
 await assert.rejects(contract.connect(operator).submitResultBound.staticCall(task,L.coordsDigest(changed),L.g1ToContract(L.commit(changed,gens))));
 const accepted=await(await contract.connect(operator).submitResultBound(task,digest,L.g1ToContract(commitment))).wait();
 const aggregateFile=path.join(dir,'aggregate.bin');
 fs.writeFileSync(aggregateFile,Buffer.concat(aggregate.map(L.be32)));
 assert.equal(ethers.keccak256(fs.readFileSync(aggregateFile)),digest);
 assert.ok(L.commit(aggregate,gens).equals(commitment));
 assert.ok(!L.commit(changed,gens).equals(commitment));
 const worker=(data,name)=>{const file=path.join(dir,name+'.json');fs.writeFileSync(file,JSON.stringify(data));
  const r=spawnSync(cfg.workerBinary,['tops_public_fhe_worker','--exact','--nocapture','--test-threads=1'],
   {env:{...process.env,TOPS_FHE_WORKER_JOB:file,RAYON_NUM_THREADS:'1'},encoding:'utf8'});
  assert.equal(r.status,0,`${r.stdout}\n${r.stderr}`);};
 for(let i=0;i<2;i++)worker({action:'normalize',evaluationKey:cfg.evaluationKey,plan,aggregate:aggregateFile,aggregateDigest:digest,
  output:path.join(dir,i===0?'output.bin':'replayed.bin')},'convert-'+i);
 assert.deepEqual(fs.readFileSync(path.join(dir,'output.bin')),fs.readFileSync(path.join(dir,'replayed.bin')));
 const report={status:'passed',profile,profileDigest,keysetDigest:cfg.keysetDigest,keyId:cfg.keyId,
  contract:contract.target,taskId:task,chainId:String((await ethers.provider.getNetwork()).chainId),datasetTag:tag,
  aggregateDigest:digest,aggregateFile,aggregateBytes:d*32,outputDigest:ethers.keccak256(fs.readFileSync(path.join(dir,'output.bin'))),
  ownerAdmissions:admission,settlementTransaction:accepted.hash,independentConversionProcesses:2,
  negativeChecks:['changed-aggregate-contract-rejected','changed-delivery-commitment-rejected'],
  authorization:'not yet an application release gateway',classification:'real-FHE-and-EVM-component'};
 fs.writeFileSync(path.join(dir,'binding.json'),JSON.stringify(report,null,2));
 console.log(JSON.stringify({status:'passed',records:n,dimension:d,aggregateBytes:d*32}));
}
main().then(()=>process.exit(0)).catch(e=>{console.error(e);process.exit(1);});
