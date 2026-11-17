// Revised deployment + real TFHE inputs + policy-gated final decryption.
// Use hardhat's --network vcfhe for the QBFT campaign; local is regression.
const fs=require("node:fs/promises"),path=require("node:path"),os=require("node:os");
const {execFile}=require("node:child_process"),{promisify}=require("node:util");
const assert=require("node:assert/strict"),hre=require("hardhat"),L=require("./mklhs-lib.js");
const exec=promisify(execFile);
async function main(){
 const {ethers}=hre;
 const {hashJson}=await import("../../fhe-pod/scripts/canonical-protocol.mjs");
 const {OutputReleasePolicy}=await import("../../fhe-pod/scripts/output-release-policy.mjs");
 const {SimulatedOutputKms}=await import("../../fhe-pod/scripts/simulated-output-kms.mjs");
 const {linearFinalityAdapter}=await import("./linear-output-policy.mjs");
 const reportFile=process.env.VCFHE_REPORT;if(!reportFile)throw new Error("set a new VCFHE_REPORT path");
 const binary=path.resolve(process.env.VCFHE_LINEAR_BINARY||"target/release/output_binding_tfhe");
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),"tops-linear-v2-"));
 const report={status:"running",classification:"linear-v2-integration",workDir:dir,cases:[],receipts:[],kms:"local full key, no threshold MPC"};
 await fs.writeFile(reportFile,JSON.stringify(report),{flag:"wx"});
 const save=()=>fs.writeFile(reportFile,JSON.stringify(report,null,2));
 try{
  const signers=await ethers.getSigners(),[admin,operator]=signers;
  const n=Number(process.env.VCFHE_LINEAR_N||10),values=Array.from({length:n},(_,i)=>i%5+1);
  if(!Number.isInteger(n)||n<2||n>33)throw new Error("linear comparison outside admitted regime");
  const owners=values.map((_,i)=>signers[2+i%(signers.length-2)]);
  const record=async(label,tx)=>{const r=await(await tx).wait();report.receipts.push({label,hash:r.hash,gasUsed:String(r.gasUsed),blockNumber:r.blockNumber,status:r.status});return r;};
  const factory=await ethers.getContractFactory("MKLHSVerificationV3");
  report.inputEncryption="seeded-regev-lwe-v2";
  const epoch=ethers.hexlify(ethers.randomBytes(32));
  const c=await factory.deploy("synthetic-linear-validation",1,n,0,epoch,owners.map(w=>w.address),{value:ethers.parseEther("1")});
  await record("deploy",c.deploymentTransaction());
  const chainId=String((await ethers.provider.getNetwork()).chainId);
  const context={kind:"linear-output-context-v2",datasetTag:await c.datasetTag(),keyEpoch:epoch,
   parameterDigest:await c.PARAMETER_DIGEST(),programDigest:hashJson({op:"SUM",n,scale:1}),
   inputBounds:values.map(()=>({min:"1",max:"5"})),
   records:owners.map((w,i)=>({protectedId:ethers.id(`synthetic-linear-record-${i}`),owner:w.address}))};
  const domain="linear-v2-validation",recipient=ethers.Wallet.createRandom(),taskId=ethers.id(`linear-v2-${c.target}`);
  const keyFile=path.join(dir,"private-kms-key.json"),liftedFile=path.join(dir,"delivered.json");
  let kmsCalls=0;
  const kms=new SimulatedOutputKms({decryptExact:async r=>{kmsCalls++;
   return JSON.parse((await exec(binary,["release-lwe",keyFile,liftedFile,r.outputDigest])).stdout);}});
  const policy=new OutputReleasePolicy({ledgerFile:path.join(dir,"ledger.json"),domain,kms,
   resolveFinalized:linearFinalityAdapter({contract:c,context,liftedFile})});
  const sign=(w,b)=>w.signMessage(ethers.getBytes(hashJson(b)));
  const approvalStart=performance.now();
  for(let i=0;i<n;i++){const r={id:context.records[i].protectedId,owner:owners[i].address,releaseLimit:1};
   await policy.registerProtectedRecord(r,await sign(owners[i],{kind:"protected-record-v1",domain,...r}));}
  const consent={kind:"final-output-consent-v1",domain,slot:ethers.id(`slot-${c.target}`),contextDigest:hashJson(context),
   programDigest:context.programDigest,keyEpoch:epoch,game:c.target,chainId,recordIds:context.records.map(r=>r.protectedId),
   outputType:"uint64",recipients:[recipient.address]};
  const sigs=Object.fromEntries(await Promise.all(owners.map(async w=>[w.address.toLowerCase(),await sign(w,consent)])));
  const consentId=await policy.registerConsent(consent,sigs);
  report.ownerPolicySetupMs=performance.now()-approvalStart;
  // Consent precedes the encrypted execution; only dataset owners may approve.
  const casesFile=path.join(dir,"cases.json"),payloadFile=path.join(dir,"payload.json");
  await fs.writeFile(casesFile,JSON.stringify({fresh_randomness:true,local_kms_key_file:keyFile,cases:[{
   label:"bounded-linear-sum",op:"SUM",values,dataset_tag:context.datasetTag}]}));
  await exec(binary,["emit-public-mk-cases",payloadFile,casesFile],{maxBuffer:8*1024*1024});
  const e=JSON.parse(await fs.readFile(payloadFile,"utf8")).sizes[0];
  for(const r of e.records){const pk=r.pubkey;
   await record("registerOwnerKey",c.connect(owners[r.index]).registerOwnerKey(r.index,pk));
   await record("admitRecord",c.admitRecord(r.index,r.commitment,r.signature));}
  await record("operatorStake",c.connect(operator).depositStake({value:ethers.parseEther("1")}));
  await record("registerTask",c.registerTask(taskId,operator.address));
  await fs.writeFile(liftedFile,JSON.stringify(e.honest.lifted));
  const request={kind:"final-output-release-v1",domain,requestId:ethers.id(`request-${c.target}`),taskId,slot:consent.slot,consentId,
   contextDigest:consent.contextDigest,keyEpoch:epoch,game:c.target,chainId,outputDigest:e.honest.output_digest,recipient:recipient.address};
  const release=async r=>policy.release(r,await sign(recipient,r));
  await assert.rejects(release(request),/finalized/);assert.equal(kmsCalls,0);
  await assert.rejects(c.connect(operator).submitResultBound.staticCall(taskId,e.attack.output_digest,e.attack.commitment));
  await record("submitResultBound",c.connect(operator).submitResultBound(taskId,e.honest.output_digest,e.honest.commitment));
  const forgedContext={...context,records:context.records.map(r=>({...r,owner:admin.address}))};
  assert.equal(await linearFinalityAdapter({contract:c,context:forgedContext,liftedFile})(request),null);
  const altered=[...e.honest.lifted];altered[0]=String((BigInt(altered[0])+1n)%L.R);
  await fs.writeFile(liftedFile,JSON.stringify(altered));await assert.rejects(release(request),/finalized/);assert.equal(kmsCalls,0);
  await fs.writeFile(liftedFile,JSON.stringify(e.honest.lifted));
  const releaseStart=performance.now();
  const output=await release(request);report.authorizedReleaseMs=performance.now()-releaseStart;
  assert.equal(output.value,String(values.reduce((a,b)=>a+b,0)));
  await assert.rejects(release(request),/consumed/);assert.equal(kmsCalls,1);
  report.cases.push({n,expected:values.reduce((a,b)=>a+b,0),output,kmsCalls,unauthorizedDecryptions:0});
  report.context=context;report.chainId=chainId;report.runtimeBytes=ethers.getBytes(await ethers.provider.getCode(c.target)).length;
  report.status="passed";
 }catch(e){report.status="failed";report.error=String(e.stack??e);throw e;}finally{await save();}
}
main().catch(e=>{console.error(e);process.exitCode=1;});
