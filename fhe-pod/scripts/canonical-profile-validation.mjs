import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import assert from "node:assert/strict";
import { ethers } from "ethers";
import { evaluateCircuitReference } from "./compliance-circuit.mjs";
import { runCanonicalBinary, createExecutionContext, detectCanonicalFault, canonicalTrace } from "./canonical-protocol.mjs";
const binary=process.env.VCFHE_CIRCUIT_EXECUTOR, reportFile=process.argv[2];
if(!binary || !reportFile) throw new Error("set canonical binary and a new report path");
const workDir=await fs.mkdtemp(path.join(os.tmpdir(),"tops-canonical-profile-"));
const report={status:"running",workDir,classification:"profile-conformance-tests",cases:[]};
await fs.writeFile(reportFile,JSON.stringify(report),{flag:"wx"});
const save=()=>fs.writeFile(reportFile,JSON.stringify(report,null,2));
try {
  const constant=value=>({kind:"constant",value:String(value)}), input=index=>({kind:"input",index});
  const names=["ADD","SUB","MUL","DIV","MOD","EQ","LT","GT","MIN","BITAND","BITOR","BITXOR","SHR","CAST_U8","ADD_CHAIN"];
  const instructions=names.map((opcode,index)=>({index,opcode,lhs:input(0),rhs:
    ["SUB","DIV","MOD","SHR","ADD_CHAIN"].includes(opcode)?constant(2):input(1)}));
  instructions.push({index:15,opcode:"ADD",lhs:{kind:"output",index:14},rhs:constant(0)});
  const program={version:"compliance-explicit-dag-v1",inputs:[{id:"a",type:"uint64"},{id:"b",type:"uint64"}],
    instructions,output:{kind:"output",index:15}};
  const values=[3000,5],reference=evaluateCircuitReference(program,values);
  await fs.writeFile(path.join(workDir,"program.json"),JSON.stringify(program));
  await fs.writeFile(path.join(workDir,"values.json"),JSON.stringify(values));
  await fs.writeFile(path.join(workDir,"reference.json"),JSON.stringify(reference.outputs.map(String)));
  const preparation=await runCanonicalBinary(binary,["setup",path.join(workDir,"program.json"),path.join(workDir,"values.json"),workDir]);
  assert.equal(preparation.inputEncryption,"tfhe-compressed-public-key-v1");
  assert.equal(preparation.ownerEncryption.secretKeyReads,0);
  // The independent owner entry point is exercised with only copied public
  // material and fresh encryption coins; no key-generation directory is used.
  const isolated=await fs.mkdtemp(path.join(os.tmpdir(),"tops-public-owner-only-"));
  await fs.mkdir(path.join(isolated,"public"));
  for(const f of ["program.json","encryption-key.bin"])
    await fs.copyFile(path.join(workDir,"public",f),path.join(isolated,"public",f));
  await fs.copyFile(path.join(workDir,"values.json"),path.join(isolated,"values.json"));
  const ownerEncryption=await runCanonicalBinary(binary,["encrypt-inputs",path.join(isolated,"public"),path.join(isolated,"values.json")]);
  assert.equal(ownerEncryption.secretKeyReads,0);
  assert.notDeepEqual(await fs.readFile(path.join(isolated,"public/input-0.ct")),await fs.readFile(path.join(workDir,"public/input-0.ct")));
  report.cases.push({name:"public-only-owner-encryption",...ownerEncryption});await save();
  const publicDir=path.join(workDir,"public"),operatorDir=path.join(workDir,"operator");
  const owner=ethers.Wallet.createRandom();
  const context=await createExecutionContext({binary,publicDir,keyEpoch:"conformance",policyDomain:"conformance",
    inputBounds:[{min:"1000",max:"5000"},{min:"0",max:"7"}],
    records:values.map((_,i)=>({id:String(i),protectedId:ethers.id(`conformance-${i}`),owner:owner.address}))});
  await runCanonicalBinary(binary,["execute-canonical",publicDir,operatorDir]);
  const plain=await runCanonicalBinary(binary,["owner-check",path.join(workDir,"owner/client-key.bin"),operatorDir,
    String(reference.value),path.join(workDir,"reference.json")]);
  report.cases.push({name:"all-15-opcodes-plaintext-and-guards",...plain}); await save();
  for(let i=0;i<2;i++) {
    const replay=await detectCanonicalFault({binary,context,publicDir,operatorDir,replayDir:path.join(workDir,`replay-${i}`)});
    assert.equal(replay.index,null);report.cases.push({name:`independent-replay-${i}`,...replay});await save();
  }
  // An equal-valued alternate ciphertext is intentionally noncanonical in V1.
  const alternate=path.join(workDir,"equal-value-alternate");
  await runCanonicalBinary(binary,["execute-canonical-fault-fixture",publicDir,alternate,"0",String(reference.outputs[0])]);
  const alternatePlain=await runCanonicalBinary(binary,["owner-check",path.join(workDir,"owner/client-key.bin"),alternate,
    String(reference.value),path.join(workDir,"reference.json")]);
  const detected=await detectCanonicalFault({binary,context,publicDir,operatorDir:alternate,replayDir:path.join(workDir,"alternate-replay")});
  assert.equal(detected.index,0);
  report.cases.push({name:"same-plaintext-alternate-is-noncanonical",...alternatePlain,...detected});await save();
  const modified={...context,keyEpoch:"changed"};
  // Public context must be registered under the exact task certificate; a
  // changed epoch changes its digest even when the ciphertexts are identical.
  assert.notEqual(JSON.stringify(context),JSON.stringify(modified));
  await assert.rejects(canonicalTrace({...context,programDigest:ethers.id("changed-program")},publicDir,operatorDir));
  report.profile=context.profile;report.status="passed";
} catch(e) {report.status="failed";report.error=String(e.stack??e);throw e;}
finally {await save();}
