import fs from 'node:fs/promises';
import {createProgress} from './progress.mjs';
const progress=createProgress('evaluation');
import assert from 'node:assert/strict';
import {json,atomic,ethers,ownerRpc} from './common.mjs';
import {benchmarkTag,groupedVectors,aggregateVectors,generators,verifyProposal,verifyBaseline} from './paired-linear.mjs';
import {createExecutionContext,runCanonicalBinary,detectCanonicalFault,hashJson} from './runtime/scripts/canonical-protocol.mjs';
export async function runPairs(cfg,prepared){
 const report={profile:cfg.pocPlan.profile,status:'running',designSha256:cfg.pocPlan.designSha256,rows:[]};
 const save=()=>atomic('/reports/paired.json',report),binary='/usr/local/bin/kms-campaign';
 await save();
 const totals={warmup:cfg.pocPlan.jobs.filter(job=>job.warmup).length,
  paired:cfg.pocPlan.jobs.filter(job=>!job.warmup).length},completed={warmup:0,paired:0};
 for(const job of cfg.pocPlan.jobs){
  const item=prepared.cases.find(c=>c.name===job.name);assert.ok(item);console.log('PAIR '+job.ordinal+' '+job.name);
  const group=job.warmup?'warmup':'paired',progressCase={caseName:item.name,group,current:completed[group]+1,total:totals[group]};
  progress('paired-comparison',progressCase);
  const dir='/fixtures/'+item.name,start=performance.now(),wallStarted=new Date().toISOString();
  let fixtureDigest,operatorMs,preparation,variants;
  if(item.half==='linear'){
   const inputs=await json(dir+'/coordinates.json'),vectors=groupedVectors(inputs);
   await ownerRpc({action:'benchmark',caseName:item.name,index:0});
   const signed=await json(dir+'/benchmark-admissions.json');
   assert.equal(signed.datasetTag,benchmarkTag({caseName:item.name,keysetDigest:prepared.keys.keysetDigest,chainId:cfg.chainId}));
   const gens=generators(signed.dimension),t=performance.now(),aggregate=aggregateVectors(vectors);operatorMs=performance.now()-t;
   fixtureDigest=hashJson({keyset:prepared.keys.keysetDigest,inputs,plan:item.plan});
   preparation={ownerEncryptionMs:item.ownerPreparationMs,generatorsMs:signed.generatorsMs,
    ownerSignatures:signed.admissions.map(a=>a.preparationTimings)};
   const args={...signed,vectors,aggregate,generators:gens};
   variants={proposed:()=>verifyProposal(args),baseline:()=>verifyBaseline(args)};
  }else{
   const publicDir=dir+'/public',program=await json(publicDir+'/program.json');
   const context=await createExecutionContext({binary,publicDir,keyEpoch:prepared.keys.keyEpoch,policyDomain:cfg.policyDomain,
    inputBounds:item.inputBounds,records:program.inputs.map((r,i)=>({id:r.id,protectedId:item.recordIds[i%item.n],owner:item.owners[i%item.n]}))});
   fixtureDigest=hashJson(context);const operatorDir=dir+'/paired-operator';
   const t=performance.now();await runCanonicalBinary(binary,['execute-canonical',publicDir,operatorDir]);operatorMs=performance.now()-t;
   preparation={ownerEncryptionMs:item.ownerPreparationMs};
   const replay=async label=>{
    const evidence=await detectCanonicalFault({context,binary,publicDir,operatorDir,replayDir:dir+'/paired-'+label});
    assert.equal(evidence.index,null);assert.equal(evidence.plaintextOpenings,0);assert.equal(evidence.operatorRoot,evidence.replayRoot);return evidence;
   };
   // Off-chain components, explicitly excluding certificates/deployment/release.
   // The full-case baseline separately measures the actual certified backend.
   variants={proposed:()=>replay('proposed'),baseline:()=>Promise.all([replay('baseline-0'),replay('baseline-1')])};
  }
  const row={...job,fixtureDigest,wallStarted,preparation,operatorMs,sharedPreparationMs:performance.now()-start-operatorMs,
   scope:item.half==='linear'?'admission-and-aggregate-verification-v1':'one-vs-two-public-replays-component-v1',observations:{}};
  for(const name of job.order){
   const t=performance.now(),startedAt=new Date().toISOString(),evidence=await variants[name]();
   row.observations[name]={ms:performance.now()-t,startedAt,finishedAt:new Date().toISOString(),evidence};
  }
  row.wallFinished=new Date().toISOString();report.rows.push(row);await save();
  completed[group]++;progress('paired-comparison',{...progressCase,state:'done'});
 }
 report.status='passed';await save();return report;
}
