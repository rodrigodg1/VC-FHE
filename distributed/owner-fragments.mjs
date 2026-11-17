// Encryption is local to each owner. Only ciphertext fragments cross hosts.
import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {configuration,rpc,pull} from './client.mjs';
import {runPublicFheProcess} from '../threshold-kms/campaign/public-worker-resources.mjs';
import {normalizeLocally} from './normalization.mjs';
const hash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
export async function distributedEncrypt(binary,job,privateDir,ownerIndices){
  if(job.action==='normalize')return normalizeLocally(binary,job,privateDir);
  const cfg=await configuration(),self=cfg.ownerIndex,name=path.basename(privateDir);
  assert.equal(cfg.role,'owner');assert.equal(ownerIndices.length,job.values.length);
  assert.ok(ownerIndices.every(i=>Number.isSafeInteger(i)&&i>=0&&i<4));
  const indices=ownerIndices.flatMap((owner,i)=>owner===self?[i]:[]);
  const fragmentRoot=`/fixtures/${name}/owner-fragments`,dest=`${fragmentRoot}/${self}`;
  await fs.mkdir(dest,{recursive:true});
  const privateFragment=privateDir+'/own-fragment',started=performance.now();
  const keys=JSON.parse(await fs.readFile('/keyset/ready.json','utf8'));
  const scope={caseName:name,action:job.action,owners:ownerIndices,keyset:keys.keysetDigest,
    configuration:job.action==='prepare'?job.plan:job.program};
  assert.ok(keys.keysetDigest,'keyset binding required');
  let coords=[],resources=null;
  if(indices.length){
    const partial={...job,values:indices.map(i=>job.values[i])};
    if(job.action==='prepare')partial.plan={...job.plan,bounds:indices.map(i=>job.plan.bounds[i])};
    else{
      assert.equal(job.action,'kms-encrypt-circuit');
      partial.publicDir=privateFragment+'/public';
      partial.program={...job.program,inputs:indices.map(i=>job.program.inputs[i])};
    }
    await fs.mkdir(privateFragment,{recursive:true,mode:0o700});
    const jobFile=privateFragment+'/encryption.job.json',resourceFile=privateFragment+'/encryption.resources.json';
    await fs.writeFile(jobFile,JSON.stringify(partial),{flag:'wx',mode:0o600});
    resources=await runPublicFheProcess({binary,jobFile,resourceFile,collectResources:true});
    if(job.action==='prepare')coords=JSON.parse(await fs.readFile(privateFragment+'/coordinates.json','utf8'));
    for(const [local,global] of indices.entries()){
      const from=job.action==='prepare'?`${privateFragment}/input-${local}.bin`:`${partial.publicDir}/input-${local}.ct`;
      await fs.copyFile(from,`${dest}/input-${global}.${job.action==='prepare'?'bin':'ct'}`);
    }
  }
  const fragment={schema:'vcfhe-owner-ciphertext-fragment-v1',scopeSha256:hash(scope),owner:self,indices,
    coordinates:job.action==='prepare'?coords:undefined,encryptionElapsedMs:performance.now()-started,
    host:cfg.host,node:cfg.node,resources};
  // Marker is written last. A reader cannot observe a partial fragment.
  await fs.writeFile(dest+'/fragment.json',JSON.stringify(fragment),{flag:'wx'});
  const deadline=Date.now()+(cfg.timeoutSeconds??14400)*1000;
  const all=[];
  for(let owner=0;owner<4;owner++){
    if(owner!==self){
      while(true){
        const response=await rpc(`owner-${owner+1}`,'public-manifest',{paths:[`${fragmentRoot}/${owner}/fragment.json`]});
        if(response.ready){
          const complete=await rpc(`owner-${owner+1}`,'public-manifest',{paths:[`${fragmentRoot}/${owner}`]});
          assert.ok(complete.ready);await pull(`owner-${owner+1}`,complete.files);break;
        }
        if(Date.now()>deadline)throw Error('owner ciphertext exchange timed out');
        await new Promise(r=>setTimeout(r,500));
      }
    }
    const piece=JSON.parse(await fs.readFile(`${fragmentRoot}/${owner}/fragment.json`,'utf8'));
    assert.equal(piece.scopeSha256,hash(scope));assert.equal(piece.owner,owner);
    assert.deepEqual(piece.indices,ownerIndices.flatMap((o,i)=>o===owner?[i]:[]));all.push(piece);
  }
  const output=job.action==='prepare'?privateDir:job.publicDir;
  await fs.mkdir(output,{recursive:true});
  const coordinates=Array(job.values.length);
  for(const piece of all)for(const [local,global] of piece.indices.entries()){
    const ext=job.action==='prepare'?'bin':'ct';
    await fs.copyFile(`${fragmentRoot}/${piece.owner}/input-${global}.${ext}`,`${output}/input-${global}.${ext}`);
    if(ext==='bin')coordinates[global]=piece.coordinates[local];
  }
  if(job.action==='prepare')await fs.writeFile(privateDir+'/coordinates.json',JSON.stringify(coordinates));
  else{
    await fs.writeFile(output+'/program.json',JSON.stringify(job.program));
    await fs.writeFile(output+'/kms-keyset.json',JSON.stringify(job.keyset));
    await fs.copyFile(job.publicKey,output+'/encryption-key.bin');
    await fs.copyFile(job.evaluationKey,output+'/server-key.bin');
  }
  return {ownerFragments:all,elapsedMs:performance.now()-started};
}
