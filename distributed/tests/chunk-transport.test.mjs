// Infrastructure fixtures only. No ciphertext/FHE/protocol execution is mocked.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {randomBytes} from 'node:crypto';
const prepared=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function deferred(){let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};}

async function fixture(t){
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'vcfhe-transport-proposal-'));
  t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const local=path.join(root,'local'),peer=path.join(root,'peer'),cache=path.join(root,'cache'),peerCache=path.join(root,'peer-cache');
  for(const dir of [local,peer,cache,peerCache,path.join(root,'reports')])await fs.mkdir(dir,{recursive:true});
  let source=await fs.readFile(path.join(prepared,'client.mjs'),'utf8');
  source=source.replace("const cache='/transport/public-chunks';",'const cache='+JSON.stringify(cache)+';')
    .replace('manifest(paths,{cas:cache})','manifest(paths,{root:'+JSON.stringify(local)+',cas:cache})')
    .replace('install(rows,cache)','install(rows,cache,{root:'+JSON.stringify(local)+'})')
    .replaceAll("'/reports/distributed'",JSON.stringify(path.join(root,'reports')))
    .replaceAll("'/reports/distributed/transport.jsonl'",JSON.stringify(path.join(root,'reports/transport.jsonl')));
  await fs.writeFile(path.join(root,'client.mjs'),source);
  await fs.copyFile(path.join(prepared,'public-files.mjs'),path.join(root,'public-files.mjs'));
  await fs.writeFile(path.join(root,'role-transport.mjs'),'export async function callRole(options){return globalThis.__vcfheInfraTransport(options);}\n');
  const certs={};for(const name of ['key','cert','ca']){certs[name]=path.join(root,name);await fs.writeFile(certs[name],'fixture-'+name);}
  const config=path.join(root,'role.json');
  await fs.writeFile(config,JSON.stringify({node:'fixture-client',host:'fixture-host',campaign:'transport-fixture',tls:certs,
    peers:[{node:'fixture-peer',url:'https://127.0.0.1:9443/v1/role',fingerprint256:'a'.repeat(64)}]}));
  process.env.VCFHE_ROLE_CONFIG=config;
  const client=await import(pathToFileURL(path.join(root,'client.mjs')));
  const files=await import(pathToFileURL(path.join(root,'public-files.mjs')));
  const state={active:0,maximum:0,put:0,get:0,tasks:0,failPut:false,failGet:false,extraMissing:false,received:[],outputRows:[]};
  globalThis.__vcfheInfraTransport=async options=>{
    const {request}=options;assert.equal(options.url,'https://127.0.0.1:9443/v1/role');
    assert.equal(options.serverFingerprint256,'a'.repeat(64));
    for(const name of ['key','cert','ca'])assert.equal(options[name].toString(),'fixture-'+name);
    assert.equal(request.campaign,'transport-fixture');assert.equal(request.sender,'fixture-client');
    let value;
    if(request.operation==='missing-chunks'){
      value=[];for(const id of request.body.ids){try{await fs.access(path.join(peerCache,id));}catch(e){if(e.code!=='ENOENT')throw e;value.push(id);}}
      if(state.extraMissing)value.push('b'.repeat(64));
    }else if(request.operation==='put-chunk'||request.operation==='get-chunk'){
      const kind=request.operation==='put-chunk'?'put':'get';state[kind]++;state.active++;state.maximum=Math.max(state.maximum,state.active);
      try{
        if(state['fail'+(kind==='put'?'Put':'Get')]&&state[kind]===1){await sleep(2);throw Error('injected infrastructure transfer failure');}
        await sleep(15);
        if(kind==='put'){await files.putBlob(peerCache,request.body.id,Buffer.from(request.body.data,'base64'));value={id:request.body.id};}
        else value={id:request.body.id,data:(await fs.readFile(path.join(peerCache,request.body.id))).toString('base64')};
      }finally{state.active--;}
    }else if(request.operation==='task'){
      state.tasks++;assert.equal(state.active,0,'task crossed upload barrier');
      await files.install(request.body.files,peerCache,{root:peer});
      value={value:{infrastructureFixture:true},files:state.outputRows};
    }else throw Error('unexpected fixture operation '+request.operation);
    state.received.push(request.operation);
    return {response:{campaign:request.campaign,node:request.target,id:request.id,value,handlerSeconds:0},
      metrics:{requestJsonBytes:JSON.stringify(request).length,responseJsonBytes:1,elapsedSeconds:0,
        scope:'infrastructure-test-only'}};
  };
  return {root,local,peer,cache,peerCache,client,files,state};
}
async function inputFiles(root,count,prefix='input'){
  const names=[];
  for(let i=0;i<count;i++){
    const name='/fixtures/'+prefix+'-'+i+'.bin',file=root+name;
    await fs.mkdir(path.dirname(file),{recursive:true});await fs.writeFile(file,randomBytes(96*1024));names.push(name);
  }
  return names;
}

test('one task uploads and downloads with eight shared slots and both barriers',async t=>{
  const f=await fixture(t),inputs=await inputFiles(f.local,19),outputs=await inputFiles(f.peer,17,'output');
  f.state.outputRows=await f.files.manifest(outputs,{root:f.peer,cas:f.peerCache});
  const result=await f.client.task('fixture-peer','infrastructure-only',{},inputs,outputs);
  assert.equal(result.value.infrastructureFixture,true);assert.equal(f.state.tasks,1);assert.equal(f.state.active,0);
  assert.equal(f.state.maximum,8);assert.equal(f.state.put,19);assert.equal(f.state.get,17);
  for(const name of inputs)assert.deepEqual(await fs.readFile(f.local+name),await fs.readFile(f.peer+name));
  for(const name of outputs)assert.deepEqual(await fs.readFile(f.local+name),await fs.readFile(f.peer+name));
});

test('parallel transfers share eight slots per process, rather than eight per call',async t=>{
  const f=await fixture(t),a=await inputFiles(f.local,18,'a'),b=await inputFiles(f.local,18,'b');
  await Promise.all([f.client.push('fixture-peer',a),f.client.push('fixture-peer',b)]);
  assert.equal(f.state.maximum,8);assert.equal(f.state.put,36);assert.equal(f.state.active,0);
});

test('duplicate files/chunks and a warm resend do not add put/get calls',async t=>{
  const f=await fixture(t),names=await inputFiles(f.local,1),copy='/fixtures/identical-copy.bin';
  await fs.copyFile(f.local+names[0],f.local+copy);
  const rows=await f.client.push('fixture-peer',[...names,...names,copy]);
  assert.equal(rows.length,2);assert.equal(f.state.put,1);
  await f.client.push('fixture-peer',[...names,copy]);assert.equal(f.state.put,1);
  await f.client.pull('fixture-peer',rows);assert.equal(f.state.get,0);
});

test('an upload failure drains admitted calls and never starts a task',async t=>{
  const f=await fixture(t),names=await inputFiles(f.local,30);f.state.failPut=true;
  await assert.rejects(f.client.task('fixture-peer','must-not-start',{},names,[]),/injected infrastructure/);
  assert.equal(f.state.active,0);assert.equal(f.state.tasks,0);assert.ok(f.state.put<=8);assert.ok(f.state.put>1);
});

test('a peer cannot request a chunk outside the authorized manifest',async t=>{
  const f=await fixture(t),names=await inputFiles(f.local,9);f.state.extraMissing=true;
  await assert.rejects(f.client.task('fixture-peer','must-not-start',{},names,[]),/outside this manifest/);
  assert.equal(f.state.put,0);assert.equal(f.state.tasks,0);
});

test('a download failure drains calls and never installs partial destinations',async t=>{
  const f=await fixture(t),names=await inputFiles(f.peer,25,'download');
  const rows=await f.files.manifest(names,{root:f.peer,cas:f.peerCache});f.state.failGet=true;
  await assert.rejects(f.client.pull('fixture-peer',rows),/injected infrastructure/);
  assert.equal(f.state.active,0);assert.ok(f.state.get<=8);assert.ok(f.state.get>1);
  for(const name of names)await assert.rejects(fs.access(f.local+name),{code:'ENOENT'});
});

test('atomic publication hides a paused partial temp and accepts a concurrent same CID',async t=>{
  const f=await fixture(t),bytes=randomBytes(1024*1024),id=f.files.digest(bytes),first=deferred(),release=deferred();
  const realOpen=fs.open;let intercepted=false;
  fs.open=async(file,...args)=>{
    const handle=await realOpen(file,...args);
    if(String(file).startsWith(path.join(f.cache,'.'+id+'.'))&&!intercepted){
      intercepted=true;const write=handle.writeFile.bind(handle);
      handle.writeFile=async value=>{await handle.write(value.subarray(0,128),0,128,0);first.resolve();await release.promise;return write(value);};
    }
    return handle;
  };
  let pending;
  try{
    pending=f.files.putBlob(f.cache,id,bytes);await first.promise;
    await assert.rejects(fs.access(path.join(f.cache,id)),{code:'ENOENT'});
    await f.files.putBlob(f.cache,id,bytes);
    assert.deepEqual(await fs.readFile(path.join(f.cache,id)),bytes);
  }finally{release.resolve();if(pending)await pending;fs.open=realOpen;}
  assert.deepEqual(await fs.readFile(path.join(f.cache,id)),bytes);
  assert.deepEqual((await fs.readdir(f.cache)).filter(name=>name.endsWith('.pending')),[]);
});

test('same CID concurrency retains one complete blob and refuses corrupt existing content',async t=>{
  const f=await fixture(t),bytes=randomBytes(128*1024),id=f.files.digest(bytes);
  await Promise.all(Array.from({length:24},()=>f.files.putBlob(f.cache,id,bytes)));
  assert.deepEqual(await fs.readFile(path.join(f.cache,id)),bytes);
  assert.deepEqual(await fs.readdir(f.cache),[id]);
  const corrupt=Buffer.from('infrastructure-corruption-fixture');await fs.writeFile(path.join(f.cache,id),corrupt);
  await assert.rejects(f.files.putBlob(f.cache,id,bytes),/corrupt cached chunk/);
  assert.deepEqual(await fs.readFile(path.join(f.cache,id)),corrupt);
  assert.deepEqual(await fs.readdir(f.cache),[id]);
});

test('chunk digest failures propagate without destination writes',async t=>{
  const f=await fixture(t),bytes=randomBytes(64),id=f.files.digest(bytes);
  await assert.rejects(f.files.putBlob(f.cache,id,Buffer.from('changed fixture')),/integrity mismatch/);
  assert.deepEqual(await fs.readdir(f.cache),[]);
});

test('a temporary-write failure propagates and removes only its own temporary file',async t=>{
  const f=await fixture(t),bytes=randomBytes(128),id=f.files.digest(bytes),realOpen=fs.open;
  fs.open=async(file,...args)=>{
    const handle=await realOpen(file,...args);
    if(String(file).startsWith(path.join(f.cache,'.'+id+'.')))handle.writeFile=async()=>{throw Error('injected temporary-write failure');};
    return handle;
  };
  try{await assert.rejects(f.files.putBlob(f.cache,id,bytes),/injected temporary-write failure/);}
  finally{fs.open=realOpen;}
  assert.deepEqual(await fs.readdir(f.cache),[]);
});
