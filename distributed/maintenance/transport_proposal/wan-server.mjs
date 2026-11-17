// Temporary infrastructure endpoint. It has no protocol task or signing API.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createRoleServer} from './role-transport-core.mjs';
import {putBlob,blobId} from './public-files.mjs';
const cfg=JSON.parse(await fs.readFile('/probe/server-config.json','utf8'));
const cas='/transport/probe-cas';await fs.mkdir(cas,{recursive:true});
const handlers={
  'probe-ping':async()=>({infrastructureOnly:true,chunks:(await fs.readdir(cas)).filter(x=>/^[a-f0-9]{64}$/.test(x)).length}),
  'missing-chunks':async({ids})=>{
    if(!Array.isArray(ids)||ids.length>256)throw Error('bounded fixture IDs required');
    const missing=[];for(const id of ids){blobId(id);try{await fs.access(path.join(cas,id));}catch(e){if(e.code!=='ENOENT')throw e;missing.push(id);}}return missing;
  },
  'put-chunk':async({id,data})=>{await putBlob(cas,id,Buffer.from(data,'base64'));return{id};},
  'get-chunk':async({id})=>({id:blobId(id),data:(await fs.readFile(path.join(cas,id))).toString('base64')}),
};
const server=createRoleServer({campaign:cfg.campaign,node:cfg.node,
  key:await fs.readFile('/probe-tls/key'),cert:await fs.readFile('/probe-tls/cert'),ca:await fs.readFile('/probe-tls/ca'),
  peers:cfg.peers,journal:'/transport/probe-journal',handlers});
server.listen(cfg.port,'0.0.0.0',()=>console.log(JSON.stringify({ready:true,infrastructureOnly:true,port:cfg.port})));
for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>server.close(()=>process.exit(0)));
