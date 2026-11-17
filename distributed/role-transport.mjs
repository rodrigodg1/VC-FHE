// Authenticated transport for the participant adapters.
// This module is not an owner, signer, evaluator, KMS or release-policy adapter.
import https from 'node:https';
import tls from 'node:tls';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash, randomUUID} from 'node:crypto';

const hash = value => createHash('sha256').update(value).digest('hex');
const canonical = value => {
  if (Array.isArray(value)) return '['+value.map(canonical).join(',')+']';
  if (value && typeof value === 'object') return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
  return JSON.stringify(value);
};
const safe = value => typeof value === 'string' && /^[a-zA-Z0-9-]{1,100}$/.test(value);
const fingerprint = value => String(value).replaceAll(':','').toLowerCase();

async function writeNew(file, value) {
  const handle = await fs.open(file,'wx',0o600);
  try { await handle.writeFile(JSON.stringify(value)); await handle.sync(); }
  finally { await handle.close(); }
}

async function finish(file,value) {
  const temporary = file+'.'+randomUUID()+'.tmp';
  await writeNew(temporary,value);
  await fs.rename(temporary,file);
  const dir = await fs.open(path.dirname(file),'r');
  try { await dir.sync(); } finally { await dir.close(); }
}

export function createRoleServer({campaign,node,key,cert,ca,peers,journal,handlers,maxBytes=8*1024*1024}) {
  if (!safe(campaign)||!safe(node)||!path.isAbsolute(journal)) throw Error('invalid role transport configuration');
  if (!Number.isSafeInteger(maxBytes)||maxBytes<1) throw Error('invalid message limit');
  const peerMap = new Map();
  for (const peer of peers) {
    if (!safe(peer.node)||peerMap.has(peer.node)||!/^[a-f0-9]{64}$/.test(fingerprint(peer.fingerprint256))||!Array.isArray(peer.operations))
      throw Error('invalid or duplicate peer identity');
    peerMap.set(peer.node,peer);
  }
  const server = https.createServer({key,cert,ca,requestCert:true,rejectUnauthorized:true,minVersion:'TLSv1.3'},async(req,res)=>{
    const reply = (status,value) => { if (!res.destroyed) {res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(value));} };
    try {
      if (req.method!=='POST'||req.url!=='/v1/role') return reply(404,{error:'unsupported endpoint'});
      if (req.headers['content-type']!=='application/json') return reply(415,{error:'JSON required'});
      const chunks=[]; let length=0;
      for await (const chunk of req) {
        length+=chunk.length;
        if (length>maxBytes) {reply(413,{error:'message too large'});return;}
        chunks.push(chunk);
      }
      let request;
      try {request=JSON.parse(Buffer.concat(chunks).toString('utf8'));} catch {return reply(400,{error:'invalid JSON'});}
      if (!request||!safe(request.id)||request.campaign!==campaign||request.target!==node||!safe(request.sender))
        return reply(403,{error:'wrong campaign or participant binding'});
      const peer=peerMap.get(request.sender);
      if (!req.socket.authorized||!peer||fingerprint(req.socket.getPeerCertificate().fingerprint256)!==fingerprint(peer.fingerprint256))
        return reply(403,{error:'unrecognized authenticated peer'});
      if (!peer.operations.includes(request.operation)||!Object.hasOwn(handlers,request.operation))
        return reply(403,{error:'operation not authorized for this peer'});
      const journalKey=hash(campaign+'\0'+request.sender+'\0'+request.id);
      const file=path.join(journal,journalKey+'.json');
      const requestHash=hash(canonical(request));
      await fs.mkdir(journal,{recursive:true,mode:0o700});
      const binding={campaign,node,sender:request.sender,id:request.id,operation:request.operation,requestHash};
      try {
        await writeNew(file,{...binding,state:'started'});
        const dir=await fs.open(journal,'r');
        try {await dir.sync();} finally {await dir.close();}
      } catch(error) {
        if(error.code!=='EEXIST') throw error;
        let old;
        try {old=JSON.parse(await fs.readFile(file,'utf8'));} catch {return reply(409,{error:'ambiguous durable request. Reconciliation required'});}
        if(old.requestHash!==requestHash) return reply(409,{error:'request ID reused with different content'});
        if(old.state==='completed') return reply(200,old.response);
        return reply(409,{error:'request already started or failed. Reconcile without replaying the action'});
      }
      const start=process.hrtime.bigint();
      try {
        // The handler must independently enforce protocol rules and verify its
        // local chain state. Peer authentication is not computation consent.
        const value=await handlers[request.operation](request.body,{campaign,node,sender:request.sender,id:request.id});
        const response={campaign,node,id:request.id,value,handlerSeconds:Number(process.hrtime.bigint()-start)/1e9};
        await finish(file,{...binding,state:'completed',response});
        return reply(200,response);
      } catch(error) {
        await finish(file,{...binding,state:'failed',errorType:error.name??'Error'});
        return reply(500,{error:'role action failed. Reconciliation required'});
      }
    } catch {reply(500,{error:'transport or durable storage failure. Reconciliation required'});}
  });
  server.requestTimeout=120000;
  server.headersTimeout=10000;
  return server;
}

export function callRole({url,request,key,cert,ca,serverFingerprint256,timeoutMs=120000,maxResponseBytes=8*1024*1024}) {
  const endpoint = new URL(url);
  if(endpoint.protocol!=='https:'||endpoint.username||endpoint.password||endpoint.pathname!=='/v1/role'||endpoint.search||endpoint.hash)
    throw Error('use the exact HTTPS role endpoint without URL credentials');
  if(!/^[a-f0-9]{64}$/.test(fingerprint(serverFingerprint256))) throw Error('pinned server certificate required');
  const body=Buffer.from(JSON.stringify(request));
  const started=process.hrtime.bigint();
  return new Promise((resolve,reject)=>{
    // Do not reuse a global TLS socket across calls with different pinned identities.
    const req=https.request(endpoint,{method:'POST',key,cert,ca,agent:false,minVersion:'TLSv1.3',rejectUnauthorized:true,
      headers:{'Content-Type':'application/json','Content-Length':body.length},
      checkServerIdentity:(hostname,certificate)=>tls.checkServerIdentity(hostname,certificate)||
        (fingerprint(certificate.fingerprint256)===fingerprint(serverFingerprint256)?undefined:Error('server identity mismatch'))},res=>{
      const chunks=[];let size=0;
      res.on('data',chunk=>{
        size+=chunk.length;
        if(size>maxResponseBytes) req.destroy(Error('response too large'));
        else chunks.push(chunk);
      });
      res.on('error',reject);
      res.on('end',()=>{
        try {
          const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if(res.statusCode!==200) throw Error(value.error??'role request failed');
          if(value.campaign!==request.campaign||value.node!==request.target||value.id!==request.id)
            throw Error('response binding mismatch');
          resolve({response:value,metrics:{requestJsonBytes:body.length,responseJsonBytes:size,
            elapsedSeconds:Number(process.hrtime.bigint()-started)/1e9,
            scope:'request-to-response-including-handler-not-network-only'}});
        } catch(error) {reject(error);}
      });
    });
    const timer=setTimeout(()=>req.destroy(Error('role request deadline expired. Reconcile using the same request ID')),timeoutMs);
    req.on('error',reject);
    req.on('close',()=>clearTimeout(timer));
    req.end(body);
  });
}
