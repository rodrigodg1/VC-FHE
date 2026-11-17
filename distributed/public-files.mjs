// Transport only public ciphertexts and protocol evidence. Private volumes are
// deliberately outside this namespace, including the recipient's plaintext.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash, randomUUID} from 'node:crypto';
export const CHUNK_BYTES=1024*1024;
export const digest=b=>createHash('sha256').update(b).digest('hex');
export function publicPath(value){
  if(typeof value!=='string'||value.includes('\0')||path.posix.normalize(value)!==value||
     !/^\/(fixtures|keyset|release-evidence|exchange)\//.test(value))throw Error('outside public namespace');
  if(value.split('/').some(p=>p.startsWith('.')||/^(private|identity|identities|signing|tls-key|expected|result-\d+\.json)(\.|$)/.test(p)))
    throw Error('private material cannot be transferred');
  if(value.startsWith('/keyset/')&&!/^\/keyset\/(ready\.json|prss\.json|encryption-key\.bin|evaluation-key\.bin|keyset\.json|keyset_descriptor\.json)$/.test(value)&&
     !/^\/keyset\/PUB-p[1-4](\/|$)/.test(value))
    throw Error('keyset file is not an admitted public key');
  return value;
}
export function blobId(id){if(typeof id!=='string'||!/^[0-9a-f]{64}$/.test(id))throw Error('invalid content hash');return id;}
export async function noSymlinks(file,root='/'){
  const resolved=path.resolve(root,'.'+publicPath(file));
  let current=path.resolve(root);
  for(const part of file.split('/').filter(Boolean)){
    current=path.join(current,part);
    try{if((await fs.lstat(current)).isSymbolicLink())throw Error('symlink in public file path');}
    catch(e){if(e.code!=='ENOENT')throw e;}
  }
  return resolved;
}
export async function manifest(paths,{root='/',cas}={}){
  const rows=[];
  async function visit(name){
    const local=await noSymlinks(name,root),s=await fs.lstat(local);
    if(s.isDirectory()){
      for(const child of (await fs.readdir(local)).sort()){
        // Native worker job/result queues are local execution bookkeeping.
        // Never transmit them with the enclosing public case directory.
        if(child==='.worker-jobs')continue;
        await visit(name+'/'+child);
      }
    }else{
      if(!s.isFile())throw Error('not a regular public file');
      const handle=await fs.open(local,'r'),chunks=[];
      try{
        let position=0;
        while(position<s.size){
          const buffer=Buffer.alloc(Math.min(CHUNK_BYTES,s.size-position));
          const {bytesRead}=await handle.read(buffer,0,buffer.length,position);
          if(bytesRead!==buffer.length)throw Error('public file changed during snapshot');
          const id=digest(buffer);chunks.push(id);
          if(cas)await putBlob(cas,id,buffer);
          position+=bytesRead;
        }
      }finally{await handle.close();}
      const after=await fs.stat(local);
      if(after.size!==s.size||after.mtimeMs!==s.mtimeMs)throw Error('public file changed during snapshot');
      rows.push({path:name,bytes:s.size,chunks});
    }
  }
  for(const name of [...new Set(paths)].sort())await visit(publicPath(name));
  return rows;
}
export async function putBlob(cas,id,bytes){
  blobId(id);
  if(bytes.length>CHUNK_BYTES||digest(bytes)!==id)throw Error('public chunk integrity mismatch');
  await fs.mkdir(cas,{recursive:true,mode:0o700});
  const temporary=path.join(cas,'.'+id+'.'+randomUUID()+'.pending');
  try{
    const handle=await fs.open(temporary,'wx',0o600);
    try{await handle.writeFile(bytes);await handle.sync();}finally{await handle.close();}
    // Same-directory hardlink publishes a complete verified blob without
    // replacing an existing CID, including an existing corrupt blob.
    try{await fs.link(temporary,path.join(cas,id));}
    catch(e){if(e.code!=='EEXIST')throw e;if(digest(await fs.readFile(path.join(cas,id)))!==id)throw Error('corrupt cached chunk');}
    const directory=await fs.open(cas,'r');
    try{await directory.sync();}finally{await directory.close();}
  }finally{await fs.rm(temporary,{force:true});}
}
export async function install(rows,cas,{root='/'}={}){
  if(!Array.isArray(rows))throw Error('public manifest required');
  const seen=new Set();
  for(const row of rows){
    publicPath(row.path);
    if(seen.has(row.path)||!Number.isSafeInteger(row.bytes)||row.bytes<0||!Array.isArray(row.chunks)||
       row.chunks.length!==Math.ceil(row.bytes/CHUNK_BYTES))throw Error('invalid public manifest');
    seen.add(row.path);
  }
  // Validate every chunk before replacing any destination.
  for(const row of rows)for(const [i,id] of row.chunks.entries()){
    const bytes=await fs.readFile(path.join(cas,blobId(id)));
    if(digest(bytes)!==id||bytes.length!==Math.min(CHUNK_BYTES,row.bytes-i*CHUNK_BYTES))throw Error('public manifest integrity mismatch');
  }
  for(const row of rows){
    const dest=await noSymlinks(row.path,root);
    await fs.mkdir(path.dirname(dest),{recursive:true});
    const temp=dest+'.'+randomUUID()+'.pending',h=await fs.open(temp,'wx',0o600);
    try{for(const id of row.chunks)await h.writeFile(await fs.readFile(path.join(cas,id)));await h.sync();}
    finally{await h.close();}
    await fs.rename(temp,dest);
  }
}
