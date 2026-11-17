#!/usr/bin/env python3
"""Render a source-bound proposal. Never apply it to the live adapter."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[1]
FILES = ('client.mjs', 'public-files.mjs')

POOL = '''const CHUNK_CONCURRENCY=8;
// Shared across concurrent transfers in this process. Control RPCs do not use
// these slots. No buffer for a pending chunk is allocated before admission.
let chunkActive=0;
const chunkWaiters=[];
async function chunkSlot(action){
  if(chunkActive<CHUNK_CONCURRENCY)chunkActive++;
  else await new Promise(resolve=>chunkWaiters.push(resolve));
  try{return await action();}
  finally{const next=chunkWaiters.shift();if(next)next();else chunkActive--;}
}
async function forEachChunk(values,action){
  let index=0,failed=false,failure;
  await Promise.all(Array.from({length:Math.min(CHUNK_CONCURRENCY,values.length)},async()=>{
    while(!failed){
      const current=index++;if(current>=values.length)return;
      try{await chunkSlot(async()=>{if(!failed)await action(values[current]);});}
      catch(error){if(!failed){failed=true;failure=error;}}
    }
  }));
  // Drain every admitted operation before reporting failure. A caller cannot
  // start its task/install while a rejected transfer is still writing chunks.
  if(failed)throw failure;
}
'''

def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('proposal source drift: ' + old[:80])
    return source.replace(old, new)

def candidate(original):
    values = dict(original)
    values['client.mjs'] = once(values['client.mjs'], "const cache='/transport/public-chunks';\n",
                               POOL + "const cache='/transport/public-chunks';\n")
    values['client.mjs'] = once(values['client.mjs'], '''    for(const id of missing){
      blobId(id);
      if(!ids.includes(id))throw Error('peer requested a chunk outside this manifest');
      await rpc(target,'put-chunk',{id,data:(await fs.readFile(path.join(cache,id))).toString('base64')});
    }''', '''    for(const id of missing){
      blobId(id);
      if(!ids.includes(id))throw Error('peer requested a chunk outside this manifest');
    }
    await forEachChunk([...new Set(missing)],async id=>{
      await rpc(target,'put-chunk',{id,data:(await fs.readFile(path.join(cache,id))).toString('base64')});
    });''')
    values['client.mjs'] = once(values['client.mjs'], '''  for(const id of new Set(rows.flatMap(r=>r.chunks))){
    blobId(id);
    try{await fs.access(path.join(cache,id));}
    catch(e){if(e.code!=='ENOENT')throw e;const value=await rpc(target,'get-chunk',{id});await putBlob(cache,id,Buffer.from(value.data,'base64'));}
  }
  await install(rows,cache);''', '''  await forEachChunk([...new Set(rows.flatMap(r=>r.chunks))],async id=>{
    blobId(id);
    try{await fs.access(path.join(cache,id));}
    catch(e){if(e.code!=='ENOENT')throw e;const value=await rpc(target,'get-chunk',{id});await putBlob(cache,id,Buffer.from(value.data,'base64'));}
  });
  await install(rows,cache);''')
    values['public-files.mjs'] = once(values['public-files.mjs'], '''  try{await fs.writeFile(path.join(cas,id),bytes,{flag:'wx',mode:0o600});}
  catch(e){if(e.code!=='EEXIST')throw e;if(digest(await fs.readFile(path.join(cas,id)))!==id)throw Error('corrupt cached chunk');}''', '''  const temporary=path.join(cas,'.'+id+'.'+randomUUID()+'.pending');
  try{
    const handle=await fs.open(temporary,'wx',0o600);
    try{await handle.writeFile(bytes);await handle.sync();}finally{await handle.close();}
    // Same-directory hardlink publishes a complete verified blob without
    // replacing an existing CID, including an existing corrupt blob.
    try{await fs.link(temporary,path.join(cas,id));}
    catch(e){if(e.code!=='EEXIST')throw e;if(digest(await fs.readFile(path.join(cas,id)))!==id)throw Error('corrupt cached chunk');}
    const directory=await fs.open(cas,'r');
    try{await directory.sync();}finally{await directory.close();}
  }finally{await fs.rm(temporary,{force:true});}''')
    return values

def hashes(values):
    return {name: hashlib.sha256(value.encode()).hexdigest() for name, value in values.items()}

def render(source=SOURCE):
    original = {name: (source/name).read_text() for name in FILES}
    changed = candidate(original)
    patch = ''.join(''.join(difflib.unified_diff(original[name].splitlines(True), changed[name].splitlines(True),
        fromfile='a/VC-FHE/distributed/'+name, tofile='b/VC-FHE/distributed/'+name)) for name in FILES)
    return original, changed, patch

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=SOURCE)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    original, changed, patch = render(args.source)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir/'proposal.patch').write_text(patch)
    (args.output_dir/'proposal.json').write_text(json.dumps({'schema':'vcfhe-transport-proposal-v1',
        'status':'unapplied-proposal','concurrencyPerProcess':8,'source':hashes(original),'candidate':hashes(changed),
        'protocolChanges':False,'cloudActions':False}, indent=2)+'\n')

if __name__ == '__main__': main()
