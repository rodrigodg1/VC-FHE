import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import ganache from 'ganache';
import {ethers} from 'ethers';
test('read-only observer binds actual calldata lengths to mined receipts before shutdown',async()=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'tops-calldata-test-'));
  const report=path.join(dir,'run.json'),out=path.join(dir,'calldata.json');
  await fs.writeFile(report,JSON.stringify({status:'running',receipts:[]}));
  const server=ganache.server({logging:{quiet:true},chain:{chainId:31337}});await server.listen(0,'127.0.0.1');
  const rpc=`http://127.0.0.1:${server.address().port}`,provider=new ethers.JsonRpcProvider(rpc,undefined,{cacheTimeout:-1,pollingInterval:20});
  const observer=spawn(process.execPath,[new URL('./observe_canonical_calldata.mjs',import.meta.url).pathname,rpc,report,out],{stdio:['ignore','pipe','pipe']});
  let errors='';observer.stderr.on('data',b=>{errors+=b;});
  const completed=once(observer,'exit');
  let closed=false;
  try{
    for(let i=0;i<100;i++){if(await fs.access(out).then(()=>true,()=>false))break;await new Promise(r=>setTimeout(r,20));}
    const signer=await provider.getSigner(0),recipient=await(await provider.getSigner(1)).getAddress(),receipts=[];
    for(const n of [0,4,68]) {
      const tx=await signer.sendTransaction({to:recipient,data:ethers.hexlify(new Uint8Array(n).fill(17))}),r=await tx.wait();
      receipts.push({txHash:r.hash,blockNumber:r.blockNumber,from:r.from,to:r.to,expectedBytes:n});
    }
    await fs.writeFile(report,JSON.stringify({status:'passed',receipts}));
    await server.close();closed=true;
    const [code]=await completed;assert.equal(code,0,errors);
    const observed=JSON.parse(await fs.readFile(out,'utf8'));assert.equal(observed.status,'passed');
    for(const r of receipts)assert.equal(observed.transactions[r.txHash].inputBytes,r.expectedBytes);
  }finally{provider.destroy();if(!closed)await server.close();if(observer.exitCode===null)observer.kill();}
});
