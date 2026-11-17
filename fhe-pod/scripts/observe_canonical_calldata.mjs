// Read-only WebSocket observer: record transaction input sizes as blocks arrive.
// This measures calldata/creation bytes, not peer-to-peer or TCP traffic.
import fs from 'node:fs/promises';
import {ethers} from 'ethers';
const [rpc,reportFile,output]=process.argv.slice(2);
if(!rpc||!reportFile||!output)throw Error('usage: observer HTTP_RPC RUN.json NEW.json');
const provider=new ethers.JsonRpcProvider(rpc,undefined,{cacheTimeout:-1,pollingInterval:50});
const socket=process.argv.includes('--poll')?null:new ethers.WebSocketProvider(rpc.replace(/^http/,'ws'));
const result={status:'observing',classification:'canonical-calldata-observation',chainId:String((await provider.getNetwork()).chainId),
  boundary:'transaction input bytes, including deployment bytecode; not network wire traffic',transactions:{}};
await fs.writeFile(output,JSON.stringify(result),{flag:'wx'});
const save=()=>fs.writeFile(output,JSON.stringify(result,null,2));
let last=-1,work=Promise.resolve();
const capture=async number=>{
  const block=await provider.send('eth_getBlockByNumber',['0x'+number.toString(16),true]);
  for(const t of block?.transactions??[])result.transactions[t.hash]={blockNumber:Number(BigInt(t.blockNumber)),
    inputBytes:ethers.getBytes(t.input).length,from:t.from,to:t.to,inputHash:ethers.keccak256(t.input)};
  last=Math.max(last,number);
};
const enqueue=number=>{work=work.then(async()=>{for(let i=last+1;i<=number;i++)await capture(i);await save();}).catch(e=>{result.observationError=String(e);});};
if(socket)await socket.on('block',enqueue);
enqueue(await provider.getBlockNumber());
try{
  while(true){
    let report;try{report=JSON.parse(await fs.readFile(reportFile,'utf8'));}catch{}
    if(report?.status==='passed'||report?.status==='failed'){
      await work;
      const receipts=report.receipts??report.cases?.flatMap(c=>c.receipts)??[];
      for(const r of receipts.filter(r=>!result.transactions[r.txHash??r.hash])) {
        try{
          const t=await provider.send('eth_getTransactionByHash',[r.txHash??r.hash]);
          if(t)result.transactions[t.hash]={blockNumber:Number(BigInt(t.blockNumber)),inputBytes:ethers.getBytes(t.input).length,
            from:t.from,to:t.to,inputHash:ethers.keccak256(t.input)};
        }catch{}
      }
      const missing=receipts.filter(r=>!result.transactions[r.txHash??r.hash]);
      result.missingHashes=missing.map(r=>r.txHash??r.hash);
      result.status=report.status==='passed'&&!missing.length?'passed':'incomplete';
      result.runReport=reportFile;result.reportedTransactions=receipts.length;
      await save();break;
    }
    if(!socket)enqueue(await provider.getBlockNumber());
    await new Promise(resolve=>setTimeout(resolve,100));
  }
}finally{if(socket)await socket.destroy();provider.destroy();}
console.log(JSON.stringify({status:result.status,transactions:Object.keys(result.transactions).length,missing:result.missingHashes.length}));
