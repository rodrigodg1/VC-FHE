import assert from 'node:assert/strict';

export const OWNER_RPC_COUNT=4;
export const OWNER_RPC_QUORUM=3;

function endpointKey(value){
 const url=new URL(value);
 if(!['http:','https:'].includes(url.protocol)||url.username||url.password||url.hash||url.search||url.pathname!=='/')
  throw Error('invalid owner validator RPC URL');
 url.hostname=url.hostname.toLowerCase();
 if((url.protocol==='http:'&&url.port==='80')||(url.protocol==='https:'&&url.port==='443'))url.port='';
 return url.origin;
}

export function validateOwnerRpcUrls(values){
 if(!Array.isArray(values)||values.length!==OWNER_RPC_COUNT)throw Error('owner requires exactly four validator RPC URLs');
 const normalized=values.map(endpointKey);
 if(new Set(normalized).size!==OWNER_RPC_COUNT)throw Error('owner validator RPC URLs must be distinct');
 return normalized;
}

function canonical(value){
 if(typeof value==='bigint')return ['bigint',value.toString()];
 if(value instanceof Uint8Array)return ['bytes',Buffer.from(value).toString('hex')];
 if(Array.isArray(value))return value.map(canonical);
 if(value&&typeof value==='object'){
  if(typeof value.toJSON==='function')return canonical(value.toJSON());
  return Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])]));
 }
 if(value===undefined)throw Error('owner quorum read returned undefined');
 return value;
}
const digest=value=>JSON.stringify(canonical(value));

function validHeight(value){return Number.isSafeInteger(value)&&value>=0;}
function blockIdentity(block,number){
 if(!block||block.number!==number||typeof block.hash!=='string'||!/^0x[0-9a-f]{64}$/i.test(block.hash)||
    typeof block.parentHash!=='string'||!/^0x[0-9a-f]{64}$/i.test(block.parentHash))return null;
 return `${block.number}:${block.hash.toLowerCase()}:${block.parentHash.toLowerCase()}`;
}

const bounded=(promise,timeoutMs)=>{
 let timer;
 return Promise.race([Promise.resolve(promise),new Promise((_,reject)=>{
  timer=setTimeout(()=>reject(Error('owner validator RPC timed out')),timeoutMs);
 })]).finally(()=>clearTimeout(timer));
};
async function available(promises,timeoutMs){
 const rows=await Promise.allSettled(promises.map(promise=>bounded(promise,timeoutMs)));
 return rows.flatMap((row,index)=>row.status==='fulfilled'?[{index,value:row.value}]:[]);
}

function majority(rows,label,expected){
 const groups=new Map();
 rows.forEach(({value,index})=>{
  let key;try{key=digest(value);}catch{return;}
  const group=groups.get(key)??{value,indexes:[]};group.indexes.push(index);groups.set(key,group);
 });
 const winners=[...groups.values()].filter(group=>group.indexes.length>=OWNER_RPC_QUORUM);
 if(winners.length!==1)throw Error(`${label}: fewer than three validator RPCs returned the same value`);
 if(expected!==undefined&&digest(winners[0].value)!==digest(expected))
  throw Error(`${label}: validator quorum changed the pinned value`);
 return winners[0];
}

export class OwnerChainQuorum {
 constructor({rpcUrls,expectedChainId,providerFactory,timeoutMs=5000}){
  this.rpcUrls=validateOwnerRpcUrls(rpcUrls);
  this.expectedChainId=BigInt(expectedChainId);
  assert.equal(typeof providerFactory,'function','owner quorum requires a provider factory');
  this.providers=this.rpcUrls.map((url,index)=>providerFactory(url,index));
  assert.equal(this.providers.length,OWNER_RPC_COUNT);
  if(!Number.isFinite(timeoutMs)||timeoutMs<=0)throw Error('invalid owner validator RPC timeout');
  this.timeoutMs=timeoutMs;
 }

 async pin(label){
  const networks=await available(this.providers.map(provider=>provider.getNetwork()),this.timeoutMs);
  const participants=networks.filter(({value})=>{
   try{return BigInt(value.chainId)===this.expectedChainId;}catch{return false;}
  }).map(({index})=>index);
  if(participants.length<OWNER_RPC_QUORUM)throw Error(`${label}: fewer than three validator RPCs are available on the expected chain`);
  const heightRows=await available(participants.map(index=>this.providers[index].getBlockNumber()),this.timeoutMs);
  const heights=new Map(heightRows.flatMap(({index,value})=>validHeight(value)?[[participants[index],value]]:[]));
  if(heights.size<OWNER_RPC_QUORUM)throw Error(`${label}: fewer than three validator RPCs returned valid heights`);
  for(const number of [...new Set(heights.values())].sort((a,b)=>b-a)){
   const queried=[...heights].filter(([,height])=>height>=number);
   const responses=await available(queried.map(([index])=>this.providers[index].getBlock(number)),this.timeoutMs);
   const groups=new Map();
   responses.forEach(({value:block,index:responseIndex})=>{
    const index=queried[responseIndex][0];
    const key=blockIdentity(block,number);if(!key)return;
    const group=groups.get(key)??{block,indexes:[]};group.indexes.push(index);groups.set(key,group);
   });
   const winners=[...groups.values()].filter(group=>group.indexes.length>=OWNER_RPC_QUORUM);
   if(winners.length===1)return Object.freeze({label,number,hash:winners[0].block.hash,
    parentHash:winners[0].block.parentHash,participants:Object.freeze([...heights.keys()]),
    supporters:Object.freeze([...winners[0].indexes])});
  }
  throw Error(`${label}: no explicit block/hash has three matching validator views`);
 }

 async read(view,label,reader){
  assert.ok(view&&validHeight(view.number)&&/^0x[0-9a-f]{64}$/i.test(view.hash),'invalid owner quorum view');
  const expected=`${view.number}:${view.hash.toLowerCase()}:${view.parentHash.toLowerCase()}`;
  const responses=await available(this.providers.map(async(provider,index)=>{
   const [network,block]=await Promise.all([provider.getNetwork(),provider.getBlock(view.number)]);
   if(BigInt(network.chainId)!==this.expectedChainId)throw Error('endpoint changed chain');
   const before=blockIdentity(block,view.number);
   if(before!==expected)throw Error('endpoint does not hold the pinned block');
   const value=await reader(provider,view.number,index);
   const after=blockIdentity(await provider.getBlock(view.number),view.number);
   if(after!==expected)throw Error('endpoint changed the pinned block during the read');
   return value;
  }),this.timeoutMs);
  return majority(responses,label).value;
 }

 async recheck(view){
  const responses=await available(this.providers.map(async provider=>{
   const [network,block]=await Promise.all([provider.getNetwork(),provider.getBlock(view.number)]);
   if(BigInt(network.chainId)!==this.expectedChainId)throw Error('endpoint changed chain');
   return block;
  }),this.timeoutMs);
  const identities=responses.flatMap(({index,value:block})=>{
   const key=blockIdentity(block,view.number);
   return key?[{index,value:key}]:[];
  });
  const expected=`${view.number}:${view.hash.toLowerCase()}:${view.parentHash.toLowerCase()}`;
  majority(identities,`${view.label} recheck`,expected);
 }

 async withView(label,action){
  const view=await this.pin(label);
  const value=await action(view);
  await this.recheck(view);
  return value;
 }
}
