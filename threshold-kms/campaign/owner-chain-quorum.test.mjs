import test from 'node:test';
import assert from 'node:assert/strict';
import {OwnerChainQuorum,validateOwnerRpcUrls} from './owner-chain-quorum.mjs';

const hash=value=>'0x'+value.toString(16).padStart(64,'0');
const block=(number,id=number)=>({number,hash:hash(id),parentHash:hash(id-1)});
class FakeProvider {
 constructor({height=12,blocks={},authorization='deny',fail=false,hang=false}={}){
  Object.assign(this,{height,blocks,authorization,fail,hang,reads:[]});
 }
 async getNetwork(){if(this.hang)return new Promise(()=>{});if(this.fail)throw Error('offline');return {chainId:46853n};}
 async getBlockNumber(){if(this.fail)throw Error('offline');return this.height;}
 async getBlock(number){
  if(this.fail)throw Error('offline');this.reads.push(['block',number]);
  return this.blocks[number]??(number<=this.height?block(number):null);
 }
 async readAuthorization(blockTag){this.reads.push(['authorization',blockTag]);return this.authorization;}
}
const urls=Array.from({length:4},(_,index)=>`http://node${index+1}:8545`);
function quorum(options){
 const providers=options.map(value=>new FakeProvider(value));
 return {providers,chain:new OwnerChainQuorum({rpcUrls:urls,expectedChainId:46853,
  providerFactory:(_url,index)=>providers[index],timeoutMs:20})};
}

test('owner quorum rejects missing and duplicate validator endpoints',()=>{
 assert.throws(()=>validateOwnerRpcUrls(urls.slice(0,3)),/exactly four/);
 assert.throws(()=>validateOwnerRpcUrls([urls[0],urls[1],urls[2],urls[2]]),/distinct/);
 assert.throws(()=>validateOwnerRpcUrls([...urls.slice(0,3),'ftp://node4']),/invalid/);
 assert.throws(()=>validateOwnerRpcUrls([...urls.slice(0,3),'http://node4:8545/alternate']),/invalid/);
});

test('one forged RPC cannot induce owner approval',async()=>{
 const {chain,providers}=quorum([
  {authorization:{approved:false,digest:hash(50)}},
  {authorization:{approved:false,digest:hash(50)}},
  {authorization:{approved:false,digest:hash(50)}},
  {authorization:{approved:true,digest:hash(999)}}
 ]);
 const result=await chain.withView('owner approval',view=>chain.read(view,'authorization state',
  (provider,blockTag)=>provider.readAuthorization(blockTag)));
 assert.deepEqual(result,{approved:false,digest:hash(50)});
 assert.ok(providers.every(provider=>provider.reads.some(([kind,number])=>kind==='authorization'&&number===12)),
  'every endpoint must be queried at the explicit quorum block');
});

test('one unavailable endpoint is tolerated but fewer than three views fail closed',async()=>{
 const split=quorum([
  {authorization:{approved:true}},{authorization:{approved:true}},
  {authorization:{approved:false}},{authorization:{approved:false}}
 ]).chain;
 await assert.rejects(split.withView('split view',view=>split.read(view,'authorization state',
  (provider,blockTag)=>provider.readAuthorization(blockTag))),/fewer than three/);
 const available=quorum([{authorization:'allow'},{authorization:'allow'},{authorization:'allow'},{fail:true}]).chain;
 assert.equal(await available.withView('one offline',view=>available.read(view,'authorization state',
  (provider,blockTag)=>provider.readAuthorization(blockTag))),'allow');
 const unavailable=quorum([{}, {}, {fail:true}, {fail:true}]).chain;
 await assert.rejects(unavailable.pin('missing validators'),/fewer than three/);
 const hung=quorum([{authorization:'allow'},{authorization:'allow'},{authorization:'allow'},{hang:true}]).chain;
 assert.equal(await hung.withView('one hung',view=>hung.read(view,'authorization state',
  (provider,blockTag)=>provider.readAuthorization(blockTag))),'allow');
});

test('pin selects the highest explicit block and hash shared by three validators',async()=>{
 const fork=block(12,1200),options=[{height:12},{height:13},{height:14},{height:99,blocks:{12:fork,13:block(13,1300),14:block(14,1400),99:block(99,9900)}}];
 const {chain}=quorum(options),view=await chain.pin('common block');
 assert.equal(view.number,12);assert.equal(view.hash,block(12).hash);assert.equal(view.supporters.length,3);
 await chain.recheck(view);
});

test('a fourth endpoint may catch up when one original block supporter fails',async()=>{
 const fork=block(12,1200),{chain,providers}=quorum([
  {authorization:'allow'},{authorization:'allow'},{authorization:'allow'},
  {authorization:'allow',blocks:{12:fork}}
 ]);
 const view=await chain.pin('supporter failover');assert.equal(view.supporters.length,3);
 providers[2].fail=true;providers[3].blocks[12]=block(12);
 assert.equal(await chain.read(view,'authorization state',(provider,blockTag)=>provider.readAuthorization(blockTag)),'allow');
 await chain.recheck(view);
});

test('a pinned block that loses quorum is rejected before an owner response',async()=>{
 const {chain,providers}=quorum([{}, {}, {}, {}]),view=await chain.pin('unstable block');
 providers[1].blocks[12]=block(12,2001);providers[2].blocks[12]=block(12,2002);
 await assert.rejects(chain.recheck(view),/fewer than three|changed the pinned value/);
});
