import test from 'node:test';
import assert from 'node:assert/strict';
import {linearPanel,qoePanel,qoeRecordIds,checkCapacity} from './poc-panels.mjs';
test('linear panel uses all 27 real rows and disjoint smaller panels',()=>{
 const users=Array.from({length:27},(_,i)=>String(i).padStart(2,'0'));
 const query={scope:{video:'v',pattern:'p'},owners:users.slice(0,16),values:Array(16).fill(3)};
 const raw='user,video_title,video_tiling_pattern,rating\n'+users.map(u=>`${u},v,p,3`).join('\n');
 const small=linearPanel(raw,query,10),medium=linearPanel(raw,query,16),all=linearPanel(raw,query,27);
 assert.equal(all.length,27);assert.equal(new Set([...small,...medium].map(r=>r.user)).size,26);
 assert.throws(()=>linearPanel(raw.replace('26,v,p,3','25,v,p,3'),query,27));
 assert.throws(()=>linearPanel(raw.replace('26,v,p,3','26,v,p,3.5'),query,27));
});
test('nonlinear workload/size panels have stable non-overlapping real row identities',()=>{
 const corpora=Object.fromEntries(['1','4'].map(bs=>[bs,{rows:Array.from({length:30000},(_,row)=>({row}))}]));
 const seen=new Set();
 for(const regional of [false,true])for(const n of [16,32,50]){
  const rows=qoePanel(corpora,n,regional),ids=qoeRecordIds(rows);assert.equal(rows.length,n);
  assert.deepEqual(rows,qoePanel(corpora,n,regional));
  for(const id of ids){assert.ok(!seen.has(id));seen.add(id);}
 }
 assert.equal(seen.size,196);
});
test('capacity includes readiness and preserves existing limits and spend',()=>{
 const ledger={records:{a:{spent:7,limit:18}}},snapshot=JSON.stringify(ledger);
 assert.equal(checkCapacity(ledger,[{ids:['a'],releases:11}]).minimumRemainingAfterPlan,0);
 assert.throws(()=>checkCapacity(ledger,[{ids:['a'],releases:12}]),/cumulative budget/);
 assert.throws(()=>checkCapacity(ledger,[{ids:['a','a'],releases:1}]));
 assert.equal(JSON.stringify(ledger),snapshot);
});
