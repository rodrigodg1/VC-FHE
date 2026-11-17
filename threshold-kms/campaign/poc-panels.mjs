// Predeclared public-dataset panels. Selection never depends on a released value.
import assert from 'node:assert/strict';
import {ethers} from './common.mjs';
export const LINEAR_SIZES=[10,16,27], NONLINEAR_SIZES=[16,32,50];
export function csv(text){
 const lines=text.trim().split(/\r?\n/),delimiter=lines[0].includes('\t')?'\t':',';
 const header=lines.shift().split(delimiter).map(s=>s.trim());
 return lines.map((s,i)=>Object.fromEntries([...s.split(delimiter).map((v,j)=>[header[j],v.trim()]),['row',i]]));
}
export function linearPanel(raw,query,n){
 assert.ok(LINEAR_SIZES.includes(n));
 const rows=csv(raw).filter(r=>r.rating!==''&&r.video_title===query.scope.video&&r.video_tiling_pattern===query.scope.pattern)
  .sort((a,b)=>a.user.localeCompare(b.user));
 assert.equal(rows.length,27);assert.equal(new Set(rows.map(r=>r.user)).size,27);
 assert.deepEqual(rows.slice(0,16).map(r=>r.user),query.owners);
 assert.deepEqual(rows.slice(0,16).map(r=>Number(r.rating)),query.values);
 assert.ok(rows.every(r=>Number.isInteger(Number(r.rating))&&Number(r.rating)>=1&&Number(r.rating)<=5));
 // Disjoint small panels; the 27-person panel is the complete condition.
 return n===16?rows.slice(10,26):rows.slice(0,n);
}
export function qoePanel(corpora,n,regional){
 assert.ok(NONLINEAR_SIZES.includes(n));
 const offset=NONLINEAR_SIZES.indexOf(n)*100+(regional?300:0);
 const sample=(bs,count)=>{
  const rows=corpora[bs].rows;assert.ok(rows.length>=1000);
  return Array.from({length:count},(_,i)=>({...rows[Math.floor((offset+i)*rows.length/1000)],bs}));
 };
 return regional?[...sample('1',n/2),...sample('4',n/2)]:sample('1',n);
}
export const linearRecordIds=(rows,query)=>rows.map(r=>ethers.id(`STAV360:${query.scope.video}:${query.scope.pattern}:${r.user}`));
export const qoeRecordIds=rows=>rows.map(r=>ethers.id(`5G-QoERA:BS_${r.bs}:row:${r.row}`));
export function checkCapacity(ledger,panels,limit=18){
 const charges=new Map();
 for(const {ids,releases} of panels){
  assert.equal(new Set(ids).size,ids.length);assert.ok(Number.isSafeInteger(releases)&&releases>=0);
  for(const id of ids)charges.set(id,(charges.get(id)??0)+releases);
 }
 let minimumRemaining=limit,maximumPlanned=0,maximumSpent=0;
 for(const [id,planned] of charges){
  const record=ledger.records?.[id],spent=record?.spent??0,bound=record?.limit??limit;
  assert.ok(Number.isSafeInteger(spent)&&spent>=0&&Number.isSafeInteger(bound)&&bound>0,'invalid durable counter');
  assert.ok(spent+planned<=bound,'planned releases exceed existing cumulative budget; no reset or limit increase permitted');
  minimumRemaining=Math.min(minimumRemaining,bound-spent-planned);maximumPlanned=Math.max(maximumPlanned,planned);maximumSpent=Math.max(maximumSpent,spent);
 }
 return {protectedRecords:charges.size,maximumExistingSpend:maximumSpent,maximumPlannedChargesPerRecord:maximumPlanned,minimumRemainingAfterPlan:minimumRemaining};
}
