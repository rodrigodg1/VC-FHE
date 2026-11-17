// Human-facing progress only. Never include inputs, outputs, keys or RPC payloads.
// A logging failure must not change protocol execution or experimental outcomes.
import {appendFileSync} from 'node:fs';
const groups=new Set(['owner-linear','owner-nonlinear','warmup','paired','full']);
export function createProgress(channel,{directory='/reports',append=appendFileSync}={}){
 if(!['owner','evaluation'].includes(channel))throw Error('unknown progress channel');
 return (phase,{state='start',caseName,current,total,group}={})=>{
  if(!/^[a-z][a-z-]{1,63}$/.test(phase)||!['start','done'].includes(state))return false;
  const row={version:1,phase,state};
  if(caseName!==undefined){if(typeof caseName!=='string'||! /^[a-zA-Z0-9_-]{1,120}$/.test(caseName))return false;row.caseName=caseName;}
  if(group!==undefined){if(!groups.has(group))return false;row.group=group;}
  if(current!==undefined||total!==undefined){
   if(!Number.isSafeInteger(current)||!Number.isSafeInteger(total)||current<1||total<current||total>100000)return false;
   row.current=current;row.total=total;
  }
  try{append(`${directory}/progress-${channel}.jsonl`,JSON.stringify(row)+'\n');return true;}catch{return false;}
 };
}
