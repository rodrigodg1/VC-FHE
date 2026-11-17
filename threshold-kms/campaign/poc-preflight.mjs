// Read-only capacity check for the approved grid PLUS one largest-size readiness
// case per selected workload. Does not reserve slots, sign or issue any release.
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {csv,linearPanel,qoePanel,linearRecordIds,qoeRecordIds,checkCapacity,LINEAR_SIZES,NONLINEAR_SIZES} from './poc-panels.mjs';
const half=process.argv[2];assert.ok(['both','linear','nonlinear'].includes(half));
const readinessWorkloads=(process.argv[3]??'regulatory,regional').split(',');
const fullPoc=process.argv[4]==='full-poc';
assert.ok(readinessWorkloads.length>0&&readinessWorkloads.every(w=>['regulatory','regional'].includes(w)));
const panels=[];
if(half!=='nonlinear'){
 const data=JSON.parse(await fs.readFile('/datasets/linear.json','utf8'));
 const query=data.queries.find(q=>q.query_id==='stav360_session_mos_sum');
 const raw=await fs.readFile('/datasets/stav.csv','utf8');
 for(const n of LINEAR_SIZES)panels.push({ids:linearRecordIds(linearPanel(raw,query,n),query),releases:5+(!fullPoc&&n===27?1:0)});
}
if(half!=='linear'){
 const corpora={};
 for(const bs of ['1','4'])corpora[bs]={rows:csv(await fs.readFile(`/datasets/qoe/MOS_BS_${bs}_Driver_PRB_10.csv`,'utf8'))
  .filter(r=>['MOS_3000kbps','Latitude','Longitude'].every(k=>r[k]!==''&&Number.isFinite(Number(r[k]))))};
 for(const regional of [false,true])for(const n of NONLINEAR_SIZES)panels.push({ids:qoeRecordIds(qoePanel(corpora,n,regional)),releases:5+(!fullPoc&&n===50&&readinessWorkloads.includes(regional?'regional':'regulatory')?1:0)});
}
let ledger={records:{}};
try{ledger=JSON.parse(await fs.readFile('/preflight-ledger.json','utf8'));}catch(e){if(e.code!=='ENOENT')throw e;}
console.log(JSON.stringify({status:'passed',selection:'poc-disjoint-panels-v1',half,includesApprovedGridAndReadiness:!fullPoc,
 plannedFullReleases:panels.reduce((a,p)=>a+p.releases,0),...checkCapacity(ledger,panels)}));
