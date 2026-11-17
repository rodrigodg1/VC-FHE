// Read-only check in the ORIGINAL Linux image: no signing identity or KMS network.
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createExecutionContext,hashJson} from './runtime/scripts/canonical-protocol.mjs';
const json=async p=>JSON.parse(await fs.readFile(p,'utf8'));
const cfg=await json('/config/campaign.json'),prepared=await json('/fixtures/prepared.json');
const paired=await json('/reports/paired.json'),names=JSON.parse(process.env.VCFHE_RECOVERY_NAMES);
const binary='/usr/local/bin/kms-campaign';
const sha=async p=>createHash('sha256').update(await fs.readFile(p)).digest('hex');
for(const name of ['kms-campaign','kms-server','kms-gen-keys','kms-init']){
 assert.equal(await sha('/usr/local/bin/'+name),await sha('/preserved-bin/'+name),'original image/binary mismatch');
}
for(const name of names){
 const item=prepared.cases.find(c=>c.name===name);assert.ok(item&&item.fullCase&&!item.warmup);
 const publicDir='/fixtures/'+name+'/public',program=await json(publicDir+'/program.json');
 const expected=await json('/owner/'+name+'/approved-context.json');
 const actual=await createExecutionContext({binary,publicDir,keyEpoch:prepared.keys.keyEpoch,policyDomain:cfg.policyDomain,
  inputBounds:item.inputBounds,records:program.inputs.map((r,i)=>({id:r.id,protectedId:item.recordIds[i%item.n],owner:item.owners[i%item.n]}))});
 assert.deepEqual(actual,expected,'owner context changed');
 assert.equal(hashJson(actual),paired.rows.find(r=>r.name===name).fixtureDigest,'original paired fixture changed');
}
console.log(JSON.stringify({status:'passed',contexts:names.length,originalBinaries:4,transactions:0,kmsCalls:0,plaintextOpenings:0}));
