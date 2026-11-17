// Inserted in the verified original owner's lexical scope in place of prepare().
// Nothing here relaxes its existing transaction, consent or signature checks.
const recovered = await json('/fixtures/prepared.json');
assert.equal(cfg.recovery.profile, 'same-keyset-full-case-continuation-v1');
assert.equal(cfg.parameters, 'Test');
assert.deepEqual(recovered.keys, keys);
assert.deepEqual(recovered.owners, owners);
assert.deepEqual(recovered.cases.map(c=>c.name), cfg.recovery.remainingCases);
for (const item of recovered.cases) {
 assert.equal(item.half, 'nonlinear');
 assert.equal(item.fullCase, true);
 assert.equal(item.warmup, false);
 const job=cfg.pocPlan.jobs.find(j=>j.name===item.name);
 assert.ok(job); for(const [key,value] of Object.entries(job))assert.deepEqual(item[key],value);
 const context=await json('/owner/'+item.name+'/approved-context.json');
 const publicDir='/fixtures/'+item.name+'/public',program=await json(publicDir+'/program.json');
 const actual=await createExecutionContext({binary,publicDir,keyEpoch:keys.keyEpoch,policyDomain:cfg.policyDomain,
  inputBounds:item.inputBounds,records:program.inputs.map((r,i)=>({id:r.id,protectedId:item.recordIds[i%item.n],owner:item.owners[i%item.n]}))});
 assert.deepEqual(actual,context,'preserved owner context no longer matches public ciphertexts');
 approvals.set(item.name,{contextDigest:hashJson(context),programDigest:context.programDigest,
  profileDigest:hashJson(context.profile),outputType:'bool',inputs:context.inputs});
 cases.push(item);
}
await atomic('/owner-rpc/recovery-ready.json',{names:cases.map(c=>c.name),keysetDigest:keys.keysetDigest});
