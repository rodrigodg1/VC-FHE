// Inserted in the verified original owner's lexical scope in place of prepare().
// V3 continuation: restores the owner's preselected cases from its own preserved
// state, without re-reading datasets, re-encrypting or re-signing anything.
// Nothing here relaxes the owner's transaction, consent or release checks.
const recovered=await json('/fixtures/prepared.json');
assert.equal(cfg.recovery?.profile,'same-keyset-full-case-continuation-v3');
assert.equal(cfg.parameters,'Test');
assert.ok(!cfg.policyRefreshPlan,'V3 policy refresh has its own recovery rule');
assert.deepEqual(recovered.keys,keys);
assert.deepEqual(recovered.owners,owners);
assert.deepEqual(recovered.cases.map(c=>c.name),cfg.recovery.remainingCases);
const preservedExpected=await json('/owner/expected.json');
for(const item of recovered.cases){
 if(casePlan){
  const job=casePlan.jobs.find(j=>j.name===item.name);assert.ok(job&&job.fullCase,'case is not a preselected full case');
  for(const [key,value] of Object.entries(job))assert.deepEqual(item[key],value);
 }
 assert.ok(Object.hasOwn(preservedExpected,item.name),'missing preserved owner oracle');
 expected[item.name]=preservedExpected[item.name];
 assert.equal(item.recordIds.length,item.n);
 for(let i=0;i<item.n;i++){
  same(item.owners[i],owners[recordOwner(item.recordReferences[i])],'changed protected-record owner assignment');
  same(item.recordIds[i],ownerBoundProtectedId(cfg.chainId,registry.target,item.owners[i],item.recordReferences[i]),
   'protected ID is not bound to this policy lineage');
 }
 if(item.half==='nonlinear'){
  const context=await json('/owner/'+item.name+'/approved-context.json');
  const publicDir='/fixtures/'+item.name+'/public';
  const actual=await createExecutionContext({binary,publicDir,keyEpoch:keys.keyEpoch,policyDomain:cfg.policyDomain,
   inputBounds:item.inputBounds,records:(await json(publicDir+'/program.json')).inputs.map((r,i)=>({id:r.id,
    protectedId:item.recordIds[i%item.n],owner:item.owners[i%item.n]}))});
  assert.deepEqual(actual,context,'preserved owner context no longer matches public ciphertexts');
  // Public, deterministic circuit parameters; identical to the original prepare().
  const program=compileComplianceCircuit({recordCount:item.n,regional:item.regional,poorThresholdMilli:2000,
   targetPermille:950,targetCell:cfg.targetCell});
  assert.equal(program.inputs.length,context.inputs.length,'recompiled circuit differs from the approved context');
  approvals.set(item.name,{context,program,contextDigest:hashJson(context),programDigest:context.programDigest,
   profileDigest:hashJson(context.profile),outputType:'bool',inputs:context.inputs,...nonlinearInputTerms(context)});
 }else{
  const coordinates=await json('/owner/'+item.name+'/coordinates.json');
  assert.equal(coordinates.length,item.n,'preserved linear coordinates are incomplete');
 }
 cases.push(item);
}
// Same cumulative-budget gate as prepare(), against a three-of-four validator view.
const restoredSpent=new Map();
const restoredView=await ownerChain.withView('continuation protected-record baseline',async view=>{
 for(const item of cases)for(let i=0;i<item.recordIds.length;i++){
  const id=item.recordIds[i];if(restoredSpent.has(id))continue;
  const record=await ownerChain.read(view,`protected record ${id}`,(_provider,blockTag,index)=>
   registries[index].protectedRecords(id,{blockTag}));
  if(record.owner===ethers.ZeroAddress)restoredSpent.set(id,item.initialSpent[i]);
  else{
   assert.equal(record.owner.toLowerCase(),item.owners[i].toLowerCase(),'registered protected-record owner changed');
   assert.equal(record.recordReference,item.recordReferences[i],'registered record reference changed');
   assert.equal(Number(record.releaseLimit),item.releaseLimits[i],'registered release limit changed');
   assert.ok(Number(record.spent)>=item.initialSpent[i],'on-chain spend regressed below migrated counter');
   restoredSpent.set(id,Number(record.spent));
  }
 }
 return {blockNumber:view.number,blockHash:view.hash};
});
const restoredPlanned=new Map();
for(const item of cases)for(let i=0;i<item.recordIds.length;i++){
 const current=restoredPlanned.get(item.recordIds[i])??{count:0,releaseLimit:item.releaseLimits[i]};
 current.count+=1;restoredPlanned.set(item.recordIds[i],current);
}
for(const [id,value] of restoredPlanned)assert.ok(restoredSpent.get(id)+value.count<=value.releaseLimit,
 'remaining continuation releases exceed the cumulative protected-record budget');
await atomic('/owner-rpc/recovery-ready.json',{names:cases.map(c=>c.name),keysetDigest:keys.keysetDigest,
 capacityView:restoredView,records:restoredPlanned.size});
