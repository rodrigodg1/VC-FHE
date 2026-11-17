// Eligibility for deliberately false audit opinions in the experiment harness.
// These controls never count as honest recomputation and earn no audit bounty.
export function allowsAdversarialAgreementControl(config,caseName){
  const full=Array.isArray(config.pocPlan?.jobs)&&config.pocPlan.jobs.some(j=>j.name===caseName&&j.fullCase&&j.half==='nonlinear');
  const smoke=config.smoke&&config.readinessOnly&&
    config.classification==='test-insecure-distributed-smoke-not-evaluation'&&
    ['regulatory_qoe_compliance-0','regional_qoe_compliance-0'].includes(caseName);
  const diagnostic=config.smoke===true&&config.readinessOnly===true&&
    config.classification==='test-insecure-distributed-regional-release-diagnostic-not-evaluation'&&
    config.distributedDiagnosticProfile==='regional-output-release-v1'&&
    config.half==='nonlinear'&&config.parameters==='Test'&&config.records===50&&config.repeats===1&&
    config.windowSeconds===120&&config.kmsRayonThreads===1&&config.kmsTokioThreads===1&&
    Array.isArray(config.linearSizes)&&config.linearSizes.length===0&&
    Array.isArray(config.nonlinearWorkloads)&&config.nonlinearWorkloads.length===1&&config.nonlinearWorkloads[0]==='regional'&&
    !config.pocPlan&&!config.policyRefreshPlan&&!config.readinessDisputesOnly&&!config.keysetReuse&&
    caseName==='regional_qoe_compliance-0';
  return Boolean(full||smoke||diagnostic);
}
