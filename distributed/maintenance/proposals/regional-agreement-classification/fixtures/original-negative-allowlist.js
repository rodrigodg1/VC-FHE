    const fullCase=config.pocPlan?.jobs.some(j=>j.name===b.caseName&&j.fullCase&&j.half==='nonlinear');
    const readinessCase=config.smoke&&config.readinessOnly&&
      config.classification==='test-insecure-distributed-smoke-not-evaluation'&&
      ['regulatory_qoe_compliance-0','regional_qoe_compliance-0'].includes(b.caseName);
    assert.ok(fullCase||readinessCase);
