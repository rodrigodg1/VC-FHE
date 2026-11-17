from diagnostic_profile import validate_campaign as is_regional_diagnostic, validate_cases as validate_regional_diagnostic
"""Nonpublishing use of the existing real-threshold readiness workflows."""
CLASSIFICATION = 'test-insecure-distributed-smoke-not-evaluation'

def validate_cases(cases, config=None):
    if config is not None and is_regional_diagnostic(config):
        return validate_regional_diagnostic(cases,config)
    expected = {'linear-acr-27-0': ('linear', 27),
                'regulatory_qoe_compliance-0': ('nonlinear', 50),
                'regional_qoe_compliance-0': ('nonlinear', 50)}
    actual = {c['name']: (c['half'], c['n']) for c in cases}
    if len(cases) != 3 or actual != expected:
        raise ValueError('distributed smoke requires the three unchanged largest-size readiness workflows')
    for case in cases:
        if case['half'] == 'nonlinear' and len(case['metrics']['disputes']) != 1:
            raise ValueError('smoke omitted a faulty-execution dispute')
    return {'fullCases': 3, 'nonlinearDisputes': 2, 'evaluationPublishable': False,
            'pairedComparisonsExecuted': False,
            'scope': 'One existing largest-size readiness workflow per computation. Not a repeated performance campaign.'}
