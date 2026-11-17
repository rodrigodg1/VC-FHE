"""An explicit nonpublishing regional retry in a fresh distributed deployment."""
import copy

PROFILE = 'regional-output-release-v1'
CLASSIFICATION = 'test-insecure-distributed-regional-release-diagnostic-not-evaluation'
CASE = 'regional_qoe_compliance-0'
RUNTIME_SECONDS = 4 * 3600


def require(condition, message):
    if not condition:
        raise ValueError('regional release diagnostic: '+message)


def requested(config):
    marker = config.get('diagnostic_profile')
    if marker is None:
        return False
    require(marker == PROFILE, 'unknown explicit diagnostic profile')
    require(config.get('execution_mode') == 'smoke' and config.get('layout') == 'four-hosts',
            'profile requires a separate four-host smoke deployment')
    require(type(config.get('maximum_vm_runtime_seconds')) is int
            and config['maximum_vm_runtime_seconds'] == RUNTIME_SECONDS,
            'profile requires the explicit four-hour VM bound')
    require(type(config.get('window_seconds')) is int and config['window_seconds'] == 120,
            'the original 120-second protocol windows must remain unchanged')
    return True


def apply_campaign_profile(config, common):
    if not requested(config):
        return common
    result = copy.deepcopy(common)
    result.update(half='nonlinear', linearSizes=[], records=50, repeats=1,
                  nonlinearWorkloads=['regional'], classification=CLASSIFICATION,
                  distributedDiagnosticProfile=PROFILE, timeoutSeconds=RUNTIME_SECONDS)
    validate_campaign(result)
    return result


def validate_campaign(config):
    marker = config.get('distributedDiagnosticProfile')
    if marker is None:
        require(config.get('classification') != CLASSIFICATION,
                'classification without its exact profile marker')
        return False
    require(marker == PROFILE, 'unknown campaign diagnostic profile')
    require(config.get('executionProfile') == 'gcp-four-hosts-role-local-v1'
            and config.get('classification') == CLASSIFICATION,
            'diagnostic must retain its distributed nonevaluation classification')
    require(config.get('smoke') is True and config.get('readinessOnly') is True
            and config.get('half') == 'nonlinear' and config.get('parameters') == 'Test',
            'diagnostic cannot be used as a full or local evaluation campaign')
    require(config.get('linearSizes') == [] and config.get('records') == 50
            and config.get('repeats') == 1 and config.get('nonlinearWorkloads') == ['regional'],
            'exactly one largest regional workflow is required')
    require(config.get('windowSeconds') == 120 and config.get('nonlinearProtocol') == 'bounty-v2'
            and config.get('kmsRayonThreads') == 1 and config.get('kmsTokioThreads') == 1,
            'protocol or admitted execution settings changed')
    require(config.get('timeoutSeconds') == RUNTIME_SECONDS,
            'participant bound differs from the explicit diagnostic bound')
    require(not any(config.get(key) for key in ('pocPlan', 'policyRefreshPlan',
                                               'readinessDisputesOnly', 'keysetReuse')),
            'paired, composed, dispute-only or restored-keyset runs are excluded')
    require(config.get('policyLineage') == {
        'kind': 'explicit-new-distributed-lineage', 'continuityWithLocalRun': False},
        'a fresh policy lineage and four-core keyset are required')
    return True


def active_grid(config):
    if requested(config):
        return {'full_workflows': 1, 'paired_measurements': 0, 'warmups': 0}
    if config.get('execution_mode') == 'smoke':
        return {'full_workflows': 3, 'paired_measurements': 0, 'warmups': 0}
    return config['measurement_grid']


def expected_counts(config):
    if validate_campaign(config):
        return 1, 1
    return (3, 2) if config.get('smoke') else (27, 18)


def validate_cases(cases, config):
    require(validate_campaign(config), 'an explicit diagnostic campaign is required')
    require(isinstance(cases, list) and len(cases) == 1, 'exactly one completed case is required')
    case = cases[0]
    require(case.get('name') == CASE and case.get('half') == 'nonlinear'
            and case.get('n') == 50 and case.get('regional') is True,
            'wrong regional case, size or workflow')
    require(isinstance(case.get('metrics'), dict)
            and isinstance(case['metrics'].get('disputes'), list)
            and len(case['metrics']['disputes']) == 1,
            'the original regional faulty-execution dispute must also complete')
    return {'fullCases': 1, 'nonlinearDisputes': 1, 'evaluationPublishable': False,
            'pairedComparisonsExecuted': False, 'diagnosticProfile': PROFILE,
            'scope': 'One fresh largest regional workflow including its original baseline and dispute. Not evaluation evidence.'}
