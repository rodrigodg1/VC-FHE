"""Explicit continuation overlays. Never patch the frozen image or predecessor."""
import hashlib
import json

PROFILE = 'distributed-same-keyset-workflows-only-v1'


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('Continuation anchor changed')
    return source.replace(old, new)


def owner_overlay(source, retained_restore):
    restore = once(retained_restore,
        "const recovered=await json('/fixtures/prepared.json');",
        "const preserved=await json('/fixtures/prepared.json');\n"
        "const recovered={...preserved,cases:preserved.cases.filter(c=>c.fullCase)};")
    restore = once(restore,
        "assert.equal(cfg.recovery?.profile,'same-keyset-full-case-continuation-v3');",
        f"assert.equal(cfg.workflowContinuation?.profile,'{PROFILE}');")
    restore = once(restore, 'cfg.recovery.remainingCases',
        'cfg.workflowContinuation.fullCases')
    return once(source, 'await prepare();', restore)


def evaluator_overlay(source):
    marker = "await (await import('/app/distributed/admission.mjs')).verifyBytes(cfg,prepared);\n if(cfg.pocPlan)await runPairs(cfg,prepared);"
    return once(source, marker,
        "await (await import('/continuation/guard.mjs')).verifyContinuation(cfg,prepared);")


def admission_overlay(source):
    """Honor explicit finish authority without resetting cost or duration accounting."""
    old="""assert.ok(projected+envelope.caseAllowanceHours*envelope.hourlyUsd+envelope.reserveUsd<=envelope.maximumUsd,
    'remaining budget does not admit another complete case');"""
    new="""const withinForecast=projected+envelope.caseAllowanceHours*envelope.hourlyUsd+envelope.reserveUsd<=envelope.maximumUsd;
  const authority=envelope.completionAuthorization;
  assert.ok(withinForecast || (authority?.schema==='explicit-campaign-completion-authorization-v1' &&
    authority.explicitUserRequest===true && authority.finishDespiteFormerBudget===true &&
    authority.stopOnBillingThreshold===false && authority.maximumVmRuntimeSeconds===86400),
    'remaining budget does not admit another complete case');"""
    result=once(source,old,new)
    return once(result,'projectedUsd:projected,caseAllowanceHours:',
        'projectedUsd:projected,forecastCeilingExceeded:!withinForecast,explicitCompletionAuthority:!!authority,caseAllowanceHours:')


def verify_configuration(parent, current, full_cases):
    if parent.get('executionProfile') != 'gcp-four-hosts-role-local-v1':
        raise ValueError('Wrong predecessor profile')
    if current.get('runId') == parent.get('runId'):
        raise ValueError('A continuation needs fresh request slots')
    extra = current.get('workflowContinuation', {})
    if extra.get('profile') != PROFILE or extra.get('fullCases') != full_cases:
        raise ValueError('Changed full-case selection')
    before = {k:v for k,v in parent.items() if k != 'runId'}
    after = {k:v for k,v in current.items() if k not in ('runId','workflowContinuation')}
    if before != after:
        raise ValueError('Protocol, parameters or measurement design changed')


def verify_prefix(paired, application, probe):
    if paired.get('status') != 'passed' or len(paired.get('rows', [])) != 498:
        raise ValueError('Incomplete paired measurements')
    rows = paired['rows']
    if sum(not r['warmup'] for r in rows) != 480 or sum(r['warmup'] for r in rows) != 18:
        raise ValueError('Changed paired/warm-up counts')
    if application.get('cases') != [] or application.get('kmsCalls') != 0:
        raise ValueError('This narrow continuation refuses any completed release')
    if probe.get('allDenied') is not True or probe.get('transactionsSubmitted') != 0:
        raise ValueError('The unreserved denial diagnostic failed')
    views = probe.get('views', [])
    if len(views) != 4 or len({v['blockHash'] for v in views}) != 1:
        raise ValueError('Missing fixed-block validator agreement')
    if not all(v.get('requestExists') is False and v.get('slotUnused') is True
               and v.get('totalReservations') == 0 for v in views):
        raise ValueError('Predecessor request or slot was consumed')
    if len(probe.get('results', [])) != 4 or not all(r.get('grpcStatus') == 7 for r in probe['results']):
        raise ValueError('All four cores must deny before any continuation')


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def retention_overlay(source, gib=256, *, scratch=False):
    """Increase only off-path evidence capacity while retaining every check."""
    if gib != 256 or source.count('100*1024**3') != 3:
        raise ValueError('Unexpected evidence-retention capacity or source')
    result = source.replace('100*1024**3',f'{gib}*1024**3')
    if scratch:
        result = once(result, 'import topology\n',
            'import topology\nfrom continuation_storage import validate_archive_attachment, archive_scratch_path\n')
        result = once(result,
            "require(attached==expected and len(actual['disks'])==2,'Unexpected disk attachment')",
            'validate_archive_attachment(campaign,host,actual,expected,attached)')
        result = once(result,
            "['df','-B1','--output=avail','/var/tmp']",
            "['df','-B1','--output=avail',archive_scratch_path(campaign,host)]")
    return result
