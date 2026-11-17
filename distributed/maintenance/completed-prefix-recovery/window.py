"""Finite continuation scheduling, separate from cumulative cost accounting."""
from datetime import datetime, timezone
import math

PROFILE = 'distributed-completed-prefix-continuation-v1'

def renewal(original, started_at, *, hours=22, vm_limit_seconds=86400):
    if hours != 22 or vm_limit_seconds != 86400:
        raise ValueError('Unsupported finite continuation window')
    start = datetime.fromisoformat(started_at)
    origin = datetime.fromisoformat(original['startedAt'])
    if start.tzinfo is None or origin.tzinfo is None or start < origin:
        raise ValueError('Invalid continuation chronology')
    if not 0 < original['caseAllowanceHours'] < hours:
        raise ValueError('Missing complete-case allowance')
    # Two hours remain for shutdown and evidence collection within the VM limit.
    return {**original, 'continuationWindow': {
        'profile': PROFILE, 'startedAt': started_at, 'hours': hours,
        'maximumVmRuntimeSeconds': vm_limit_seconds,
        'originalStartedAt': original['startedAt'],
        'pastElapsedHours': (start-origin).total_seconds()/3600,
        'costAccountingReset': False, 'protocolDeadlinesChanged': False}}

def check(envelope, now):
    w = envelope['continuationWindow']
    expected = renewal({k:v for k,v in envelope.items() if k!='continuationWindow'}, w['startedAt'])
    if expected != envelope:
        raise ValueError('Continuation window or original accounting changed')
    t = datetime.fromisoformat(now)
    elapsed = (t-datetime.fromisoformat(w['startedAt'])).total_seconds()/3600
    total = (t-datetime.fromisoformat(envelope['startedAt'])).total_seconds()/3600
    if not math.isfinite(elapsed) or elapsed < 0 or elapsed+envelope['caseAllowanceHours'] > w['hours']:
        raise ValueError('Insufficient finite allowance for a complete case')
    return {'windowElapsedHours':elapsed, 'totalElapsedHours':total}

def overlay(source):
    old = "assert.ok(elapsed+envelope.caseAllowanceHours<=envelope.plannedHours,\n    'budget duration leaves insufficient allowance for another complete case');"
    new = """const window=envelope.continuationWindow;
  assert.equal(window?.profile,'distributed-completed-prefix-continuation-v1');
  assert.equal(window.originalStartedAt,envelope.startedAt);
  assert.equal(window.costAccountingReset,false);
  assert.equal(window.protocolDeadlinesChanged,false);
  assert.equal(window.hours,22);assert.equal(window.maximumVmRuntimeSeconds,86400);
  const windowElapsed=(Date.now()-Date.parse(window.startedAt))/3600000;
  assert.ok(Number.isFinite(windowElapsed)&&windowElapsed>=0);
  assert.ok(windowElapsed+envelope.caseAllowanceHours<=window.hours,
    'renewed duration leaves insufficient allowance for another complete case');"""
    if source.count(old)!=1:
        raise ValueError('Admission source anchor changed')
    return source.replace(old,new).replace('projectedUsd:projected,',
        'windowElapsedHours:windowElapsed,originalStartedAt:envelope.startedAt,projectedUsd:projected,')
