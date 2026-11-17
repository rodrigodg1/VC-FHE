"""Explicit completion authority for a forecast above the former budget.

This is an admission forecast, never a live billing cutoff. It does not change
protocol time windows, repetitions, native code or the original cost inventory.
"""
from contextlib import contextmanager
from decimal import Decimal
import budget
from cloud_results.common import require

_BASE_ASSESS = budget.assess
SCHEMA = 'explicit-campaign-completion-authorization-v1'


def authorization(config):
    value = config.get('completion_authorization')
    if value is None:
        return None
    require(isinstance(value, dict) and value.get('schema') == SCHEMA
            and value.get('explicitUserRequest') is True
            and value.get('finishDespiteFormerBudget') is True,
            'Explicit completion authorization is required')
    require(config.get('execution_mode', 'evaluation') == 'evaluation'
            and config.get('diagnostic_profile') is None and config.get('layout') == 'four-hosts',
            'Completion authority is restricted to the full cloud campaign')
    reference = budget.amount(config['budget']['maximum'])
    maximum = budget.amount(value.get('estimatedAdmissionEnvelopeUsd'))
    require(budget.amount(value.get('referenceBudgetUsd')) == reference
            and reference < maximum <= Decimal('125'), 'Invalid completion forecast envelope')
    require(config.get('maximum_vm_runtime_seconds') == 86400
            and value.get('maximumVmRuntimeSeconds') == 86400,
            'Completion authority requires the explicit 24-hour technical bound')
    require(value.get('stopOnBillingThreshold') is False
            and isinstance(value.get('requestedAt'), str), 'Invalid completion authority scope')
    return value


def assess(config, quote, **kwargs):
    result = _BASE_ASSESS(config, quote, **kwargs)
    value = authorization(config)
    if value is None:
        return result
    maximum = budget.amount(value['estimatedAdmissionEnvelopeUsd'])
    result.update(reference_budget_usd=result['maximum_usd'], maximum_usd=str(maximum),
        status='admit' if budget.amount(result['projected_usd']) + budget.amount(result['reserve_usd']) <= maximum else 'refuse',
        authority=SCHEMA, finish_despite_former_budget=True, stop_on_billing_threshold=False)
    return result


@contextmanager
def original_admission(config):
    """Apply the same recorded authority to the unchanged launch preflight only."""
    if authorization(config) is None:
        yield
        return
    original = budget.assess
    require(original is _BASE_ASSESS, 'Concurrent financial admission override refused')
    budget.assess = assess
    try:
        yield
    finally:
        budget.assess = original
