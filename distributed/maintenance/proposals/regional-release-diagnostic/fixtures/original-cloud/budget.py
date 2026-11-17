"""Admission accounting. Estimates are explicit and never a billing hard cap."""
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone
import hashlib
import json

def amount(value):
    if isinstance(value,bool):raise ValueError('boolean cost')
    try:result=Decimal(str(value))
    except InvalidOperation as exc:raise ValueError('numeric cost required') from exc
    if not result.is_finite() or result<0:raise ValueError('invalid cost')
    return result

def assess(config, quote, *, elapsed_hours=0, spent_transfer_storage=0, remaining_hours=None):
    """Require the complete remaining experiment and retained resources to fit.

    A quote is an input, not an invented current price. Admission cannot shrink
    the grid or stop an in-flight dispute to make the estimate fit the budget.
    """
    if quote.get('currency')!='USD' or quote.get('campaign')!=config['campaign']:
        raise ValueError('quote does not identify this campaign in USD')
    if quote.get('layout')!=config['layout']:raise ValueError('quote layout mismatch')
    if set(quote.get('hourly',{}))!={'compute','nat','disks','ipv4'}:
        raise ValueError('quote must include all four hourly charge categories')
    if not quote.get('source_urls') or not all(isinstance(url,str) and url.startswith('https://') for url in quote['source_urls']):
        raise ValueError('price sources required')
    timestamp=quote.get('quoted_at')
    if not isinstance(timestamp,str):raise ValueError('dated quote required')
    quoted=datetime.fromisoformat(timestamp.replace('Z','+00:00'))
    if quoted.tzinfo is None:raise ValueError('quote timezone required')
    age=(datetime.now(timezone.utc)-quoted).total_seconds()
    if age<0 or age>7*86400:raise ValueError('quote expired or in the future')
    rate=sum((amount(v) for v in quote['hourly'].values()),Decimal(0))
    if rate<=0:raise ValueError('nonzero hourly cost required')
    hours=amount(quote['planned_hours'] if remaining_hours is None else remaining_hours)
    # Keep every honest/disputed path and all six windows per nonlinear case.
    nonlinear_cases=2 if config.get('execution_mode')=='smoke' else 18
    lower_bound=Decimal(nonlinear_cases*6*config['window_seconds'])/3600
    if remaining_hours is None and hours<lower_bound:raise ValueError('planned duration is below mandatory protocol windows')
    fixed=amount(quote['build_registry'])+amount(quote['retained_resources'])
    transfers=amount(quote['transfer_storage_upper_bound'])
    spent=rate*amount(elapsed_hours)+amount(spent_transfer_storage)
    prior=amount(quote.get('prior_experiment_upper_bound_usd',0))
    projected=prior+spent+rate*hours+transfers+fixed
    maximum=amount(config['budget']['maximum']);reserve=amount(config['budget']['reserve'])
    return {'schema':'vcfhe-distributed-budget-v1','status':'admit' if projected+reserve<=maximum else 'refuse',
        'projected_usd':str(projected),'reserve_usd':str(reserve),'maximum_usd':str(maximum),
        'hourly_usd':str(rate),'mandatory_window_hours':str(lower_bound),
        'prior_experiment_upper_bound_usd':str(prior),
        'quote_sha256':hashlib.sha256(json.dumps(quote,sort_keys=True).encode()).hexdigest(),
        'billing_hard_cap':False,'changes_protocol_windows':False,'reduces_repetitions':False}
