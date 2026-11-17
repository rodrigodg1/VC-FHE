"""Presentation boundary for a separately validated multi-host campaign.

This does not validate protocol execution or convert a local run into WAN
evidence. Callers must obtain the descriptor from sealed distributed evidence.
"""
PROFILE='gcp-four-hosts-role-local-v1'

def descriptor(value):
    if not isinstance(value,dict) or value.get('executionProfile')!=PROFILE:
        raise ValueError('unknown distributed execution profile')
    hosts=value.get('hosts')
    if not isinstance(hosts,list) or len(hosts)!=4 or len({h['id'] for h in hosts})!=4:
        raise ValueError('four distinct measured hosts required')
    if len({h['region'] for h in hosts})!=4:raise ValueError('four measured regions required')
    required={'validator':4,'kms':4,'owner':4,'operator':1,'auditor':3,'adjudicator':3,'recipient':1,'coordinator':1}
    assignments=value.get('roles',[])
    if len({r['id'] for r in assignments})!=sum(required.values()):raise ValueError('incomplete role inventory')
    for role,count in required.items():
        rows=[r for r in assignments if r['role']==role]
        if len(rows)!=count or any(r['host'] not in {h['id'] for h in hosts} for r in rows):
            raise ValueError('incorrect role placement: '+role)
        if role in ('validator','kms') and len({r['host'] for r in rows})!=4:
            raise ValueError('validator/KMS roles must occupy four hosts')
    if value.get('administration')!='same-gcp-project':raise ValueError('administration scope missing')
    if value.get('pairTiming')!='coordinator-request-response-including-public-transfer':
        raise ValueError('distributed paired timer scope missing')
    return value

def is_distributed(report):
    value=report.get('distributedExecution')
    if value is None:return False
    descriptor(value)
    return True

def topology_text(value):
    d=descriptor(value)
    types={h['machine_type'] for h in d['hosts']}
    machine=next(iter(types)) if len(types)==1 else 'mixed machine types'
    return f'Google Cloud VMs ({machine}) in four geographic regions'
