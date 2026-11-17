"""Select an unstarted suffix without changing original design or owner inputs."""
from copy import deepcopy
from window import PROFILE

def select(prepared, completed, remaining):
    names=[c['name'] for c in prepared['cases']]
    if names!=completed+remaining or len(names)!=27 or len(set(names))!=27:
        raise ValueError('Not the original complete preselected grid')
    if len(completed)!=10 or len(remaining)!=17:
        raise ValueError('This recovery is scoped to the verified 10/17 frontier')
    if any(c['half']!='nonlinear' for c in prepared['cases'][10:]):
        raise ValueError('Unexpected unfinished workload')
    return {**prepared,'cases':deepcopy(prepared['cases'][10:])}

def configuration(parent, new_id, completed, remaining):
    if new_id==parent['runId'] or not new_id.endswith('-workflows-c4'):
        raise ValueError('A separate continuation identity is required')
    return {**parent,'runId':new_id,'workflowContinuation':{
        'profile':PROFILE,'parentRunId':parent['runId'],
        'completedCases':list(completed),'fullCases':list(remaining)}}

def verify_config(parent,current,completed,remaining):
    if current!=configuration(parent,current['runId'],completed,remaining):
        raise ValueError('Protocol, parameters, deadlines or measurement design changed')

def verify_exchange(names,count):
    # Coordinator and recipient may own different subsets of these files.
    import re
    allowed={'request','wire','pre-reservation','reserved','responses','result'}
    for name in names:
        m=re.fullmatch(r'([a-z-]+)-(0|[1-9][0-9]*)\.json',name)
        if not m or m[1] not in allowed or int(m[2])>=count:
            raise ValueError('Unknown or unfinished exchange item requires reconciliation')
