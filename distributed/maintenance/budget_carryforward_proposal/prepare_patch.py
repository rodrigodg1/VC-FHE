#!/usr/bin/env python3
"""Stage optional prior-experiment accounting without modifying live code."""
import difflib
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SOURCE=HERE.parents[1]

def once(value,old,new):
    if value.count(old)!=1:raise ValueError('source drift: '+old[:70])
    return value.replace(old,new)

def render():
    original={name:(SOURCE/name).read_text() for name in ['budget.py','launch.py']}
    changed=dict(original)
    changed['budget.py']=once(changed['budget.py'],
        "    projected=spent+rate*hours+transfers+fixed",
        "    prior=amount(quote.get('prior_experiment_upper_bound_usd',0))\n"
        "    projected=prior+spent+rate*hours+transfers+fixed")
    changed['budget.py']=once(changed['budget.py'],
        "        'hourly_usd':str(rate),'mandatory_window_hours':str(lower_bound),",
        "        'hourly_usd':str(rate),'mandatory_window_hours':str(lower_bound),\n"
        "        'prior_experiment_upper_bound_usd':str(prior),")
    changed['launch.py']=once(changed['launch.py'],
        "        fixed=sum(float(self.quote[k]) for k in ['build_registry','retained_resources','transfer_storage_upper_bound'])",
        "        fixed=sum(float(self.quote[k]) for k in ['build_registry','retained_resources','transfer_storage_upper_bound'])\n"
        "        fixed+=float(budget.amount(self.quote.get('prior_experiment_upper_bound_usd',0)))")
    patch=''.join(''.join(difflib.unified_diff(original[name].splitlines(True),changed[name].splitlines(True),
        fromfile='a/VC-FHE/distributed/'+name,tofile='b/VC-FHE/distributed/'+name)) for name in original)
    return original,changed,patch

def hashes(values):return {k:hashlib.sha256(v.encode()).hexdigest() for k,v in values.items()}
if __name__=='__main__':
    original,changed,patch=render()
    (HERE/'proposal.patch').write_text(patch)
    (HERE/'proposal.json').write_text(json.dumps({'schema':'vcfhe-budget-carryforward-proposal-v1',
        'status':'unapplied','source':hashes(original),'candidate':hashes(changed),
        'defaultPriorUsd':'0','changesBuildReservations':False,'cloudActions':False},indent=2)+'\n')
