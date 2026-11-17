"""Read a controller snapshot. Never contacts, starts or retries a cloud actor."""
import json
from pathlib import Path

def snapshot(run):
    run=Path(run)
    state=json.loads((run/'launch-state.json').read_text())
    progress=run/'live-progress.local.json'
    return {'status':state['status'],'evaluationStatus':state.get('evaluationStatus'),'evaluationSource':state.get('evaluationSource'),
            'phases':[{'name':s['name'],'status':s['status']} for s in state['stages']],
            'progress':json.loads(progress.read_text()) if progress.exists() else None,
            'note':'Snapshot recorded by the active launcher. An old snapshot does not establish continued progress.'}
