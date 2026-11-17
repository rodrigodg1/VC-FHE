"""Enable missing controller-management APIs only for an explicit cloud start."""
from cloud_results.common import gcloud,run,require

REQUIRED={'cloudresourcemanager.googleapis.com','serviceusage.googleapis.com'}


def ensure(config,*,execute=False):
    rows=gcloud('services','list','--enabled','--project',config['project_id'])
    enabled={v['config']['name'] for v in rows};missing=sorted(REQUIRED-enabled)
    if missing:
        require(execute,'Controller management APIs are missing. Explicit execution is required to enable them')
        run(['gcloud','services','enable',*missing,'--project',config['project_id'],'--quiet'])
        current=gcloud('services','list','--enabled','--project',config['project_id'])
        require(REQUIRED<={v['config']['name'] for v in current},'Controller management API activation is incomplete')
    return {'status':'passed','managementApis':sorted(REQUIRED),'newlyEnabled':missing,
            'protocolOperations':0,'participantPermissionsChanged':False}
