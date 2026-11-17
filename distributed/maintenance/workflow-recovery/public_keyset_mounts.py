"""Restore original public-key transfer permissions without changing secret mounts."""
import copy


def restore(compose, new_base):
    result=copy.deepcopy(compose)
    for name,service in result['services'].items():
        if name in ('init','setup','policy-init') or name.startswith('validator-'):
            continue
        for mount in service.get('volumes',[]):
            if mount['target']=='/keyset':
                mount['source']=new_base+'/'+name+'/keyset'
                mount['read_only']=False
    return result
