"""Resolve pinned public inputs before any paid cloud build or evaluation."""
import hashlib
import json
from pathlib import Path
import subprocess
import deployment

ROOT=Path(__file__).resolve().parents[1]

def prepare():
    module=deployment.campaign_module()
    datasets=module.ensure_datasets('both')
    fixture=ROOT/'datasets/outputs/linear-inputs.json'
    if not fixture.exists():
        subprocess.run(['node',str(ROOT/'datasets/prepare/prepare-linear-inputs.mjs'),
                        '--dataset','stav360'],check=True)
    value=json.loads(fixture.read_text())
    selected=[q for q in value['queries'] if q['query_id']=='stav360_session_mos_sum']
    if len(selected)!=1 or selected[0].get('dataset')!='STAV360' or len(selected[0]['values'])!=16:
        raise ValueError('linear dataset fixture is invalid. Existing input was preserved.')
    return {'datasets':datasets,'linearFixtureSha256':hashlib.sha256(fixture.read_bytes()).hexdigest()}
