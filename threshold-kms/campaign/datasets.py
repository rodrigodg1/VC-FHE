"""Fetch only pinned evaluation files; never clone rating/demographics history."""
import hashlib
from pathlib import Path
import time
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[2]
STAV='ef4dd1ea35f275d4240b5886dcc0e372de73d330'
QOERA='3add3121ded7a31f1434e863073917772993b74b'
SOURCES=[
 ('linear','datasets/raw/stav360/Raw_Ratings.csv',f'https://raw.githubusercontent.com/SLG-European-Projects/STAV360/{STAV}/Raw_Ratings.csv','19e171b0704287f1492ebb2cff505ed5ea0c1f538c3972524117358b57646ead',False),
 ('nonlinear','data/MOS_BS_1_Driver_PRB_10.csv',f'https://raw.githubusercontent.com/telematics-lab/5G-QoERA/{QOERA}/5G-QoERA/MOS_BS_1_Driver_PRB_10.tsv','af369d082bc4d54674dd3c25cfe54d67694f9df5872114799d6544e83bff8f64',True),
 ('nonlinear','data/MOS_BS_4_Driver_PRB_10.csv',f'https://raw.githubusercontent.com/telematics-lab/5G-QoERA/{QOERA}/5G-QoERA/MOS_BS_4_Driver_PRB_10.tsv','7810fe63758b128f6696a06c35704cb6473d3a747cfa8ff902275aeece37a823',True),
]

def ensure(half):
    evidence={}
    for which,name,url,digest,convert in SOURCES:
        if half not in ('both',which):continue
        target=ROOT/name
        if not target.exists():
            print('Fetching pinned dataset file: '+name,flush=True)
            if which=='linear':print('STAV360: local research input only; redistribution rights are not established. Raw data remains gitignored.',flush=True)
            for attempt in range(3):
                try:
                    with urllib.request.urlopen(url,timeout=90) as response:content=response.read(40*1024*1024+1)
                    if len(content)>40*1024*1024:raise ValueError('dataset exceeds expected download size')
                    if convert:content=content.replace(b'\t',b',')
                    if hashlib.sha256(content).hexdigest()!=digest:raise ValueError('downloaded dataset checksum mismatch: '+name)
                    target.parent.mkdir(parents=True,exist_ok=True)
                    tmp=target.with_name(target.name+'.'+uuid.uuid4().hex+'.pending')
                    with tmp.open('xb') as f:f.write(content)
                    tmp.rename(target);break
                except OSError:
                    if attempt==2:raise
                    time.sleep(2**attempt)
        if hashlib.sha256(target.read_bytes()).hexdigest()!=digest:raise ValueError('dataset changed; existing input preserved: '+name)
        evidence[name]={'sha256':digest,'source':url,'conversion':'tab to comma' if convert else 'none'}
    return evidence

if __name__=='__main__':
    import json,sys
    print(json.dumps(ensure(sys.argv[1] if len(sys.argv)>1 else 'both'),indent=2))
