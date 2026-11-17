#!/usr/bin/env python3
"""Inspect a source distribution for private state, external links and missing files."""
import argparse
import ast
import gzip
import json
import os
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'distributed'))
from privacy import PATTERNS
from source_bundle import public_sources

IGNORED={'.git','node_modules','target','__pycache__','.cache','.deps','.venv'}
PRIVATE={'.policy-state','private','identity','recipient','keyset','runs','composites','generated','raw'}
RESULT_PATTERNS={
    'email address in results':re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'),
    'cloud resource locator in results':re.compile(r'(?:projects/[^/\s]+/|gs://|[\w.-]+\.iam\.gserviceaccount\.com)'),
    'network address in results':re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])'),
    'raw account address in results':re.compile(r'(?<![0-9a-fA-F])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])'),
}
PRIVATE_FIELDS={'privatekey','secretkey','accesstoken','refreshtoken','clientsecret',
                'credentials','mnemonic','password','projectid','accountemail','ipaddress'}

def private_fields(value):
    if isinstance(value,dict):
        for key,item in value.items():
            if re.sub(r'[^a-z]','',key.lower()) in PRIVATE_FIELDS and item not in (None,'',False,[],{}):
                yield key
            yield from private_fields(item)
    elif isinstance(value,list):
        for item in value:yield from private_fields(item)

def inspect(root=ROOT):
    findings=[];count=0;compressed=0
    for current,dirs,names in os.walk(root,followlinks=False):
        dirs[:]=[d for d in dirs if d not in IGNORED]
        for d in dirs:
            p=Path(current)/d
            if p.is_symlink():findings.append((str(p.relative_to(root)),'linked source directory'))
            if d in PRIVATE and any(p.iterdir()):findings.append((str(p.relative_to(root)),'private/runtime directory'))
        for name in names:
            p=Path(current)/name;rel=str(p.relative_to(root));count+=1
            if p.is_symlink():findings.append((rel,'linked source file'));continue
            if name.startswith('.env') or '.local.' in name or '.tfstate' in name or p.suffix in {'.pem','.key','.nodekey'}:
                findings.append((rel,'private file type'))
            if p.suffix in {'.tex','.bib','.cls','.sty','.bst'}:findings.append((rel,'unsupported document source'))
            try:
                if p.suffix=='.gz':
                    text=gzip.decompress(p.read_bytes()).decode('utf-8');compressed+=1
                else:text=p.read_text()
            except UnicodeError:
                if p.suffix=='.gz':findings.append((rel,'non-text compressed result'))
                continue
            except (OSError,EOFError):
                findings.append((rel,'unreadable compressed result'));continue
            for label,pattern in PATTERNS.items():
                if pattern.search(text):findings.append((rel,label))
            if re.search(r'/(?:Users|home)/[A-Za-z0-9_-]+/',text):findings.append((rel,'personal absolute path'))
            if p.relative_to(root).parts[0]=='results':
                for label,pattern in RESULT_PATTERNS.items():
                    if pattern.search(text):findings.append((rel,label))
                try:
                    records=([json.loads(line) for line in text.splitlines() if line.strip()]
                             if p.name.endswith('.jsonl.gz') else
                             [json.loads(text)] if p.suffix=='.json' else [])
                    for record in records:
                        if any(private_fields(record)):findings.append((rel,'private field in results'))
                except json.JSONDecodeError:findings.append((rel,'invalid result JSON'))
            if p.suffix=='.py':
                try:ast.parse(text)
                except SyntaxError:findings.append((rel,'invalid Python syntax'))
    selected=public_sources(root)
    for required in ['distributed/terraform.lock.hcl','threshold-kms/postprocess/render.py','threshold-kms/campaign/Dockerfile']:
        if required not in selected:findings.append((required,'missing deployment input'))
    if findings:raise ValueError(json.dumps(findings,indent=2))
    return {'status':'passed','filesChecked':count,'compressedFilesChecked':compressed,'deploymentSources':len(selected),
            'scope':'Configured text/decompressed-result patterns, JSON fields and required inputs; binary media metadata requires separate inspection.'}

if __name__=='__main__':print(json.dumps(inspect(),indent=2))
