"""Check publishable reproduction files without reading ignored credentials."""
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[1]
PATTERNS={
    'Google API key':re.compile(r'AIza[0-9A-Za-z_-]{35}'),
    'OAuth credential':re.compile(r'1//[A-Za-z0-9_-]{30,}'),
    'private key':re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'personal Google account':re.compile(r'[A-Za-z0-9._%+-]+@(?:gmail|googlemail)\.com'),
    'personal project identifier':re.compile(r'gen-lang-client-\d{10}'),
    'billing account identifier':re.compile(r'billingAccounts/[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}'),
}

def require_private(path):
    path=Path(path).resolve()
    if path.is_relative_to(ROOT):
        parts=path.relative_to(ROOT).parts
        allowed={'generated','runs','composites','preserved','reproduction','private','.cache','.deps','.policy-state'}
        if not set(parts)&allowed and not path.name.endswith(('.local.json','.local.sh','.local.py')):
            raise ValueError('Account configuration and cloud records must use a private ignored path: '+str(path))
    return path


def audit():
    from source_bundle import public_sources
    findings=[];checked=0
    for name,path in public_sources(ROOT).items():
        text=path.read_text(errors='replace');checked+=1
        for label,pattern in PATTERNS.items():
            if pattern.search(text):findings.append({'file':name,'kind':label})
    if findings:raise ValueError('Public-source privacy check failed: '+str(findings))
    return {'status':'passed','filesChecked':checked,'scope':'Public reproduction source files',
            'ignoredPrivateFilesRead':False,'findings':[]}
