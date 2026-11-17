#!/usr/bin/env python3
"""Check relative Markdown links/anchors in the public documentation, offline.

Does not fetch external URLs or execute examples. Code fences are excluded.
"""
from collections import Counter
import json
import os
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SKIP = {'.git', 'node_modules', 'target', '__pycache__', '.cache', '.deps',
        '.venv', '.lake', '.checked', 'generated', 'artifacts', 'derived'}
LINK = re.compile(r'!?\[[^\]\n]*\]\(([^\s)]+)(?:\s+"[^"]*")?\)')


def prose(text):
    return re.sub(r'^```[^\n]*\n.*?^```\s*$', '', text, flags=re.M | re.S)


def anchors(text):
    text = prose(text)
    result = set(re.findall(r'\b(?:id|name)=["\']([^"\']+)["\']', text))
    counts = Counter()
    for heading in re.findall(r'^#{1,6}\s+(.+?)\s*#*$', text, re.M):
        label = re.sub(r'<[^>]*>', '', heading).lower()
        label = re.sub(r'[^\w\- ]', '', label).replace(' ', '-')
        suffix = f'-{counts[label]}' if counts[label] else ''
        result.add(label + suffix)
        counts[label] += 1
    return result


def inspect():
    documents = []
    for current, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP and not d.startswith('.')]
        documents.extend(Path(current) / name for name in files if name.endswith('.md'))
    checked = 0
    errors = []
    for path in sorted(documents):
        for match in LINK.finditer(prose(path.read_text())):
            link = match.group(1).strip('<>')
            parsed = urlsplit(link)
            if parsed.scheme or parsed.netloc:
                continue
            target = (path.parent / unquote(parsed.path)).resolve() if parsed.path else path
            checked += 1
            issue = None
            if not target.is_relative_to(ROOT):
                issue = 'outside public repository'
            elif not target.exists():
                issue = 'missing target'
            elif parsed.fragment and target.suffix == '.md' and unquote(parsed.fragment) not in anchors(target.read_text()):
                issue = 'missing Markdown anchor'
            if issue:
                errors.append({'file':str(path.relative_to(ROOT)), 'link':link, 'issue':issue})
    return {'status':'failed' if errors else 'passed', 'documents':len(documents),
            'relativeLinks':checked, 'errors':errors,
            'scope':'Relative inline Markdown links and heading anchors; no external URL, CLI execution or semantic validation.'}


if __name__ == '__main__':
    result = inspect()
    print(json.dumps(result, indent=2))
    raise SystemExit(bool(result['errors']))
