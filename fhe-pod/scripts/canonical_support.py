"""Hash the local JS dependency closure in addition to measured core sources."""
import re
from canonical_evidence import ROOT,digest
def support_files(snapshot):
    known=set(snapshot['sourceFiles']); queue=[ROOT/p for p in known if p.endswith(('.js','.mjs'))]; seen=set(); out={}
    pattern=re.compile(r'''(?:from\s*|import\s*\(?\s*|require\s*\(\s*)["'](\.[^"']+)["']''')
    while queue:
        p=queue.pop().resolve()
        if p in seen:continue
        seen.add(p)
        code=re.sub(r'/\*.*?\*/','',p.read_text(),flags=re.S)
        code=re.sub(r'^\s*//.*$','',code,flags=re.M)
        for ref in pattern.findall(code):
            q=(p.parent/ref).resolve()
            if not q.suffix:q=q.with_suffix('.js')
            if not q.is_file():raise ValueError('missing local dependency '+str(q))
            rel=str(q.relative_to(ROOT.resolve()))
            if rel not in known:out[rel]=digest(q)
            if q.suffix in ('.js','.mjs'):queue.append(q)
    return dict(sorted(out.items()))
