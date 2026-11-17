"""Read bounded, public progress events without parsing private service logs."""
import json
import re
from pathlib import Path

PHASES={
 'owner-encrypt':'Data owners encrypt the selected records',
 'paired-comparison':'Run proposed and baseline verification on the same encrypted inputs',
 'full-case':'Complete workflow case',
 'workflow-deploy':'Deploy workflow verification and dispute contracts',
 'linear-admission':'Owners sign records and the contract verifies admissions',
 'owner-consent':'Data owners authorize the computation and recipient',
 'operator-execution':'Operator computes over ciphertexts',
 'auditor-recomputation':'Auditor recomputes the complete encrypted execution',
 'context-certification':'Adjudicators certify the execution context',
 'full-certification':'Baseline adjudicators independently recompute the complete execution',
 'leaf-certification':'Adjudicators recompute the disputed encrypted instruction',
 'honest-finalization':'Submit audit opening and wait for contract finalization',
 'recipient-verification':'Recipient checks delivery and prepares the exact decryption request',
 'release-approval':'Owners approve the exact request and the contract reserves its slot',
 'threshold-release':'KMS checks authorization and returns responses encrypted for the recipient',
 'recipient-recovery':'Recipient recovers the authorized result off-chain',
 'faulty-execution':'Operator executes the separate faulty-task test',
 'trace-disclosure':'Publish the authenticated encrypted trace for auditing',
 'dispute-settlement':'Contract coordinates challenge, bisection and certified settlement',
}
STAGES={
 'committee-availability-controls':'Test adjudicator availability with isolated contract controls',
 'besu':'Start four Besu validators and wait for the blockchain',
 'identities':'Prepare persistent owner and recipient identities',
 'release-policy':'Deploy or verify the retained result-authorization contract',
 'kms-cores':'Start the four KMS participants',
 'prss':'Initialize distributed KMS preprocessing',
 'dkg':'Generate the shared FHE keyset through the KMS protocol',
 'owner-start':'Start data-owner encryption service',
 'worker-start':'Start public encrypted-computation worker',
 'recipient-start':'Start recipient service',
 'evaluation':'Prepare encrypted inputs, run paired comparisons and complete workflows',
}
GROUPS={'owner-linear':'linear encryption','owner-nonlinear':'non-linear encryption',
        'warmup':'warm-ups','paired':'measured pairs','full':'full cases'}

def format_event(row):
    if not isinstance(row,dict) or set(row)-{'version','phase','state','caseName','group','current','total'}:
        return None
    if row.get('version')!=1 or row.get('phase') not in PHASES or row.get('state') not in ('start','done'):
        return None
    name=row.get('caseName')
    if name is not None and (not isinstance(name,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,120}',name)):
        return None
    group=row.get('group')
    if group is not None and group not in GROUPS:return None
    count=''
    if 'current' in row or 'total' in row:
        current,total=row.get('current'),row.get('total')
        if type(current) is not int or type(total) is not int or not 1<=current<=total<=100000:return None
        count=f" [{GROUPS.get(group,'items')} {current}/{total}"
        item_finished=(row['phase']=='full-case' and group=='full' or
                       row['phase']=='paired-comparison' and group in ('paired','warmup') or
                       row['phase']=='owner-encrypt' and group in ('owner-linear','owner-nonlinear'))
        if row['state']=='done' and item_finished:count+=f", {100*current//total}% complete"
        count+=']'
    status='Completed' if row['state']=='done' else 'Starting'
    return f"{status}{count}: {PHASES[row['phase']]}"+(f" ({name})" if name else '')

class ProgressMonitor:
    def __init__(self,run,emit=print):
        self.paths=[Path(run)/'reports'/f'progress-{channel}.jsonl' for channel in ('owner','evaluation')]
        self.offsets={p:0 for p in self.paths};self.emit=emit

    def poll(self):
        # Bounded lines and reads prevent malformed logs from affecting execution.
        for path in self.paths:
            try:
                with path.open('rb') as source:
                    source.seek(self.offsets[path])
                    for _ in range(256):
                        line=source.readline(2049)
                        if not line:break
                        if not line.endswith(b'\n'):
                            if len(line)>2048:self.offsets[path]=source.tell()
                            break
                        self.offsets[path]=source.tell()
                        if len(line)>2048:continue
                        try:message=format_event(json.loads(line))
                        except (ValueError,UnicodeError):continue
                        if message:self.emit(message)
            except OSError:continue

def stage_message(name):
    return STAGES.get(name,name.replace('-',' '))
