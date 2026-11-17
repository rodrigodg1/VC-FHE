"""Review-only wait replacement. Writes only a new, explicit source copy."""
import ast
import hashlib
from pathlib import Path

WAIT_METHOD = '''    def wait(self):
        # Observation reads never repeat an actor task, release or transaction.
        deadline = self.started + float(self.quote['planned_hours']) * 3600
        unavailable = object()

        def remaining():
            value = deadline - time.monotonic()
            if value <= 0:
                raise ValueError('planned infrastructure duration exhausted. Preserve incomplete evidence')
            return value

        def read_json(remote, args):
            try:
                result = remote.run(args, stdout=subprocess.PIPE, text=True,
                                    timeout=min(45, remaining()))
                value = json.loads(result.stdout)
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
                    json.JSONDecodeError, UnicodeError):
                remaining()
                return unavailable
            remaining()
            return value

        def accept_exit(value, node, role):
            if (not isinstance(value, dict) or value.get('node') != node
                    or value.get('role') != role or type(value.get('exitCode')) is not int):
                raise ValueError('malformed or misassigned participant exit record')
            if value['exitCode'] != 0:
                raise ValueError('distributed participant failed. Releases and tasks will not be retried')

        node = 'coordinator-1'
        remote = self.remote(node)
        root = self.root(node)
        recipient_node = 'recipient-1'
        recipient_remote = self.remote(recipient_node)
        recipient_args = ['sudo', 'cat', self.root(recipient_node) + '/reports/participant-exit.json']
        recipient_finished = False
        while True:
            # Recipient failure must not remain hidden behind a coordinator
            # that is still waiting for the recipient's output file.
            if not recipient_finished:
                recipient = read_json(recipient_remote, recipient_args)
                if recipient is not unavailable:
                    accept_exit(recipient, recipient_node, 'recipient')
                    recipient_finished = True
            try:
                self.compose_run(node, 'logs', '--no-color', '--tail', '8', node,
                                 timeout=min(45, remaining()))
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                remaining()
            progress = read_json(remote, ['sudo', 'tail', '-n', '1', root + '/reports/progress-evaluation.jsonl'])
            if isinstance(progress, dict) and 'observedAt' not in progress:
                try:
                    write(self.run / 'live-progress.local.json',
                          dict(observedAt=datetime.now(timezone.utc).isoformat(), **progress))
                    print('WORKFLOW PROGRESS ' + json.dumps(progress), flush=True)
                except (OSError, ValueError, TypeError):
                    # Host-side progress is observation only. Exit validation
                    # below is deliberately outside this exception handler.
                    pass
            result = read_json(remote, ['sudo', 'cat', root + '/reports/participant-exit.json'])
            if result is not unavailable:
                # Validation stays outside the transport-read exception handler.
                # A real nonzero exit or a wrong role cannot become a retry.
                accept_exit(result, node, 'coordinator')
                break
            time.sleep(min(30, remaining()))

        if recipient_finished:
            return
        while True:
            result = read_json(recipient_remote, recipient_args)
            if result is not unavailable:
                accept_exit(result, recipient_node, 'recipient')
                return
            time.sleep(min(2, remaining()))

'''


def proposed_source(source):
    source = str(source)
    start = '    def wait(self):\n'
    end = '    def collect(self):\n'
    if source.count(start) != 1 or source.count(end) != 1:
        raise ValueError('Review exact wait/collect anchors before creating a proposal')
    first, last = source.index(start), source.index(end)
    if last <= first:
        raise ValueError('Invalid method order')
    result = source[:first] + WAIT_METHOD + source[last:]
    ast.parse(result)
    return result


def write_copy(source, destination):
    source, destination = Path(source).resolve(), Path(destination).absolute()
    if (destination.exists() or destination.is_symlink() or source == destination.resolve()
            or destination.parent.resolve() == source.parent
            or any(parent.is_symlink() for parent in destination.parents)):
        raise ValueError('Proposal requires a fresh separate source copy')
    original = source.read_bytes()
    proposed = proposed_source(original.decode()).encode()
    with destination.open('xb') as output:
        output.write(proposed)
    return {'originalSha256': hashlib.sha256(original).hexdigest(),
            'proposedSha256': hashlib.sha256(proposed).hexdigest(),
            'originalUnchanged': source.read_bytes() == original,
            'protocolActionsAdded': [], 'appliedToOriginal': False}
