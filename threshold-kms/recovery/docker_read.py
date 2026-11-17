"""Bounded retries for Docker reads only; never use for an action or RPC."""
import json
import subprocess
import time


def docker_read(args, *, attempts=3, timeout=5, sleep=time.sleep, run=subprocess.run):
    allowed = (args[:2] == ['docker', 'inspect'] or
               args[:3] == ['docker', 'image', 'inspect'] or
               args[:2] == ['docker', 'ps'] or
               (args[:2] == ['docker', 'compose'] and len(args) > 4 and args[4] == 'ps'))
    if not allowed:
        raise ValueError('retry helper accepts only Docker inspection commands')
    if attempts not in range(1, 4) or not 0 < timeout <= 5:
        raise ValueError('read retry bounds exceeded')
    for attempt in range(attempts):
        try:
            result = run(args, check=False, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            if attempt == attempts - 1:
                raise
        else:
            if result.returncode == 0:
                return result.stdout.strip()
            if 'cannot connect to the docker daemon' not in result.stderr.lower():
                raise subprocess.CalledProcessError(result.returncode, args, result.stdout, result.stderr)
            if attempt == attempts - 1:
                raise RuntimeError('Docker control-plane unavailable after bounded read retries')
        print('READ_ONLY_DOCKER_RETRY '+json.dumps({'attempt': attempt+1, 'command': args}), flush=True)
        sleep(1)


def require_running(compose, roles, complete=False):
    for role in roles:
        ids = docker_read(compose+['ps', '--all', '--quiet', role]).splitlines()
        if len(ids) != 1:
            raise RuntimeError('missing/ambiguous service: '+role)
        state = json.loads(docker_read(['docker', 'inspect', '--format', '{{json .State}}', ids[0]]))
        if state.get('OOMKilled') or state.get('Dead') or state.get('Restarting'):
            raise RuntimeError('failed service: '+role)
        if not state['Running'] and not (role == 'recipient' and complete and state['ExitCode'] == 0):
            raise RuntimeError('stopped service: '+role+'; requests will not be replayed')
