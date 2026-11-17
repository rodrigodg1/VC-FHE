#!/usr/bin/env python3
"""Observe an already-running smoke after a controller-only monitoring failure.

No actor, task, transaction, release or setup is started or retried. The original
failed launch record is immutable. The suspended parent's original deadline is
retained. Output is private, derived observation evidence, never publication.
"""
from datetime import datetime, timezone, timedelta
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import deployment
import image
import launch
from remote import Remote
import smoke_cleanup as safe
import topology


class ProtocolFailure(ValueError):
    pass


class ObservationDeadline(ValueError):
    pass


def read(path):
    return safe._read(path)


def sha(path):
    return safe._sha(path)


def parent_state(pid):
    def query(field):
        result = subprocess.run(['ps', '-p', str(pid), '-o', field + '='], capture_output=True, text=True)
        if result.returncode or not result.stdout.strip():
            raise ValueError('Suspended original controller is unavailable')
        return result.stdout.strip()
    status, started, command = query('stat'), query('lstart'), query('command')
    if not status.startswith('T'):
        raise ValueError('Original controller is not suspended. Observation must stop')
    return {'pid': pid, 'started': started, 'commandSha256': hashlib.sha256(command.encode()).hexdigest()}, command


def deadline(created_at, hours):
    created = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
    if created.tzinfo is None or not 0 < float(hours) <= 24:
        raise ValueError('Original absolute timing scope is invalid')
    return created + timedelta(hours=float(hours))


class ReadOnlyRemote:
    """Only exact original wait reads and fixed container inspection are allowed."""
    def __init__(self, observer, host):
        self.observer, self.host = observer, host
        self.remote = Remote(observer.config, host)

    def allowed(self, args):
        o = self.observer
        if args == ['sudo', 'docker', 'compose', '-f', o.base + '/' + self.host['id'] + '/compose.json',
                    'logs', '--no-color', '--tail', '8', 'coordinator-1'] and self.host['id'] == o.nodes['coordinator-1']['host']:
            return 'logs'
        for node in ['coordinator-1', 'recipient-1']:
            if self.host['id'] == o.nodes[node]['host']:
                if args == ['sudo', 'cat', o.nodes[node]['state_directory'] + '/reports/participant-exit.json']:
                    return 'exit:' + node
        if (self.host['id'] == o.nodes['coordinator-1']['host']
                and args == ['sudo', 'tail', '-n', '1', o.nodes['coordinator-1']['state_directory'] + '/reports/progress-evaluation.jsonl']):
            return 'progress'
        expected = o.container_names(self.host['id'])
        if args == ['sudo', 'docker', 'inspect', '--format', '{{json .}}', *expected]:
            return 'inspection'
        raise ValueError('Observer refused a command outside exact read-only observation')

    def run(self, args, **kwargs):
        kind = self.allowed(args)
        self.observer.guard()
        remaining = self.observer.remaining()
        kwargs['timeout'] = min(45, remaining)
        try:
            result = self.remote.run(args, **kwargs)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            self.observer.monitor_error(kind, error)
            if kind == 'logs':
                return subprocess.CompletedProcess(args, 255)
            raise subprocess.CalledProcessError(255, ['read-only-observation', kind]) from None
        if kind.startswith('exit:'):
            try:
                value = json.loads(result.stdout)
            except (json.JSONDecodeError, UnicodeError) as error:
                self.observer.monitor_error(kind, error)
                raise subprocess.CalledProcessError(255, ['read-only-observation', kind]) from None
            node = kind.split(':', 1)[1]
            if (not isinstance(value, dict) or value.get('node') != node
                    or value.get('role') != self.observer.nodes[node]['role']
                    or type(value.get('exitCode')) is not int):
                raise ProtocolFailure('Participant exit record is malformed or belongs to another role')
            self.observer.exits[node] = value
            if value['exitCode'] != 0:
                raise ProtocolFailure('Real participant failure. No computation or release will be retried')
        return result

    def text(self, args):
        return self.run(args, stdout=subprocess.PIPE, text=True).stdout.strip()

    def json(self, args):
        kind = self.allowed(args)
        try:
            value = json.loads(self.text(args))
        except (OSError, json.JSONDecodeError, UnicodeError) as error:
            self.observer.monitor_error(kind, error)
            raise subprocess.CalledProcessError(255, ['read-only-observation', kind]) from None
        if kind == 'progress' and (not isinstance(value, dict) or 'observedAt' in value):
            self.observer.monitor_error(kind, ValueError('Malformed read-only progress observation'))
            raise subprocess.CalledProcessError(255, ['read-only-observation', kind])
        return value


class Observer:
    def __init__(self, journal, reconciliation=None, output=None):
        self.journal = safe._private(journal)
        session = read(self.journal)
        self.original = (HERE.parent / session['activeRun']).resolve()
        if self.original.parent != HERE.parent / 'threshold-kms/runs':
            raise ValueError('Observation requires the original direct run directory')
        self.reconciliation = safe._private(reconciliation or self.journal.with_name('monitor-reconciliation.local.json'))
        handoff = read(self.reconciliation)
        if (handoff.get('status') != 'controller-suspended-before-cleanup'
                or type(handoff.get('pid')) is not int):
            raise ValueError('No explicit suspended-parent reconciliation exists')
        self.parent, command = parent_state(handoff['pid'])
        if 'cli.py' not in command or self.original.name not in command:
            raise ValueError('Suspended process is not the original run controller')
        self.config = read(self.original / 'distributed-config.json')
        topology.validate(self.config)
        if self.config.get('execution_mode') != 'smoke' or not self.config['campaign'].endswith('-smoke'):
            raise ValueError('Only the explicitly nonpublishing smoke is supported')
        self.state = read(self.original / 'launch-state.json')
        if self.state.get('status') != 'failed' or self.state.get('config') != self.config:
            raise ValueError('Original failed launch record is unavailable')
        stages = self.state.get('stages', [])
        failed = [x for x in stages if x.get('status') == 'failed']
        if (len(failed) != 1 or failed[0].get('name') != 'Full evaluation'
                or not stages or stages[-1].get('name') != 'Preserve private smoke state before resource removal'
                or stages[-1].get('status') != 'running'
                or 'logs' not in self.state.get('error', '') or 'gcloud' not in self.state.get('error', '')):
            raise ValueError('Failure is not the reconciled read-only wait/log observation failure')
        backup = self.original / 'private-smoke-backup'
        if (backup.exists() and any(backup.iterdir())) or (self.original / 'compute-stop.local.json').exists() or (self.original / 'smoke-cleanup.local.json').exists():
            raise ValueError('Quiescence or cleanup may already have started')
        self.quote = read(self.original / 'distributed/quote.json')
        self.expires = deadline(self.state['createdAt'], self.quote['planned_hours'])
        self.started = time.monotonic() - (datetime.now(timezone.utc) - datetime.fromisoformat(self.state['createdAt'].replace('Z', '+00:00'))).total_seconds()
        self.record = read(self.original / 'distributed/source.json')
        self.build = (HERE.parent / session['activeBuild']).resolve()
        if read(self.build / 'distributed-source.json') != self.record:
            raise ValueError('Original run source record differs from preserved image context')
        image.verify_adapter_sources(self.record)
        if deployment.campaign_module().source_manifest() != self.record['localSource']:
            raise ValueError('Original FHE/protocol sources changed')
        receipt = read(self.build / 'published-image.json')
        if (receipt.get('sourceSha256') != topology.digest(self.record)
                or receipt.get('digest') != self.config['images']['campaign']
                or receipt.get('besuDigest') != self.config['images']['besu']):
            raise ValueError('Source-bound immutable image receipt differs')
        self.plan = topology.plan(self.config)
        self.nodes = {n['id']: n for n in self.plan['nodes']}
        self.compose = {h['id']: read(self.original / 'compose' / h['id'] / 'compose.json') for h in self.plan['hosts']}
        if self.compose != deployment.manifests(self.config, self.original.name):
            raise ValueError('Original Compose descriptors changed')
        self.base = '/srv/vcfhe/' + self.config['campaign']
        self.identities = read(self.original / 'distributed/public-identities.json')
        self.datasets = read(self.original / 'distributed/controller-inputs.json')['datasets']
        paths = ['launch-state.json', 'distributed-config.json', 'distributed/quote.json', 'distributed/source.json',
                 'terraform/terraform.tfstate', 'terraform/main.tf.json', 'distributed/public-identities.json',
                 'distributed/controller-inputs.json']
        self.hashes = {name: sha(self.original / name) for name in paths}
        self.reconciliation_sha = sha(self.reconciliation)
        self.output = safe._private(output or self.journal.parent / 'protocol-export' / self.original.name)
        if self.output.exists() or self.output.is_relative_to(self.original):
            raise ValueError('Use a new private derived observation directory outside the original run')
        self.output.mkdir(parents=True, mode=0o700)
        os.chmod(self.output, 0o700)
        self.exits = {}
        self.errors = 0
        self.remotes = {h['id']: ReadOnlyRemote(self, h) for h in self.plan['hosts']}
        self.report = {'schema': 'vcfhe-read-only-observation-v1', 'status': 'prepared', 'originalRun': str(self.original),
                       'originalLaunchStatus': 'failed', 'originalFiles': self.hashes,
                       'sourceSha256': topology.digest(self.record), 'parent': self.parent,
                       'observerSourceSha256': sha(__file__),
                       'absoluteDeadline': self.expires.isoformat(), 'initialObservationAt': datetime.now(timezone.utc).isoformat(),
                       'protocolActionsStartedOrRetried': [], 'evaluationPublishable': False}
        self.save()

    def remaining(self):
        seconds = (self.expires - datetime.now(timezone.utc)).total_seconds()
        if seconds <= 0:
            raise ObservationDeadline('Original infrastructure deadline exhausted. No extension or protocol retry is allowed')
        return seconds

    def guard(self):
        current, _ = parent_state(self.parent['pid'])
        if current != self.parent or sha(self.reconciliation) != self.reconciliation_sha:
            raise ValueError('Suspended parent identity or reconciliation changed')
        if any(sha(self.original / name) != value for name, value in self.hashes.items()):
            raise ValueError('Original failed run changed. Observation stopped')
        self.remaining()

    def save(self):
        safe._write(self.output / 'observation.local.json', self.report)

    def monitor_error(self, kind, error):
        self.errors += 1
        with (self.output / 'monitor-errors.local.jsonl').open('a') as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(json.dumps({'at': datetime.now(timezone.utc).isoformat(), 'kind': kind,
                                     'type': type(error).__name__, 'error': str(error)}) + '\n')
        self.report['monitoringErrors'] = self.errors
        self.save()

    def container_names(self, host):
        names = []
        for node in self.plan['nodes']:
            if node['host'] == host:
                names.append(self.config['campaign'] + '-' + host + '-' + node['id'] + '-1')
                if node['role'] == 'kms':
                    names.extend(self.config['campaign'] + '-' + host + '-' + node['id'] + '-' + suffix + '-1' for suffix in ['core', 'public'])
        return names

    def campaign(self):
        # No initializer, dependency preparation, infrastructure or protocol
        # methods are called. Only the exact original wait method is used.
        campaign = launch.Campaign.__new__(launch.Campaign)
        for field in ['config', 'quote', 'record', 'plan', 'nodes', 'compose', 'base', 'identities', 'datasets', 'started']:
            setattr(campaign, field, copy.deepcopy(getattr(self, field)))
        campaign.run = self.output
        campaign.state = copy.deepcopy(self.state)
        campaign.remotes = self.remotes
        return campaign

    def preflight(self):
        self.guard()
        rows, _ = safe._state(self.config, self.original)
        vms = [r for r in rows.values() if r['type'] == 'google_compute_instance']
        if len(vms) != 4:
            raise ValueError('Original four-VM ownership is incomplete')
        observations = []
        for row in vms:
            self.guard()
            live = safe._cloud(safe._args(self.config, safe._describe_args(row)))
            safe._check_identity(self.config, row, live)
            if live.get('status') != 'RUNNING' or live.get('labels', {}).get('experiment') != self.config['campaign']:
                raise ValueError('An original VM is stopped or does not match this campaign')
            observations.append({'address': row['address'], 'identity': safe._identity(live)})
        containers = []
        for host in self.plan['hosts']:
            args = ['sudo', 'docker', 'inspect', '--format', '{{json .}}', *self.container_names(host['id'])]
            records = [json.loads(line) for line in self.remotes[host['id']].text(args).splitlines()]
            if len(records) != len(self.container_names(host['id'])):
                raise ValueError('Incomplete original container inventory')
            for row in records:
                labels = row.get('Config', {}).get('Labels', {})
                service = labels.get('com.docker.compose.service', '')
                expected = self.config['images']['besu'] if service.startswith('validator-') else self.config['images']['campaign']
                if (labels.get('com.docker.compose.project') != self.config['campaign'] + '-' + host['id']
                        or row.get('Config', {}).get('Image') != expected or row.get('State', {}).get('OOMKilled')
                        or not row.get('State', {}).get('Running')):
                    raise ProtocolFailure('An original participant container failed or has a different image/scope')
                containers.append({'host': host['id'], 'service': service, 'id': row['Id'], 'image': expected})
        if len(containers) != 29:
            raise ValueError('Expected the original 29 running containers')
        self.report.update(status='observing', vmIdentities=observations, containerIdentities=containers)
        self.save()

    def wait(self):
        try:
            self.preflight()
            while True:
                self.guard()
                try:
                    launch.Campaign.wait(self.campaign())
                    break
                except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                    self.monitor_error('original-wait-transport', error)
                    time.sleep(min(5, self.remaining()))
            if set(self.exits) != {'coordinator-1', 'recipient-1'} or any(r['exitCode'] != 0 for r in self.exits.values()):
                raise ProtocolFailure('Both original applications must exit zero before any collection')
            self.guard()
            self.report.update(status='participants-exited-zero', participantExits=self.exits,
                               observedAt=datetime.now(timezone.utc).isoformat(), originalLaunchRecordUnchanged=True,
                               dataValidation='pending-original-A9-collector')
            self.save()
            return self.report
        except BaseException as error:
            self.report.update(status='failed-observation', errorType=type(error).__name__, error=str(error),
                               participantExits=self.exits, originalLaunchRecordUnchanged=True)
            self.save()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--journal', required=True)
    parser.add_argument('--reconciliation')
    parser.add_argument('--output')
    args = parser.parse_args()
    import cloud_tools
    cloud_tools.ensure()
    observer = Observer(args.journal, args.reconciliation, args.output)
    report = observer.wait()
    print(json.dumps({'status': report['status'], 'absoluteDeadline': report['absoluteDeadline'],
                      'monitoringErrors': report.get('monitoringErrors', 0), 'evaluationPublishable': False}, indent=2))


if __name__ == '__main__':
    main()
