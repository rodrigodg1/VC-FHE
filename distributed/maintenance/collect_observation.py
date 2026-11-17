#!/usr/bin/env python3
"""Collect original A9 evidence into a separate private derived export.

Requires a completed read-only observation with both application exits zero.
Calls only the unchanged original collector. It never modifies or reseals the
original failed launch directory and never starts/retries protocol work.
"""
import argparse
import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import observe_running as observed
import deployment
import image
import launch
from remote import Remote
import smoke_cleanup as safe
import topology

PROFILE_SCRIPT = 'import json,platform;from pathlib import Path;cpu=next(s.split(":",1)[1].strip() for s in Path("/proc/cpuinfo").read_text().splitlines() if s.startswith("model name"));print(json.dumps(dict(cpuModel=cpu,kernelRelease=platform.release(),architecture=platform.machine())))'


def require_zero(report):
    rows = report.get('participantExits', {})
    if report.get('status') != 'participants-exited-zero' or set(rows) != {'coordinator-1', 'recipient-1'}:
        raise ValueError('Both original application exits must be observed before collection')
    for node, row in rows.items():
        if (row.get('node') != node or row.get('role') != node.rsplit('-', 1)[0]
                or type(row.get('exitCode')) is not int or row['exitCode'] != 0):
            raise observed.ProtocolFailure('Nonzero, malformed or misassigned application exit cannot authorize collection')


def copy_exact(source, destination):
    source, destination = Path(source), Path(destination)
    if source.is_symlink() or destination.exists():
        raise ValueError('Derived descriptor must be a fresh exact copy')
    if source.is_dir():
        for child in sorted(source.rglob('*')):
            if child.is_symlink():
                raise ValueError('Descriptor symlink is not admitted')
        shutil.copytree(source, destination)
        os.chmod(destination, 0o700)
    elif source.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(source, destination)
    else:
        raise ValueError('An original required descriptor is missing')
    paths = destination.rglob('*') if destination.is_dir() else [destination]
    for target in paths:
        os.chmod(target, 0o700 if target.is_dir() else 0o600)


class CollectionRemote:
    """Allow only the original collector's evidence export housekeeping."""
    def __init__(self, collector, host):
        self.collector, self.host, self.config = collector, host, collector.observer.config
        self.native = Remote(self.config, host)
        self.holders = set()
        self.download_context = None

    @property
    def extract(self):
        return self.collector.observer.base + '/collected-image'

    def allowed(self, args):
        base = self.collector.observer.base
        if args == ['sudo', 'touch', base + '/' + self.host['id'] + '/stop-sampler']:
            return 'stop-measurement-sampler'
        if args == ['sudo', 'install', '-d', '-m', '700', self.extract + '/bin']:
            return 'collection-directory'
        if args == ['sudo', 'docker', 'create', self.config['images']['campaign']]:
            return 'unstarted-image-holder'
        if args[:3] == ['sudo', 'docker', 'cp'] and len(args) == 5:
            for holder in self.holders:
                allowed = {(holder + ':/usr/local/bin/' + name, self.extract + '/bin/' + name)
                           for name in ['kms-campaign', 'kms-server', 'kms-gen-keys', 'kms-init']}
                allowed.update({(holder + ':/app/threshold-kms/campaign/build-evidence', self.extract + '/build-evidence'),
                                (holder + ':/app/threshold-kms/campaign/distributed-adapter.json', self.extract + '/distributed-adapter.json')})
                if (args[3], args[4]) in allowed:
                    return 'image-evidence-copy'
        if args[:3] == ['sudo', 'docker', 'rm'] and len(args) == 4 and args[3] in self.holders:
            return 'remove-unstarted-holder'
        if args == ['sudo', 'find', self.extract + '/build-evidence', '-type', 'l', '-delete']:
            return 'remove-build-cache-links-only'
        if args == ['python3', '-c', PROFILE_SCRIPT]:
            return 'public-host-profile'
        if self.download_context:
            root, names = self.download_context
            if args == ['sudo', 'tar', '-cf', '-', '-C', root, *names]:
                return 'public-evidence-read'
        raise ValueError('Collector refused a command outside original evidence export')

    def run(self, args, **kwargs):
        kind = self.allowed(args)
        self.collector.guard()
        kwargs['timeout'] = min(kwargs.get('timeout', 900), self.collector.observer.remaining())
        result = self.native.run(args, **kwargs)
        if kind == 'unstarted-image-holder':
            holder = (result.stdout or '').strip()
            if not re.fullmatch(r'[a-f0-9]{64}', holder):
                raise ValueError('Invalid unstarted image-holder identity')
            self.holders.add(holder)
        if kind == 'remove-unstarted-holder':
            self.holders.remove(args[3])
        return result

    def text(self, args):
        return self.run(args, stdout=subprocess.PIPE, text=True).stdout.strip()

    def json(self, args):
        return json.loads(self.text(args))

    def download(self, root, names, destination):
        o = self.collector.observer
        roots = {o.base + '/' + self.host['id'], self.extract}
        roots.update(n['state_directory'] for n in o.plan['nodes'] if n['host'] == self.host['id'])
        if root not in roots or not Path(destination).resolve().is_relative_to(self.collector.output):
            raise ValueError('Evidence download scope is outside the derived export')
        self.collector.guard()
        self.download_context = (root, names)
        try:
            # The original method validates traversal and forbids private vault,
            # signing identities, chain and policy state. Its tar command is
            # routed through this object's exact export allowlist.
            return Remote.download(self, root, names, destination)
        finally:
            self.download_context = None


class Collector:
    def __init__(self, output, journal, reconciliation=None):
        self.output = safe._private(output)
        self.observation_path = self.output / 'observation.local.json'
        report = safe._read(self.observation_path)
        require_zero(report)
        self.observation_sha = safe._sha(self.observation_path)
        if report.get('observerSourceSha256') != safe._sha(observed.__file__):
            raise ValueError('The observation implementation changed after monitoring')
        self.journal = safe._private(journal)
        session = safe._read(self.journal)
        original = (HERE.parent / session['activeRun']).resolve()
        if (str(original) != report.get('originalRun') or original.parent != HERE.parent / 'threshold-kms/runs'
                or self.output.name != original.name or self.output.is_relative_to(original)):
            raise ValueError('Export hierarchy must preserve the original basename outside the original run')
        for name in ['state.json', 'seal.json', 'reports', 'config', 'distributed/deployment.json', 'derived-collection.local.json']:
            if (self.output / name).exists():
                raise ValueError('An earlier collection is preserved. No overwrite or reseal is permitted')
        o = observed.Observer.__new__(observed.Observer)
        self.observer = o
        o.original, o.output, o.journal = original, self.output, self.journal
        o.hashes = report['originalFiles']
        if any(safe._sha(original / name) != value for name, value in o.hashes.items()):
            raise ValueError('Original failed launch evidence changed')
        o.state = safe._read(original / 'launch-state.json')
        if o.state.get('status') != 'failed':
            raise ValueError('The original failed launcher record must remain failed')
        o.config = safe._read(original / 'distributed-config.json')
        topology.validate(o.config)
        o.quote = safe._read(original / 'distributed/quote.json')
        o.expires = observed.deadline(o.state['createdAt'], o.quote['planned_hours'])
        if o.expires.isoformat() != report.get('absoluteDeadline'):
            raise ValueError('Original observation deadline changed')
        o.started = time.monotonic() - (datetime.now(timezone.utc) - datetime.fromisoformat(o.state['createdAt'].replace('Z', '+00:00'))).total_seconds()
        o.record = safe._read(original / 'distributed/source.json')
        image.verify_adapter_sources(o.record)
        if deployment.campaign_module().source_manifest() != o.record['localSource']:
            raise ValueError('Original A9 protocol sources changed')
        o.build = (HERE.parent / session['activeBuild']).resolve()
        receipt = safe._read(o.build / 'published-image.json')
        if (safe._read(o.build / 'distributed-source.json') != o.record
                or report.get('sourceSha256') != topology.digest(o.record)
                or receipt.get('sourceSha256') != topology.digest(o.record)
                or receipt.get('digest') != o.config['images']['campaign']
                or receipt.get('besuDigest') != o.config['images']['besu']):
            raise ValueError('Original source-bound image context differs')
        o.plan = topology.plan(o.config)
        o.nodes = {n['id']: n for n in o.plan['nodes']}
        o.compose = {h['id']: safe._read(original / 'compose' / h['id'] / 'compose.json') for h in o.plan['hosts']}
        if o.compose != deployment.manifests(o.config, original.name):
            raise ValueError('Original deployed Compose descriptors changed')
        o.base = '/srv/vcfhe/' + o.config['campaign']
        o.identities = safe._read(original / 'distributed/public-identities.json')
        o.datasets = safe._read(original / 'distributed/controller-inputs.json')['datasets']
        o.exits = copy.deepcopy(report['participantExits'])
        o.parent = report['parent']
        o.reconciliation = safe._private(reconciliation or self.journal.with_name('monitor-reconciliation.local.json'))
        reconciliation_record = safe._read(o.reconciliation)
        if (reconciliation_record.get('pid') != o.parent['pid']
                or reconciliation_record.get('status') != 'controller-suspended-before-cleanup'):
            raise ValueError('Original suspended parent reconciliation changed')
        o.reconciliation_sha = safe._sha(o.reconciliation)
        o.remotes = {h['id']: observed.ReadOnlyRemote(o, h) for h in o.plan['hosts']}
        o.report, o.errors = report, report.get('monitoringErrors', 0)
        self.copy_roots = ['compose', 'validator-config', 'network', 'dataset-transfer',
                           'distributed/source.json', 'distributed/budget.json', 'distributed/quote.json',
                           'distributed/public-identities.json',
                           'distributed/controller-inputs.json']
        self.descriptors = {}
        for name in self.copy_roots + ['participant-config/coordinator-1/campaign.json']:
            source = original / name
            files = source.rglob('*') if source.is_dir() else [source]
            for path in files:
                if path.is_symlink():
                    raise ValueError('Original descriptor contains a symlink')
                if path.is_file():
                    self.descriptors[str(path.relative_to(original))] = safe._sha(path)
        self.report = {'schema': 'vcfhe-derived-collection-v1', 'status': 'prepared', 'originalRun': str(original),
                       'originalLaunchStatus': 'failed', 'observationSha256': self.observation_sha,
                       'collectorSourceSha256': safe._sha(__file__), 'originalDescriptors': self.descriptors,
                       'originalCollectorSha256': o.record['distributedSource']['collect.py'],
                       'protocolActionsStartedOrRetried': [], 'evaluationPublishable': False}
        self.guard()

    def guard(self):
        self.observer.guard()
        if safe._sha(self.observation_path) != self.observation_sha:
            raise ValueError('Validated zero-exit observation changed')
        if any(safe._sha(self.observer.original / name) != value for name, value in self.descriptors.items()):
            raise ValueError('Original descriptor changed during derived collection')

    def save(self):
        safe._write(self.output / 'derived-collection.local.json', self.report)

    def collect(self):
        self.guard()
        # Re-read the already completed applications. Never touch a start marker
        # or call any participant task/transaction/release endpoint.
        for node in ['coordinator-1', 'recipient-1']:
            remote = self.observer.remotes[self.observer.nodes[node]['host']]
            row = remote.json(['sudo', 'cat', self.observer.nodes[node]['state_directory'] + '/reports/participant-exit.json'])
            if row != self.observer.exits[node]:
                raise observed.ProtocolFailure('Application exit record changed after observation')
        self.report['status'] = 'collecting-original-evidence'
        self.save()
        try:
            for name in self.copy_roots:
                copy_exact(self.observer.original / name, self.output / name)
            for name, digest in self.descriptors.items():
                if name.startswith('participant-config/'):
                    continue
                if safe._sha(self.output / name) != digest:
                    raise ValueError('Derived descriptor copy differs from original')
            campaign = self.observer.campaign()
            campaign.remotes = {h['id']: CollectionRemote(self, h) for h in self.observer.plan['hosts']}
            # The unchanged A9 collector performs its original validations and
            # creates a seal only for this separate derived directory.
            spec = importlib.util.spec_from_file_location('original_a9_collector', HERE / 'collect.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.collect(campaign)
            self.guard()
            if safe._sha(self.output / 'config/campaign.json') != self.descriptors['participant-config/coordinator-1/campaign.json']:
                raise ValueError('Exported campaign configuration differs from the original statement')
            cfg = safe._read(self.output / 'config/campaign.json')
            if cfg.get('runId') != self.observer.original.name or not cfg.get('smoke'):
                raise ValueError('Derived export changed the original run identifier or scope')
            if (safe._read(self.output / 'state.json').get('stages') != self.observer.state['stages']
                    or safe._read(self.observer.original / 'launch-state.json') != self.observer.state):
                raise ValueError('Original failed stages or launcher state were changed')
            original_runner = deployment.campaign_module()
            original_runner.verify(self.output)
            if safe._read(self.output / 'distributed/smoke-result.json').get('status') != 'passed':
                raise ValueError('Original smoke validation did not pass')
            self.report.update(status='derived-data-validated', originalLaunchRecordUnchanged=True,
                               originalStagesPreserved=True, sealSha256=safe._sha(self.output / 'seal.json'),
                               validatedAt=datetime.now(timezone.utc).isoformat(),
                               scope='Validated original remote protocol data after controller-only observation failure. Original launcher remains failed.')
            self.save()
            return self.report
        except BaseException as error:
            self.report.update(status='failed-derived-collection', errorType=type(error).__name__, error=str(error))
            self.save()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--journal', required=True)
    parser.add_argument('--reconciliation')
    args = parser.parse_args()
    import cloud_tools
    cloud_tools.ensure()
    result = Collector(args.output, args.journal, args.reconciliation).collect()
    print(json.dumps({'status': result['status'], 'originalLaunchStatus': 'failed', 'evaluationPublishable': False}, indent=2))


if __name__ == '__main__':
    main()
