"""Describe the measured setup from sealed evidence, never from this computer."""
import json
from pathlib import Path
import re
from single_run import sealed_reader
from verify_composite import read, require, sha

JSON_NAME = 'setup-review.json'
TEXT_NAME = 'setup-review.md'


def measured_disclosure(cfg, app):
    """Count authenticated leaf events in sealed, successful relay receipts.

    The requested batch size is not necessarily the size used by the client.
    Keep that configuration separate from the largest batch actually measured.
    """
    requested = cfg.get('disclosureBatchSize')
    require(type(requested) is int and 1 <= requested <= 64, 'invalid configured disclosure batch')
    topic = '0x4f06e2771c770611ac4e425d815922b2bf8b3693fdbd5e5262fcb7190d360ff6'
    # DisputedTraceLeafPublished(bytes32,uint32,bytes32,bytes32,bytes32,bytes32)
    tasks = {}
    for case in app['cases']:
        if case['half'] == 'linear':
            continue
        m = case['metrics']
        require(m.get('nonlinearProtocol') == 'bounty-v2' and len(m['disputes']) == 1,
                'incomplete measured bounty case')
        b = m['disputes'][0]['settlement']['bounty']
        key = (b['availability'].lower(), b['taskId'].lower())
        require(key not in tasks, 'duplicate measured disclosure task')
        tasks[key] = dict(leaves=m['leaves'], indices=set())
    require(tasks, 'no measured disclosure tasks')
    counts, hashes = [], set()
    for receipt in app['receipts']:
        if receipt['label'] != 'publishAuthenticatedTraceBatch':
            continue
        tx = receipt.get('txHash', receipt.get('hash'))
        require(tx and tx not in hashes and receipt['status'] == 1, 'invalid disclosure receipt')
        hashes.add(tx)
        leaves = [log for log in receipt['logs'] if log['topics'] and log['topics'][0].lower() == topic]
        require(0 < len(leaves) <= requested, 'invalid measured disclosure size')
        keys = set()
        for log in leaves:
            require(len(log['topics']) == 3, 'invalid disclosure leaf event')
            key = (log['address'].lower(), log['topics'][1].lower())
            require(key in tasks and receipt['to'].lower() == key[0], 'unbound disclosure event')
            index = int(log['topics'][2], 16)
            row = tasks[key]
            require(0 <= index < row['leaves'] and index not in row['indices'],
                    'duplicate or out-of-range disclosure leaf')
            row['indices'].add(index)
            keys.add(key)
        require(len(keys) == 1, 'mixed disclosure tasks in one batch')
        counts.append(len(leaves))
    require(counts and all(len(row['indices']) == row['leaves'] for row in tasks.values()),
            'incomplete measured disclosure coverage')
    return dict(configuredBatchSize=requested, measuredMaximumBatchSize=max(counts),
                batchCount=len(counts), publishedLeaves=sum(counts), taskCount=len(tasks),
                batchSizeCounts={str(n):counts.count(n) for n in sorted(set(counts))},
                eventTopic=topic, method='authenticated leaf events per sealed successful relay receipt')


def build(base):
    provenance = read(base/'provenance.json')
    require(provenance.get('kind') == 'single-complete-run', 'setup review requires single-run evidence')
    run = Path(provenance['run'])
    sealed = sealed_reader(run)
    state, cfg = sealed('state.json'), sealed('config/campaign.json')
    require(sha(run/'state.json') == provenance['stateSha256'] and state['config'] == cfg,
            'setup state/configuration differs from provenance')
    host = state.get('hostEnvironment')
    distributed=provenance.get('distributedExecution')
    if distributed is not None:
        from distributed_evidence import validate as validate_distributed
        require(validate_distributed(run,sealed)==distributed,'distributed setup differs from validated execution')
    if host is not None:
        require(host.get('schema') == 'launcher-host-environment-v1'
                and host.get('scope') == 'launcher-host-not-docker-daemon', 'unknown host metadata scope')
    disclosure = None
    if cfg['half'] != 'linear' and cfg.get('nonlinearProtocol') == 'bounty-v2':
        disclosure = measured_disclosure(cfg, sealed('reports/application.json'))
    return dict(schema='measured-setup-review-v1',
                provenanceSha256=sha(base/'provenance.json'), stateSha256=sha(run/'state.json'),
                configurationSha256=sha(run/'config/campaign.json'), scriptSha256=sha(Path(__file__)),
                half=cfg['half'], hostEnvironment=host,
                **({'distributedExecution':distributed} if distributed is not None else {}),
                hostMetadataStatus='recorded' if host is not None else 'unavailable in this historical run',
                dockerResources=state.get('resources', {}),
                measuredPairs=provenance['measuredPairs'], warmups=provenance['warmups'],
                fullCases=provenance['fullCases'],
                windowSeconds=cfg.get('windowSeconds'),
                configuredDisclosureBatchSize=cfg.get('disclosureBatchSize'),
                disclosureBatchSize=disclosure['measuredMaximumBatchSize'] if disclosure else cfg.get('disclosureBatchSize'),
                disclosureBatchEvidence=disclosure,
                kmsRayonThreads=cfg.get('kmsRayonThreads'), kmsTokioThreads=cfg.get('kmsTokioThreads'),
                nonlinearProtocol=cfg.get('nonlinearProtocol', 'canonical'),
                nonlinearSchedulingVersion=cfg.get('nonlinearSchedulingVersion'),
                keysetScope='one campaign keyset for the selected half or halves',
                otherHalfSetup='unchanged and not established by this run' if cfg['half'] != 'both' else None)


def display(value):
    return 'not recorded' if value is None else str(value)


def render(report):
    if report.get('distributedExecution'):
        d=report['distributedExecution']
        rows=['# Setup recorded for this distributed campaign','',
            f"{report['measuredPairs']} measured pairs, {report['warmups']} warm-ups and {report['fullCases']} full workflows.",
            'Four hosts in four regions. Roles are co-located under common administration.',
            '| Host | Region | Machine type |','|---|---|---|']
        rows += [f"| {h['id']} | {h['region']} | {h['machine_type']} |" for h in d['hosts']]
        rows += ['',f"Phase window: {report['windowSeconds']} seconds. Maximum measured disclosure batch: {report['disclosureBatchSize']} leaves.",
            'Paired request-response durations include public transfers and participant processing. Native FHE CPU is reported separately.',
            'Two baseline participants execute on separate hosts. The old serialized one-host baseline is not substituted.',
            'Raw participant, host, transfer and authorization evidence is retained with the distributed seal.']
        return '\n'.join(rows)+'\n'
    host, docker = report['hostEnvironment'] or {}, report['dockerResources']
    lines = ['# Setup recorded for this campaign',
             f"Selected scope: **{report['half']}**. Counts: {report['measuredPairs']} measured pairs, "
             f"{report['warmups']} warm-ups and {report['fullCases']} full cases.",
             'The values below come from the sealed run. They are not observations of the computer generating this report.',
             '| Field | Recorded value |', '|---|---|',
             f"| Launcher CPU model | {display(host.get('cpuModel'))} |",
             f"| Launcher logical CPUs | {display(host.get('logicalCpuCount'))} |",
             f"| Launcher OS-visible memory (bytes) | {display(host.get('osVisibleMemoryBytes'))} |",
             f"| Launcher OS / release | {display(host.get('operatingSystem'))} / {display(host.get('operatingSystemRelease'))} |",
             f"| Launcher architecture | {display(host.get('architecture'))} |",
             f"| Docker CPUs | {display(docker.get('NCPU'))} |",
             f"| Docker memory (bytes) | {display(docker.get('MemTotal'))} |",
             f"| Docker OS / architecture | {display(docker.get('OperatingSystem'))} / {display(docker.get('Architecture'))} |",
             f"| Phase window (seconds) | {display(report['windowSeconds'])} |",
             f"| Configured leaves per disclosure batch | {display(report['configuredDisclosureBatchSize'])} |",
             f"| Maximum leaves per measured disclosure batch | {display(report['disclosureBatchSize'])} |",
             f"| KMS Rayon / Tokio workers per core | {display(report['kmsRayonThreads'])} / {display(report['kmsTokioThreads'])} |",
             f"| Non-linear protocol | {display(report['nonlinearProtocol']) if report['half'] != 'linear' else 'not used'} |",
             f"| Non-linear scheduling | {display(report['nonlinearSchedulingVersion']) if report['half'] != 'linear' else 'not used'} |",
             '', 'Launcher hardware and Docker limits are different quantities. With a remote Docker daemon, '
             'launcher hardware does not identify the machine executing the experiments. '
             'Missing fields remain unavailable and must not be replaced with the prior implementation hardware.']
    if report['half'] != 'both':
        lines.append('Only this selected half is measured here. Retain or explicitly distinguish the other half\'s '
                     'hardware, keyset and measurements in the implementation. Separate campaigns do not share a keyset by implication.')
    return '\n'.join(lines)+'\n'


def ensure(base):
    report = build(base)
    expected = {JSON_NAME:json.dumps(report, indent=2)+'\n', TEXT_NAME:render(report)}
    for name, content in expected.items():
        target = base/name
        if target.exists():
            require(target.read_text() == content, 'changed setup review: '+name)
        else:
            target.write_text(content)
    return report


def validate(base):
    report = build(base)
    require(read(base/JSON_NAME) == report and (base/TEXT_NAME).read_text() == render(report),
            'setup review differs from sealed measurement evidence')
    return report


