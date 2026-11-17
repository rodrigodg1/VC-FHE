"""Smoke teardown tests. All cloud, SSH and private-state reads are synthetic."""
import copy
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import gcp
import smoke_cleanup as cleanup
import topology


class SmokeCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.run = self.root / 'original-smoke-run'
        self.run.mkdir(mode=0o700)
        self.config = json.loads((HERE / 'config.example.json').read_text())
        self.config.update(project_id='example-research-project', campaign='vcfhe-test-smoke',
                           execution_mode='smoke', operator_principal='user:operator@example.test')
        self.config.update(getattr(self, 'config_overrides', {}))
        self.generated = gcp.terraform(self.config)
        (self.run / 'terraform').mkdir()
        self.put('distributed-config.json', self.config)
        self.put('launch-state.json', {'config': self.config, 'status': 'completed'})
        self.put('distributed/smoke-result.json', {'status': 'passed', 'classification': 'smoke-not-evaluation'})
        self.put('terraform/main.tf.json', self.generated)
        self.put('terraform/terraform.tfvars.json', {'project_id': self.config['project_id']})
        self.rows = []
        self.live = {}
        self.mutations = []
        self.project = self.config['project_id']
        self.base = 'https://www.googleapis.com/compute/v1/projects/' + self.project
        self.physical = topology.hosts(self.config)
        self.values = {}
        # Resolve the exact generated Terraform references, as a provider does.
        for kind, entries in self.generated['resource'].items():
            for name, original in entries.items():
                value = {k: copy.deepcopy(v) for k, v in original.items()
                         if k not in {'lifecycle', 'depends_on', 'metadata_startup_script'}}
                value['project'] = self.project
                if kind == 'google_service_account':
                    value['email'] = value['account_id'] + '@' + self.project + '.iam.gserviceaccount.com'
                    value['unique_id'] = str(9000 + len(self.values))
                    value['name'] = 'projects/' + self.project + '/serviceAccounts/' + value['email']
                    value['id'] = value['name']
                elif kind.startswith('google_compute_') and not kind.endswith('_iam_member'):
                    scope = '/zones/' + value['zone'] if 'zone' in value else '/regions/' + value['region'] if 'region' in value else '/global'
                    group = {'google_compute_instance': 'instances', 'google_compute_disk': 'disks',
                             'google_compute_network': 'networks', 'google_compute_subnetwork': 'subnetworks',
                             'google_compute_router': 'routers', 'google_compute_router_nat': 'nats',
                             'google_compute_firewall': 'firewalls'}[kind]
                    value['self_link'] = self.base + scope + '/' + group + '/' + value['name']
                    value['id'] = value['self_link'].split('/compute/v1/')[1]
                    if kind == 'google_compute_instance':
                        value['instance_id'] = str(1000 + len(self.values))
                    elif kind == 'google_compute_disk':
                        value['disk_id'] = str(2000 + len(self.values))
                else:
                    value['id'] = kind + '.' + name
                self.values[kind + '.' + name] = value
        def resolve(item):
            if isinstance(item, dict):
                return {k: resolve(v) for k, v in item.items()}
            if isinstance(item, list):
                return [resolve(v) for v in item]
            if isinstance(item, str) and '${' in item:
                for address, value in self.values.items():
                    for key, replacement in value.items():
                        if isinstance(replacement, str) and '${' not in replacement:
                            item = item.replace('${' + address + '.' + key + '}', replacement)
            return item
        self.values = {key: resolve(value) for key, value in self.values.items()}
        for address, value in self.values.items():
            kind, name = address.split('.')
            self.rows.append({'mode': 'managed', 'type': kind, 'name': name,
                              'instances': [{'attributes': value}]})
            row = {'type': kind, 'attributes': value}
            args = cleanup._describe_args(row)
            if args is None:
                continue
            live = {'name': value['name'], 'id': str(3000 + len(self.live))}
            if 'self_link' in value:
                live['selfLink'] = value['self_link']
            if kind == 'google_service_account':
                live.update(email=value['email'], uniqueId=value['unique_id'])
            if kind == 'google_compute_instance':
                host = next(h for h in self.physical if h['id'].replace('-', '_') == name)
                live.update(id=value['instance_id'], status='RUNNING', labels={'experiment': self.config['campaign']},
                            metadata={'items': [{'key': 'vcfhe-campaign', 'value': self.config['campaign']},
                                                {'key': 'vcfhe-host', 'value': host['id']}]},
                            disks=[{'boot': True, 'source': self.base + '/zones/' + host['zone'] + '/disks/' + host['name']},
                                   {'boot': False, 'deviceName': 'vcfhe-state', 'source': self.base + '/zones/' + host['zone'] + '/disks/' + host['name'] + '-state'}])
                self.live[('compute', 'disks', 'describe', host['name'], '--zone', host['zone'])] = {
                    'name': host['name'], 'id': 'boot-' + name,
                    'selfLink': live['disks'][0]['source'], 'users': [live['selfLink']]}
            elif kind == 'google_compute_disk':
                host = next(h for h in self.physical if h['id'].replace('-', '_') == name)
                live.update(id=value['disk_id'], users=[self.base + '/zones/' + host['zone'] + '/instances/' + host['name']])
            self.live[tuple(args)] = live
        self.put('terraform/terraform.tfstate', {'serial': 1, 'lineage': 'synthetic-only', 'resources': self.rows})

    def put(self, name, value):
        path = self.run / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def cloud(self, args, missing=False):
        args = list(args)
        for flag in ['--project', '--member', '--role']:
            if flag in args:
                i = args.index(flag)
                del args[i:i + 2]
        args = [v for v in args if v not in {'--quiet', '--condition=None'}]
        if args[:2] == ['projects', 'describe']:
            return {'projectId': self.project, 'projectNumber': '123456789'}
        if 'get-iam-policy' in args:
            return {'bindings': []}
        if 'describe' in args:
            value = self.live.get(tuple(args))
            if value is None and not missing:
                raise AssertionError('Unexpected absent synthetic resource: ' + str(args))
            return copy.deepcopy(value)
        if 'update' in args or 'stop' in args:
            self.mutations.append(args)
            updated = ['describe' if x in {'update', 'stop'} else x for x in args if x != '--no-deletion-protection']
            if 'stop' in args:
                self.live[tuple(updated)]['status'] = 'TERMINATED'
            return {}
        if 'delete' in args:
            self.mutations.append(args)
            key = tuple('describe' if x == 'delete' else x for x in args if x != '--keep-disks=all')
            self.live.pop(key, None)
            return {}
        if 'remove-iam-policy-binding' in args:
            self.mutations.append(args)
            return {}
        raise AssertionError('Unexpected synthetic cloud request: ' + str(args))

    def remote_factory(self, config, host):
        test = self
        class FakeRemote:
            def text(self, args):
                if 'cat' in args:
                    return config['campaign'] + '/' + host['id']
                if 'du' in args:
                    return '4096 /srv/vcfhe'
                if 'docker' in args:
                    return ''
                raise AssertionError(args)
            def run(self, args, **kwargs):
                if 'tar' in args:
                    with tarfile.open(fileobj=kwargs['stdout'], mode='w') as archive:
                        data = {'.': None, './scope.txt': config['campaign'] + '/' + host['id'] + '\n'}
                        for role in host['roles']:
                            for name in ['private/kms-share', 'identity/key', 'chain/ledger',
                                         'policy-state/counters', 'recipient/session']:
                                data['./' + config['campaign'] + '/' + role + '/' + name] = 'synthetic-private-state'
                        for name, value in data.items():
                            member = tarfile.TarInfo(name)
                            if value is None:
                                member.type = tarfile.DIRTYPE
                                archive.addfile(member)
                            else:
                                content = value.encode()
                                member.size = len(content)
                                archive.addfile(member, io.BytesIO(content))
                return subprocess.CompletedProcess(args, 0)
        return FakeRemote()

    def make_backup(self):
        destination = self.run / 'private-smoke-backup'
        with patch.object(cleanup, '_cloud', side_effect=self.cloud), patch.object(cleanup, 'Remote', side_effect=self.remote_factory):
            cleanup.backup(self.config, self.run, destination)
        return destination

    def test_plan_is_read_only_and_keeps_shared_registry(self):
        with patch.object(cleanup, '_cloud', side_effect=self.cloud):
            plan = cleanup.inspect_plan(self.config, self.run)
        self.assertEqual(len([r for r in plan['resources'] if r['type'] == 'google_compute_instance']), 4)
        self.assertIn('shared-image-repository', plan['preserved'])
        self.assertFalse(self.mutations)

    def test_evaluation_run_and_wrong_config_cannot_be_cleaned(self):
        for field, value in [('execution_mode', 'evaluation'), ('campaign', 'evaluation-campaign')]:
            changed = dict(self.config, **{field: value})
            with patch.object(cleanup, '_cloud') as cloud:
                with self.assertRaises(ValueError):
                    cleanup.inspect_plan(changed, self.run)
                cloud.assert_not_called()

    def test_partial_or_foreign_terraform_scope_is_refused(self):
        for rows in [self.rows[:-1], self.rows + [{'mode': 'managed', 'type': 'google_storage_bucket', 'name': 'foreign', 'instances': [{}]}]]:
            self.put('terraform/terraform.tfstate', {'resources': rows})
            with patch.object(cleanup, '_cloud') as cloud:
                with self.assertRaises(ValueError):
                    cleanup.inspect_plan(self.config, self.run)
                cloud.assert_not_called()

    def test_replaced_vm_and_foreign_disk_are_refused(self):
        name = self.physical[0]['name']
        key = ('compute', 'instances', 'describe', name, '--zone', self.physical[0]['zone'])
        original = copy.deepcopy(self.live[key])
        self.live[key]['id'] = 'replaced'
        with patch.object(cleanup, '_cloud', side_effect=self.cloud):
            with self.assertRaisesRegex(ValueError, 'replaced'):
                cleanup.inspect_plan(self.config, self.run)
            self.live[key] = original
            self.live[key]['disks'][0]['source'] += '-foreign'
            with self.assertRaisesRegex(ValueError, 'foreign'):
                cleanup.inspect_plan(self.config, self.run)

    def test_backup_preserves_all_private_roles_and_separate_original_evidence(self):
        destination = self.make_backup()
        manifest = cleanup.verify_backup(destination)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        self.assertEqual(set(manifest['archives']), {'host-1', 'host-2', 'host-3', 'host-4'})
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in destination.iterdir()))
        with tarfile.open(destination / 'host-1-private-state.tar') as archive:
            names = archive.getnames()
        self.assertTrue(any('/kms-1/private/kms-share' in n for n in names))
        self.assertTrue(any('/owner-1/identity/key' in n for n in names))
        with tarfile.open(destination / 'original-run-evidence.tar') as archive:
            names = archive.getnames()
        self.assertIn('distributed/smoke-result.json', names)
        self.assertFalse(any(n.startswith('private-smoke-backup/') for n in names))
        self.assertFalse(self.mutations)

    def test_archive_path_traversal_links_devices_and_duplicate_names_are_refused(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
                           ('foreign-data/file', tarfile.REGTYPE), ('./scope.txt', tarfile.SYMTYPE),
                           ('./scope.txt', tarfile.LNKTYPE), ('./scope.txt', tarfile.CHRTYPE)]:
            with self.subTest(name=name, kind=kind):
                file = self.root / 'unsafe.tar'
                with tarfile.open(file, 'w') as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    archive.addfile(member, io.BytesIO())
                with self.assertRaises(ValueError):
                    cleanup._archive_info(file, self.config['campaign'])

    def test_changed_private_archive_prevents_all_removal(self):
        destination = self.make_backup()
        with (destination / 'host-1-private-state.tar').open('ab') as output:
            output.write(b'changed')
        with patch.object(cleanup, '_cloud') as cloud:
            with self.assertRaises(ValueError):
                cleanup.apply(self.config, self.run, destination)
            cloud.assert_not_called()

    def test_missing_backup_cannot_disable_deletion_protection(self):
        with patch.object(cleanup, '_cloud') as cloud:
            with self.assertRaises((ValueError, FileNotFoundError)):
                cleanup.apply(self.config, self.run, self.root / 'missing-private-backup')
            cloud.assert_not_called()

    def test_changed_state_after_backup_prevents_removal(self):
        destination = self.make_backup()
        self.put('terraform/terraform.tfstate', {'serial': 2, 'resources': self.rows})
        with patch.object(cleanup, '_cloud') as cloud:
            with self.assertRaisesRegex(ValueError, 'unchanged'):
                cleanup.apply(self.config, self.run, destination)
            cloud.assert_not_called()

    def test_removal_is_exact_and_tolerates_nat_already_removed_by_stop(self):
        destination = self.make_backup()
        for key in list(self.live):
            if key[:4] == ('compute', 'routers', 'nats', 'describe'):
                del self.live[key]
        with patch.object(cleanup, '_cloud', side_effect=self.cloud), patch.object(cleanup, '_remove_iap') as iap:
            result = cleanup.apply(self.config, self.run, destination)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(iap.call_count, 4)
        self.assertFalse(self.live)
        commands = [' '.join(args) for args in self.mutations]
        self.assertEqual(sum('--no-deletion-protection' in c for c in commands), 4)
        self.assertEqual(sum('--keep-disks=all' in c for c in commands), 4)
        self.assertFalse(any('artifacts repositories delete' in c or 'storage' in c for c in commands))
        self.assertTrue((self.run / 'terraform/terraform.tfstate').is_file())
        cleanup.verify_backup(destination)

    def test_replacement_after_backup_prevents_any_deletion(self):
        destination = self.make_backup()
        key = next(k for k in self.live if k[:3] == ('compute', 'instances', 'describe'))
        self.live[key]['id'] = 'different-live-id'
        with patch.object(cleanup, '_cloud', side_effect=self.cloud):
            with self.assertRaisesRegex(ValueError, 'replaced'):
                cleanup.apply(self.config, self.run, destination)
        self.assertFalse(self.mutations)

    def test_backup_never_silently_restarts_stopped_vms(self):
        key = next(k for k in self.live if k[:3] == ('compute', 'instances', 'describe'))
        self.live[key]['status'] = 'TERMINATED'
        with patch.object(cleanup, '_cloud', side_effect=self.cloud), patch.object(cleanup, 'Remote') as remote:
            with self.assertRaisesRegex(ValueError, 'will not restart'):
                cleanup.backup(self.config, self.run, self.root / 'backup')
            remote.assert_not_called()

    def test_permission_ambiguity_is_never_absence(self):
        cases = [('ERROR: NOT_FOUND: absent', True),
                 ("ERROR: The resource 'projects/example/zones/zone/instances/smoke' was not found", True),
                 ('ERROR: PERMISSION_DENIED: NOT_FOUND', False),
                 ('ERROR: not found or no permission', False),
                 ('Connection timed out', False)]
        for message, absent in cases:
            with self.subTest(message=message), patch.object(cleanup.subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], 1, '', message)):
                if absent:
                    self.assertIsNone(cleanup._cloud(['synthetic-read-only'], missing=True))
                else:
                    with self.assertRaises(ValueError):
                        cleanup._cloud(['synthetic-read-only'], missing=True)

    def test_failed_smoke_requires_explicit_inspection_flag(self):
        self.put('launch-state.json', {'config': self.config, 'status': 'failed'})
        with patch.object(cleanup, '_cloud', side_effect=self.cloud):
            with self.assertRaises(ValueError):
                cleanup.inspect_plan(self.config, self.run)
            self.assertEqual(cleanup.inspect_plan(self.config, self.run, allow_failed=True)['campaign'], self.config['campaign'])

    def test_deleted_service_account_absence_uses_authorized_complete_inventory(self):
        email = 'owned@' + self.project + '.iam.gserviceaccount.com'
        args = ['iam', 'service-accounts', 'describe', email, '--project', self.project]
        with patch.object(cleanup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '[]', '')) as command:
            self.assertIsNone(cleanup._cloud(args, missing=True))
            self.assertEqual(command.call_args.args[0], ['gcloud', 'iam', 'service-accounts', 'list', '--project', self.project, '--format=json'])
        for error in ['PERMISSION_DENIED: resource may not exist', 'NOT_FOUND: project absent']:
            with patch.object(cleanup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', error)):
                with self.assertRaises(ValueError):
                    cleanup._cloud(args, missing=True)

    def test_service_account_inventory_retains_unique_id_and_refuses_partial_identity(self):
        email = 'owned@' + self.project + '.iam.gserviceaccount.com'
        args = ['iam', 'service-accounts', 'describe', email, '--project', self.project]
        account = {'email': email, 'name': 'projects/' + self.project + '/serviceAccounts/' + email, 'uniqueId': '123456789'}
        with patch.object(cleanup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps([account]), '')):
            self.assertEqual(cleanup._cloud(args, missing=True), account)
        for value in [{}, [{'email': email}], [account, account]]:
            with patch.object(cleanup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(value), '')):
                with self.assertRaises(ValueError):
                    cleanup._cloud(args, missing=True)
        with patch.object(cleanup.subprocess, 'run') as command:
            with self.assertRaises(ValueError):
                cleanup._cloud(['iam', 'service-accounts', 'describe', 'foreign@other-project.iam.gserviceaccount.com', '--project', self.project], missing=True)
            command.assert_not_called()

    def test_cleanup_retry_requires_passed_result_and_verified_original_backup(self):
        destination = self.make_backup()
        self.put('launch-state.json', {'config': self.config, 'status': 'smoke-complete-cleanup-failed'})
        self.live.clear()
        with patch.object(cleanup, '_cloud', side_effect=self.cloud), patch.object(cleanup, '_remove_iap'):
            self.assertEqual(cleanup.apply(self.config, self.run, destination)['status'], 'passed')
        self.assertFalse(self.mutations)
        with patch.object(cleanup, '_cloud') as cloud:
            with self.assertRaises(ValueError):
                cleanup.inspect_plan(self.config, self.run)
            with self.assertRaises(ValueError):
                cleanup.backup(self.config, self.run, self.root / 'replacement-backup')
            cloud.assert_not_called()

    def test_cleanup_retry_refuses_failed_result_missing_backup_and_changed_live_id(self):
        destination = self.make_backup()
        self.put('launch-state.json', {'config': self.config, 'status': 'smoke-complete-cleanup-failed'})
        self.put('distributed/smoke-result.json', {'status': 'failed'})
        with patch.object(cleanup, '_cloud') as cloud:
            with self.assertRaises(ValueError):
                cleanup.apply(self.config, self.run, destination)
            cloud.assert_not_called()
        self.put('distributed/smoke-result.json', {'status': 'passed'})
        with patch.object(cleanup, '_cloud') as cloud:
            with self.assertRaises((ValueError, FileNotFoundError)):
                cleanup.apply(self.config, self.run, self.root / 'missing-backup')
            cloud.assert_not_called()
        key = next(k for k in self.live if k[:3] == ('compute', 'instances', 'describe'))
        self.live[key]['id'] = 'replaced-after-backup'
        with patch.object(cleanup, '_cloud', side_effect=self.cloud):
            with self.assertRaisesRegex(ValueError, 'replaced'):
                cleanup.apply(self.config, self.run, destination)
        self.assertFalse(self.mutations)

    def test_cleanup_retry_does_not_accept_other_launch_statuses(self):
        destination = self.make_backup()
        for status in ['prepared', 'running', 'failed', 'cleanup-failed']:
            self.put('launch-state.json', {'config': self.config, 'status': status})
            with patch.object(cleanup, '_cloud') as cloud:
                with self.assertRaises(ValueError):
                    cleanup.apply(self.config, self.run, destination)
                cloud.assert_not_called()

    def test_registry_iam_uses_bound_registry_location_when_first_host_moves(self):
        config=copy.deepcopy(self.config)
        config['registry_region']='us-central1'
        config['regions'][0].update(name='us-east1',zone='us-east1-b')
        resources=[{'type':r['type'],'key':r['name'],'attributes':r['instances'][0]['attributes']} for r in self.rows]
        row=copy.deepcopy(next(r for r in resources if r['type']=='google_artifact_registry_repository_iam_member' and r['key']=='host_1'))
        member=row['attributes']['member']
        policy={'bindings':[{'role':'roles/artifactregistry.reader','members':[member]}]}
        with patch.object(cleanup,'_cloud',side_effect=[policy,{}]) as command:
            cleanup._remove_iam(config,row,resources)
        self.assertEqual(command.call_count,2)
        for call in command.call_args_list:
            args=call.args[0]
            self.assertEqual(args[args.index('--location')+1],'us-central1')
            self.assertNotIn('delete',args)
        row['attributes']['location']='us-east1'
        with patch.object(cleanup,'_cloud') as command:
            with self.assertRaises(ValueError):cleanup._remove_iam(config,row,resources)
            command.assert_not_called()

    def test_iap_removes_only_exact_unconditional_member_without_logging_token(self):
        policy = {'etag': 'synthetic-etag', 'version': 3, 'bindings': [
            {'role': 'roles/iap.tunnelResourceAccessor', 'members': ['user:operator@example.test', 'user:other@example.test']},
            {'role': 'roles/iap.tunnelResourceAccessor', 'members': ['user:operator@example.test'], 'condition': {'title': 'preserve'}}]}
        requests = []
        class Response(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *args): self.close()
        def open_url(request, **kwargs):
            requests.append(request)
            return Response(json.dumps(policy if request.full_url.endswith(':getIamPolicy') else {}).encode())
        with patch.object(cleanup, '_cloud', return_value={'projectId': self.project, 'projectNumber': '123456789'}), \
             patch.object(cleanup.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'synthetic-short-lived-token\n', '')), \
             patch.object(cleanup.urllib.request, 'urlopen', side_effect=open_url):
            cleanup._remove_iap(self.config, self.physical[0], {'id': '12345'}, 'user:operator@example.test', 'roles/iap.tunnelResourceAccessor')
        self.assertEqual(len(requests), 2)
        changed = json.loads(requests[1].data)['policy']
        self.assertEqual(changed['bindings'][0]['members'], ['user:other@example.test'])
        self.assertEqual(changed['bindings'][1], policy['bindings'][1])
        self.assertEqual(changed['etag'], 'synthetic-etag')
        self.assertFalse(list(self.root.glob('**/*token*')))


if __name__ == '__main__':
    unittest.main()
