"""Temporary synthetic SDKs only. Never run gcloud or read real credentials."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import stat
import string
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import prepare_patch
import sdk_invocation as candidate

HERE=Path(__file__).resolve().parent
SOURCE=HERE.parents[1]


class SdkInvocationProposalTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix='vcfhe-sdk-proposal-')
        self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name).resolve()
        self.aliases=self.root/'ascii-aliases'

    def sdk(self,name):
        root=self.root/name; (root/'bin').mkdir(parents=True);(root/'lib').mkdir()
        (root/'lib/gcloud.py').write_text('# synthetic SDK, never a real cloud call\n')
        executable=root/'bin/gcloud';executable.write_text('#!/bin/sh\nexit 0\n');executable.chmod(0o755)
        return executable

    def test_ascii_space_and_ascii_apostrophe_paths_preserved(self):
        for name in ['plain-sdk','SDK with spaces',"SDK user's path"]:
            with self.subTest(name=name):
                sdk=self.sdk(name)
                self.assertEqual(candidate.safe_sdk_invocation(sdk,alias_directory=self.aliases),str(sdk))
                self.assertFalse(self.aliases.exists())

    def test_unicode_apostrophe_uses_directory_alias_and_exact_sdk_identity(self):
        sdk=self.sdk('Rodrigo\u2019s moved SDK')
        before={str(p.relative_to(sdk.parent.parent)):hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sdk.parent.parent.rglob('*') if p.is_file()}
        result=Path(candidate.safe_sdk_invocation(sdk,alias_directory=self.aliases))
        self.assertTrue(candidate.proxy_safe(str(result)))
        self.assertTrue(result.parent.parent.is_symlink())
        self.assertFalse(result.is_symlink())
        self.assertEqual(result.resolve(),sdk.resolve())
        self.assertEqual(stat.S_IMODE(self.aliases.stat().st_mode),0o700)
        self.assertEqual(candidate.safe_sdk_invocation(sdk,alias_directory=self.aliases),str(result))
        after={str(p.relative_to(sdk.parent.parent)):hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sdk.parent.parent.rglob('*') if p.is_file()}
        self.assertEqual(before,after)

    def test_existing_safe_logical_ancestor_is_preserved(self):
        sdk=self.sdk('SDK\u2019s physical home')
        logical=self.root/'logical-workspace';logical.symlink_to(sdk.parent.parent,target_is_directory=True)
        expected=logical/'bin/gcloud'
        self.assertEqual(candidate.safe_sdk_invocation(expected,alias_directory=self.aliases),str(expected))
        self.assertFalse(self.aliases.exists())

    def test_direct_executable_symlink_cannot_hide_unsafe_target(self):
        sdk=self.sdk('SDK\u2019s physical home')
        link=self.root/'gcloud';link.symlink_to(sdk)
        result=Path(candidate.safe_sdk_invocation(link,alias_directory=self.aliases))
        self.assertNotEqual(result,link);self.assertEqual(result.resolve(),sdk.resolve())
        self.assertTrue(candidate.proxy_safe(str(result)))

    def test_conflicting_stale_and_foreign_aliases_preserved(self):
        sdk=self.sdk('SDK\u2019s physical home')
        name='google-cloud-sdk-'+hashlib.sha256(str(sdk.parent.parent).encode()).hexdigest()[:16]
        self.aliases.mkdir(mode=0o700);alias=self.aliases/name
        alias.write_text('unrelated existing data')
        with self.assertRaisesRegex(ValueError,'Conflicting'):
            candidate.safe_sdk_invocation(sdk,alias_directory=self.aliases)
        self.assertEqual(alias.read_text(),'unrelated existing data')
        alias.unlink();alias.symlink_to(self.root/'missing')
        with self.assertRaisesRegex(ValueError,'Stale'):
            candidate.safe_sdk_invocation(sdk,alias_directory=self.aliases)
        self.assertEqual(os.readlink(alias),str(self.root/'missing'))
        alias.unlink();foreign=self.root/'foreign';foreign.mkdir();alias.symlink_to(foreign)
        with self.assertRaisesRegex(ValueError,'different installation'):
            candidate.safe_sdk_invocation(sdk,alias_directory=self.aliases)
        self.assertEqual(alias.resolve(),foreign)

    def test_alias_directory_permissions_and_symlink_conflicts_refused(self):
        sdk=self.sdk('SDK\u2019s physical home')
        self.aliases.mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError,'mode0700'):
            candidate.safe_sdk_invocation(sdk,alias_directory=self.aliases)
        self.aliases.rmdir();other=self.root/'other';other.mkdir();self.aliases.symlink_to(other)
        with self.assertRaisesRegex(ValueError,'mode0700'):
            candidate.safe_sdk_invocation(sdk,alias_directory=self.aliases)

    def test_auth_environment_and_synthetic_credentials_unchanged(self):
        sdk=self.sdk('SDK\u2019s physical home')
        auth=self.root/'synthetic-auth';auth.mkdir();credentials=auth/'credentials.db'
        credentials.write_bytes(b'SYNTHETIC NOT REAL AUTH');before=credentials.read_bytes()
        env={'CLOUDSDK_CONFIG':str(auth),'CLOUDSDK_ACTIVE_CONFIG_NAME':'synthetic-existing',
             'CLOUDSDK_PYTHON':'/usr/bin/python3','SDK_AUTH_SENTINEL':'do not change'}
        with patch.dict(os.environ,env):
            prior=dict(os.environ)
            candidate.safe_sdk_invocation(sdk,alias_directory=self.aliases)
            candidate.validate_python_invocation(os.environ['CLOUDSDK_PYTHON'])
            self.assertEqual(dict(os.environ),prior)
        self.assertEqual(credentials.read_bytes(),before)

    def test_unsafe_python_is_refused_without_rewriting_selection(self):
        for value in ['/path/SDK\u2019s/python','/path/python\n3','']:
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'CLOUDSDK_PYTHON'):
                candidate.validate_python_invocation(value)

    def test_exact_pinned_sdk_proxy_escaping_rejects_unicode_accepts_alias(self):
        sdk_source=SOURCE.parents[1]/'tmp/gcp-preparation-tools/google-cloud-sdk/lib/googlecloudsdk/command_lib/util/ssh/ssh.py'
        if not sdk_source.is_file():self.skipTest('pinned SDK source unavailable, no download attempted')
        tree=ast.parse(sdk_source.read_text())
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)
               and n.name in {'_EscapeForBash','_EscapeProxyCommandArg'}]
        self.assertEqual(len(nodes),2)
        class BadCharacterError(Exception):pass
        scope={'string':string,'Suite':SimpleNamespace(PUTTY='putty'),'BadCharacterError':BadCharacterError}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<pinned SDK escaping only>','exec'),scope)
        env=SimpleNamespace(suite='openssh',is_windows=False)
        sdk=self.sdk('SDK\u2019s physical home')
        with self.assertRaises(BadCharacterError):scope['_EscapeProxyCommandArg'](str(sdk),env)
        logical=Path(candidate.safe_sdk_invocation(sdk,alias_directory=self.aliases))
        escaped=scope['_EscapeProxyCommandArg'](str(logical.parent.parent/'lib/gcloud.py'),env)
        self.assertEqual(shlex.split(escaped),[str(logical.parent.parent/'lib/gcloud.py')])
        self.assertEqual(shlex.split(scope['_EscapeProxyCommandArg']("/ASCII user's path/python",env)),
                         ["/ASCII user's path/python"])

    def test_pinned_shell_root_selection_preserves_directory_alias(self):
        real=SOURCE.parents[1]/'tmp/gcp-preparation-tools/google-cloud-sdk/bin/gcloud'
        if not real.is_file():self.skipTest('pinned SDK shell unavailable, no download attempted')
        source=real.read_text();start=source.index('_cloudsdk_root_dir() {')
        end=source.index('CLOUDSDK_ROOT_DIR=$(_cloudsdk_root_dir "$0")',start)
        function=source[start:end]
        sdk=self.sdk('SDK\u2019s physical home')
        sdk.write_text('#!/bin/sh\n'+function+'\n_cloudsdk_root_dir "$0"\n')
        logical=Path(candidate.safe_sdk_invocation(sdk,alias_directory=self.aliases))
        result=subprocess.run(['/bin/sh',str(logical)],capture_output=True,text=True,check=True,timeout=5)
        self.assertEqual(result.stdout.strip(),str(logical.parent.parent))
        self.assertTrue(candidate.proxy_safe(result.stdout.strip()))

    def test_source_bound_patch_only_applied_to_temporary_copy(self):
        original,changed,diff=prepare_patch.render();record=json.loads((HERE/'proposal.json').read_text())
        self.assertEqual(record['source'],prepare_patch.hashes(original))
        self.assertEqual(record['candidate'],prepare_patch.hashes(changed))
        self.assertEqual((HERE/'proposal.patch').read_text(),diff)
        dest=self.root/'VC-FHE/distributed';dest.mkdir(parents=True)
        for name,value in original.items():(dest/name).write_text(value)
        subprocess.run(['patch','--batch','-p1','-d',str(self.root),'-i',str(HERE/'proposal.patch')],
                       capture_output=True,text=True,check=True,timeout=5)
        self.assertEqual({name:(dest/name).read_text() for name in changed},changed)
        self.assertEqual(prepare_patch.render()[0],original)


if __name__=='__main__':unittest.main(verbosity=2)
