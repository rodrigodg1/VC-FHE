"""No FHE execution: native-stage reuse must be immutable and compile-free."""
from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cloud_results.native_reuse import render

class NativeReuseTests(unittest.TestCase):
    def test_imports_native_stage_without_repeating_cargo_work(self):
        source='FROM node@sha256:'+'a'*64+' AS node\nFROM rust:reviewed AS build\nRUN cargo build && cargo test\nFROM node AS runtime\nCOPY --from=build /binaries/ /usr/local/bin/\nCOPY app/ /app/\n'
        pinned='us-central1-docker.pkg.dev/example/project/native-cache@sha256:'+'b'*64
        text=render(source,pinned)
        self.assertIn('FROM '+pinned+' AS build',text)
        self.assertNotIn('cargo build',text);self.assertNotIn('cargo test',text)
        self.assertEqual(text.split('FROM node AS runtime\n')[1],source.split('FROM node AS runtime\n')[1])
    def test_mutable_or_foreign_command_reference_is_refused(self):
        for value in ('repo/native:latest','repo/native@sha256:abc','repo/native;cmd@sha256:'+'a'*64):
            with self.assertRaises(ValueError):render('FROM rust:x\nFROM node AS runtime\n',value)
    def test_unreviewed_stage_layout_is_refused(self):
        with self.assertRaises(ValueError):render('FROM other AS runtime\n','repo/native@sha256:'+'a'*64)
if __name__=='__main__':unittest.main()
