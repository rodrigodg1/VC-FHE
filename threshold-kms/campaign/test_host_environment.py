"""Metadata collection never starts infrastructure or invents missing hardware."""
from pathlib import Path
import unittest
from unittest.mock import patch
import host_environment as host
import run


class HostEnvironmentTests(unittest.TestCase):
    def test_macos_uses_host_values_not_docker_limits(self):
        with patch.object(host.platform, 'system', return_value='Darwin'), \
             patch.object(host.platform, 'release', return_value='fixture'), \
             patch.object(host.platform, 'machine', return_value='arm64'), \
             patch.object(host.os, 'cpu_count', return_value=12), \
             patch.object(host, 'query', side_effect=['Apple M4 Pro', str(24*2**30)]):
            result = host.capture()
        self.assertEqual(result['cpuModel'], 'Apple M4 Pro')
        self.assertEqual(result['osVisibleMemoryBytes'], 24*2**30)
        self.assertEqual(result['logicalCpuCount'], 12)
        self.assertEqual(result['scope'], 'launcher-host-not-docker-daemon')
        self.assertEqual(result['unavailableFields'], [])

    def test_linux_cpu_and_memory_are_observed(self):
        with patch.object(host.platform, 'system', return_value='Linux'), \
             patch.object(Path, 'read_text', return_value='model name\t: Fixture CPU\n'), \
             patch.object(host.os, 'sysconf', side_effect=[1024, 4096]):
            result = host.capture()
        self.assertEqual(result['cpuModel'], 'Fixture CPU')
        self.assertEqual(result['osVisibleMemoryBytes'], 1024*4096)

    def test_unavailable_values_are_null_not_docker_or_zero(self):
        with patch.object(host.platform, 'system', return_value='Darwin'), \
             patch.object(host, 'query', return_value=None), \
             patch.object(host.os, 'cpu_count', return_value=None):
            result = host.capture()
        for key in ['cpuModel', 'osVisibleMemoryBytes', 'logicalCpuCount']:
            self.assertIsNone(result[key])
            self.assertIn(key, result['unavailableFields'])

    def test_collector_is_in_measured_source_closure(self):
        path = Path(host.__file__).resolve()
        self.assertIn(path, run.source_files())
        self.assertEqual(run.source_manifest()[str(path.relative_to(run.ROOT))], run.sha(path))


if __name__ == '__main__':
    unittest.main()
