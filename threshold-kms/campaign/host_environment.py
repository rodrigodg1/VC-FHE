"""Read-only launcher-host metadata, kept separate from Docker resource limits."""
import os
from pathlib import Path
import platform
import re
import subprocess

VERSION = 'launcher-host-environment-v1'


def query(*args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL,
                                       timeout=2).strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def positive(value):
    try:
        number = int(value)
        return number if number > 0 else None
    except (TypeError, ValueError):
        return None


def capture():
    system = platform.system()
    cpu, memory = None, None
    if system == 'Darwin':
        cpu = query('sysctl', '-n', 'machdep.cpu.brand_string')
        memory = positive(query('sysctl', '-n', 'hw.memsize'))
    elif system == 'Linux':
        try:
            info = Path('/proc/cpuinfo').read_text()
            match = re.search(r'^(?:model name|Hardware)\s*:\s*(.+)$', info, re.MULTILINE)
            cpu = match.group(1).strip() if match else None
        except OSError:
            pass
        try:
            memory = positive(os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE'))
        except (OSError, ValueError, AttributeError):
            pass
    result = dict(schema=VERSION, scope='launcher-host-not-docker-daemon',
                  operatingSystem=system or None, operatingSystemRelease=platform.release() or None,
                  architecture=platform.machine() or None, cpuModel=cpu,
                  logicalCpuCount=positive(os.cpu_count()), osVisibleMemoryBytes=memory)
    result['unavailableFields'] = [key for key, value in result.items() if value is None]
    return result
