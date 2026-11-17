#!/usr/bin/env python3
"""Measure one command without adding resource output to its stdout.

wait4 reports the command and descendants whose usage is propagated when they
are waited for. maxrss is a process high-water statistic, not simultaneous tree
memory. Missing platform measurements remain null. No input or environment is
copied into the resource report.
"""
import argparse
import datetime
import json
import os
import signal
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required")
    # Refuse overwriting evidence before executing the command.
    with open(args.report, "x", encoding="utf-8") as report:
        started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        started = time.perf_counter()
        child = None
        usage = None
        spawn_error = None
        try:
            child = subprocess.Popen(command, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
            def forward(signum, _frame):
                try:
                    os.kill(child.pid, signum)
                except ProcessLookupError:
                    pass
            for signum in (signal.SIGINT, signal.SIGTERM):
                signal.signal(signum, forward)
            if hasattr(os, "wait4"):
                while True:
                    try:
                        _, status, usage = os.wait4(child.pid, 0)
                        break
                    except InterruptedError:
                        continue
                child.returncode = os.waitstatus_to_exitcode(status)
            else:
                child.wait()
            code = child.returncode
        except OSError as exc:
            code = 127
            spawn_error = str(exc)
            print(f"measured command could not start: {exc}", file=sys.stderr)
        user = usage.ru_utime * 1000 if usage is not None else None
        system = usage.ru_stime * 1000 if usage is not None else None
        rss = None
        if usage is not None:
            if sys.platform == "darwin":
                rss = usage.ru_maxrss
            elif sys.platform.startswith("linux"):
                rss = usage.ru_maxrss * 1024
        json.dump({
            "startedAt": started_at,
            "finishedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "elapsedMs": (time.perf_counter() - started) * 1000,
            "exitCode": code if code >= 0 else None,
            "signal": -code if code < 0 else None,
            "spawnError": spawn_error,
            "resources": {
                "scope": "command-and-waited-descendants",
                "userCpuMs": user,
                "systemCpuMs": system,
                "totalCpuMs": user + system if user is not None else None,
                "maxRssBytes": rss,
                "maxRssScope": "process-high-water-not-simultaneous-tree-peak",
                "source": "os.wait4" if usage is not None else None,
                "unavailableReason": None if usage is not None else (
                    "command-did-not-start" if spawn_error else "platform-has-no-wait4"),
                "maxRssUnavailableReason": None if rss is not None else (
                    "no-resource-usage" if usage is None else "unsupported-platform-rss-unit"),
            },
        }, report, indent=2)
        report.write("\n")
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    sys.exit(main())
