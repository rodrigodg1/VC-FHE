#!/usr/bin/env python3
"""Read-only host sampling. No computation, signing, decryption or transactions."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import subprocess
import time

def command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10, check=True)
        return {"available": True, "output": result.stdout.strip()}
    except (OSError, subprocess.SubprocessError) as error:
        return {"available": False, "error": type(error).__name__}

def host_sample(host):
    sample = {"kind": "host_sample", "host": host,
              "utc": datetime.now(timezone.utc).isoformat(), "monotonic_ns": time.monotonic_ns()}
    for name in ("meminfo", "loadavg", "stat"):
        path = Path("/proc")/name
        sample[name] = path.read_text() if path.is_file() else None
    # Per-interface bytes include background traffic. They are not payload bytes.
    sample["network_interfaces"] = {}
    for interface in Path("/sys/class/net").glob("*"):
        if interface.name == "lo": continue
        try:
            sample["network_interfaces"][interface.name] = {kind: int((interface/"statistics"/(kind+"_bytes")).read_text())
                                                          for kind in ("rx", "tx")}
        except OSError: continue
    # No docker inspect/environment output, which could expose credentials.
    sample["containers"] = command(["docker", "stats", "--no-stream", "--format", "{{json .}}"])
    sample["clock"] = command(["chronyc", "tracking"])
    return sample

def network_sample(source, target, port, timeout=2.0):
    start = time.monotonic_ns()
    try:
        with socket.create_connection((target["private_ip"], port), timeout=timeout): pass
        status, error = "connected", None
    except OSError as failure:
        status, error = "unavailable", type(failure).__name__
    return {"kind": "network_probe", "host": source, "target_host": target["id"],
            "port": port, "status": status, "error": error,
            "elapsed_seconds": (time.monotonic_ns()-start)/1e9,
            "utc": datetime.now(timezone.utc).isoformat(),
            "metric": "tcp-connection-time-not-message-rtt"}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--interval", type=float, default=15)
    parser.add_argument("--network", action="store_true", help="also connect to the private validator RPC ports")
    parser.add_argument('--stop-file',type=Path)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    if args.host not in {h["id"] for h in plan["hosts"]}: parser.error("unknown host")
    if args.samples < 1 or args.interval < 1: parser.error("positive samples and interval >= 1 required")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        for index in range(args.samples):
            if args.stop_file and args.stop_file.exists():break
            rows = [host_sample(args.host)]
            if args.network:
                targets = {n["host"] for n in plan["nodes"] if n["role"] == "validator"}
                rows += [network_sample(args.host, h, 8545) for h in plan["hosts"] if h["id"] in targets]
            for row in rows: stream.write(json.dumps(row)+"\n")
            stream.flush()
            print(f"[{index+1}/{args.samples}] host metrics recorded", flush=True)
            if index+1 < args.samples:
                until=time.monotonic()+args.interval
                while time.monotonic()<until:
                    if args.stop_file and args.stop_file.exists():break
                    time.sleep(min(1,max(0,until-time.monotonic())))

if __name__ == "__main__": main()
