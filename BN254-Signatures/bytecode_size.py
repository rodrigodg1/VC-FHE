#!/usr/bin/env python3
import json
from pathlib import Path
import sys

# Default artifact path (Hardhat)
DEFAULT_ARTIFACT = Path(__file__).parent / "artifacts" / "contract" / "MKLHS-Verification.sol" / "MKLHSVerification.json"

path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_ARTIFACT
if not path.exists():
    print(f"Error: artifact not found: {path}")
    print("Run: npx hardhat compile (from BN254-Signatures) to generate artifacts.")
    sys.exit(1)

art = json.loads(path.read_text())
bytecode = art.get("bytecode", "") or ""
deployed = art.get("deployedBytecode", "") or ""

# Strip 0x prefix if present
if bytecode.startswith("0x"):
    bytecode = bytecode[2:]
if deployed.startswith("0x"):
    deployed = deployed[2:]

creation_bytes = len(bytecode) // 2
runtime_bytes = len(deployed) // 2

print(f"creation_bytecode_bytes={creation_bytes}")
print(f"runtime_bytecode_bytes={runtime_bytes}")
