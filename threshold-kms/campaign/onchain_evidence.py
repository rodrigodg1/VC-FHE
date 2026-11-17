#!/usr/bin/env python3
"""Fail-closed validator for V3 on-chain consent and release evidence.

The validator is intentionally independent from the transaction relayer.  It
checks the preserved application report, the recipient outputs, and the owner
oracle.  It does not contact a live chain and therefore does not replace the
four-validator observations preserved by the campaign.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Mapping, Sequence


SCHEMA = "onchain-release-evidence-v3"
CAMPAIGN_VERSION = "dataset-threshold-campaign-v3"
ZERO32 = "0x" + "00" * 32
ZERO_ADDRESS = "0x" + "00" * 20
CANONICAL_VERSION = "canonical-kms-dag-execution-v1"
INPUT_ENCRYPTION = "kms-compact-public-key-expanded-v1"
DOMAIN_VERSION = "public-interval-admission-v1"
DOMAIN_ASSUMPTION = "owners honestly encrypt records within their authenticated public bounds"
PROGRAM_VERSION = "compliance-explicit-dag-v1"
UINT64_MAX = (1 << 64) - 1

# Python's hashlib.sha3_256 implements the FIPS SHA-3 padding, not the
# Keccak-256 padding used by Ethereum and ethers.  Keep this verifier free of
# optional host packages by carrying the small permutation needed for the
# three hashes that are independently reconstructed below.
_KECCAK_ROUNDS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_KECCAK_ROTATION = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_MASK64 = (1 << 64) - 1


def _rotate64(value: int, shift: int) -> int:
    if shift == 0:
        return value
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_permute(state: list[int]) -> None:
    for constant in _KECCAK_ROUNDS:
        columns = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15]
                   ^ state[x + 20] for x in range(5)]
        deltas = [columns[(x - 1) % 5] ^ _rotate64(columns[(x + 1) % 5], 1)
                  for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= deltas[x]
        rotated = [0] * 25
        for y in range(5):
            for x in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = _rotate64(
                    state[x + 5 * y], _KECCAK_ROTATION[x][y])
        for y in range(5):
            row = rotated[5 * y:5 * y + 5]
            for x in range(5):
                state[x + 5 * y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
        state[0] ^= constant


def _keccak256_bytes(payload: bytes) -> bytes:
    rate = 136
    padded = bytearray(payload)
    padded.append(0x01)
    padded.extend(b"\x00" * ((rate - len(padded) % rate) % rate))
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for lane in range(rate // 8):
            state[lane] ^= int.from_bytes(block[8 * lane:8 * lane + 8], "little")
        _keccak_permute(state)
    return b"".join(value.to_bytes(8, "little") for value in state)[:32]


def _keccak256(payload: bytes) -> str:
    return "0x" + _keccak256_bytes(payload).hex()


def _json_keccak(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False,
                         separators=(",", ":")).encode("utf-8")
    return _keccak256(encoded)


def _policy_keccak(value: Any) -> str:
    """Reproduce recipient-output-policy.mjs canonical, recursively sorted JSON."""
    def canonical(item: Any) -> Any:
        if isinstance(item, list):
            return [canonical(child) for child in item]
        if isinstance(item, dict):
            return {key: canonical(item[key]) for key in sorted(item)}
        require(item is None or isinstance(item, (str, bool))
                or (isinstance(item, int) and not isinstance(item, bool)
                    and -(1 << 53) < item < (1 << 53)),
                "noncanonical policy JSON value")
        return item
    return _json_keccak(canonical(value))


class EvidenceError(ValueError):
    """Raised when preserved evidence is incomplete or inconsistent."""


def require(condition: Any, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _object(value: Any, label: str) -> Mapping[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    require(isinstance(value, list), f"{label} must be an array")
    return value


def _uint(value: Any, label: str, bits: int | None = None) -> int:
    require(not isinstance(value, bool), f"{label} must be an unsigned integer")
    if isinstance(value, str):
        require(re.fullmatch(r"0|[1-9][0-9]*", value) is not None,
                f"{label} must be a canonical decimal integer")
        value = int(value)
    require(isinstance(value, int) and value >= 0, f"{label} must be an unsigned integer")
    if bits is not None:
        require(value < 1 << bits, f"{label} exceeds uint{bits}")
    return value


def _hex(value: Any, size: int, label: str, *, nonzero: bool = False) -> str:
    require(isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]+", value) is not None,
            f"{label} must be 0x-prefixed hexadecimal")
    require(len(value) == 2 + size * 2, f"{label} must contain {size} bytes")
    result = value.lower()
    if nonzero:
        require(result != "0x" + "00" * size, f"{label} must be nonzero")
    return result


def _bytes32(value: Any, label: str, *, nonzero: bool = True) -> str:
    return _hex(value, 32, label, nonzero=nonzero)


def _address(value: Any, label: str, *, nonzero: bool = True) -> str:
    return _hex(value, 20, label, nonzero=nonzero)


def _plain_hex(value: Any, label: str) -> str:
    require(isinstance(value, str) and re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value) is not None,
            f"{label} must be byte-aligned hexadecimal")
    return value.lower()


def _sha256_hex(value: Any, label: str) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None,
            f"{label} must be a SHA-256 digest")
    return value.lower()


def _workflow_manifest(value: Any, half: str, label: str) -> dict[str, Any]:
    manifest = _object(value, label)
    require(manifest.get("schema") == "vcfhe-workflow-deployment-v1",
            f"{label} has the wrong schema")
    deployments = _object(manifest.get("deployments"), f"{label}.deployments")
    if half == "linear":
        require(set(manifest) == {"schema", "kind", "workflow", "deployments"}
                and manifest.get("kind") == "grouped-linear",
                f"{label} is not the canonical grouped-linear manifest")
        require(set(deployments) == {"workflow"},
                f"{label}.deployments has unexpected fields")
        return {"workflow": _address(manifest.get("workflow"), f"{label}.workflow"),
                "deploymentTransactions": {
                    "workflow": _bytes32(deployments.get("workflow"),
                                           f"{label}.deployments.workflow")}}
    require(set(manifest) == {"schema", "kind", "game", "availability", "verifier",
                              "objective", "canonicalSigners", "deployments"}
            and manifest.get("kind") in {"canonical-nonlinear", "canonical-bounty-nonlinear-v2"},
            f"{label} is not the canonical nonlinear manifest")
    addresses = {field: _address(manifest.get(field), f"{label}.{field}")
                 for field in ("game", "availability", "verifier", "objective")}
    require(len(set(addresses.values())) == 4, f"{label} reuses a workflow contract address")
    signers = [_address(item, f"{label}.canonicalSigners")
               for item in _array(manifest.get("canonicalSigners"),
                                  f"{label}.canonicalSigners")]
    require(len(signers) == len(set(signers)) == 3,
            f"{label} does not name three distinct canonical signers")
    require(set(deployments) == {"game", "availability", "verifier", "objective"},
            f"{label}.deployments has unexpected fields")
    transactions = {field: _bytes32(deployments.get(field), f"{label}.deployments.{field}")
                    for field in ("game", "availability", "verifier", "objective")}
    return {"workflow": addresses["game"], "contracts": addresses,
            "canonicalSigners": signers, "deploymentTransactions": transactions}


def _abi_bytes32_array_digest(values: Any, label: str) -> tuple[list[str], str]:
    """Reproduce ethers AbiCoder.encode(['bytes32[]'], [values])."""
    normalized = [_bytes32(value, f"{label}[{index}]")
                  for index, value in enumerate(_array(values, label))]
    require(normalized, f"{label} must not be empty")
    encoded = ((32).to_bytes(32, "big") + len(normalized).to_bytes(32, "big")
               + b"".join(bytes.fromhex(value[2:]) for value in normalized))
    return normalized, _keccak256(encoded)


def _word(kind: str, value: Any, label: str) -> str:
    if kind == "bytes32":
        return _bytes32(value, label, nonzero=False)[2:]
    if kind == "address":
        return "00" * 12 + _address(value, label, nonzero=False)[2:]
    match = re.fullmatch(r"uint(8|32|64|256)", kind)
    require(match is not None, f"unsupported ABI type {kind}")
    number = _uint(value, label, int(match.group(1)))
    return number.to_bytes(32, "big").hex()


# The signatures are pinned to OnChainReleasePolicy.sol V3.  All event fields
# are static, which permits a small independent ABI check without web3/ethers.
EVENTS: dict[str, tuple[str, tuple[tuple[str, str, bool], ...]]] = {
    "ProtectedRecordRegistered": (
        "0x52ab677d937d0a947ff7bc4b17acd69b2e36739d479d8133cece548d094c4bb4",
        (("protectedId", "bytes32", True), ("owner", "address", True),
         ("recordReference", "bytes32", True), ("releaseLimit", "uint64", False),
         ("initialSpent", "uint64", False)),
    ),
    "ConsentCreated": (
        "0x9d4dcc672f1ecd155a9dab65c7a6a2ebf4b00ee01caf418398461ca7234b8fb7",
        (("consentId", "bytes32", True), ("taskId", "bytes32", True),
         ("recipient", "address", True), ("workflowKind", "uint8", False),
         ("workflow", "address", False), ("slot", "bytes32", False),
         ("recordCount", "uint32", False), ("requiredOwnerCount", "uint32", False)),
    ),
    "ConsentApproved": (
        "0x45351259c2ba2acf277b81748ae0b3b89ae575121c563e953357552d15e96d9f",
        (("consentId", "bytes32", True), ("owner", "address", True),
         ("approvalCount", "uint32", False)),
    ),
    "ReleaseProposed": (
        "0x6e11ac308dedc87deda1b8ab28455880f45726ef9d87aae184b349bc0e914f47",
        (("requestId", "bytes32", True), ("consentId", "bytes32", True),
         ("requestKey", "bytes32", True), ("releaseDigest", "bytes32", False)),
    ),
    "ReleaseApproved": (
        "0x373cafe272e979bd8a4bb9f1a2ff2c169202229ff8ee4fe4c1b20bba051e91e7",
        (("requestId", "bytes32", True), ("owner", "address", True),
         ("approvalCount", "uint32", False), ("releaseDigest", "bytes32", False)),
    ),
    "ReleaseReserved": (
        "0xf78c4be0fe8fa41ccb6e26d4d289da7f7f7cc5751b941f23bf0591f46dbc35b5",
        (("requestId", "bytes32", True), ("consentId", "bytes32", True),
         ("requestKey", "bytes32", True), ("submitWireDigest", "bytes32", False),
         ("resultQueryDigest", "bytes32", False), ("finalOutputDigest", "bytes32", False),
         ("aggregateDigest", "bytes32", False),
         ("recipientEncryptionKeyDigest", "bytes32", False),
         ("recipient", "address", False), ("slot", "bytes32", False)),
    ),
}


def _validate_raw_event(event: Mapping[str, Any], index: int) -> dict[str, Any]:
    label = f"policyEvents[{index}]"
    name = event.get("name")
    require(name in EVENTS, f"{label} has an event outside policy V3")
    signature, fields = EVENTS[name]
    args = _object(event.get("args"), f"{label}.args")
    expected_names = {field[0] for field in fields}
    require(set(args) == expected_names, f"{label}.args does not match the V3 ABI")

    topics = _array(event.get("topics"), f"{label}.topics")
    indexed = [field for field in fields if field[2]]
    require(len(topics) == 1 + len(indexed), f"{label} has the wrong topic count")
    expected_topics = [signature]
    expected_topics.extend("0x" + _word(kind, args[field], f"{label}.args.{field}")
                           for field, kind, _ in indexed)
    require([_bytes32(topic, f"{label}.topics", nonzero=False) for topic in topics]
            == [topic.lower() for topic in expected_topics], f"{label} topics do not encode args")

    unindexed = [field for field in fields if not field[2]]
    expected_data = "0x" + "".join(_word(kind, args[field], f"{label}.args.{field}")
                                      for field, kind, _ in unindexed)
    require(_plain_hex(event.get("data"), f"{label}.data") == expected_data,
            f"{label} data does not encode args")
    normalized_args: dict[str, Any] = {}
    for field, kind, _ in fields:
        if kind == "bytes32":
            normalized_args[field] = _bytes32(args[field], f"{label}.args.{field}", nonzero=False)
        elif kind == "address":
            normalized_args[field] = _address(args[field], f"{label}.args.{field}", nonzero=False)
        else:
            normalized_args[field] = _uint(args[field], f"{label}.args.{field}", int(kind[4:]))
    return {
        "name": name,
        "transactionHash": _bytes32(event.get("transactionHash"), f"{label}.transactionHash"),
        "blockNumber": _uint(event.get("blockNumber"), f"{label}.blockNumber"),
        "blockHash": _bytes32(event.get("blockHash"), f"{label}.blockHash"),
        "logIndex": _uint(event.get("logIndex"), f"{label}.logIndex"),
        "args": normalized_args,
    }


def _reject_legacy_authority(value: Any, path: str = "evidence") -> None:
    """Reject a live gateway or file-ledger field, including nested aliases."""
    if isinstance(value, dict):
        for key, child in value.items():
            require(isinstance(key, str), f"{path} has a non-string field")
            folded = re.sub(r"[^a-z0-9]", "", key.lower())
            require("gateway" not in folded and "ledger" not in folded,
                    f"{path}.{key} reintroduces a gateway or file ledger as evidence")
            _reject_legacy_authority(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_legacy_authority(child, f"{path}[{index}]")
    elif isinstance(value, str):
        require(value not in {"kms-final-consent-v2", "recipient-output-policy-v2",
                              "VCFHE_GATEWAY_V1", "x-vcfhe-signature"},
                f"{path} contains a legacy authorization marker")


def _unique(values: Sequence[str], label: str) -> None:
    require(len(set(values)) == len(values), f"{label} must be unique")


def _event_position(event: Mapping[str, Any]) -> tuple[int, int]:
    return event["blockNumber"], event["logIndex"]


def _receipt_map(app: Mapping[str, Any], policy: str) -> dict[str, Mapping[str, Any]]:
    receipts: dict[str, Mapping[str, Any]] = {}
    for index, raw in enumerate(_array(app.get("receipts"), "receipts")):
        row = _object(raw, f"receipts[{index}]")
        tx = _bytes32(row.get("hash", row.get("txHash")), f"receipts[{index}].hash")
        require(tx not in receipts, "duplicate transaction receipt")
        require(isinstance(row.get("label"), str) and row["label"], f"receipts[{index}] lacks label")
        block = row.get("block", row.get("blockNumber"))
        if block is not None:
            _uint(block, f"receipts[{index}].block")
        if row.get("blockHash") is not None:
            _bytes32(row["blockHash"], f"receipts[{index}].blockHash")
        if row.get("to") is not None:
            _address(row["to"], f"receipts[{index}].to", nonzero=False)
        receipts[tx] = row
    return receipts


def _match_receipt(event: Mapping[str, Any], receipts: Mapping[str, Mapping[str, Any]], label: str,
                   policy: str, owner: str | None = None) -> None:
    tx = event["transactionHash"]
    require(tx in receipts, f"{event['name']} has no preserved successful receipt")
    receipt = receipts[tx]
    require(receipt["label"] == label, f"{event['name']} is assigned to the wrong receipt scope")
    require(_uint(receipt.get("block", receipt.get("blockNumber")), "receipt.block") == event["blockNumber"],
            f"{event['name']} receipt block mismatch")
    require(_bytes32(receipt["blockHash"], "receipt.blockHash") == event["blockHash"],
            f"{event['name']} receipt block hash mismatch")
    if "to" in receipt:
        require(_address(receipt["to"], "receipt.to") == policy, "policy receipt target mismatch")
    if owner is not None:
        require("from" in receipt and _address(receipt["from"], "receipt.from") == owner,
                f"{event['name']} was not sent by the approving owner")


_SUBMIT_FIELDS = (
    "requestId", "requestKey", "submitWireDigest", "consentId", "finalOutputDigest",
    "aggregateDigest", "recipientEncryptionKeyDigest", "recipient", "keyId", "keyEpoch",
    "mpcContext", "outputType", "workflow", "chainId", "policyDomain", "policy", "slot",
    "workflowKind", "taskId", "contextDigest", "programDigest", "programRoot",
    "profileDigest", "keysetDigest", "inputBindingsDigest",
)
_SUBMIT_TYPES = (
    "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32",
    "address", "bytes32", "bytes32", "bytes32", "bytes32", "address", "uint256",
    "bytes32", "address", "bytes32", "uint8", "bytes32", "bytes32", "bytes32",
    "bytes32", "bytes32", "bytes32", "bytes32",
)
_SUBMIT_SIGNATURE = (
    "isSubmitAuthorized((bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,address,"
    "bytes32,bytes32,bytes32,bytes32,address,uint256,bytes32,address,bytes32,uint8,bytes32,"
    "bytes32,bytes32,bytes32,bytes32,bytes32,bytes32))")
_CONSENT_FIELDS = (
    "domain", "chainId", "workflowKind", "workflow", "taskId", "contextDigest",
    "programDigest", "programRoot", "profileDigest", "keysetDigest", "keyId", "keyEpoch",
    "mpcContext", "outputType", "recipient", "slot", "inputRoot", "inputBindingsDigest",
    "recordCount", "actualInputCount", "paddedInputCount", "requiredOwnerCount",
    "approvalCount", "exists",
)
_CONSENT_TYPES = (
    "bytes32", "uint256", "uint8", "address", "bytes32", "bytes32", "bytes32",
    "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32",
    "address", "bytes32", "bytes32", "bytes32", "uint32", "uint32", "uint32",
    "uint32", "uint32", "uint8",
)


def _normalize_submit(value: Any, label: str) -> dict[str, Any]:
    row = _object(value, label)
    require(set(row) == set(_SUBMIT_FIELDS), f"{label} does not match the V3 submit ABI")
    result: dict[str, Any] = {}
    for field, kind in zip(_SUBMIT_FIELDS, _SUBMIT_TYPES, strict=True):
        if kind == "bytes32": result[field] = _bytes32(row.get(field), f"{label}.{field}", nonzero=False)
        elif kind == "address": result[field] = _address(row.get(field), f"{label}.{field}", nonzero=False)
        else: result[field] = _uint(row.get(field), f"{label}.{field}", int(kind[4:]))
    return result


def _decode_consent_result(value: Any, label: str) -> dict[str, Any]:
    raw = _plain_hex(value, label)
    require(len(raw) == 2 + 32 * 2 * len(_CONSENT_FIELDS),
            f"{label} has the wrong static ConsentState length")
    result: dict[str, Any] = {}
    payload = raw[2:]
    for index, (field, kind) in enumerate(zip(_CONSENT_FIELDS, _CONSENT_TYPES, strict=True)):
        word = payload[index * 64:(index + 1) * 64]
        if kind == "bytes32": result[field] = "0x" + word
        elif kind == "address":
            require(word[:24] == "0" * 24, f"{label}.{field} is not canonical ABI address data")
            result[field] = "0x" + word[24:]
        else:
            number = int(word, 16)
            bits = int(kind[4:])
            require(number < 1 << bits, f"{label}.{field} exceeds {kind}")
            result[field] = bool(number) if field == "exists" else number
            if field == "exists": require(number in {0, 1}, f"{label}.exists is not a canonical bool")
    return result


def _policy_call_evidence(submit: Mapping[str, Any], consent_state: Mapping[str, Any],
                          request_id: str, request_key: str, result_digest: str) -> dict[str, Any]:
    submit_values = [submit[field] for field in _SUBMIT_FIELDS]
    return {
        "consent": {
            "calldata": _call_data("getConsent(bytes32)", ["bytes32"],
                                   [submit["consentId"]], "getConsent"),
            "result": "0x" + _static_abi(_CONSENT_TYPES,
                                             [1 if consent_state[field] is True else
                                              0 if consent_state[field] is False else consent_state[field]
                                              for field in _CONSENT_FIELDS],
                                             "ConsentState").hex(),
        },
        "submit": {
            "calldata": _call_data(_SUBMIT_SIGNATURE, _SUBMIT_TYPES, submit_values,
                                   "isSubmitAuthorized"),
            "result": "0x" + "00" * 31 + "01",
        },
        "result": {
            "calldata": _call_data("isResultAuthorized(bytes32,bytes32,bytes32)",
                                   ["bytes32", "bytes32", "bytes32"],
                                   [request_id, request_key, result_digest],
                                   "isResultAuthorized"),
            "result": "0x" + "00" * 31 + "01",
        },
    }


def _confirmations(value: Any, label: str, block_number: int, block_hash: str,
                   runtime_hash: str, chain_id: int, *,
                   expected_policy_calls: Mapping[str, Any] | None = None,
                   expected_consent_state: Mapping[str, Any] | None = None
                   ) -> tuple[tuple[Any, ...], ...]:
    rows = _array(value, label)
    require(3 <= len(rows) <= 4, f"{label} must contain three or four validator confirmations")
    normalized = []
    for index, raw in enumerate(rows):
        row = _object(raw, f"{label}[{index}]")
        validator = _uint(row.get("validator"), f"{label}[{index}].validator")
        observed_chain = _uint(row.get("chainId"), f"{label}[{index}].chainId")
        observed_block = _uint(row.get("blockNumber"), f"{label}[{index}].blockNumber")
        observed_hash = _bytes32(row.get("blockHash"), f"{label}[{index}].blockHash")
        code_hash = _bytes32(row.get("policyCodeHash"), f"{label}[{index}].policyCodeHash")
        require(1 <= validator <= 4, f"{label}[{index}] names an unknown validator")
        require(observed_block == block_number and observed_hash == block_hash,
                f"{label}[{index}] observed a different reservation block")
        require(code_hash == runtime_hash, f"{label}[{index}] observed different policy code")
        require(observed_chain == chain_id, f"{label}[{index}] observed a different chain")
        calls = row.get("policyCalls")
        if expected_policy_calls is not None:
            require(calls == expected_policy_calls,
                    f"{label}[{index}] did not preserve the exact canonical policy calls")
            decoded = _decode_consent_result(
                _object(_object(calls, f"{label}[{index}].policyCalls").get("consent"),
                        f"{label}[{index}].policyCalls.consent").get("result"),
                f"{label}[{index}].policyCalls.consent.result")
            require(expected_consent_state is not None
                    and decoded == {field: expected_consent_state[field]
                                    for field in _CONSENT_FIELDS},
                    f"{label}[{index}] canonical consent response decodes differently")
        normalized.append((validator, observed_chain, observed_block, observed_hash, code_hash,
                           json.dumps(calls, sort_keys=True, separators=(",", ":"))
                           if calls is not None else None))
    validators = [row[0] for row in normalized]
    require(len(set(validators)) == len(validators), f"{label} repeats a validator")
    require(validators == sorted(validators), f"{label} is not in canonical validator order")
    return tuple(normalized)


def _normalized_record_map(value: Any, label: str) -> dict[str, Mapping[str, Any]]:
    raw = _object(value, label)
    result: dict[str, Mapping[str, Any]] = {}
    for key, row in raw.items():
        identifier = _bytes32(key, f"{label} key")
        require(identifier not in result, f"{label} contains a normalized duplicate")
        result[identifier] = _object(row, f"{label}[{key}]")
    return result


def validate_onchain_evidence(app: Mapping[str, Any], recipient_results: Sequence[Mapping[str, Any]],
                              expected_outputs: Mapping[str, Any], *,
                              case_materials: Mapping[str, Mapping[str, Any]] | None = None,
                              policy_config: Mapping[str, Any] | None = None,
                              keyset: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Validate one complete V3 report and return a deterministic summary.

    ``recipient_results`` must be ordered by their numeric ``result-N.json``
    index.  ``expected_outputs`` is the owner-side oracle saved before release.
    A caller that cannot supply either input cannot establish delivered-result
    reconciliation and must not treat this validation as passed.
    """
    app = _object(app, "application")
    expected_outputs = _object(expected_outputs, "expected outputs")
    _reject_legacy_authority(app, "application")
    _reject_legacy_authority(list(recipient_results), "recipient results")
    require(app.get("status") == "passed", "application report did not pass")
    require(app.get("version") == CAMPAIGN_VERSION, "application is not campaign V3")
    config = _object(app.get("config"), "config")
    from bounty_evidence import validate_bounty_evidence
    validate_bounty_evidence(config, app)
    require(config.get("version") == CAMPAIGN_VERSION, "configuration is not campaign V3")
    require(app.get("plaintextInRelayer") is False, "relayer plaintext exposure is not excluded")
    refresh = config.get("policyRefreshPlan") is not None
    if refresh:
        require(case_materials is not None and policy_config is not None and keyset is not None,
                "V3 policy refresh requires sealed raw input-binding and policy evidence")

    policy_row = _object(app.get("onChainPolicy"), "onChainPolicy")
    require(_uint(policy_row.get("version"), "onChainPolicy.version") == 3,
            "on-chain policy version is not 3")
    policy = _address(policy_row.get("address"), "onChainPolicy.address")
    runtime_hash = _bytes32(policy_row.get("runtimeCodeHash"), "onChainPolicy.runtimeCodeHash")
    policy_domain = _bytes32(policy_row.get("domain"), "onChainPolicy.domain")
    owners_sha256 = None
    if config.get("policyRefreshPlan") is not None:
        owners_sha256 = _sha256_hex(policy_row.get("ownersSha256"),
                                    "onChainPolicy.ownersSha256")
    if policy_config is not None:
        policy_config = _object(policy_config, "release policy configuration")
        require(policy_config.get("schema") == "vcfhe-release-policy-config-v3",
                "release policy configuration is not V3")
        require(_uint(policy_config.get("policyVersion"), "release policy policyVersion") == 3,
                "release policy configuration has the wrong version")
        require(_uint(policy_config.get("chainId"), "release policy chainId")
                == _uint(config.get("chainId"), "config.chainId"),
                "release policy configuration has the wrong chain")
        require(_address(policy_config.get("address"), "release policy address") == policy
                and _bytes32(policy_config.get("runtimeCodeHash"),
                             "release policy runtimeCodeHash") == runtime_hash
                and _bytes32(policy_config.get("policyDomain"),
                             "release policy policyDomain") == policy_domain,
                "application policy evidence differs from the preserved policy configuration")
        if refresh:
            require(_sha256_hex(policy_config.get("ownersSha256"),
                                "release policy ownersSha256") == owners_sha256,
                    "owner identity digest differs from the preserved policy configuration")

    chain = _object(app.get("chain"), "chain")
    chain_id = _uint(config.get("chainId"), "config.chainId")
    require(_uint(chain.get("chainId"), "chain.chainId") == chain_id, "chain id mismatch")
    require(chain.get("consensus") == "QBFT", "release evidence is not from QBFT")
    validators = [_address(value, "chain.validators")
                  for value in _array(chain.get("validators"), "chain.validators")]
    require(len(validators) == 4 and len(set(validators)) == 4,
            "chain evidence does not name four distinct validators")
    require(_uint(chain.get("advancedBlock"), "chain.advancedBlock")
            > _uint(chain.get("observedBlock"), "chain.observedBlock"),
            "chain did not advance during the campaign")

    receipts = _receipt_map(app, policy)
    events = [_validate_raw_event(_object(row, f"policyEvents[{index}]"), index)
              for index, row in enumerate(_array(app.get("policyEvents"), "policyEvents"))]
    event_keys = [(row["transactionHash"], row["logIndex"]) for row in events]
    _unique(event_keys, "policy event transaction/log identities")
    by_name: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for event in events:
        by_name[event["name"]].append(event)

    cases = _array(app.get("cases"), "cases")
    results = list(recipient_results)
    require(cases and len(results) == len(cases), "recipient results do not cover every case")
    require(_uint(app.get("kmsCalls"), "kmsCalls") == len(cases),
            "KMS call count does not match released cases")
    # The owner oracle also covers off-chain paired measurements that never
    # reach a KMS release (--poc plans); it must include, but need not equal,
    # the released case names. A policy-refresh plan has only full cases, so
    # equality still holds there.
    require({case.get("name") for case in cases if isinstance(case, dict)} <= set(expected_outputs),
            "owner oracle does not cover every released case")

    names: list[str] = []
    consent_ids: list[str] = []
    request_ids: list[str] = []
    request_keys: list[str] = []
    slots: list[str] = []
    reservation_transactions: list[str] = []
    charges: collections.Counter[str] = collections.Counter()
    record_claims: dict[str, tuple[str, str, int, int]] = {}
    case_summaries = []

    def matching(name: str, **wanted: str) -> list[dict[str, Any]]:
        return [event for event in by_name.get(name, [])
                if all(event["args"].get(field) == value for field, value in wanted.items())]

    for index, (raw_case, raw_result) in enumerate(zip(cases, results, strict=True)):
        case = _object(raw_case, f"cases[{index}]")
        result = _object(raw_result, f"recipient result {index}")
        name = case.get("name")
        require(isinstance(name, str) and name, f"cases[{index}] has no name")
        require(result.get("index") == index and result.get("name") == name,
                f"recipient result {index} is reordered or belongs to another case")
        require(result.get("actual") == expected_outputs[name], f"{name}: delivered plaintext differs from owner oracle")
        require(_uint(case.get("finalOutputKmsCalls"), f"{name}.finalOutputKmsCalls") == 1,
                f"{name}: final output was not released exactly once")
        for field, count in (("responses", 3), ("directUserAndPublicDenied", 4),
                             ("negativeResponseChecks", 4), ("directAdministrativeDenied", 28),
                             ("changedReservedWireDenied", 4)):
            require(_uint(result.get(field), f"{name}.{field}") == count,
                    f"{name}: missing threshold or ingress rejection evidence")
        accepted_submit_cores = [_uint(value, f"{name}.acceptedSubmitCores")
                                 for value in _array(result.get("acceptedSubmitCores"),
                                                     f"{name}.acceptedSubmitCores")]
        failed_submit_cores = [_uint(value, f"{name}.failedSubmitCores")
                               for value in _array(result.get("failedSubmitCores"),
                                                   f"{name}.failedSubmitCores")]
        require(3 <= len(accepted_submit_cores) <= 4,
                f"{name}: fewer than three KMS cores accepted the reserved request")
        require(accepted_submit_cores == sorted(accepted_submit_cores)
                and failed_submit_cores == sorted(failed_submit_cores),
                f"{name}: KMS submission core identities are not canonical")
        require(set(accepted_submit_cores).isdisjoint(failed_submit_cores)
                and set(accepted_submit_cores + failed_submit_cores) == {1, 2, 3, 4},
                f"{name}: KMS submission evidence does not cover four distinct cores")

        half = case.get("half")
        require(half in {"linear", "nonlinear"}, f"{name}: invalid workflow half")
        workflow_kind = _uint(case.get("workflowKind"), f"{name}.workflowKind", 8)
        require(workflow_kind == (1 if half == "linear" else 2),
                f"{name}: workflow kind does not match its half")
        raw_manifest = case.get("workflowManifest")
        if half == "nonlinear":
            expected_kind = ("canonical-bounty-nonlinear-v2" if config.get("nonlinearProtocol") == "bounty-v2"
                             else "canonical-nonlinear")
            require(isinstance(raw_manifest, dict) and raw_manifest.get("kind") == expected_kind,
                    f"{name}: nonlinear protocol differs from the selected campaign")
        manifest = _workflow_manifest(raw_manifest, half, f"{name}.workflowManifest")
        manifest_digest = _bytes32(case.get("workflowManifestDigest"),
                                   f"{name}.workflowManifestDigest")
        require(_json_keccak(raw_manifest) == manifest_digest,
                f"{name}: workflow manifest digest does not match the preserved manifest")
        input_bindings_digest = _bytes32(case.get("inputBindingsDigest"),
                                         f"{name}.inputBindingsDigest")
        material = None if case_materials is None else case_materials.get(name)
        if case_materials is not None:
            material = _object(material, f"{name}.rawMaterial")
            bindings, reconstructed_bindings_digest = _abi_bytes32_array_digest(
                material.get("inputBindings"), f"{name}.rawMaterial.inputBindings")
            require(reconstructed_bindings_digest == input_bindings_digest,
                    f"{name}: input-binding digest does not match preserved owner inputs")
        if half == "linear":
            linear_witness_digest = _bytes32(case.get("linearWitnessDigest"),
                                             f"{name}.linearWitnessDigest")
            if material is not None:
                witness_bytes = material.get("linearWitnessBytes")
                require(isinstance(witness_bytes, bytes) and witness_bytes,
                        f"{name}: linear witness bytes are missing")
                require(_keccak256(witness_bytes) == linear_witness_digest,
                        f"{name}: linear witness digest does not match preserved evidence")
                try:
                    witness = json.loads(witness_bytes.decode("utf-8"),
                                         object_pairs_hook=_no_duplicate_object,
                                         parse_constant=lambda token: (_ for _ in ()).throw(
                                             EvidenceError(
                                                 f"non-finite number in {name} linear witness: {token}")))
                except (UnicodeError, json.JSONDecodeError) as error:
                    raise EvidenceError(f"{name}: invalid linear witness JSON: {error}") from error
                witness = _object(witness, f"{name}.linearWitness")
                require(set(witness) == {"schema", "inputPreparationAssumption", "plan", "vectors"}
                        and witness.get("schema") == "vcfhe-linear-release-witness-v1"
                        and witness.get("inputPreparationAssumption")
                        == "honest-owner-preparation-required"
                        and witness.get("plan") == case.get("plan"),
                        f"{name}: linear witness metadata differs from the measured case")
                vectors = _array(witness.get("vectors"), f"{name}.linearWitness.vectors")
                require(len(vectors) == _uint(case.get("n"), f"{name}.n"),
                        f"{name}: linear witness does not cover every input vector")
                witness_bindings = []
                width = None
                scalar_modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617
                for vector_index, raw_vector in enumerate(vectors):
                    vector = _object(raw_vector, f"{name}.linearWitness.vectors[{vector_index}]")
                    require(set(vector) == {"coordsDigest", "coordinates"},
                            f"{name}: linear witness vector has unexpected fields")
                    coordinates = _array(vector.get("coordinates"),
                                         f"{name}.linearWitness.vectors[{vector_index}].coordinates")
                    require(coordinates and (width is None or len(coordinates) == width),
                            f"{name}: linear witness vector width changed")
                    width = len(coordinates)
                    scalars = []
                    for coordinate_index, coordinate in enumerate(coordinates):
                        label = (f"{name}.linearWitness.vectors[{vector_index}]"
                                 f".coordinates[{coordinate_index}]")
                        require(isinstance(coordinate, str)
                                and re.fullmatch(r"0|[1-9][0-9]*", coordinate) is not None,
                                f"{label} is not a canonical field element")
                        scalar = int(coordinate)
                        require(scalar < (1 << 64), f"{label} is outside the core's uint64 coordinate domain")
                        require(scalar < scalar_modulus, f"{label} is outside the scalar field")
                        scalars.append(scalar)
                    reconstructed = _keccak256(
                        b"".join(scalar.to_bytes(32, "big") for scalar in scalars))
                    claimed = _bytes32(vector.get("coordsDigest"),
                                       f"{name}.linearWitness.vectors[{vector_index}].coordsDigest")
                    require(reconstructed == claimed,
                            f"{name}: linear witness coordinate digest is incorrect")
                    witness_bindings.append(claimed)
                require(witness_bindings == bindings,
                        f"{name}: linear witness vectors differ from the authorized input bindings")
        else:
            require(case.get("linearWitnessDigest") is None,
                    f"{name}: nonlinear case carries a linear witness")
            if material is not None:
                require(material.get("linearWitnessBytes") is None,
                        f"{name}: nonlinear raw evidence carries a linear witness")
            linear_witness_digest = None
        n = _uint(case.get("n"), f"{name}.n")
        record_ids = [_bytes32(value, f"{name}.recordIds")
                      for value in _array(case.get("recordIds"), f"{name}.recordIds")]
        owners = [_address(value, f"{name}.owners")
                  for value in _array(case.get("owners"), f"{name}.owners")]
        references = [_bytes32(value, f"{name}.recordReferences")
                      for value in _array(case.get("recordReferences"), f"{name}.recordReferences")]
        limits = [_uint(value, f"{name}.releaseLimits", 64)
                  for value in _array(case.get("releaseLimits"), f"{name}.releaseLimits")]
        initial = [_uint(value, f"{name}.initialSpent", 64)
                   for value in _array(case.get("initialSpent"), f"{name}.initialSpent")]
        require(n > 0 and all(len(values) == n for values in (record_ids, owners, references, limits, initial)),
                f"{name}: protected-record arrays do not match n")
        require(len(set(record_ids)) == n, f"{name}: protected records are duplicated")
        owner_set = set(owners)
        for record_id, owner, reference, limit, spent in zip(
                record_ids, owners, references, limits, initial, strict=True):
            require(limit > 0 and spent <= limit, f"{name}: invalid record budget")
            claim = (owner, reference, limit, spent)
            if record_id in record_claims:
                require(record_claims[record_id] == claim, f"{name}: record metadata changed across cases")
            else:
                record_claims[record_id] = claim
            charges[record_id] += 1

        consent_id = _bytes32(case.get("consentId"), f"{name}.consentId")
        request_id = _bytes32(case.get("releaseRequestId"), f"{name}.releaseRequestId")
        request_key = _bytes32(case.get("requestKey"), f"{name}.requestKey")
        submit_digest = _bytes32(case.get("submitWireDigest"), f"{name}.submitWireDigest")
        result_digest = _bytes32(case.get("resultQueryDigest"), f"{name}.resultQueryDigest")
        output_digest = _bytes32(case.get("outputDigest"), f"{name}.outputDigest")
        aggregate_digest = _bytes32(case.get("aggregateDigest"), f"{name}.aggregateDigest")
        recipient_key_digest = _bytes32(case.get("recipientEncryptionKeyDigest"),
                                        f"{name}.recipientEncryptionKeyDigest")
        recipient = _address(case.get("recipient"), f"{name}.recipient")
        slot = _bytes32(case.get("releaseSlot"), f"{name}.releaseSlot")
        reservation_tx = _bytes32(case.get("reservationTransaction"), f"{name}.reservationTransaction")
        reservation_hash = _bytes32(case.get("reservationBlockHash"), f"{name}.reservationBlockHash")
        require(request_key == result_digest, f"{name}: request key and result-query digest diverge")
        require(_bytes32(result.get("outputDigest"), f"{name}.result.outputDigest") == output_digest,
                f"{name}: delivered ciphertext differs from the case output")

        delivered = _object(result.get("onChainRelease"), f"{name}.onChainRelease")
        links = {
            "policy": policy, "policyDomain": policy_domain, "consentId": consent_id,
            "requestId": request_id, "requestKey": request_key, "submitWireDigest": submit_digest,
            "resultQueryDigest": result_digest, "recipientEncryptionKeyDigest": recipient_key_digest,
            "recipient": recipient, "slot": slot, "reservationTransaction": reservation_tx,
            "reservationBlockHash": reservation_hash,
        }
        for field, expected in links.items():
            actual = (_address(delivered.get(field), f"{name}.onChainRelease.{field}")
                      if field in {"policy", "recipient"}
                      else _bytes32(delivered.get(field), f"{name}.onChainRelease.{field}"))
            require(actual == expected, f"{name}: recipient evidence changed {field}")
        reservation_block = _uint(delivered.get("reservationBlock"),
                                  f"{name}.onChainRelease.reservationBlock")
        created = matching("ConsentCreated", consentId=consent_id)
        proposed = matching("ReleaseProposed", requestId=request_id)
        reserved = matching("ReleaseReserved", requestId=request_id)
        require(len(created) == len(proposed) == len(reserved) == 1,
                f"{name}: missing or duplicate policy lifecycle event")
        created, proposed, reserved = created[0], proposed[0], reserved[0]
        create_args, propose_args, reserve_args = created["args"], proposed["args"], reserved["args"]
        require(create_args["recipient"] == recipient and create_args["slot"] == slot,
                f"{name}: consent recipient or slot mismatch")
        require(create_args["workflowKind"] == (1 if half == "linear" else 2)
                and create_args["workflow"] != ZERO_ADDRESS and create_args["taskId"] != ZERO32,
                f"{name}: consent workflow mismatch")
        require(manifest["workflow"] == create_args["workflow"],
                f"{name}: workflow manifest address differs from owner consent")
        require(create_args["recordCount"] == n and create_args["requiredOwnerCount"] == len(owner_set),
                f"{name}: consent owner or record count mismatch")
        require(propose_args["consentId"] == consent_id and propose_args["requestKey"] == request_key
                and propose_args["releaseDigest"] != ZERO32,
                f"{name}: proposal is not bound to the consent/request")
        reserved_links = {
            "consentId": consent_id, "requestKey": request_key, "submitWireDigest": submit_digest,
            "resultQueryDigest": result_digest, "finalOutputDigest": output_digest,
            "aggregateDigest": aggregate_digest,
            "recipientEncryptionKeyDigest": recipient_key_digest, "recipient": recipient, "slot": slot,
        }
        require(all(reserve_args[field] == expected for field, expected in reserved_links.items()),
                f"{name}: reservation fields differ from the authorized release")
        require(reserved["transactionHash"] == reservation_tx and reserved["blockHash"] == reservation_hash
                and reserved["blockNumber"] == reservation_block,
                f"{name}: reservation receipt identity mismatch")

        expected_calls = None
        expected_consent_state = None
        if refresh:
            submit = _normalize_submit(case.get("submitAuthorization"),
                                       f"{name}.submitAuthorization")
            expected_common = {
                "requestId": request_id, "requestKey": request_key,
                "submitWireDigest": submit_digest, "consentId": consent_id,
                "finalOutputDigest": output_digest, "aggregateDigest": aggregate_digest,
                "recipientEncryptionKeyDigest": recipient_key_digest,
                "recipient": recipient, "workflow": manifest["workflow"],
                "chainId": chain_id, "policyDomain": policy_domain, "policy": policy,
                "slot": slot, "workflowKind": workflow_kind,
                "taskId": create_args["taskId"], "inputBindingsDigest": input_bindings_digest,
            }
            for field, expected_value in expected_common.items():
                require(submit[field] == expected_value,
                        f"{name}: submit authorization changed {field}")
            assert keyset is not None
            for field in ("keyId", "keyEpoch", "mpcContext", "keysetDigest"):
                require(submit[field] == _bytes32(keyset.get(field), f"keyset.{field}"),
                        f"{name}: submit authorization uses a different KMS keyset")
            expected_output_type = _keccak256(
                f"VCFHE_OUTPUT_TYPE_V1:{'uint16' if half == 'linear' else 'bool'}".encode())
            require(submit["outputType"] == expected_output_type,
                    f"{name}: submit authorization has the wrong output type")
            if half == "nonlinear":
                assert material is not None
                require(submit["contextDigest"] == material.get("contextDigest")
                        and submit["programDigest"] == material.get("programDigest")
                        and submit["profileDigest"] == material.get("profileDigest"),
                        f"{name}: authorized nonlinear context differs from sealed canonical bytes")
                computed_root = _program_root(submit["taskId"],
                                              _object(material.get("program"), f"{name}.program"),
                                              f"{name}.program")
                require(submit["programRoot"] == computed_root,
                        f"{name}: authorized program root differs from sealed canonical program")
                require(output_digest == material.get("terminalHandle")
                        and aggregate_digest == material.get("terminalHandle"),
                        f"{name}: authorized nonlinear output is not the sealed terminal ciphertext")
                protected_inputs = [_bytes32(value, f"{name}.inputProtectedRecordIds")
                                    for value in _array(material.get("inputProtectedRecordIds"),
                                                        f"{name}.inputProtectedRecordIds")]
                owner_by_record = dict(zip(record_ids, owners, strict=True))
                input_root, padded_count = _consent_input_root(
                    submit["taskId"], protected_inputs, bindings, owner_by_record, name)
                actual_count = len(bindings)
            else:
                assert material is not None
                require(submit["taskId"] == material.get("taskId")
                        and submit["contextDigest"] == material.get("contextDigest")
                        and submit["profileDigest"] == material.get("profileDigest")
                        and submit["programDigest"] == material.get("programDigest")
                        and submit["programRoot"] == material.get("programRoot"),
                        f"{name}: authorized linear context differs from sealed witness, keyset, and workflow")
                require(output_digest == material.get("outputDigest")
                        and aggregate_digest == material.get("aggregateDigest"),
                        f"{name}: authorized linear output or aggregate differs from sealed bytes")
                input_root, actual_count, padded_count = ZERO32, 0, 0
            expected_consent_state = {
                "domain": policy_domain, "chainId": chain_id,
                "workflowKind": workflow_kind, "workflow": manifest["workflow"],
                "taskId": submit["taskId"], "contextDigest": submit["contextDigest"],
                "programDigest": submit["programDigest"], "programRoot": submit["programRoot"],
                "profileDigest": submit["profileDigest"], "keysetDigest": submit["keysetDigest"],
                "keyId": submit["keyId"], "keyEpoch": submit["keyEpoch"],
                "mpcContext": submit["mpcContext"], "outputType": submit["outputType"],
                "recipient": recipient, "slot": slot, "inputRoot": input_root,
                "inputBindingsDigest": input_bindings_digest, "recordCount": n,
                "actualInputCount": actual_count, "paddedInputCount": padded_count,
                "requiredOwnerCount": len(owner_set), "approvalCount": len(owner_set),
                "exists": True,
            }
            expected_calls = _policy_call_evidence(
                submit, expected_consent_state, request_id, request_key, result_digest)
        case_confirmations = _confirmations(
            case.get("validatorConfirmations"), f"{name}.validatorConfirmations",
            reservation_block, reservation_hash, runtime_hash, chain_id,
            expected_policy_calls=expected_calls,
            expected_consent_state=expected_consent_state)
        result_confirmations = _confirmations(
            delivered.get("validatorConfirmations"),
            f"{name}.onChainRelease.validatorConfirmations", reservation_block,
            reservation_hash, runtime_hash, chain_id,
            expected_policy_calls=expected_calls,
            expected_consent_state=expected_consent_state)
        require(case_confirmations == result_confirmations,
                f"{name}: case and recipient validator observations differ")

        consent_approvals = matching("ConsentApproved", consentId=consent_id)
        release_approvals = matching("ReleaseApproved", requestId=request_id)
        require(len(consent_approvals) == len(release_approvals) == len(owner_set),
                f"{name}: approval event count does not cover affected owners")
        require({row["args"]["owner"] for row in consent_approvals} == owner_set
                and {row["args"]["owner"] for row in release_approvals} == owner_set,
                f"{name}: an unaffected owner approved or an affected owner is missing")
        ordered_consent = sorted(consent_approvals, key=_event_position)
        ordered_release = sorted(release_approvals, key=_event_position)
        require([row["args"]["approvalCount"] for row in ordered_consent]
                == list(range(1, len(owner_set) + 1)), f"{name}: consent approval count is discontinuous")
        require([row["args"]["approvalCount"] for row in ordered_release]
                == list(range(1, len(owner_set) + 1)), f"{name}: release approval count is discontinuous")
        require(all(row["args"]["releaseDigest"] == propose_args["releaseDigest"]
                    for row in release_approvals),
                f"{name}: an owner approval names a different release digest")
        require(_event_position(created) < _event_position(ordered_consent[0])
                and _event_position(ordered_consent[-1]) < _event_position(proposed)
                and _event_position(proposed) < _event_position(ordered_release[0])
                and _event_position(ordered_release[-1]) < _event_position(reserved),
                f"{name}: policy lifecycle events are out of order")

        _match_receipt(created, receipts, "create-release-consent", policy)
        _match_receipt(proposed, receipts, "propose-exact-release", policy)
        _match_receipt(reserved, receipts, "reserve-exact-release", policy)
        for approval in consent_approvals:
            _match_receipt(approval, receipts, "approve-release-consent", policy,
                           approval["args"]["owner"])
        for approval in release_approvals:
            _match_receipt(approval, receipts, "approve-exact-release", policy,
                           approval["args"]["owner"])

        names.append(name)
        consent_ids.append(consent_id)
        request_ids.append(request_id)
        request_keys.append(request_key)
        slots.append(slot)
        reservation_transactions.append(reservation_tx)
        case_summaries.append({
            "name": name, "consentId": consent_id, "requestId": request_id,
            "requestKey": request_key, "slot": slot, "recipient": recipient,
            "reservationTransaction": reservation_tx, "reservationBlock": reservation_block,
            "reservationBlockHash": reservation_hash, "affectedOwners": len(owner_set),
            "protectedRecords": n, "workflowKind": workflow_kind,
            "workflowManifestDigest": manifest_digest,
            "inputBindingsDigest": input_bindings_digest,
            "linearWitnessDigest": linear_witness_digest,
        })

    for values, label in ((names, "case names"), (consent_ids, "consent ids"),
                          (request_ids, "request ids"), (request_keys, "request keys"),
                          (slots, "release slots"),
                          (reservation_transactions, "reservation transactions")):
        _unique(values, label)
    if case_materials is not None:
        require(set(case_materials) == set(names),
                "raw input-binding evidence does not cover exactly the released cases")

    # Every lifecycle event must belong to exactly one reported case.  Optional
    # registration events can be absent for records migrated before this run.
    require(len(by_name["ConsentCreated"]) == len(cases)
            and len(by_name["ReleaseProposed"]) == len(cases)
            and len(by_name["ReleaseReserved"]) == len(cases),
            "report contains an unreported consent or release")
    require(len(by_name["ConsentApproved"]) == sum(row["affectedOwners"] for row in case_summaries)
            and len(by_name["ReleaseApproved"]) == sum(row["affectedOwners"] for row in case_summaries),
            "report contains an unreported owner approval")

    baselines = _normalized_record_map(app.get("protectedRecordBaselines"), "protectedRecordBaselines")
    final_records = _normalized_record_map(app.get("protectedRecords"), "protectedRecords")
    require(set(baselines) == set(final_records) == set(record_claims),
            "protected-record snapshots do not cover exactly the released records")
    for record_id, (owner, reference, limit, initial_spent) in record_claims.items():
        before, after = baselines[record_id], final_records[record_id]
        for snapshot, label in ((before, "baseline"), (after, "final")):
            require(_address(snapshot.get("owner"), f"{record_id}.{label}.owner") == owner,
                    f"{record_id}: {label} owner mismatch")
            require(_bytes32(snapshot.get("recordReference"), f"{record_id}.{label}.recordReference")
                    == reference, f"{record_id}: {label} reference mismatch")
            require(_uint(snapshot.get("releaseLimit"), f"{record_id}.{label}.releaseLimit", 64)
                    == limit, f"{record_id}: {label} release limit mismatch")
        baseline_spent = _uint(before.get("spent"), f"{record_id}.baseline.spent", 64)
        final_spent = _uint(after.get("spent"), f"{record_id}.final.spent", 64)
        require(baseline_spent >= initial_spent, f"{record_id}: on-chain spend regressed below migration")
        require(final_spent == baseline_spent + charges[record_id],
                f"{record_id}: final spend does not equal baseline plus reservations")
        require(final_spent <= limit, f"{record_id}: final spend exceeds release limit")

    registrations = by_name.get("ProtectedRecordRegistered", [])
    registered_ids: set[str] = set()
    for event in registrations:
        args = event["args"]
        record_id = args["protectedId"]
        require(record_id in baselines and record_id not in registered_ids,
                "registration event is duplicate or outside the released record set")
        registered_ids.add(record_id)
        baseline = baselines[record_id]
        require(args["owner"] == _address(baseline["owner"], "baseline.owner")
                and args["recordReference"] == _bytes32(baseline["recordReference"], "baseline.recordReference")
                and args["releaseLimit"] == _uint(baseline["releaseLimit"], "baseline.releaseLimit", 64)
                and args["initialSpent"] == _uint(baseline["spent"], "baseline.spent", 64),
                "registration event differs from the first on-chain snapshot")
        _match_receipt(event, receipts, "protected-record-registration", policy, args["owner"])

    canonical_input = json.dumps({"application": app, "recipientResults": results,
                                  "expectedOutputs": expected_outputs},
                                 sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                                 allow_nan=False).encode()
    result = {
        "schema": SCHEMA,
        "status": "passed",
        "policyVersion": 3,
        "policy": policy,
        "policyDomain": policy_domain,
        "runtimeCodeHash": runtime_hash,
        "chainId": chain_id,
        "validatorCount": 4,
        "caseCount": len(cases),
        "consentApprovalCount": len(by_name["ConsentApproved"]),
        "releaseApprovalCount": len(by_name["ReleaseApproved"]),
        "protectedRecordCount": len(final_records),
        "rawInputBindingsRecomputed": case_materials is not None,
        "inputSha256": hashlib.sha256(canonical_input).hexdigest(),
        "cases": case_summaries,
        "validatorConfirmationQuorum": 3,
        "scope": "V3 on-chain consent, exact release reservation, 3-of-4 validator confirmation, and delivered-result reconciliation",
    }
    if owners_sha256 is not None:
        result["ownerIdentitySetSha256"] = owners_sha256
    return result


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> Any:
    require(path.is_file(), f"missing evidence file: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_object,
                          parse_constant=lambda token: (_ for _ in ()).throw(
                              EvidenceError(f"non-finite JSON number in {path}: {token}")))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read strict JSON {path}: {error}") from error


def _relative_name(run: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(run).as_posix()
    except ValueError as error:
        raise EvidenceError(f"evidence path escapes the run directory: {path}") from error


def _sealed_bytes(run: Path, relative: str, sealed_files: Mapping[str, Any] | None) -> bytes:
    path = (run / relative).resolve()
    name = _relative_name(run, path)
    require(path.is_file(), f"missing evidence file: {path}")
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"cannot read evidence file {path}: {error}") from error
    if sealed_files is not None:
        expected = sealed_files.get(name)
        require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
                f"strict validator input is absent from the seal: {name}")
        require(hashlib.sha256(payload).hexdigest() == expected,
                f"strict validator input differs from its seal: {name}")
    return payload


def _sealed_json(run: Path, relative: str, sealed_files: Mapping[str, Any] | None) -> Any:
    payload = _sealed_bytes(run, relative, sealed_files)
    try:
        return json.loads(payload.decode("utf-8"), object_pairs_hook=_no_duplicate_object,
                          parse_constant=lambda token: (_ for _ in ()).throw(
                              EvidenceError(f"non-finite JSON number in {relative}: {token}")))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read strict JSON {relative}: {error}") from error


def _sealed_keccak_many(run: Path, relatives: Sequence[str],
                         sealed_files: Mapping[str, Any] | None) -> dict[str, str]:
    """Verify sealed SHA-256 bytes, then hash the same files with Keccak in Node."""
    names: list[str] = []
    paths: list[Path] = []
    for relative in relatives:
        require(isinstance(relative, str) and relative.replace("\\", "/") == relative,
                "Keccak input path is not canonical")
        path = (run / relative).resolve()
        name = _relative_name(run, path)
        require(name == relative and path.is_file(), f"missing evidence file: {path}")
        if sealed_files is not None:
            expected = sealed_files.get(name)
            require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
                    f"strict validator input is absent from the seal: {name}")
            digest = hashlib.sha256()
            try:
                with path.open("rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
            except OSError as error:
                raise EvidenceError(f"cannot read evidence file {path}: {error}") from error
            require(digest.hexdigest() == expected,
                    f"strict validator input differs from its seal: {name}")
        names.append(name)
        paths.append(path)
    require(len(names) == len(set(names)), "duplicate Keccak input path")
    helper = Path(__file__).with_name("keccak-files.mjs")
    require(helper.is_file(), "missing pinned Keccak file helper")
    try:
        completed = subprocess.run(
            ["node", str(helper)], input=json.dumps([str(path) for path in paths]),
            text=True, capture_output=True, check=False, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvidenceError(f"cannot hash sealed binary evidence: {error}") from error
    require(completed.returncode == 0,
            f"sealed binary Keccak helper failed: {completed.stderr.strip()}")
    try:
        values = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise EvidenceError("sealed binary Keccak helper returned invalid JSON") from error
    require(isinstance(values, list) and len(values) == len(names),
            "sealed binary Keccak helper returned the wrong number of hashes")
    return {name: _bytes32(value, f"Keccak({name})", nonzero=False)
            for name, value in zip(names, values, strict=True)}


def _static_abi(types: Sequence[str], values: Sequence[Any], label: str) -> bytes:
    require(len(types) == len(values), f"{label}: ABI arity mismatch")
    return bytes.fromhex("".join(_word(kind, value, f"{label}.{index}")
                                 for index, (kind, value) in enumerate(
                                     zip(types, values, strict=True))))


def _call_data(signature: str, types: Sequence[str], values: Sequence[Any], label: str) -> str:
    selector = _keccak256(signature.encode("ascii"))[2:10]
    return "0x" + selector + _static_abi(types, values, label).hex()


def _constant_handle(value: Any, label: str) -> str:
    number = _uint(value, label, 256)
    return "0x" + number.to_bytes(32, "big").hex()


def _compile_compliance_program(record_count: int, regional: bool,
                                target_cell: int) -> dict[str, Any]:
    require(record_count >= 2, "canonical compliance circuit requires at least two records")
    require(target_cell >= 0, "canonical target cell is negative")
    inputs: list[dict[str, Any]] = []
    instructions: list[dict[str, Any]] = []

    def constant(value: int) -> dict[str, str]:
        return {"kind": "constant", "value": str(value)}

    def source(identifier: str) -> dict[str, Any]:
        result = {"kind": "input", "index": len(inputs)}
        inputs.append({"id": identifier, "type": "uint64"})
        return result

    def emit(opcode: str, lhs: Mapping[str, Any], rhs: Mapping[str, Any]) -> dict[str, Any]:
        result = {"kind": "output", "index": len(instructions)}
        instructions.append({"index": result["index"], "opcode": opcode,
                             "lhs": dict(lhs), "rhs": dict(rhs)})
        return result

    def sum_tree(values: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        layer = [dict(value) for value in values]
        size = 1
        while size < len(layer):
            size *= 2
        while len(layer) < size:
            layer.append(constant(0))
        while len(layer) > 1:
            layer = [emit("ADD", layer[index], layer[index + 1])
                     for index in range(0, len(layer), 2)]
        return layer[0]

    ratings = [source(f"rating:{index}") for index in range(record_count)]
    cells = ([source(f"cell:{index}") for index in range(record_count)]
             if regional else [])
    in_area = [emit("EQ", cell, constant(target_cell)) for cell in cells]
    good = [emit("GT", rating, constant(2000)) for rating in ratings]
    selected = ([emit("BITAND", in_area[index], bit)
                 for index, bit in enumerate(good)] if regional else good)
    count = sum_tree(in_area) if regional else constant(record_count)
    good_count = sum_tree(selected)
    scaled = emit("MUL", good_count, constant(1000))
    required = emit("MUL", count, constant(950))
    violation = emit("LT", scaled, required)
    result = emit("BITXOR", violation, constant(1))
    if regional:
        result = emit("BITAND", result, emit("GT", count, constant(0)))
    unpadded = len(instructions)
    size = 1
    while size < len(instructions):
        size *= 2
    while len(instructions) < size:
        result = emit("ADD", result, constant(0))
    return {"version": PROGRAM_VERSION, "integerDomain": "checked-uint64",
            "inputs": inputs, "instructions": instructions, "output": result,
            "unpaddedLength": unpadded,
            "predicate": ("nonempty-and-share-meets-target" if regional
                          else "share-meets-target")}


def _canonical_domain(program: Mapping[str, Any], bounds_value: Any,
                      label: str) -> dict[str, Any]:
    bounds = _array(bounds_value, f"{label}.inputBounds")
    inputs = _array(program.get("inputs"), f"{label}.program.inputs")
    require(len(bounds) == len(inputs), f"{label}: input-bound count mismatch")
    ranges: list[tuple[int, int]] = []
    normalized_bounds = []
    for index, raw in enumerate(bounds):
        row = _object(raw, f"{label}.inputBounds[{index}]")
        require(set(row) == {"min", "max"}, f"{label}: noncanonical input bound")
        low = _uint(row.get("min"), f"{label}.inputBounds[{index}].min", 64)
        high = _uint(row.get("max"), f"{label}.inputBounds[{index}].max", 64)
        require(low <= high, f"{label}: reversed input bound")
        ranges.append((low, high))
        normalized_bounds.append({"min": str(low), "max": str(high)})
    outputs: list[tuple[int, int]] = []

    def resolve(ref_value: Any, before: int) -> tuple[int, int]:
        ref = _object(ref_value, f"{label}.program.reference")
        kind = ref.get("kind")
        if kind == "constant":
            value = _uint(ref.get("value"), f"{label}.program.constant", 64)
            return value, value
        index = _uint(ref.get("index"), f"{label}.program.reference.index")
        if kind == "input":
            require(index < len(ranges), f"{label}: input reference out of range")
            return ranges[index]
        require(kind == "output" and index < before, f"{label}: invalid output reference")
        return outputs[index]

    for index, raw in enumerate(_array(program.get("instructions"),
                                       f"{label}.program.instructions")):
        instruction = _object(raw, f"{label}.program.instructions[{index}]")
        require(_uint(instruction.get("index"), f"{label}.instruction.index") == index,
                f"{label}: noncanonical instruction index")
        a, upper_a = resolve(instruction.get("lhs"), index)
        b, upper_b = resolve(instruction.get("rhs"), index)
        opcode = instruction.get("opcode")
        if opcode == "ADD": result = (a + b, upper_a + upper_b)
        elif opcode == "SUB":
            require(a >= upper_b, f"{label}: possible subtraction underflow")
            result = (a - upper_b, upper_a - b)
        elif opcode == "MUL": result = (a * b, upper_a * upper_b)
        elif opcode in {"DIV", "MOD"}:
            require(b == upper_b and b != 0, f"{label}: invalid public divisor")
            result = ((a // b, upper_a // b) if opcode == "DIV"
                      else (0, min(upper_a, b - 1)))
        elif opcode == "SHR":
            require(b == upper_b and b < 64, f"{label}: invalid public shift")
            result = (a >> b, upper_a >> b)
        elif opcode == "ADD_CHAIN":
            require(b == upper_b and 1 <= b <= 8, f"{label}: invalid public chain")
            result = (a + b, upper_a + b)
        elif opcode in {"EQ", "GT", "LT"}: result = (0, 1)
        elif opcode == "MIN": result = (min(a, b), min(upper_a, upper_b))
        elif opcode == "BITAND": result = (0, min(upper_a, upper_b))
        elif opcode in {"BITOR", "BITXOR"}:
            width = max(upper_a, upper_b).bit_length()
            result = (0, (1 << width) - 1)
        elif opcode == "CAST_U8": result = ((a, upper_a) if upper_a < 256 else (0, 255))
        else: raise EvidenceError(f"{label}: unsupported opcode {opcode}")
        require(result[1] <= UINT64_MAX, f"{label}: possible uint64 overflow")
        outputs.append(result)
    return {"version": DOMAIN_VERSION, "inputBounds": normalized_bounds,
            "outputBounds": [{"min": str(low), "max": str(high)}
                             for low, high in outputs],
            "assumption": DOMAIN_ASSUMPTION}


_PROGRAM_OPCODES = {"MUL": 1, "SHR": 2, "CAST_U8": 3, "MIN": 4,
                    "BITAND": 5, "ADD": 6, "SUB": 7, "DIV": 8, "MOD": 9,
                    "EQ": 10, "LT": 11, "GT": 12, "BITOR": 13,
                    "BITXOR": 14, "ADD_CHAIN": 15}
_PROGRAM_LEAF_TYPEHASH = _keccak256(
    b"FHE_POD_PROGRAM_LEAF_V1(bytes32 taskId,uint32 leafIndex,uint8 opcode,uint8 lhsSourceKind,uint32 lhsSourceIndex,uint8 rhsSourceKind,uint32 rhsSourceIndex,uint256 lhsConstant,uint256 rhsConstant)")
_INPUT_RECORD_TYPEHASH = _keccak256(
    b"FHE_POD_INPUT_RECORD_V1(address owner,bytes32 ciphertextHandle,bytes32 metadataHash)")


def _program_root(task_id: str, program: Mapping[str, Any], label: str) -> str:
    instructions = _array(program.get("instructions"), f"{label}.instructions")
    require(instructions and len(instructions) & (len(instructions) - 1) == 0,
            f"{label}: instruction count is not a power of two")

    def source(ref_value: Any, before: int) -> tuple[int, int, int]:
        ref = _object(ref_value, f"{label}.reference")
        kind = ref.get("kind")
        require(kind in {"input", "output", "constant"}, f"{label}: invalid source")
        if kind == "constant":
            return 2, 0, _uint(ref.get("value"), f"{label}.constant", 256)
        index = _uint(ref.get("index"), f"{label}.source.index", 32)
        require(kind != "output" or index < before, f"{label}: forward output reference")
        return (0 if kind == "input" else 1), index, 0

    level = []
    for index, raw in enumerate(instructions):
        row = _object(raw, f"{label}[{index}]")
        require(_uint(row.get("index"), f"{label}[{index}].index") == index
                and row.get("opcode") in _PROGRAM_OPCODES,
                f"{label}: invalid canonical instruction")
        lhs_kind, lhs_index, lhs_constant = source(row.get("lhs"), index)
        rhs_kind, rhs_index, rhs_constant = source(row.get("rhs"), index)
        types = ["bytes32", "bytes32", "uint32", "uint8", "uint8", "uint32",
                 "uint8", "uint32", "uint256", "uint256"]
        values = [_PROGRAM_LEAF_TYPEHASH, task_id, index, _PROGRAM_OPCODES[row["opcode"]],
                  lhs_kind, lhs_index, rhs_kind, rhs_index, lhs_constant, rhs_constant]
        level.append(_keccak256(_static_abi(types, values, f"{label}[{index}]")))
    while len(level) > 1:
        level = [_keccak256(bytes.fromhex(level[index][2:] + level[index + 1][2:]))
                 for index in range(0, len(level), 2)]
    return level[0]


def _abi_string_metadata(task_id: str, index: int, value: str) -> bytes:
    encoded = value.encode("utf-8")
    padding = b"\x00" * ((32 - len(encoded) % 32) % 32)
    return (_static_abi(["bytes32", "uint32", "uint256"],
                        [task_id, index, 96], "input metadata head")
            + len(encoded).to_bytes(32, "big") + encoded + padding)


def _linear_dataset_tag(chain_id: int, workflow: str, key_epoch: str,
                        profile_digest: str, keyset_digest: str,
                        count: int, operation: int) -> str:
    """Reproduce abi.encode(string,uint256,address,bytes32,bytes32,bytes32,uint64,uint8)."""
    domain = b"VCFHE-LINEAR-GROUPED-V1"
    tail = len(domain).to_bytes(32, "big") + domain + b"\x00" * (32 - len(domain))
    head = _static_abi(
        ["uint256", "uint256", "address", "bytes32", "bytes32", "bytes32",
         "uint64", "uint8"],
        [8 * 32, chain_id, workflow, key_epoch, profile_digest, keyset_digest,
         count, operation], "linear dataset tag")
    return _keccak256(head + tail)


def _consent_input_root(task_id: str, protected_ids: Sequence[str],
                        bindings: Sequence[str], owner_by_record: Mapping[str, str],
                        label: str) -> tuple[str, int]:
    require(0 < len(bindings) == len(protected_ids) <= 128,
            f"{label}: invalid consent input list")
    leaves = []
    for index, (record, binding) in enumerate(zip(protected_ids, bindings, strict=True)):
        owner = owner_by_record.get(record)
        require(owner is not None, f"{label}: input record has no owner")
        metadata = _keccak256(_abi_string_metadata(task_id, index, "record"))
        leaves.append(_keccak256(_static_abi(
            ["bytes32", "address", "bytes32", "bytes32"],
            [_INPUT_RECORD_TYPEHASH, owner, binding, metadata], f"{label}.leaf")))
    padded = 1
    while padded < len(leaves):
        padded *= 2
    padding_owner = owner_by_record[protected_ids[0]]
    for index in range(len(leaves), padded):
        handle = _keccak256(b"VCFHE_INPUT_TREE_PADDING" + bytes.fromhex(task_id[2:])
                            + index.to_bytes(4, "big"))
        metadata = _keccak256(_abi_string_metadata(task_id, index, "padding"))
        leaves.append(_keccak256(_static_abi(
            ["bytes32", "address", "bytes32", "bytes32"],
            [_INPUT_RECORD_TYPEHASH, padding_owner, handle, metadata], f"{label}.padding")))
    while len(leaves) > 1:
        leaves = [_keccak256(bytes.fromhex(leaves[index][2:] + leaves[index + 1][2:]))
                  for index in range(0, len(leaves), 2)]
    return leaves[0], padded


def _case_name(value: Any) -> str:
    require(isinstance(value, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value) is not None
            and ".." not in value,
            "case name is not a safe evidence-directory name")
    return value


def _validate_keyset(run: Path, cfg: Mapping[str, Any], app: Mapping[str, Any],
                     sealed_files: Mapping[str, Any] | None,
                     file_hashes: dict[str, str]) -> Mapping[str, Any]:
    ready = _object(_sealed_json(run, "keyset/ready.json", sealed_files), "keyset.ready")
    require(app.get("keys") == ready, "application keys differ from sealed keyset/ready.json")
    required = {"status", "parameters", "parties", "corruptionThreshold",
                "fullPreprocessing", "preloadedFheKey", "keyId", "keyEpoch",
                "mpcContext", "keysetDigest", "keyDescriptor", "upstreamCommit",
                "preprocessingSeconds", "dkgSeconds", "publicKeyPreparationSeconds"}
    require(set(ready) == required, "keyset/ready.json has unexpected or missing fields")
    require(ready.get("status") == "passed"
            and ready.get("parameters") == cfg.get("parameters")
            and _uint(ready.get("parties"), "keyset.parties") == 4
            and _uint(ready.get("corruptionThreshold"), "keyset.corruptionThreshold") == 1
            and ready.get("fullPreprocessing") is True
            and ready.get("preloadedFheKey") is False,
            "keyset does not describe the evaluated four-party preprocessing and DKG")
    for field in ("preprocessingSeconds", "dkgSeconds", "publicKeyPreparationSeconds"):
        value = ready.get(field)
        require(isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0,
                f"keyset.{field} is invalid")
    descriptor = _object(ready.get("keyDescriptor"), "keyset.keyDescriptor")
    require(set(descriptor) == {"encryptionKeyDigest", "evaluationKeyDigest", "parameters", "tfhe"}
            and descriptor.get("parameters") == cfg.get("parameters")
            and descriptor.get("tfhe") == "1.6.1",
            "keyset descriptor does not match the evaluated TFHE profile")
    names = ["keyset/encryption-key.bin", "keyset/evaluation-key.bin", "bin/kms-campaign"]
    missing = [name for name in names if name not in file_hashes]
    if missing:
        file_hashes.update(_sealed_keccak_many(run, missing, sealed_files))
    require(_bytes32(descriptor.get("encryptionKeyDigest"), "keyset.encryptionKeyDigest")
            == file_hashes["keyset/encryption-key.bin"],
            "keyset encryption-key digest differs from sealed bytes")
    require(_bytes32(descriptor.get("evaluationKeyDigest"), "keyset.evaluationKeyDigest")
            == file_hashes["keyset/evaluation-key.bin"],
            "keyset evaluation-key digest differs from sealed bytes")
    require(_bytes32(ready.get("keysetDigest"), "keyset.keysetDigest") == _json_keccak(descriptor),
            "keyset digest differs from the exact key descriptor")
    for field in ("keyId", "keyEpoch", "mpcContext"):
        _bytes32(ready.get(field), f"keyset.{field}")
    require(isinstance(ready.get("upstreamCommit"), str)
            and re.fullmatch(r"[0-9a-f]{40}", ready["upstreamCommit"]) is not None,
            "keyset upstream commit is invalid")
    for critical in ("build-evidence/vcfhe-adapter.json",
                     "build-evidence/installed-files.json.gz"):
        _sealed_bytes(run, critical, sealed_files)
    adapter = _object(_sealed_json(run, "build-evidence/vcfhe-adapter.json", sealed_files),
                      "build evidence adapter")
    require(adapter.get("upstreamCommit") == ready.get("upstreamCommit")
            and adapter.get("releaseAuthorization") == "on-chain-release-policy-v3-per-core-check",
            "build evidence does not identify the evaluated V3 KMS adapter")
    require(isinstance(adapter.get("files"), dict) and adapter["files"],
            "build evidence lacks adapted source files")
    return ready


def _strict_nonlinear_material(run: Path, case: Mapping[str, Any], name: str,
                               program_bytes: bytes, program: Mapping[str, Any],
                               context: Mapping[str, Any], manifest: Mapping[str, Any],
                               cfg: Mapping[str, Any], keyset: Mapping[str, Any],
                               sealed_files: Mapping[str, Any] | None,
                               file_hashes: dict[str, str]) -> dict[str, Any]:
    regional = case.get("regional")
    require(isinstance(regional, bool), f"{name}: nonlinear regional flag is missing")
    n = _uint(case.get("n"), f"{name}.n")
    expected_program = _compile_compliance_program(
        n, regional, _uint(cfg.get("targetCell"), "config.targetCell"))
    require(program == expected_program,
            f"{name}: preserved program differs from the canonical compliance compiler output")
    program_inputs = _array(program.get("inputs"), f"{name}.program.inputs")
    instructions = _array(program.get("instructions"), f"{name}.program.instructions")
    base = f"fixtures/{name}"
    paths = [f"{base}/public/encryption-key.bin", f"{base}/public/server-key.bin"]
    paths.extend(f"{base}/public/input-{index}.ct" for index in range(len(program_inputs)))
    paths.extend(f"{base}/honest/result-{index}.ct" for index in range(len(instructions)))
    missing = [path for path in paths if path not in file_hashes]
    if missing:
        file_hashes.update(_sealed_keccak_many(run, missing, sealed_files))
    descriptor = _object(keyset.get("keyDescriptor"), "keyset.keyDescriptor")
    encryption_digest = file_hashes[f"{base}/public/encryption-key.bin"]
    server_digest = file_hashes[f"{base}/public/server-key.bin"]
    require(encryption_digest == _bytes32(descriptor.get("encryptionKeyDigest"),
                                          "keyset.encryptionKeyDigest")
            and server_digest == _bytes32(descriptor.get("evaluationKeyDigest"),
                                          "keyset.evaluationKeyDigest"),
            f"{name}: case keys are not the sealed campaign keyset")
    require(set(context) == {"version", "profile", "inputEncryption", "encryptionKeyDigest",
                             "programDigest", "keyDigest", "keyEpoch", "policyDomain",
                             "inputs", "domain", "kmsKeyset"},
            f"{name}: canonical context has unexpected or missing fields")
    require(context.get("version") == CANONICAL_VERSION
            and context.get("inputEncryption") == INPUT_ENCRYPTION
            and context.get("policyDomain") == cfg.get("policyDomain")
            and _bytes32(context.get("encryptionKeyDigest"), f"{name}.context.encryptionKeyDigest")
            == encryption_digest
            and _bytes32(context.get("keyDigest"), f"{name}.context.keyDigest") == server_digest
            and _bytes32(context.get("keyEpoch"), f"{name}.context.keyEpoch")
            == _bytes32(keyset.get("keyEpoch"), "keyset.keyEpoch"),
            f"{name}: canonical context profile, keys, epoch, or policy domain changed")
    profile = _object(context.get("profile"), f"{name}.context.profile")
    require(set(profile) == {"version", "binaryDigest", "tfhe", "threads", "fixedFFT",
                             "arch", "os", "osRelease", "cpu"}
            and profile.get("version") == CANONICAL_VERSION
            and _bytes32(profile.get("binaryDigest"), f"{name}.profile.binaryDigest")
            == file_hashes["bin/kms-campaign"]
            and profile.get("tfhe") == "1.6.1"
            and profile.get("threads") == 1 and profile.get("fixedFFT") is True
            and all(isinstance(profile.get(field), str) and profile[field]
                    for field in ("arch", "os", "osRelease", "cpu")),
            f"{name}: canonical execution profile differs from the sealed implementation")
    expected_kms = {
        "encryptionKeyDigest": descriptor["encryptionKeyDigest"],
        "evaluationKeyDigest": descriptor["evaluationKeyDigest"],
        "keyEpoch": keyset["keyEpoch"], "keyId": keyset["keyId"],
        "keysetDigest": keyset["keysetDigest"], "mpcContext": keyset["mpcContext"],
        "parameters": keyset["parameters"], "tfhe": descriptor["tfhe"],
    }
    require(context.get("kmsKeyset") == expected_kms,
            f"{name}: context KMS keyset differs from sealed ready.json")
    require(_bytes32(context.get("programDigest"), f"{name}.context.programDigest")
            == _keccak256(program_bytes),
            f"{name}: program digest differs from exact sealed program bytes")
    context_inputs = [_object(value, f"{name}.context.inputs[{index}]")
                      for index, value in enumerate(_array(context.get("inputs"),
                                                          f"{name}.context.inputs"))]
    record_ids = [_bytes32(value, f"{name}.recordIds")
                  for value in _array(case.get("recordIds"), f"{name}.recordIds")]
    owners = [_address(value, f"{name}.owners")
              for value in _array(case.get("owners"), f"{name}.owners")]
    require(len(record_ids) == len(owners) == n and len(context_inputs) == len(program_inputs),
            f"{name}: canonical input cardinalities do not match the case")
    bindings = []
    protected_inputs = []
    for index, (actual, declared) in enumerate(zip(context_inputs, program_inputs, strict=True)):
        require(set(actual) == {"id", "protectedId", "owner", "handle"}
                and actual.get("id") == _object(declared, f"{name}.program.input").get("id"),
                f"{name}: context input metadata differs from the canonical program")
        record_index = index % n
        protected = _bytes32(actual.get("protectedId"), f"{name}.context.inputs.protectedId")
        owner = _address(actual.get("owner"), f"{name}.context.inputs.owner")
        handle = _bytes32(actual.get("handle"), f"{name}.context.inputs.handle")
        require(protected == record_ids[record_index] and owner == owners[record_index]
                and handle == file_hashes[f"{base}/public/input-{index}.ct"],
                f"{name}: context input is not the exact owner record and ciphertext")
        protected_inputs.append(protected)
        bindings.append(handle)
    expected_domain = _canonical_domain(program, case.get("inputBounds"), name)
    require(context.get("domain") == expected_domain,
            f"{name}: admitted public interval domain differs from canonical analysis")
    require(set(manifest) == {"boundary", "elapsedMs", "inputs", "leaves", "profile",
                              "programDigest", "publicDecisionsReleased", "serverKeyDigest",
                              "terminalHandle", "version"}
            and manifest.get("version") == CANONICAL_VERSION
            and manifest.get("boundary")
            == "public execution transcript; certificates require independent verification"
            and _uint(manifest.get("publicDecisionsReleased"),
                      f"{name}.manifest.publicDecisionsReleased") == 0
            and _uint(manifest.get("elapsedMs"), f"{name}.manifest.elapsedMs") >= 0
            and _bytes32(manifest.get("programDigest"), f"{name}.manifest.programDigest")
            == _keccak256(program_bytes)
            and _bytes32(manifest.get("serverKeyDigest"), f"{name}.manifest.serverKeyDigest")
            == server_digest,
            f"{name}: execution manifest header differs from sealed canonical inputs")
    rust_arch = "aarch64" if profile["arch"] == "arm64" else (
        "x86_64" if profile["arch"] == "x64" else profile["arch"])
    rust_os = "macos" if profile["os"] == "darwin" else profile["os"]
    require(manifest.get("profile") == {"arch": rust_arch,
                                        "binaryDigest": profile["binaryDigest"],
                                        "fixedFFT": True, "os": rust_os,
                                        "tfhe": "1.6.1", "threads": 1}
            and [_bytes32(value, f"{name}.manifest.inputs") for value in
                 _array(manifest.get("inputs"), f"{name}.manifest.inputs")] == bindings,
            f"{name}: execution manifest profile or inputs differ from the context")
    leaves = [_object(value, f"{name}.manifest.leaves[{index}]")
              for index, value in enumerate(_array(manifest.get("leaves"),
                                                   f"{name}.manifest.leaves"))]
    require(len(leaves) == len(instructions), f"{name}: execution manifest leaf count changed")
    result_handles: list[str] = []
    for index, (leaf, instruction) in enumerate(zip(leaves, instructions, strict=True)):
        require(set(leaf) == {"index", "lhs", "lhsHandle", "ms", "opcode", "resultHandle",
                              "rhs", "rhsHandle"}
                and leaf.get("index") == index and leaf.get("opcode") == instruction.get("opcode")
                and leaf.get("lhs") == instruction.get("lhs")
                and leaf.get("rhs") == instruction.get("rhs")
                and _uint(leaf.get("ms"), f"{name}.manifest.leaves[{index}].ms") >= 0,
                f"{name}: execution manifest leaf metadata changed")
        def resolve(ref_value: Any) -> str:
            ref = _object(ref_value, f"{name}.instruction.reference")
            if ref.get("kind") == "constant":
                return _constant_handle(ref.get("value"), f"{name}.constant")
            source_index = _uint(ref.get("index"), f"{name}.reference.index")
            if ref.get("kind") == "input":
                require(source_index < len(bindings), f"{name}: leaf input reference out of range")
                return bindings[source_index]
            require(ref.get("kind") == "output" and source_index < index,
                    f"{name}: leaf output reference is forward or invalid")
            return result_handles[source_index]
        result_handle = _bytes32(leaf.get("resultHandle"), f"{name}.leaf.resultHandle")
        require(_bytes32(leaf.get("lhsHandle"), f"{name}.leaf.lhsHandle", nonzero=False)
                == resolve(instruction.get("lhs"))
                and _bytes32(leaf.get("rhsHandle"), f"{name}.leaf.rhsHandle", nonzero=False)
                == resolve(instruction.get("rhs"))
                and result_handle == file_hashes[f"{base}/honest/result-{index}.ct"],
                f"{name}: execution manifest leaf does not match sealed ciphertext bytes")
        result_handles.append(result_handle)
    require(result_handles
            and _bytes32(manifest.get("terminalHandle"), f"{name}.manifest.terminalHandle")
            == result_handles[-1], f"{name}: terminal handle differs from the final sealed leaf")
    return {"inputBindings": bindings, "inputProtectedRecordIds": protected_inputs,
            "linearWitnessBytes": None, "program": program, "context": context,
            "contextDigest": _json_keccak(context), "profileDigest": _json_keccak(profile),
            "programDigest": _keccak256(program_bytes), "terminalHandle": result_handles[-1]}


def _load_case_material(run: Path, case: Mapping[str, Any],
                        sealed_files: Mapping[str, Any] | None, *,
                        strict: bool = False, cfg: Mapping[str, Any] | None = None,
                        keyset: Mapping[str, Any] | None = None,
                        file_hashes: dict[str, str] | None = None) -> dict[str, Any]:
    name = _case_name(case.get("name"))
    half = case.get("half")
    require(half in {"linear", "nonlinear"}, f"{name}: invalid workflow half")
    if half == "linear":
        digest = _bytes32(case.get("linearWitnessDigest"), f"{name}.linearWitnessDigest")
        witness_bytes = _sealed_bytes(
            run, f"release-evidence/{digest[2:]}.json", sealed_files)
        try:
            witness = json.loads(witness_bytes.decode("utf-8"),
                                 object_pairs_hook=_no_duplicate_object,
                                 parse_constant=lambda token: (_ for _ in ()).throw(
                                     EvidenceError(
                                         f"non-finite number in {name} linear witness: {token}")))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise EvidenceError(f"{name}: invalid linear witness JSON: {error}") from error
        witness = _object(witness, f"{name}.linearWitness")
        vectors = _array(witness.get("vectors"), f"{name}.linearWitness.vectors")
        fixture_coordinates = _sealed_json(
            run, f"fixtures/{name}/coordinates.json", sealed_files)
        owner_coordinates = _sealed_json(
            run, f"owner/{name}/coordinates.json", sealed_files)
        witness_coordinates = [
            _object(vector, f"{name}.linearWitness.vector").get("coordinates")
            for vector in vectors
        ]
        require(fixture_coordinates == owner_coordinates == witness_coordinates,
                f"{name}: owner, fixture, and release-witness coordinates differ")
        for index in range(len(vectors)):
            fixture_ciphertext = _sealed_bytes(
                run, f"fixtures/{name}/input-{index}.bin", sealed_files)
            owner_ciphertext = _sealed_bytes(
                run, f"owner/{name}/input-{index}.bin", sealed_files)
            require(fixture_ciphertext == owner_ciphertext,
                    f"{name}: public and owner-preserved linear ciphertext differ")
        result = {
            "inputBindings": [
                _object(vector, f"{name}.linearWitness.vector").get("coordsDigest")
                for vector in vectors
            ],
            "linearWitnessBytes": witness_bytes,
        }
        if strict:
            require(cfg is not None and keyset is not None and file_hashes is not None,
                    f"{name}: strict linear validation lacks campaign key material")
            plan = _object(case.get("plan"), f"{name}.plan")
            require(witness.get("plan") == plan, f"{name}: witness plan differs from case plan")
            count = _uint(case.get("n"), f"{name}.n")
            require(set(plan) == {"profile", "op", "bounds"}
                    and plan.get("profile") == "kms-grouped-radix-v1"
                    and plan.get("op") == "SUM"
                    and plan.get("bounds") == [[1, 5] for _ in range(count)],
                    f"{name}: linear plan differs from the evaluated SUM-of-ratings profile")
            refresh_plan = _object(cfg.get("policyRefreshPlan"), "config.policyRefreshPlan")
            if refresh_plan.get("profile") == "v3-policy-refresh-full-cases-v1":
                require(count in {10, 16, 27},
                        f"{name}: linear size is outside the frozen refresh design")
            coordinates = [_array(_object(vector, f"{name}.linearWitness.vector").get("coordinates"),
                                  f"{name}.linearWitness.coordinates") for vector in vectors]
            require(coordinates and coordinates[0], f"{name}: empty linear coordinate vectors")
            width = len(coordinates[0])
            require(width % 8 == 0 and all(len(row) == width for row in coordinates),
                    f"{name}: invalid grouped linear coordinate width")
            dimension = 9 * width
            profile = {**dict(plan), "dimension": dimension, "lweSize": width // 8,
                       "keyId": keyset.get("keyId"), "keysetDigest": keyset.get("keysetDigest"),
                       "binaryDigest": file_hashes["bin/kms-campaign"], "tfhe": "1.6.1",
                       "threads": 1, "fixedFFT": True}
            profile_digest = _policy_keccak(profile)
            raw_workflow_manifest = _object(case.get("workflowManifest"),
                                            f"{name}.workflowManifest")
            raw_workflow = raw_workflow_manifest.get("workflow")
            _address(raw_workflow, f"{name}.workflowManifest.workflow")
            manifest = _workflow_manifest(raw_workflow_manifest, "linear",
                                          f"{name}.workflowManifest")
            chain_id = _uint(cfg.get("chainId"), "config.chainId")
            require(count == len(vectors), f"{name}: witness vector count differs from n")
            dataset_tag = _linear_dataset_tag(
                chain_id, manifest["workflow"],
                _bytes32(keyset.get("keyEpoch"), "keyset.keyEpoch"), profile_digest,
                _bytes32(keyset.get("keysetDigest"), "keyset.keysetDigest"), count, 0)
            record_ids = [_bytes32(value, f"{name}.recordIds")
                          for value in _array(case.get("recordIds"), f"{name}.recordIds")]
            owners = [_address(value, f"{name}.owners")
                      for value in _array(case.get("owners"), f"{name}.owners")]
            require(len(record_ids) == len(owners) == count,
                    f"{name}: linear record map differs from n")
            context = {
                "profileDigest": profile_digest,
                "keysetDigest": _bytes32(keyset.get("keysetDigest"), "keyset.keysetDigest"),
                "datasetTag": dataset_tag,
                "records": [{"id": record, "owner": owner_raw}
                            for record, owner_raw in zip(record_ids,
                                                         _array(case.get("owners"), f"{name}.owners"),
                                                         strict=True)],
                "ownerCiphertextDigests": result["inputBindings"],
            }
            base = f"fixtures/{name}"
            paths = [f"{base}/aggregate.bin", f"{base}/output.bin"]
            missing = [path for path in paths if path not in file_hashes]
            if missing:
                file_hashes.update(_sealed_keccak_many(run, missing, sealed_files))
            aggregate_bytes = _sealed_bytes(run, f"{base}/aggregate.bin", sealed_files)
            require(len(aggregate_bytes) == dimension * 32,
                    f"{name}: aggregate byte length differs from grouped dimension")
            modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617
            aggregate_words = [int.from_bytes(aggregate_bytes[offset:offset + 32], "big")
                               for offset in range(0, len(aggregate_bytes), 32)]
            require(all(value < modulus for value in aggregate_words),
                    f"{name}: aggregate contains a noncanonical BN254 scalar")
            op = plan.get("op")
            require(op in {"SUM", "SUB"}, f"{name}: unsupported grouped linear operation")
            positive_count = count if op == "SUM" else 1
            negative_start = (positive_count + 3) // 4
            expected_aggregate = [0] * dimension
            positive = negative = 0
            for index, row in enumerate(coordinates):
                if op == "SUM" or index == 0:
                    group, sign = positive // 4, 1
                    positive += 1
                else:
                    group, sign = negative_start + negative // 4, -1
                    negative += 1
                require(group < 9, f"{name}: grouped linear layout overflow")
                for column, raw_coordinate in enumerate(row):
                    coordinate = _uint(raw_coordinate, f"{name}.coordinate", 64)
                    require(coordinate < modulus, f"{name}: coordinate is outside BN254 Fr")
                    position = group * width + column
                    expected_aggregate[position] = (
                        expected_aggregate[position] + sign * coordinate) % modulus
            require(aggregate_words == expected_aggregate,
                    f"{name}: aggregate.bin differs from the exact witness coordinates")
            program_digest = _policy_keccak(plan)
            result.update({
                "inputProtectedRecordIds": [], "profile": profile,
                "profileDigest": profile_digest, "context": context,
                "contextDigest": _policy_keccak(context), "programDigest": program_digest,
                "programRoot": program_digest,
                "taskId": _keccak256(f"{name}:{raw_workflow}".encode()),
                "aggregateDigest": file_hashes[f"{base}/aggregate.bin"],
                "outputDigest": file_hashes[f"{base}/output.bin"],
            })
        return result

    fixture_context = _sealed_json(run, f"fixtures/{name}/context.json", sealed_files)
    approved_context = _sealed_json(run, f"owner/{name}/approved-context.json", sealed_files)
    require(fixture_context == approved_context,
            f"{name}: public execution context differs from the owner-approved context")
    context = _object(fixture_context, f"{name}.context")
    inputs = [_object(value, f"{name}.context.inputs[{index}]")
              for index, value in enumerate(_array(context.get("inputs"), f"{name}.context.inputs"))]
    require(inputs, f"{name}: canonical context has no inputs")
    program_relative = f"fixtures/{name}/public/program.json"
    program_bytes = _sealed_bytes(run, program_relative, sealed_files)
    try:
        program = _object(json.loads(program_bytes.decode("utf-8"),
                                     object_pairs_hook=_no_duplicate_object,
                                     parse_constant=lambda token: (_ for _ in ()).throw(
                                         EvidenceError(f"non-finite JSON number in {program_relative}: {token}"))),
                          f"{name}.program")
    except (UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read strict JSON {program_relative}: {error}") from error
    require(_bytes32(context.get("programDigest"), f"{name}.context.programDigest")
            == _keccak256(program_bytes),
            f"{name}: program digest differs from exact preserved program bytes")
    program_inputs = [_object(value, f"{name}.program.inputs[{index}]")
                      for index, value in enumerate(
                          _array(program.get("inputs"), f"{name}.program.inputs"))]
    require([value.get("id") for value in program_inputs]
            == [value.get("id") for value in inputs],
            f"{name}: context inputs differ from the preserved program")
    execution_manifest = _object(
        _sealed_json(run, f"fixtures/{name}/honest/manifest.json", sealed_files),
        f"{name}.honestManifest")
    if strict:
        require(cfg is not None and keyset is not None and file_hashes is not None,
                f"{name}: strict canonical validation lacks campaign key material")
        return _strict_nonlinear_material(run, case, name, program_bytes, program, context,
                                          execution_manifest, cfg, keyset, sealed_files,
                                          file_hashes)
    bindings = [_bytes32(value.get("handle"), f"{name}.context.inputs.handle")
                for value in inputs]
    require([_bytes32(value, f"{name}.honestManifest.inputs") for value in
             _array(execution_manifest.get("inputs"), f"{name}.honestManifest.inputs")]
            == bindings, f"{name}: execution manifest inputs differ from the approved context")
    record_ids = [_bytes32(value, f"{name}.recordIds")
                  for value in _array(case.get("recordIds"), f"{name}.recordIds")]
    owners = [_address(value, f"{name}.owners")
              for value in _array(case.get("owners"), f"{name}.owners")]
    require(len(record_ids) == len(owners) and len(set(record_ids)) == len(record_ids),
            f"{name}: protected-record owner map is invalid")
    owner_by_record = dict(zip(record_ids, owners, strict=True))
    for index, (value, binding) in enumerate(zip(inputs, bindings, strict=True)):
        protected_id = _bytes32(value.get("protectedId"),
                                f"{name}.context.inputs[{index}].protectedId")
        owner = _address(value.get("owner"), f"{name}.context.inputs[{index}].owner")
        require(protected_id in owner_by_record and owner_by_record[protected_id] == owner,
                f"{name}: context input is not bound to a released protected record owner")
        ciphertext = _sealed_bytes(run, f"fixtures/{name}/public/input-{index}.ct", sealed_files)
        require(_keccak256(ciphertext) == binding,
                f"{name}: context input handle differs from the preserved ciphertext")
    return {"inputBindings": bindings, "linearWitnessBytes": None}


def validate_run(run: Path) -> dict[str, Any]:
    """Load a run directory and validate its complete V3 evidence set."""
    run = Path(run).resolve()
    sealed_files = None
    seal_path = run / "seal.json"
    if seal_path.is_file():
        seal = _object(_read_json(seal_path), "seal")
        raw_files = _object(seal.get("files"), "seal.files")
        sealed_files = {}
        for raw_name, digest in raw_files.items():
            require(isinstance(raw_name, str), "seal file name must be a string")
            name = raw_name.replace("\\", "/")
            require(name not in sealed_files, "seal contains duplicate normalized file names")
            sealed_files[name] = digest
    cfg = _sealed_json(run, "config/campaign.json", sealed_files)
    app = _sealed_json(run, "reports/application.json", sealed_files)
    require(_object(app, "application").get("config") == cfg,
            "application evidence is not bound to the exact campaign configuration")
    refresh = _object(cfg, "campaign configuration").get("policyRefreshPlan") is not None
    require(not refresh or sealed_files is not None,
            "V3 policy refresh evidence must be checked against a seal")
    file_hashes: dict[str, str] = {}
    keyset = (_validate_keyset(run, _object(cfg, "campaign configuration"),
                               _object(app, "application"), sealed_files, file_hashes)
              if refresh else None)
    expected = _sealed_json(run, "owner/expected.json", sealed_files)
    policy_config = _sealed_json(run, "config/release-policy.json", sealed_files)
    if refresh:
        owners_bytes = _sealed_bytes(run, "config/owners.json", sealed_files)
        require(hashlib.sha256(owners_bytes).hexdigest()
                == _sha256_hex(_object(policy_config, "release policy configuration").get(
                    "ownersSha256"), "release policy ownersSha256"),
                "owner identity file differs from the deployed policy-lineage digest")
    recipient_dir = run / "recipient"
    require(recipient_dir.is_dir(), f"missing recipient directory: {recipient_dir}")
    indexed: dict[int, Path] = {}
    for path in recipient_dir.glob("result-*.json"):
        match = re.fullmatch(r"result-(0|[1-9][0-9]*)\.json", path.name)
        require(match is not None, f"noncanonical recipient result filename: {path.name}")
        number = int(match.group(1))
        require(number not in indexed, "duplicate recipient result index")
        indexed[number] = path
    require(indexed and sorted(indexed) == list(range(len(indexed))),
            "recipient result indices are incomplete or noncontiguous")
    results = [_sealed_json(run, indexed[index].relative_to(run).as_posix(), sealed_files)
               for index in range(len(indexed))]
    cases = _array(_object(app, "application").get("cases"), "cases")
    case_materials = {}
    for case in cases:
        row = _object(case, "case")
        name = _case_name(row.get("name"))
        require(name not in case_materials, "duplicate case name in raw material loader")
        case_materials[name] = _load_case_material(
            run, row, sealed_files, strict=refresh,
            cfg=_object(cfg, "campaign configuration"), keyset=keyset,
            file_hashes=file_hashes)
    return validate_onchain_evidence(app, results, expected, case_materials=case_materials,
                                     policy_config=policy_config, keyset=keyset)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate V3 on-chain consent and recipient-release evidence without mutating the run.")
    parser.add_argument("run", type=Path, help="campaign run directory")
    parser.add_argument("--output", type=Path,
                        help="write the summary to a new file; existing files are never replaced")
    args = parser.parse_args(argv)
    try:
        summary = validate_run(args.run)
        rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
        else:
            sys.stdout.write(rendered)
        return 0
    except (EvidenceError, OSError) as error:
        print(f"on-chain evidence rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
