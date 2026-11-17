"""Synthetic structural tests for the V3 on-chain evidence gate."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import onchain_evidence as evidence


def h(number):
    return "0x" + format(number, "064x")


def address(number):
    return "0x" + format(number, "040x")


TEST_BINARY = b"synthetic-kms-campaign-binary"
TEST_ENCRYPTION_KEY = b"synthetic-public-encryption-key"
TEST_EVALUATION_KEY = b"synthetic-evaluation-key"


def test_keyset():
    descriptor = {
        "encryptionKeyDigest": evidence._keccak256(TEST_ENCRYPTION_KEY),
        "evaluationKeyDigest": evidence._keccak256(TEST_EVALUATION_KEY),
        "parameters": "Test", "tfhe": "1.6.1",
    }
    return {
        "corruptionThreshold": 1, "dkgSeconds": 1.0, "fullPreprocessing": True,
        "keyDescriptor": descriptor, "keyEpoch": h(0x8001), "keyId": h(0x4001),
        "keysetDigest": evidence._json_keccak(descriptor), "mpcContext": h(0x7001),
        "parameters": "Test", "parties": 4, "preloadedFheKey": False,
        "preprocessingSeconds": 2.0, "publicKeyPreparationSeconds": 0.5,
        "status": "passed", "upstreamCommit": "1" * 40,
    }


def abi_word(kind, value):
    if kind == "bytes32":
        return value[2:].lower()
    if kind == "address":
        return "00" * 12 + value[2:].lower()
    return int(value).to_bytes(32, "big").hex()


def refresh_log(row):
    signature, fields = evidence.EVENTS[row["name"]]
    row["topics"] = [signature] + ["0x" + abi_word(kind, row["args"][name])
                                         for name, kind, indexed in fields if indexed]
    row["data"] = "0x" + "".join(abi_word(kind, row["args"][name])
                                     for name, kind, indexed in fields if not indexed)


def raw_material_spec(case):
    name, half, n = case["name"], case["half"], case["n"]
    if half == "linear":
        coordinates = [[str(1000 + 10 * vector + coordinate)
                        for coordinate in range(8)] for vector in range(n)]
        bindings = [evidence._keccak256(
            b"".join(int(value).to_bytes(32, "big") for value in vector))
                    for vector in coordinates]
        witness = {
            "schema": "vcfhe-linear-release-witness-v1",
            "inputPreparationAssumption": "honest-owner-preparation-required",
            "plan": case["plan"],
            "vectors": [{"coordsDigest": digest, "coordinates": vector}
                        for digest, vector in zip(bindings, coordinates, strict=True)],
        }
        witness_bytes = json.dumps(witness, separators=(",", ":")).encode()
        dimension = 9 * len(coordinates[0])
        aggregate = [0] * dimension
        for vector in coordinates:
            for coordinate, value in enumerate(vector):
                aggregate[coordinate] += int(value)
        aggregate_bytes = b"".join(value.to_bytes(32, "big") for value in aggregate)
        output_bytes = b"synthetic-grouped-linear-output"
        return {"bindings": bindings, "witness": witness_bytes,
                 "coordinates": coordinates,
                 "ciphertexts": [(name + ":input:" + str(index)).encode()
                                 for index in range(n)],
                 "aggregateBytes": aggregate_bytes, "outputBytes": output_bytes}
    keyset = test_keyset()
    program = evidence._compile_compliance_program(n, bool(case.get("regional")), 7)
    ciphertexts = [(name + ":input:" + str(index)).encode()
                   for index in range(len(program["inputs"]))]
    bindings = [evidence._keccak256(value) for value in ciphertexts]
    context_inputs = [
        {"id": program["inputs"][index]["id"],
         "protectedId": case["recordIds"][index % n],
         "owner": case["owners"][index % n], "handle": bindings[index]}
        for index in range(len(program["inputs"]))
    ]
    program_bytes = json.dumps(program).encode()
    profile = {"version": evidence.CANONICAL_VERSION,
               "binaryDigest": evidence._keccak256(TEST_BINARY), "tfhe": "1.6.1",
               "threads": 1, "fixedFFT": True, "arch": "x64", "os": "linux",
               "osRelease": "synthetic", "cpu": "synthetic"}
    kms = {"encryptionKeyDigest": keyset["keyDescriptor"]["encryptionKeyDigest"],
           "evaluationKeyDigest": keyset["keyDescriptor"]["evaluationKeyDigest"],
           "keyEpoch": keyset["keyEpoch"], "keyId": keyset["keyId"],
           "keysetDigest": keyset["keysetDigest"], "mpcContext": keyset["mpcContext"],
           "parameters": "Test", "tfhe": "1.6.1"}
    context = {"version": evidence.CANONICAL_VERSION, "profile": profile,
               "inputEncryption": evidence.INPUT_ENCRYPTION,
               "encryptionKeyDigest": keyset["keyDescriptor"]["encryptionKeyDigest"],
               "programDigest": evidence._keccak256(program_bytes),
               "keyDigest": keyset["keyDescriptor"]["evaluationKeyDigest"],
               "keyEpoch": keyset["keyEpoch"], "policyDomain": evidence.CAMPAIGN_VERSION,
               "inputs": context_inputs,
               "domain": evidence._canonical_domain(program, case["inputBounds"], name),
               "kmsKeyset": kms}
    result_bytes = [(name + ":result:" + str(index)).encode()
                    for index in range(len(program["instructions"]))]
    result_handles = [evidence._keccak256(value) for value in result_bytes]
    leaves = []
    for index, instruction in enumerate(program["instructions"]):
        def resolve(ref):
            if ref["kind"] == "constant":
                return evidence._constant_handle(ref["value"], "fixture.constant")
            return bindings[ref["index"]] if ref["kind"] == "input" else result_handles[ref["index"]]
        leaves.append({"index": index, "lhs": instruction["lhs"],
                       "lhsHandle": resolve(instruction["lhs"]), "ms": 1,
                       "opcode": instruction["opcode"], "resultHandle": result_handles[index],
                       "rhs": instruction["rhs"], "rhsHandle": resolve(instruction["rhs"])})
    execution_manifest = {
        "boundary": "public execution transcript; certificates require independent verification",
        "elapsedMs": len(leaves), "inputs": bindings, "leaves": leaves,
        "profile": {"arch": "x86_64", "binaryDigest": profile["binaryDigest"],
                    "fixedFFT": True, "os": "linux", "tfhe": "1.6.1", "threads": 1},
        "programDigest": context["programDigest"], "publicDecisionsReleased": 0,
        "serverKeyDigest": context["keyDigest"], "terminalHandle": result_handles[-1],
        "version": evidence.CANONICAL_VERSION,
    }
    return {"bindings": bindings, "ciphertexts": ciphertexts, "program": program,
            "programBytes": program_bytes, "context": context,
            "executionManifest": execution_manifest, "resultBytes": result_bytes,
            "terminalHandle": result_handles[-1]}


def write_raw_run(root, app, results, expected):
    for directory in ("config", "reports", "recipient", "owner"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "config" / "campaign.json").write_text(json.dumps(app["config"]))
    (root / "reports" / "application.json").write_text(json.dumps(app))
    (root / "owner" / "expected.json").write_text(json.dumps(expected))
    policy = app["onChainPolicy"]
    policy_config = {
        "schema": "vcfhe-release-policy-config-v3", "chainId": app["config"]["chainId"],
        "address": policy["address"], "runtimeCodeHash": policy["runtimeCodeHash"],
        "policyVersion": policy["version"], "policyDomain": policy["domain"],
    }
    if "ownersSha256" in policy:
        policy_config["ownersSha256"] = policy["ownersSha256"]
    (root / "config" / "release-policy.json").write_text(json.dumps(policy_config))
    keyset = test_keyset()
    (root / "keyset").mkdir()
    (root / "keyset" / "ready.json").write_text(json.dumps(keyset))
    (root / "keyset" / "encryption-key.bin").write_bytes(TEST_ENCRYPTION_KEY)
    (root / "keyset" / "evaluation-key.bin").write_bytes(TEST_EVALUATION_KEY)
    (root / "bin").mkdir(); (root / "bin" / "kms-campaign").write_bytes(TEST_BINARY)
    (root / "build-evidence").mkdir()
    (root / "build-evidence" / "installed-files.json.gz").write_bytes(b"synthetic inventory")
    (root / "build-evidence" / "vcfhe-adapter.json").write_text(json.dumps({
        "upstreamCommit": keyset["upstreamCommit"], "files": {"adapter.rs": {"adapted": "a" * 64}},
        "releaseAuthorization": "on-chain-release-policy-v3-per-core-check"}))
    for index, (case, result) in enumerate(zip(app["cases"], results, strict=True)):
        (root / "recipient" / f"result-{index}.json").write_text(json.dumps(result))
        material = raw_material_spec(case)
        fixture = root / "fixtures" / case["name"]
        owner = root / "owner" / case["name"]
        fixture.mkdir(parents=True)
        owner.mkdir(parents=True)
        if case["half"] == "linear":
            (root / "release-evidence").mkdir(exist_ok=True)
            (root / "release-evidence" / (case["linearWitnessDigest"][2:] + ".json")).write_bytes(
                material["witness"])
            (fixture / "coordinates.json").write_text(json.dumps(material["coordinates"]))
            (owner / "coordinates.json").write_text(json.dumps(material["coordinates"]))
            for input_index, ciphertext in enumerate(material["ciphertexts"]):
                (fixture / f"input-{input_index}.bin").write_bytes(ciphertext)
                (owner / f"input-{input_index}.bin").write_bytes(ciphertext)
            (fixture / "aggregate.bin").write_bytes(material["aggregateBytes"])
            (fixture / "output.bin").write_bytes(material["outputBytes"])
        else:
            public = fixture / "public"
            honest = fixture / "honest"
            public.mkdir(); honest.mkdir()
            (fixture / "context.json").write_text(json.dumps(material["context"]))
            (owner / "approved-context.json").write_text(json.dumps(material["context"]))
            (public / "program.json").write_bytes(material["programBytes"])
            (public / "encryption-key.bin").write_bytes(TEST_ENCRYPTION_KEY)
            (public / "server-key.bin").write_bytes(TEST_EVALUATION_KEY)
            (honest / "manifest.json").write_text(json.dumps(material["executionManifest"]))
            for input_index, ciphertext in enumerate(material["ciphertexts"]):
                (public / f"input-{input_index}.ct").write_bytes(ciphertext)
            for result_index, ciphertext in enumerate(material["resultBytes"]):
                (honest / f"result-{result_index}.ct").write_bytes(ciphertext)


def write_test_seal(root, omitted=()):
    omitted = set(omitted)
    files = {}
    for path in root.rglob("*"):
        if not path.is_file() or path.name == "seal.json":
            continue
        name = path.relative_to(root).as_posix()
        if name not in omitted:
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    (root / "seal.json").write_text(json.dumps({"files": files}))


def fixture():
    policy = address(500)
    runtime_hash = h(501)
    policy_domain = h(502)
    recipient = address(503)
    owners = [address(601), address(602)]
    records = [h(701), h(702)]
    references = [h(703), h(704)]
    events = []
    receipts = []
    next_tx = 800
    next_block = 10

    def add_event(name, args, label, sender=address(900)):
        nonlocal next_tx, next_block
        tx = h(next_tx)
        block_hash = h(10_000 + next_block)
        row = {"name": name, "transactionHash": tx, "blockNumber": next_block,
               "blockHash": block_hash, "logIndex": 0, "args": args}
        refresh_log(row)
        events.append(row)
        receipts.append({"label": label, "hash": tx, "gasUsed": "21000", "block": next_block,
                         "blockHash": block_hash, "calldataBytes": 68, "from": sender,
                         "to": policy, "dataDigest": h(20_000 + next_tx)})
        next_tx += 1
        next_block += 1
        return row

    # Record 0 represents migrated state. Record 1 is first registered in this run.
    add_event("ProtectedRecordRegistered", {
        "protectedId": records[1], "owner": owners[1], "recordReference": references[1],
        "releaseLimit": "6", "initialSpent": "0",
    }, "protected-record-registration", owners[1])

    cases = []
    results = []
    expected = {}
    specifications = [
        ("linear-case", "linear", [records[0], records[1]], owners, references, [6, 6], [1, 0], 41),
        ("nonlinear-case", "nonlinear", records, owners, references, [6, 6], [1, 0], 1),
    ]
    for index, (name, half, case_records, case_owners, case_references, limits, initial, actual) in enumerate(specifications):
        consent_id = h(1000 + index)
        request_id = h(1100 + index)
        request_key = h(1200 + index)
        submit_digest = h(1300 + index)
        output_digest = h(1400 + index)
        aggregate_digest = h(1500 + index)
        recipient_key_digest = h(1600 + index)
        slot = h(1700 + index)
        workflow = address(1800 + index)
        task_id = h(1900 + index)
        release_digest = h(2000 + index)
        if half == "linear":
            workflow_manifest = {"schema": "vcfhe-workflow-deployment-v1",
                                 "kind": "grouped-linear", "workflow": workflow,
                                 "deployments": {"workflow": h(2100 + index)}}
        else:
            workflow_manifest = {"schema": "vcfhe-workflow-deployment-v1",
                                 "kind": "canonical-nonlinear", "game": workflow,
                                 "availability": address(2800), "verifier": address(2801),
                                 "objective": address(2802),
                                 "canonicalSigners": [address(2803), address(2804), address(2805)],
                                 "deployments": {"game": h(2100 + index),
                                                 "availability": h(2110 + index),
                                                 "verifier": h(2120 + index),
                                                 "objective": h(2130 + index)}}
        affected = []
        for owner in case_owners:
            if owner not in affected:
                affected.append(owner)
        created = add_event("ConsentCreated", {
            "consentId": consent_id, "taskId": task_id, "recipient": recipient,
            "workflowKind": "1" if half == "linear" else "2", "workflow": workflow,
            "slot": slot, "recordCount": str(len(case_records)),
            "requiredOwnerCount": str(len(affected)),
        }, "create-release-consent")
        for approval_count, owner in enumerate(affected, 1):
            add_event("ConsentApproved", {"consentId": consent_id, "owner": owner,
                                           "approvalCount": str(approval_count)},
                      "approve-release-consent", owner)
        add_event("ReleaseProposed", {"requestId": request_id, "consentId": consent_id,
                                       "requestKey": request_key, "releaseDigest": release_digest},
                  "propose-exact-release")
        for approval_count, owner in enumerate(affected, 1):
            add_event("ReleaseApproved", {"requestId": request_id, "owner": owner,
                                           "approvalCount": str(approval_count),
                                           "releaseDigest": release_digest},
                      "approve-exact-release", owner)
        reserved = add_event("ReleaseReserved", {
            "requestId": request_id, "consentId": consent_id, "requestKey": request_key,
            "submitWireDigest": submit_digest, "resultQueryDigest": request_key,
            "finalOutputDigest": output_digest, "aggregateDigest": aggregate_digest,
            "recipientEncryptionKeyDigest": recipient_key_digest, "recipient": recipient,
            "slot": slot,
        }, "reserve-exact-release")
        confirmations = [{"validator": validator, "chainId": "46853", "blockNumber": reserved["blockNumber"],
                          "blockHash": reserved["blockHash"], "policyCodeHash": runtime_hash}
                         for validator in range(1, 5)]
        case = {
            "name": name, "half": half, "n": len(case_records), "recordIds": case_records,
            "owners": case_owners, "recordReferences": case_references,
            "releaseLimits": limits, "initialSpent": initial, "finalOutputKmsCalls": 1,
            "consentId": consent_id, "releaseRequestId": request_id, "requestKey": request_key,
            "submitWireDigest": submit_digest, "resultQueryDigest": request_key,
            "aggregateDigest": aggregate_digest, "recipientEncryptionKeyDigest": recipient_key_digest,
            "recipient": recipient, "releaseSlot": slot, "outputDigest": output_digest,
            "reservationTransaction": reserved["transactionHash"],
            "reservationBlockHash": reserved["blockHash"], "validatorConfirmations": confirmations,
            "workflowKind": 1 if half == "linear" else 2,
            "workflowManifest": workflow_manifest,
            "workflowManifestDigest": evidence._json_keccak(workflow_manifest),
            "plan": ({"profile": "kms-grouped-radix-v1", "op": "SUM",
                      "bounds": [[1, 5] for _ in case_records]} if half == "linear" else None),
            "regional": False if half == "nonlinear" else None,
            "inputBounds": ([{"min": "0", "max": "5000"} for _ in case_records]
                            if half == "nonlinear" else None),
        }
        material = raw_material_spec(case)
        case["inputBindingsDigest"] = evidence._abi_bytes32_array_digest(
            material["bindings"], name + ".bindings")[1]
        case["linearWitnessDigest"] = (evidence._keccak256(material["witness"])
                                         if half == "linear" else None)
        release = {
            "policy": policy, "policyDomain": policy_domain, "consentId": consent_id,
            "requestId": request_id, "requestKey": request_key, "submitWireDigest": submit_digest,
            "resultQueryDigest": request_key, "recipientEncryptionKeyDigest": recipient_key_digest,
            "recipient": recipient, "slot": slot,
            "reservationTransaction": reserved["transactionHash"],
            "reservationBlock": reserved["blockNumber"],
            "reservationBlockHash": reserved["blockHash"], "validatorConfirmations": confirmations,
        }
        result = {"index": index, "name": name, "actual": actual, "outputDigest": output_digest,
                  "responses": 3, "directUserAndPublicDenied": 4, "negativeResponseChecks": 4,
                  "directAdministrativeDenied": 28, "changedReservedWireDenied": 4,
                  "acceptedSubmitCores": [1, 2, 3, 4], "failedSubmitCores": [],
                  "onChainRelease": release}
        cases.append(case)
        results.append(result)
        expected[name] = actual
        self_check = created  # Retain the local name to make event order explicit in the fixture.
        assert self_check["blockNumber"] < reserved["blockNumber"]

    app = {
        "version": evidence.CAMPAIGN_VERSION, "status": "passed",
        "config": {"version": evidence.CAMPAIGN_VERSION, "chainId": "46853",
                   "parameters": "Test", "targetCell": 7,
                   "policyDomain": evidence.CAMPAIGN_VERSION,
                   "policyLineage": "owner-attested-legacy-migration"},
        "keys": test_keyset(),
        "plaintextInRelayer": False,
        "onChainPolicy": {"address": policy, "runtimeCodeHash": runtime_hash,
                          "version": 3, "domain": policy_domain},
        "chain": {"chainId": "46853", "consensus": "QBFT",
                  "validators": [address(3001 + i) for i in range(4)],
                  "observedBlock": 1, "advancedBlock": next_block},
        "receipts": receipts, "policyEvents": events, "cases": cases, "kmsCalls": 2,
        "protectedRecordBaselines": {
            records[0]: {"owner": owners[0], "recordReference": references[0],
                         "releaseLimit": 6, "spent": 2},
            records[1]: {"owner": owners[1], "recordReference": references[1],
                         "releaseLimit": 6, "spent": 0},
        },
        "protectedRecords": {
            records[0]: {"owner": owners[0], "recordReference": references[0],
                         "releaseLimit": 6, "spent": 4},
            records[1]: {"owner": owners[1], "recordReference": references[1],
                         "releaseLimit": 6, "spent": 2},
        },
    }
    return app, results, expected


def event(app, name, predicate=lambda row: True):
    return next(row for row in app["policyEvents"] if row["name"] == name and predicate(row))


def enable_strict_refresh(app, results, owners_bytes):
    app["config"]["policyRefreshPlan"] = {"profile": "test-refresh"}
    app["onChainPolicy"]["ownersSha256"] = hashlib.sha256(owners_bytes).hexdigest()
    keyset = app["keys"]
    policy = app["onChainPolicy"]["address"]
    policy_domain = app["onChainPolicy"]["domain"]
    for case, result in zip(app["cases"], results, strict=True):
        material = raw_material_spec(case)
        created = event(app, "ConsentCreated",
                        lambda row: row["args"]["consentId"] == case["consentId"])
        reserved = event(app, "ReleaseReserved",
                         lambda row: row["args"]["requestId"] == case["releaseRequestId"])
        workflow_kind = case["workflowKind"]
        workflow_raw = case["workflowManifest"].get("workflow", case["workflowManifest"].get("game"))
        created["args"]["taskId"] = evidence._keccak256(
            f"{case['name']}:{workflow_raw}".encode())
        refresh_log(created)
        if case["half"] == "nonlinear":
            output_digest = aggregate_digest = material["terminalHandle"]
            context_digest = evidence._json_keccak(material["context"])
            program_digest = material["context"]["programDigest"]
            profile_digest = evidence._json_keccak(material["context"]["profile"])
            program_root = evidence._program_root(
                created["args"]["taskId"], material["program"], case["name"] + ".program")
            protected_inputs = [row["protectedId"] for row in material["context"]["inputs"]]
        else:
            width = len(material["coordinates"][0]); dimension = 9 * width
            profile = {**case["plan"], "dimension": dimension, "lweSize": width // 8,
                       "keyId": keyset["keyId"], "keysetDigest": keyset["keysetDigest"],
                       "binaryDigest": evidence._keccak256(TEST_BINARY), "tfhe": "1.6.1",
                       "threads": 1, "fixedFFT": True}
            profile_digest = evidence._policy_keccak(profile)
            dataset_tag = evidence._linear_dataset_tag(
                int(app["config"]["chainId"]), workflow_raw, keyset["keyEpoch"],
                profile_digest, keyset["keysetDigest"], case["n"], 0)
            context = {"profileDigest": profile_digest,
                       "keysetDigest": keyset["keysetDigest"], "datasetTag": dataset_tag,
                       "records": [{"id": record, "owner": owner}
                                   for record, owner in zip(case["recordIds"], case["owners"], strict=True)],
                       "ownerCiphertextDigests": material["bindings"]}
            context_digest = evidence._policy_keccak(context)
            program_digest = evidence._policy_keccak(case["plan"])
            program_root = program_digest
            protected_inputs = []
            output_digest = evidence._keccak256(material["outputBytes"])
            aggregate_digest = evidence._keccak256(material["aggregateBytes"])
        case["outputDigest"] = output_digest
        case["aggregateDigest"] = aggregate_digest
        result["outputDigest"] = output_digest
        reserved["args"]["finalOutputDigest"] = output_digest
        reserved["args"]["aggregateDigest"] = aggregate_digest
        refresh_log(reserved)
        bindings = material["bindings"]
        case["inputBindingsDigest"] = evidence._abi_bytes32_array_digest(
            bindings, case["name"] + ".bindings")[1]
        submit = {
            "requestId": case["releaseRequestId"], "requestKey": case["requestKey"],
            "submitWireDigest": case["submitWireDigest"], "consentId": case["consentId"],
            "finalOutputDigest": case["outputDigest"], "aggregateDigest": case["aggregateDigest"],
            "recipientEncryptionKeyDigest": case["recipientEncryptionKeyDigest"],
            "recipient": case["recipient"], "keyId": keyset["keyId"],
            "keyEpoch": keyset["keyEpoch"], "mpcContext": keyset["mpcContext"],
            "outputType": evidence._keccak256(
                f"VCFHE_OUTPUT_TYPE_V1:{'uint16' if case['half'] == 'linear' else 'bool'}".encode()),
            "workflow": case["workflowManifest"].get("workflow", case["workflowManifest"].get("game")),
            "chainId": app["config"]["chainId"], "policyDomain": policy_domain,
            "policy": policy, "slot": case["releaseSlot"], "workflowKind": workflow_kind,
            "taskId": created["args"]["taskId"], "contextDigest": context_digest,
            "programDigest": program_digest, "programRoot": program_root,
            "profileDigest": profile_digest, "keysetDigest": keyset["keysetDigest"],
            "inputBindingsDigest": case["inputBindingsDigest"],
        }
        case["submitAuthorization"] = submit
        owner_by_record = dict(zip(case["recordIds"], case["owners"], strict=True))
        if case["half"] == "nonlinear":
            input_root, padded = evidence._consent_input_root(
                submit["taskId"], protected_inputs, bindings, owner_by_record, case["name"])
            actual = len(bindings)
        else:
            input_root, actual, padded = evidence.ZERO32, 0, 0
        owner_count = len(set(owner.lower() for owner in case["owners"]))
        consent_state = {
            "domain": policy_domain, "chainId": int(app["config"]["chainId"]),
            "workflowKind": workflow_kind, "workflow": submit["workflow"].lower(),
            "taskId": submit["taskId"], "contextDigest": context_digest,
            "programDigest": program_digest, "programRoot": program_root,
            "profileDigest": profile_digest, "keysetDigest": keyset["keysetDigest"],
            "keyId": keyset["keyId"], "keyEpoch": keyset["keyEpoch"],
            "mpcContext": keyset["mpcContext"], "outputType": submit["outputType"],
            "recipient": case["recipient"].lower(), "slot": case["releaseSlot"],
            "inputRoot": input_root, "inputBindingsDigest": case["inputBindingsDigest"],
            "recordCount": case["n"], "actualInputCount": actual,
            "paddedInputCount": padded, "requiredOwnerCount": owner_count,
            "approvalCount": owner_count, "exists": True,
        }
        normalized = evidence._normalize_submit(submit, case["name"] + ".submit")
        calls = evidence._policy_call_evidence(
            normalized, consent_state, case["releaseRequestId"], case["requestKey"],
            case["resultQueryDigest"])
        for confirmation in case["validatorConfirmations"]:
            confirmation["policyCalls"] = copy.deepcopy(calls)
        result["onChainRelease"]["validatorConfirmations"] = copy.deepcopy(
            case["validatorConfirmations"])


class OnChainEvidenceTests(unittest.TestCase):
    def test_complete_v3_evidence_reconciles(self):
        app, results, expected = fixture()
        summary = evidence.validate_onchain_evidence(app, results, expected)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["caseCount"], 2)
        self.assertEqual(summary["consentApprovalCount"], 4)
        self.assertEqual(summary["releaseApprovalCount"], 4)
        self.assertEqual(summary["protectedRecordCount"], 2)
        self.assertEqual(len(summary["inputSha256"]), 64)

    def test_owner_oracle_may_cover_unreleased_paired_jobs(self):
        # --poc plans compute the oracle for 480 paired measurements too;
        # only the released cases need to be a subset of that oracle.
        app, results, expected = fixture()
        expected["linear-acr-10-warmup0"] = 999
        expected["regulatory_qoe_compliance-16-0"] = 0
        summary = evidence.validate_onchain_evidence(app, results, expected)
        self.assertEqual(summary["status"], "passed")

    def test_owner_oracle_missing_a_released_case_fails_closed(self):
        app, results, expected = fixture()
        del expected[app["cases"][0]["name"]]
        with self.assertRaisesRegex(evidence.EvidenceError, "does not cover every released case"):
            evidence.validate_onchain_evidence(app, results, expected)

    def test_policy_refresh_fails_closed_without_raw_materials(self):
        app, results, expected = fixture()
        app["config"]["policyRefreshPlan"] = {"profile": "refresh"}
        app["onChainPolicy"]["ownersSha256"] = "12" * 32
        with self.assertRaisesRegex(evidence.EvidenceError, "sealed raw input-binding"):
            evidence.validate_onchain_evidence(app, results, expected)

    def test_workflow_manifest_and_linear_witness_are_required(self):
        for mutation in (
            lambda cases: cases[0].update(linearWitnessDigest=None),
            lambda cases: cases[0]["workflowManifest"].update(workflow=address(9990)),
            lambda cases: cases[1]["workflowManifest"].update(canonicalSigners=[address(1)] * 3),
            lambda cases: cases[1].update(linearWitnessDigest=h(9991)),
        ):
            app, results, expected = fixture()
            mutation(app["cases"])
            with self.subTest(mutation=mutation), self.assertRaises(evidence.EvidenceError):
                evidence.validate_onchain_evidence(app, results, expected)

    def test_v2_or_off_chain_authority_fields_are_rejected(self):
        variants = []
        app, results, expected = fixture()
        changed = copy.deepcopy(app); changed["onChainPolicy"]["version"] = 2
        variants.append((changed, results, expected))
        changed = copy.deepcopy(app); changed["gatewayAuthorization"] = {"approved": True}
        variants.append((changed, results, expected))
        changed_results = copy.deepcopy(results); changed_results[0]["onChainRelease"]["ledgerEntry"] = "approved"
        variants.append((app, changed_results, expected))
        changed = copy.deepcopy(app); changed["version"] = "dataset-threshold-campaign-v2"
        variants.append((changed, results, expected))
        for values in variants:
            with self.subTest(change=variants.index(values)), self.assertRaises(evidence.EvidenceError):
                evidence.validate_onchain_evidence(*values)

    def test_all_affected_owners_must_approve_both_stages(self):
        for event_name in ("ConsentApproved", "ReleaseApproved"):
            app, results, expected = fixture()
            rows = [row for row in app["policyEvents"] if row["name"] == event_name]
            app["policyEvents"].remove(rows[0])
            with self.subTest(event=event_name), self.assertRaisesRegex(evidence.EvidenceError, "approval"):
                evidence.validate_onchain_evidence(app, results, expected)

    def test_raw_log_and_named_args_must_encode_the_same_event(self):
        app, results, expected = fixture()
        row = event(app, "ReleaseReserved")
        row["args"]["submitWireDigest"] = h(999_999)
        with self.assertRaisesRegex(evidence.EvidenceError, "data does not encode"):
            evidence.validate_onchain_evidence(app, results, expected)
        app, results, expected = fixture()
        event(app, "ConsentCreated")["topics"][0] = h(123)
        with self.assertRaisesRegex(evidence.EvidenceError, "topics"):
            evidence.validate_onchain_evidence(app, results, expected)

    def test_unique_requests_slots_and_consents_are_required(self):
        app, results, expected = fixture()
        old = app["cases"][1]["releaseSlot"]
        replacement = app["cases"][0]["releaseSlot"]
        app["cases"][1]["releaseSlot"] = replacement
        results[1]["onChainRelease"]["slot"] = replacement
        created = event(app, "ConsentCreated", lambda row: row["args"]["slot"] == old)
        reserved = event(app, "ReleaseReserved", lambda row: row["args"]["slot"] == old)
        created["args"]["slot"] = replacement; refresh_log(created)
        reserved["args"]["slot"] = replacement; refresh_log(reserved)
        with self.assertRaisesRegex(evidence.EvidenceError, "release slots"):
            evidence.validate_onchain_evidence(app, results, expected)

    def test_reservation_accepts_three_matching_validator_views(self):
        # An unavailable or forged fourth endpoint is omitted by the evaluator.
        # The evidence retains the three validator identities that confirmed.
        for omitted_validator in (2, 4):
            app, results, expected = fixture()
            confirmations = [row for row in app["cases"][0]["validatorConfirmations"]
                             if row["validator"] != omitted_validator]
            app["cases"][0]["validatorConfirmations"] = copy.deepcopy(confirmations)
            results[0]["onChainRelease"]["validatorConfirmations"] = copy.deepcopy(confirmations)
            with self.subTest(omitted=omitted_validator):
                summary = evidence.validate_onchain_evidence(app, results, expected)
                self.assertEqual(summary["validatorConfirmationQuorum"], 3)

    def test_reservation_rejects_two_views_duplicates_and_disagreement(self):
        for mutate in (
            lambda rows: rows.__setitem__(slice(None), rows[:2]),
            lambda rows: rows[1].update(validator=1),
            lambda rows: rows[2].update(blockHash=h(8888)),
            lambda rows: rows[3].update(policyCodeHash=h(7777)),
            lambda rows: rows.reverse(),
        ):
            app, results, expected = fixture()
            mutate(app["cases"][0]["validatorConfirmations"])
            results[0]["onChainRelease"]["validatorConfirmations"] = copy.deepcopy(
                app["cases"][0]["validatorConfirmations"])
            with self.subTest(mutation=mutate), self.assertRaises(evidence.EvidenceError):
                evidence.validate_onchain_evidence(app, results, expected)

    def test_case_and_recipient_must_name_the_same_confirming_subset(self):
        app, results, expected = fixture()
        app["cases"][0]["validatorConfirmations"] = app["cases"][0]["validatorConfirmations"][:3]
        results[0]["onChainRelease"]["validatorConfirmations"] = \
            results[0]["onChainRelease"]["validatorConfirmations"][1:]
        with self.assertRaisesRegex(evidence.EvidenceError, "observations differ"):
            evidence.validate_onchain_evidence(app, results, expected)

    def test_three_kms_submit_acceptances_tolerate_one_failed_core(self):
        app, results, expected = fixture()
        results[0]["acceptedSubmitCores"] = [1, 2, 3]
        results[0]["failedSubmitCores"] = [4]
        evidence.validate_onchain_evidence(app, results, expected)

    def test_two_kms_submit_acceptances_and_invalid_partitions_fail_closed(self):
        for accepted, failed in (([1, 2], [3, 4]), ([1, 2, 2], [4]), ([1, 2, 3], [])):
            app, results, expected = fixture()
            results[0]["acceptedSubmitCores"] = accepted
            results[0]["failedSubmitCores"] = failed
            with self.subTest(accepted=accepted, failed=failed), self.assertRaises(evidence.EvidenceError):
                evidence.validate_onchain_evidence(app, results, expected)

    def test_recipient_delivery_is_bound_to_owner_oracle_and_reservation(self):
        mutations = [
            lambda app, results, expected: results[0].update(actual=expected["linear-case"] + 1),
            lambda app, results, expected: results[0].update(outputDigest=h(3333)),
            lambda app, results, expected: results[0]["onChainRelease"].update(recipient=address(9999)),
            lambda app, results, expected: results[0]["onChainRelease"].update(reservationTransaction=h(4444)),
            lambda app, results, expected: results[0].update(changedReservedWireDenied=3),
        ]
        for mutate in mutations:
            app, results, expected = fixture(); mutate(app, results, expected)
            with self.subTest(mutation=mutate), self.assertRaises(evidence.EvidenceError):
                evidence.validate_onchain_evidence(app, results, expected)

    def test_cumulative_record_state_must_reconcile_exactly(self):
        app, results, expected = fixture()
        record_id = app["cases"][0]["recordIds"][0]
        app["protectedRecords"][record_id]["spent"] -= 1
        with self.assertRaisesRegex(evidence.EvidenceError, "baseline plus reservations"):
            evidence.validate_onchain_evidence(app, results, expected)
        app, results, expected = fixture()
        del app["protectedRecordBaselines"][record_id]
        with self.assertRaisesRegex(evidence.EvidenceError, "snapshots"):
            evidence.validate_onchain_evidence(app, results, expected)

    def test_approval_receipt_sender_and_event_order_are_checked(self):
        app, results, expected = fixture()
        approval = event(app, "ReleaseApproved")
        receipt = next(row for row in app["receipts"] if row["hash"] == approval["transactionHash"])
        receipt["from"] = address(9999)
        with self.assertRaisesRegex(evidence.EvidenceError, "approving owner"):
            evidence.validate_onchain_evidence(app, results, expected)
        app, results, expected = fixture()
        approval = event(app, "ReleaseApproved")
        approval["args"]["releaseDigest"] = h(999999)
        refresh_log(approval)
        with self.assertRaisesRegex(evidence.EvidenceError, "different release digest"):
            evidence.validate_onchain_evidence(app, results, expected)
        app, results, expected = fixture()
        proposed = event(app, "ReleaseProposed")
        created = event(app, "ConsentCreated", lambda row: row["args"]["consentId"] == proposed["args"]["consentId"])
        proposed["blockNumber"] = created["blockNumber"]
        proposed["blockHash"] = created["blockHash"]
        receipt = next(row for row in app["receipts"] if row["hash"] == proposed["transactionHash"])
        receipt["block"] = created["blockNumber"]; receipt["blockHash"] = created["blockHash"]
        with self.assertRaisesRegex(evidence.EvidenceError, "out of order"):
            evidence.validate_onchain_evidence(app, results, expected)

    def test_run_loader_requires_strict_contiguous_json_evidence(self):
        app, results, expected = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_raw_run(root, app, results, expected)
            self.assertEqual(evidence.validate_run(root)["caseCount"], 2)
            (root / "recipient" / "result-1.json").rename(root / "recipient" / "result-2.json")
            with self.assertRaisesRegex(evidence.EvidenceError, "noncontiguous"):
                evidence.validate_run(root)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"value":1,"value":2}')
            with self.assertRaisesRegex(evidence.EvidenceError, "duplicate JSON field"):
                evidence._read_json(path)

    def test_run_loader_recomputes_manifest_input_and_witness_digests(self):
        app, results, expected = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_raw_run(root, app, results, expected)
            summary = evidence.validate_run(root)
            self.assertTrue(summary["rawInputBindingsRecomputed"])

            changed = copy.deepcopy(app)
            changed["cases"][0]["workflowManifestDigest"] = h(999001)
            (root / "reports" / "application.json").write_text(json.dumps(changed))
            with self.assertRaisesRegex(evidence.EvidenceError, "workflow manifest digest"):
                evidence.validate_run(root)

            (root / "reports" / "application.json").write_text(json.dumps(app))
            changed = copy.deepcopy(app)
            changed["cases"][1]["inputBindingsDigest"] = h(999002)
            (root / "reports" / "application.json").write_text(json.dumps(changed))
            with self.assertRaisesRegex(evidence.EvidenceError, "input-binding digest"):
                evidence.validate_run(root)

            (root / "reports" / "application.json").write_text(json.dumps(app))
            witness = (root / "release-evidence"
                       / (app["cases"][0]["linearWitnessDigest"][2:] + ".json"))
            witness.write_bytes(witness.read_bytes() + b"\n")
            with self.assertRaisesRegex(evidence.EvidenceError, "linear witness digest"):
                evidence.validate_run(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_raw_run(root, app, results, expected)
            (root / "owner" / "linear-case" / "input-0.bin").write_bytes(
                b"changed linear ciphertext")
            with self.assertRaisesRegex(evidence.EvidenceError,
                                        "owner-preserved linear ciphertext"):
                evidence.validate_run(root)

    def test_program_digest_uses_exact_sealed_bytes_not_parsed_json(self):
        app, results, expected = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_raw_run(root, app, results, expected)
            program = root / "fixtures" / "nonlinear-case" / "public" / "program.json"
            # This preserves the parsed JSON value.  The old verifier therefore accepted it,
            # even though canonical-protocol hashes the exact bytes.
            program.write_bytes(program.read_bytes() + b"\n")
            write_test_seal(root)
            with self.assertRaisesRegex(evidence.EvidenceError, "exact preserved program bytes"):
                evidence.validate_run(root)

    def test_run_loader_binds_nonlinear_context_to_ciphertexts_and_owner_approval(self):
        app, results, expected = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_raw_run(root, app, results, expected)
            ciphertext = root / "fixtures" / "nonlinear-case" / "public" / "input-0.ct"
            ciphertext.write_bytes(b"changed ciphertext")
            with self.assertRaisesRegex(evidence.EvidenceError, "preserved ciphertext"):
                evidence.validate_run(root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_raw_run(root, app, results, expected)
            approved = root / "owner" / "nonlinear-case" / "approved-context.json"
            value = json.loads(approved.read_text())
            value["inputs"][0]["handle"] = h(999003)
            approved.write_text(json.dumps(value))
            with self.assertRaisesRegex(evidence.EvidenceError, "owner-approved context"):
                evidence.validate_run(root)

    def test_refresh_binds_owner_identity_file_and_requires_it_in_the_seal(self):
        app, results, expected = fixture()
        owners_bytes = b'[{"owner":"preserved"}]\n'
        enable_strict_refresh(app, results, owners_bytes)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_raw_run(root, app, results, expected)
            (root / "config" / "owners.json").write_bytes(owners_bytes)
            write_test_seal(root, ["config/owners.json"])
            with self.assertRaisesRegex(evidence.EvidenceError,
                                        "strict validator input is absent from the seal"):
                evidence.validate_run(root)
            write_test_seal(root)
            self.assertEqual(evidence.validate_run(root)["caseCount"], 2)
            changed = b'[{"owner":"changed"}]\n'
            (root / "config" / "owners.json").write_bytes(changed)
            write_test_seal(root)
            with self.assertRaisesRegex(evidence.EvidenceError, "owner identity file"):
                evidence.validate_run(root)

    def test_refresh_rejects_alternate_context_manifest_and_authorization_evidence(self):
        owners_bytes = b'[{"owner":"preserved"}]\n'
        mutations = [
            ("context version", lambda root, app, results: self._mutate_context(
                root, lambda value: value.update(version="attacker-profile")), "canonical context"),
            ("profile threads", lambda root, app, results: self._mutate_context(
                root, lambda value: value["profile"].update(threads=2)), "execution profile"),
            ("key epoch", lambda root, app, results: self._mutate_context(
                root, lambda value: value.update(keyEpoch=h(99991))), "epoch"),
            ("policy domain", lambda root, app, results: self._mutate_context(
                root, lambda value: value.update(policyDomain="attacker-domain")), "policy domain"),
            ("manifest result", self._mutate_manifest_result, "sealed ciphertext bytes"),
            ("submit context", self._mutate_submit_context, "authorized nonlinear context"),
            ("linear submit context", self._mutate_linear_submit_context,
             "authorized linear context"),
            ("linear aggregate bytes", self._mutate_linear_aggregate,
             "aggregate.bin differs"),
            ("linear output bytes", self._mutate_linear_output,
             "authorized linear output"),
            ("linear coordinate above uint64", self._mutate_linear_uint64,
             "uint64"),
            ("linear alternate plan", self._mutate_linear_plan,
             "SUM-of-ratings"),
            ("missing canonical calls", self._remove_policy_calls, "canonical policy calls"),
        ]
        for label, mutate, message in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                app, results, expected = fixture()
                enable_strict_refresh(app, results, owners_bytes)
                root = Path(temporary)
                write_raw_run(root, app, results, expected)
                (root / "config" / "owners.json").write_bytes(owners_bytes)
                mutate(root, app, results)
                (root / "reports" / "application.json").write_text(json.dumps(app))
                for index, result in enumerate(results):
                    (root / "recipient" / f"result-{index}.json").write_text(json.dumps(result))
                write_test_seal(root)
                with self.assertRaisesRegex(evidence.EvidenceError, message):
                    evidence.validate_run(root)

    @staticmethod
    def _mutate_context(root, mutation):
        public = root / "fixtures" / "nonlinear-case" / "context.json"
        owner = root / "owner" / "nonlinear-case" / "approved-context.json"
        value = json.loads(public.read_text()); mutation(value)
        public.write_text(json.dumps(value)); owner.write_text(json.dumps(value))

    @staticmethod
    def _mutate_manifest_result(root, app, results):
        path = root / "fixtures" / "nonlinear-case" / "honest" / "manifest.json"
        value = json.loads(path.read_text()); value["leaves"][0]["resultHandle"] = h(99992)
        path.write_text(json.dumps(value))

    @staticmethod
    def _mutate_submit_context(root, app, results):
        case = next(row for row in app["cases"] if row["name"] == "nonlinear-case")
        case["submitAuthorization"]["contextDigest"] = h(99993)

    @staticmethod
    def _mutate_linear_submit_context(root, app, results):
        case = next(row for row in app["cases"] if row["name"] == "linear-case")
        case["submitAuthorization"]["contextDigest"] = h(99994)

    @staticmethod
    def _mutate_linear_aggregate(root, app, results):
        path = root / "fixtures" / "linear-case" / "aggregate.bin"
        payload = bytearray(path.read_bytes()); payload[-1] ^= 1; path.write_bytes(payload)

    @staticmethod
    def _mutate_linear_output(root, app, results):
        path = root / "fixtures" / "linear-case" / "output.bin"
        path.write_bytes(path.read_bytes() + b"changed")

    @staticmethod
    def _rewrite_linear_witness(root, app, mutate):
        case = next(row for row in app["cases"] if row["name"] == "linear-case")
        old = root / "release-evidence" / (case["linearWitnessDigest"][2:] + ".json")
        value = json.loads(old.read_text()); mutate(value, case)
        payload = json.dumps(value, separators=(",", ":")).encode()
        digest = evidence._keccak256(payload); case["linearWitnessDigest"] = digest
        (root / "release-evidence" / (digest[2:] + ".json")).write_bytes(payload)
        return value

    @staticmethod
    def _mutate_linear_uint64(root, app, results):
        value = OnChainEvidenceTests._rewrite_linear_witness(
            root, app, lambda witness, case: witness["vectors"][0]["coordinates"].__setitem__(
                0, str(1 << 64)))
        coordinates = [row["coordinates"] for row in value["vectors"]]
        (root / "fixtures/linear-case/coordinates.json").write_text(json.dumps(coordinates))
        (root / "owner/linear-case/coordinates.json").write_text(json.dumps(coordinates))

    @staticmethod
    def _mutate_linear_plan(root, app, results):
        OnChainEvidenceTests._rewrite_linear_witness(
            root, app, lambda witness, case: (
                witness["plan"].update(op="SUB"), case["plan"].update(op="SUB")))

    @staticmethod
    def _remove_policy_calls(root, app, results):
        case = next(row for row in app["cases"] if row["name"] == "nonlinear-case")
        case["validatorConfirmations"][0].pop("policyCalls")
        result = next(row for row in results if row["name"] == "nonlinear-case")
        result["onChainRelease"]["validatorConfirmations"] = copy.deepcopy(
            case["validatorConfirmations"])

    def test_refresh_requires_critical_keyset_binary_and_build_evidence_in_seal(self):
        owners_bytes = b'[{"owner":"preserved"}]\n'
        critical = ["keyset/ready.json", "keyset/encryption-key.bin",
                    "keyset/evaluation-key.bin", "bin/kms-campaign",
                    "build-evidence/vcfhe-adapter.json",
                    "build-evidence/installed-files.json.gz"]
        for missing in critical:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                app, results, expected = fixture(); enable_strict_refresh(app, results, owners_bytes)
                root = Path(temporary); write_raw_run(root, app, results, expected)
                (root / "config" / "owners.json").write_bytes(owners_bytes)
                write_test_seal(root, [missing])
                with self.assertRaisesRegex(evidence.EvidenceError,
                                            "absent from the seal|missing evidence file"):
                    evidence.validate_run(root)

    def test_every_strict_raw_input_must_be_present_in_the_seal(self):
        app, results, expected = fixture()
        required = [
            "owner/expected.json",
            "config/release-policy.json",
            "owner/nonlinear-case/approved-context.json",
            "fixtures/nonlinear-case/public/input-0.ct",
            "release-evidence/" + app["cases"][0]["linearWitnessDigest"][2:] + ".json",
        ]
        for missing in required:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                write_raw_run(root, app, results, expected)
                write_test_seal(root, [missing])
                with self.assertRaisesRegex(evidence.EvidenceError,
                                            "strict validator input is absent from the seal"):
                    evidence.validate_run(root)


if __name__ == "__main__":
    unittest.main()
