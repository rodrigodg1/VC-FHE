/**
 * Runner of the minimal arithmetic teaching example.
 *
 * WHAT IT DOES, in order:
 *   1. loads the declared values and lowers `total = x + y * z` to two leaves --
 *      already a power of two, so nothing is padded -- re-checking every leaf
 *      against the micro-ISA;
 *   2. exports both trace variants and executes them over TFHE ciphertexts, so
 *      every handle registered on chain is keccak256 of a real ciphertext;
 *   3. writes the run artifacts, whose trace root is computed over those handles;
 *   4. spawns `npm run demo:hardhat`, the SAME dispute driver the ANATEL
 *      demonstrations and the evaluation's evaluations use;
 *   5. writes a run record with every transaction, block and gas figure, plus the
 *      measured leaf decision.
 *
 * ISOLATION. This example must not be able to affect the implementation:
 *   - its workload id is not in `allApplicationWorkloadSpecs()` and its operation
 *     type is not in `operationRegistry`;
 *   - its ciphertext manifest lives in artifacts/fhe/arithmetic-demo/, selected
 *     through VCFHE_CIPHERTEXT_MANIFEST, so it never touches the evaluation's;
 *   - its record lives in artifacts/evaluations/arithmetic-demo/, one directory
 *     below the level where collect_results.py and generate_experiment_tables.py glob
 *     for `latest_*`, so no collector, table or plot can pick it up.
 *
 * Usage:
 *   node examples/exemplo-aritmetico/run-arithmetic-demo.mjs --dry-run
 *   node examples/exemplo-aritmetico/run-arithmetic-demo.mjs
 *   node examples/exemplo-aritmetico/run-arithmetic-demo.mjs --manipulated-leaf-index 3
 */
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

import { arithmeticInputs } from "./arithmetic-demo-fixtures.mjs";
import { lowerArithmeticDemo } from "./arithmetic-demo-lowering.mjs";
import { evaluateLeaf } from "../../fhe-pod/scripts/micro-isa.mjs";
import { opcodeCounts } from "../../fhe-pod/scripts/application-lowering.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));

/** Resolve fhe-pod from the repository root two levels above this directory. */
const projectRoot = path.resolve(scriptDir, "..", "..", "fhe-pod");

const RUN_PREFIX = "arithmetic-demo";
const EVALUATION_SUBDIR = "arithmetic-demo";
const FHE_SUBDIR = "arithmetic-demo";

// ------------------------------------------------------------------ options --

function parseArgs(argv) {
  const config = { dryRun: false, refreshFhe: false, skipFhe: false, manipulatedLeafIndex: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--dry-run") config.dryRun = true;
    else if (arg === "--refresh-fhe") config.refreshFhe = true;
    else if (arg === "--skip-fhe") config.skipFhe = true;
    else if (arg === "--manipulated-leaf-index") {
      i += 1;
      const value = Number(argv[i]);
      if (!Number.isInteger(value) || value < 0) {
        throw new Error("--manipulated-leaf-index requires a non-negative integer");
      }
      config.manipulatedLeafIndex = value;
    } else if (arg === "--help" || arg === "-h") {
      console.log(`Minimal arithmetic teaching example.

  node examples/exemplo-aritmetico/run-arithmetic-demo.mjs [options]

  --dry-run                      build, verify and print the trace; contact no chain, write nothing
  --manipulated-leaf-index <n>   corrupt leaf n instead of the ADD that yields total
  --refresh-fhe                  re-run the TFHE executor even if a manifest already covers this trace
  --skip-fhe                     register clear values instead of ciphertexts (needs VCFHE_ALLOW_CLEAR_DEMO=1)
`);
      process.exit(0);
    } else {
      throw new Error(`unrecognized argument: ${arg}`);
    }
  }
  return config;
}

const config = parseArgs(process.argv.slice(2));

// ------------------------------------------------------------------ output ---

function title(text) {
  console.log();
  console.log("=".repeat(74));
  console.log(` ${text}`);
  console.log("=".repeat(74));
}

function step(text, details = []) {
  console.log();
  console.log(text);
  for (const detail of details) console.log(`  - ${detail}`);
}

function printTrace(witnesses, unpaddedLeafCount) {
  console.log();
  console.log("  idx  opcode  lhs         rhs         claimed     note");
  console.log("  ---  ------  ----------  ----------  ----------  ----------------------------------");
  for (const w of witnesses) {
    const note = w.leaf_index >= unpaddedLeafCount ? "padding no-op" : (w.note ?? "");
    console.log(
      `  ${String(w.leaf_index).padStart(3)}  ${String(w.opcode_name).padEnd(6)}  ` +
      `${String(w.lhs).padStart(10)}  ${String(w.rhs).padStart(10)}  ` +
      `${String(w.claimed).padStart(10)}  ${note}`
    );
  }
}

function printReferenceValues(workload) {
  const m = workload.model;
  const p = m.declaredParameters;
  console.log();
  console.log(`Reference values for ${m.expression} (declared values; nothing here is measured)`);
  console.log(`  - x = ${p.x}, y = ${p.y}, z = ${p.z}`);
  console.log(`  - y * z         = ${p.y} * ${p.z} = ${m.product}   [leaf ${m.leafIndex.product}]`);
  console.log(`  - total         = ${m.product} + ${p.x} = ${m.total}   [leaf ${m.leafIndex.total}, the released value]`);
  console.log(`                    no division here, so integer arithmetic loses nothing: this is exact`);
  console.log(`  - public scalar = NONE. Every operand of this trace is a ciphertext.`);
  console.log(`                    the ${m.publicScalarOpcodes.length} opcodes that take a cleartext right operand (${m.publicScalarOpcodes.join(", ")})`);
  console.log(`                    are all absent; see ../../Anatel/anatel-rqual-simplificado/ for a trace that uses them`);
}

/** Third independent pass over the trace, from this file rather than the lowering. */
function verifyTrace(witnesses) {
  for (const w of witnesses) {
    const verdict = evaluateLeaf(w.opcode_name, w.lhs, w.rhs);
    if (!verdict.valid || Number(verdict.value) !== Number(w.claimed)) {
      throw new Error(
        `leaf ${w.leaf_index} (${w.opcode_name}) claims ${w.claimed} but the micro-ISA yields ` +
        `${verdict.valid ? verdict.value : `invalid (${verdict.reason})`}`
      );
    }
  }
  return witnesses.length;
}

// ------------------------------------------------------------- run artifacts --

async function writeRunArtifacts(workload, runDir, manipulatedLeafIndex, sessionId, startedAt, fheHandles) {
  // `ethers` comes THROUGH evm-lib rather than as a bare specifier: this file
  // lives outside fhe-pod/, and Node resolves bare specifiers by walking up from
  // the importing file, so `import("ethers")` from here would not find the pod's
  // node_modules. evm-lib re-exports it for exactly this reason.
  const { attachTraceHandles, buildMerkleTree, writeJson, ethers } = await import(
    "../../fhe-pod/scripts/evm-lib.mjs"
  );

  // The committed leaf is (opcode, lhsHandle, rhsHandle, claimedHandle), so the
  // root advertised here has to be computed over the SAME ciphertext handles the
  // dispute registers on chain. That is why the artifacts are written only after
  // the encrypted-execution stage: the handles have to exist first.
  const tree = buildMerkleTree(attachTraceHandles(workload.witnesses, workload.witnesses, fheHandles));

  const resultPayload = {
    workloadId: workload.id,
    title: workload.title,
    model: workload.model,
    lowering: workload.lowering,
    finalClaimed: workload.witnesses.at(-1)?.claimed,
    generatedAt: startedAt.toISOString()
  };
  const resultHash = ethers.sha256(ethers.toUtf8Bytes(JSON.stringify(resultPayload)));
  const metadataHash = ethers.keccak256(
    ethers.toUtf8Bytes(
      JSON.stringify({
        workloadId: workload.id,
        domain: workload.domain,
        title: workload.title,
        applicability: workload.applicability,
        limitation: workload.limitation
      })
    )
  );

  const microTraceBundle = {
    session_id: sessionId,
    workload: workload.id,
    title: workload.title,
    domain: workload.domain,
    micro_trace_root: tree.root.slice(2),
    leaf_count: workload.witnesses.length,
    lowering: workload.lowering,
    witnesses: workload.witnesses,
    applicability: workload.applicability,
    limitation: workload.limitation
  };

  const attestationPayload = {
    version: "pod-evm-v2",
    domain_name: "VerifiableFHEDisputeGame",
    domain_version: "2",
    primary_type: "TaskClaim",
    chain_family: "evm",
    proof_type: "POD_DISPUTE_GAME_ARITHMETIC_TEACHING_EXAMPLE",
    session_id: sessionId,
    task_id_keccak256: ethers.keccak256(ethers.toUtf8Bytes(sessionId)),
    trace_root_keccak256: tree.root.slice(2),
    micro_trace_root_keccak256: tree.root.slice(2),
    result_hash_sha256: resultHash,
    metadata_hash_keccak256: metadataHash,
    content_uri_hint: runDir,
    content_uri_hash_keccak256: ethers.keccak256(ethers.toUtf8Bytes(runDir)),
    objective_verifier_hint:
      "Arithmetic teaching example lowered to supported deterministic micro-instructions; contested leaf decided homomorphically and attested by t+1 signatures."
  };

  const summary = {
    evaluation_id: sessionId,
    workload_id: workload.id,
    title: workload.title,
    domain: workload.domain,
    output_dir: runDir,
    micro_trace_root: tree.root.slice(2),
    micro_steps: workload.witnesses.length,
    manipulated_leaf_index: manipulatedLeafIndex,
    manipulated_operation: workload.witnesses[manipulatedLeafIndex].opcode_name,
    opcode_counts: opcodeCounts(workload.witnesses),
    lowering_engine: workload.lowering?.engineVersion,
    operation_type: workload.lowering?.operationType,
    applicability: workload.applicability,
    limitation: workload.limitation,
    demonstration_only: true
  };

  await fs.mkdir(runDir, { recursive: true });
  await Promise.all([
    writeJson(path.join(runDir, "application_workload.json"), workload),
    writeJson(path.join(runDir, "micro_trace_bundle.json"), microTraceBundle),
    writeJson(path.join(runDir, "attestation_payload.json"), attestationPayload),
    writeJson(path.join(runDir, "summary.json"), summary),
    fs.writeFile(path.join(runDir, "root.txt"), `${tree.root}\n`)
  ]);

  return { tree, summary, writeJson };
}

// --------------------------------------------------------------- subprocess --

function resolveCommand(command) {
  if (process.platform === "win32" && command === "npm") return "npm.cmd";
  return command;
}

/** Passes a variable through only when the caller actually set it. */
function passthrough(names) {
  const out = {};
  for (const name of names) {
    if (process.env[name] !== undefined && process.env[name] !== "") {
      out[name] = process.env[name];
    }
  }
  return out;
}

function runTool(command, args, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const resolved = resolveCommand(command);
    const child = spawn(resolved, args, {
      cwd: projectRoot,
      env: { ...process.env, ...extraEnv },
      stdio: ["ignore", "inherit", "inherit"],
      shell: process.platform === "win32" && resolved.endsWith(".cmd")
    });
    child.on("error", reject);
    child.on("close", (code) => (code === 0
      ? resolve()
      : reject(new Error(`${command} ${args.join(" ")} exited with ${code}`))));
  });
}

function runHardhatDispute(runDir, workloadId, manipulatedLeafIndex, fheManifestPath) {
  return new Promise((resolve, reject) => {
    const command = resolveCommand("npm");
    const child = spawn(command, ["run", "demo:hardhat"], {
      cwd: projectRoot,
      env: {
        ...process.env,
        FHE_POD_RUN_DIR: runDir,
        DEMO_MANIPULATED_LEAF_INDEX: String(manipulatedLeafIndex),
        DEMO_FHE_WORKLOAD_ID: workloadId,
        // Point the plan builder at this example's own manifest and, unless the
        // caller explicitly opted out, forbid the clear-value fallback.
        // --skip-fhe must actually skip: pointing at a manifest a previous run
        // left on disk would silently use ciphertext handles anyway, so the flag
        // would not mean what it says.
        VCFHE_CIPHERTEXT_MANIFEST: config.skipFhe
          ? path.join("artifacts", "fhe", FHE_SUBDIR, "no-such-manifest.json")
          : path.relative(projectRoot, fheManifestPath),
        VCFHE_REQUIRE_FHE_HANDLES: config.skipFhe ? "0" : "1",
        // Windows and chain selection belong to the caller; an unset variable
        // keeps the driver's own default rather than becoming an empty string.
        ...passthrough([
          "DEMO_COMMIT_WINDOW_SECONDS",
          "DEMO_OPEN_WINDOW_SECONDS",
          "DEMO_CHALLENGE_WINDOW_SECONDS",
          "DEMO_DISCLOSURE_WINDOW_SECONDS",
          "FHE_POD_NETWORK",
          "VCFHE_RPC_URL",
          "VCFHE_EXPECTED_CHAIN_ID",
          "VCFHE_MNEMONIC"
        ])
      },
      stdio: ["ignore", "pipe", "pipe"],
      shell: process.platform === "win32" && command.endsWith(".cmd")
    });
    child.stdout.on("data", (chunk) => process.stdout.write(chunk));
    child.stderr.on("data", (chunk) => process.stderr.write(chunk));
    child.on("error", reject);
    child.on("close", (code) => (code === 0
      ? resolve()
      : reject(new Error(`npm run demo:hardhat failed for ${runDir} with exit code ${code}`))));
  });
}

// --------------------------------------------------------------------- main --

const startedAt = new Date();
const runStamp = startedAt.toISOString().replace(/[-:.]/g, "").replace("Z", "Z");
const runName = `${RUN_PREFIX}-${runStamp}`;
const runDir = path.join(projectRoot, "artifacts", "runs", runName);
const evaluationsDir = path.join(projectRoot, "artifacts", "evaluations", EVALUATION_SUBDIR);
const sessionId = `${RUN_PREFIX}-${runStamp}`;

title("VC-FHE  |  minimal arithmetic teaching example  |  total = x + y * z");
console.log();
console.log("  The three values are arbitrary, chosen to explain the process. Nothing is measured,");
console.log("  nothing is regulated, and this example is not part of the implementation's evaluated set.");

const inputs = arithmeticInputs();
const workload = lowerArithmeticDemo(inputs);
const manipulatedLeafIndex = config.manipulatedLeafIndex ?? workload.defaultManipulatedLeafIndex;
if (manipulatedLeafIndex >= workload.witnesses.length) {
  throw new Error(
    `--manipulated-leaf-index ${manipulatedLeafIndex} is outside the ${workload.witnesses.length} leaves of this trace`
  );
}

const verifiedLeaves = verifyTrace(workload.witnesses);

step("Declared values", [
  `expression: ${workload.model.expression}`,
  `x = ${inputs.x}, y = ${inputs.y}, z = ${inputs.z}  ->  encrypted operands`,
  "every operand is ENCRYPTED: this expression has no public scalar at all",
  "arbitrary values; each one carries its own note in arithmetic-demo-params.json"
]);

step("Micro-ISA trace", [
  `workload id: ${workload.id}`,
  `unpadded leaves: ${workload.lowering.unpaddedLeafCount}`,
  `padded leaves:   ${workload.lowering.paddedLeafCount}`
    + (workload.lowering.paddedLeafCount === workload.lowering.unpaddedLeafCount
        ? "  (already a power of two: nothing was padded)"
        : ""),
  `bisection rounds: log2(${workload.lowering.paddedLeafCount}) = ${Math.log2(workload.lowering.paddedLeafCount)}`,
  `opcode histogram: ${JSON.stringify(workload.lowering.opcodeHistogram)}`,
  `every leaf re-evaluated against the micro-ISA: OK ${verifiedLeaves} leaves`,
  `manipulated leaf index: ${manipulatedLeafIndex} (${workload.witnesses[manipulatedLeafIndex].opcode_name})`
]);

printReferenceValues(workload);
printTrace(workload.witnesses, workload.lowering.unpaddedLeafCount);

if (config.dryRun) {
  step("Dry run", [
    "no chain was contacted, no process was spawned and no file was written",
    `the live run would write ${path.relative(projectRoot, runDir)} and ${path.relative(projectRoot, evaluationsDir)}`
  ]);
  console.log();
  process.exit(0);
}

// ------------------------------------------------- encrypted execution ------
// Every operand handle the dispute registers on chain is keccak256 of a
// serialized TFHE ciphertext, produced by executing THIS trace over FheUint64
// values. Without this stage the plan would fall back to deriving a handle from
// the clear value, which is the representation gap the evaluated workloads no
// longer have; a teaching example must not reintroduce it.
const fheDir = path.join(projectRoot, "artifacts", "fhe", FHE_SUBDIR);
const fheTracesPath = path.join(fheDir, "traces.json");
const fheManifestPath = path.join(fheDir, "ciphertext-manifest.json");
const fheCiphertextDir = path.join(fheDir, "ciphertexts");

/** True when every file exists. Async so a large trace does not stall the loop. */
async function allExist(files) {
  const checks = await Promise.all(
    files.map((file) => fs.access(file).then(() => true, () => false))
  );
  return checks.every(Boolean);
}

/**
 * Is the cached encrypted execution reusable?
 *
 * TWO conditions, and the second one is the whole point. The manifest has to
 * cover both variants, AND the ciphertext BLOBS the dispute reads have to be on
 * disk. They are separate artifacts with separate lifetimes: the manifest is
 * versioned, while `artifacts/fhe/**\/ciphertexts/` is gitignored (fhe-pod
 * /.gitignore) because a single FheUint64 is ~516 KB. So a fresh clone -- or any
 * checkout after the manifest was committed -- has the manifest and none of the
 * ciphertexts.
 *
 * Checking only the manifest, which is what this did, made the cache predicate
 * LIE: the run printed "Encrypted execution (cached)", skipped the executor,
 * spent about thirteen minutes and a hundred transactions driving the chain, and
 * only then died inside decideLeaf on a missing `result-1.ct`. The expensive
 * work was already done and thrown away.
 *
 * The files below are exactly what `decideLeaf` opens (see leaf-decision.mjs:
 * `operandCiphertextPath` and `resultCiphertextPath`): the key pair, plus, per
 * variant, every leaf result and every authenticated input. A public-constant
 * operand is a scalar of the program and has no ciphertext, so it is skipped.
 */
async function manifestCoversTrace() {
  let manifest;
  try {
    manifest = JSON.parse(await fs.readFile(fheManifestPath, "utf8"));
  } catch {
    return { ok: false, reason: "no manifest yet" };
  }

  const wanted = [workload.id, `${workload.id}#corrupted`];
  const entries = [];
  for (const key of wanted) {
    const entry = manifest.workloads?.find((w) => w.workloadId === key);
    if (!entry
      || entry.leaves.length !== workload.lowering.paddedLeafCount
      || !entry.leaves.every((l) => l.ok !== false)) {
      return { ok: false, reason: `the manifest does not cover ${key} with verified leaves` };
    }
    entries.push([key, entry]);
  }

  const needed = [
    path.join(fheCiphertextDir, "keys", "server-key.bin"),
    path.join(fheCiphertextDir, "keys", "client-key.bin")
  ];
  for (const [key, entry] of entries) {
    for (const leaf of entry.leaves) {
      needed.push(path.join(fheCiphertextDir, key, `result-${leaf.index}.ct`));
      for (const side of ["lhs", "rhs"]) {
        const source = side === "lhs" ? leaf.lhsSource : leaf.rhsSource;
        if (source === "AUTHENTICATED_INPUT") {
          needed.push(path.join(fheCiphertextDir, key, `input-${leaf.index}-${side}.ct`));
        }
      }
    }
  }
  if (!await allExist(needed)) {
    return {
      ok: false,
      reason:
        `the manifest is present but ${path.relative(projectRoot, fheCiphertextDir)}/ does not hold `
        + "the ciphertexts the leaf decision reads (that directory is gitignored)"
    };
  }

  return { ok: true };
}

let fheMode = "ciphertext handles from the TFHE executor";
if (config.skipFhe) {
  if (process.env.VCFHE_ALLOW_CLEAR_DEMO !== "1") {
    console.error(
      "--skip-fhe registers clear values as ciphertext handles and misrepresents what the\n"
      + "architecture does. Set VCFHE_ALLOW_CLEAR_DEMO=1 if you accept that for a rehearsal."
    );
    process.exit(1);
  }
  fheMode = "CLEAR VALUES (--skip-fhe): the handles are NOT ciphertexts";
  step("Encrypted execution SKIPPED", [
    "the registered handles are the clear operands, not TFHE ciphertexts;",
    "do not present this run as evidence of encrypted computation"
  ]);
} else {
  const cache = config.refreshFhe
    ? { ok: false, reason: "--refresh-fhe was passed" }
    : await manifestCoversTrace();
  if (cache.ok) {
    step("Encrypted execution (cached)", [
      `reusing ${path.relative(projectRoot, fheManifestPath)}`,
      "every leaf of both variants already executed under TFHE and checked",
      `ciphertexts present in ${path.relative(projectRoot, fheCiphertextDir)}/`,
      "re-run with --refresh-fhe to execute again"
    ]);
  } else {
    step("Encrypted execution", [
      `cache not reusable: ${cache.reason}`,
      `exporting both trace variants to ${path.relative(projectRoot, fheTracesPath)}`,
      `executing ${workload.lowering.paddedLeafCount} leaves per variant over FheUint64 with tfhe-rs`,
      "each result is decrypted and compared against the value the lowering claims",
      "first run also builds tfhe-rs, which takes minutes on its own"
    ]);
    await runTool("node", [
      "scripts/export-traces-for-fhe.mjs",
      "--only-arithmetic-demo",
      "--out", fheTracesPath,
      "--manipulated-leaf-index", String(manipulatedLeafIndex)
    ]);
    await runTool("cargo", [
      "run", "--release", "--bin", "fhe-executor", "--",
      "--traces", fheTracesPath,
      "--out", fheManifestPath,
      "--ciphertext-dir", fheCiphertextDir,
      "--verify-determinism"
    ]);
    // Same predicate, now as a post-condition. It also covers the ciphertext
    // files, so an executor build that only persisted handles fails HERE --
    // before the chain is touched -- instead of thirteen minutes later inside
    // the leaf decision.
    const after = await manifestCoversTrace();
    if (!after.ok) {
      throw new Error(
        `the TFHE executor finished but the cache is still not usable: ${after.reason}`
      );
    }
  }
}

process.env.VCFHE_CIPHERTEXT_MANIFEST = path.relative(projectRoot, fheManifestPath);
const { fheHandlesForWorkload } = await import("../../fhe-pod/scripts/fhe-handles.mjs");
const honestFheHandles = config.skipFhe
  ? null
  : fheHandlesForWorkload(workload.id, workload.witnesses.length, "honest");

const { tree, writeJson } = await writeRunArtifacts(
  workload, runDir, manipulatedLeafIndex, sessionId, startedAt, honestFheHandles
);
step("Run artifacts written", [
  `dir: ${path.relative(projectRoot, runDir)}`,
  `micro trace root (over ciphertext handles): ${tree.root}`,
  "files: micro_trace_bundle.json, application_workload.json, attestation_payload.json, summary.json, root.txt"
]);

step("Dispute pipeline", [
  "spawning `npm run demo:hardhat`: task creation, auditors, challenge,",
  "trace disclosure, bisection, homomorphic leaf decision and settlement",
  `operand handles: ${fheMode}`
]);
const disputeStart = performance.now();
await runHardhatDispute(runDir, workload.id, manipulatedLeafIndex, fheManifestPath);
const disputeWallClockMs = Math.round(performance.now() - disputeStart);

const hardhatResultPath = path.join(runDir, "hardhat_dispute_result.json");
const hardhatResult = JSON.parse(await fs.readFile(hardhatResultPath, "utf8"));
const transactions = hardhatResult.transactions ?? [];
const dishonest = hardhatResult.dishonestNode ?? {};

const decisionNames = { 0: "None", 1: "OperatorAccepted", 2: "OperatorSlashed", 3: "ChallengerSlashed" };

const record = {
  schema: "arithmetic-teaching-example-v1",
  demonstrationOnly: true,
  notPartOfEvaluatedWorkloadSet: true,
  disclaimer: workload.model.disclaimer,
  whyThisShape: workload.model.whyThisShape,
  whatIsNotHere: workload.model.whatIsNotHere,
  generatedAt: startedAt.toISOString(),
  sessionId,
  workload: {
    id: workload.id,
    title: workload.title,
    domain: workload.domain,
    applicability: workload.applicability,
    limitation: workload.limitation
  },
  expression: workload.model.expression,
  declaredParameters: workload.model.declaredParameters,
  parameterNotes: workload.model.parameterNotes,
  referenceValues: {
    product: workload.model.product,
    integerArithmeticLosesNothingHere: workload.model.integerArithmeticLosesNothingHere,
    total: workload.model.total,
    leafIndex: workload.model.leafIndex,
    releasedLeafIndex: workload.model.releasedLeafIndex,
    releasedValue: workload.model.releasedValue,
    publicScalarInThisTrace: workload.model.publicScalarInThisTrace,
    everyOperandEncrypted: workload.model.everyOperandEncrypted
  },
  trace: {
    unpaddedLeafCount: workload.lowering.unpaddedLeafCount,
    paddedLeafCount: workload.lowering.paddedLeafCount,
    bisectionRoundsExpected: Math.log2(workload.lowering.paddedLeafCount),
    opcodeHistogram: workload.lowering.opcodeHistogram,
    microIsaSize: workload.lowering.microIsaSize,
    microTraceRoot: tree.root,
    witnesses: workload.witnesses
  },
  dispute: {
    network: hardhatResult.network ?? null,
    chainId: hardhatResult.chainId ?? null,
    contractAddress: hardhatResult.contractAddress ?? null,
    objectiveVerifier: hardhatResult.objectiveVerifier ?? null,
    config: hardhatResult.config ?? null,
    // Provenance of the on-chain handles: which manifest, under which TFHE key.
    ciphertextHandles: hardhatResult.ciphertextHandles ?? null,
    manipulatedLeafIndex,
    manipulatedOpcode: workload.witnesses[manipulatedLeafIndex].opcode_name,
    bisectionRounds: dishonest.bisectionRounds ?? null,
    bisectionRoundDetail: dishonest.bisectionRoundDetail ?? null,
    // The leaf bisection ended on. `dishonest.isolatedLeaf` does not exist --
    // the dispute driver never sets it, so this field was always null -- and the
    // authoritative value is the start of the last bisection interval, which is
    // what the contract narrowed to. Cross-checked against manipulatedLeafIndex
    // below: they must agree, or the search landed on the wrong leaf.
    isolatedLeaf: dishonest.bisectionRounds?.at(-1)?.disputeStart ?? null,
    disputeWallClockMs,
    hardhatResultPath: path.relative(projectRoot, hardhatResultPath)
  },
  settlement: {
    honestDecision: hardhatResult.honestNode?.decision ?? null,
    honestDecisionName: decisionNames[hardhatResult.honestNode?.decision] ?? null,
    dishonestDecision: dishonest.decision ?? null,
    dishonestDecisionName: decisionNames[dishonest.decision] ?? null,
    dishonestOperatorSlashWei: dishonest.dishonestStakeDeltaWei ?? null,
    challengerRewardWei: dishonest.challengerStakeDeltaWei ?? null,
    settledBy:
      "objective leaf decision: FHE.eq evaluated over the ciphertexts with only the "
      + "equality bit decrypted, attested by t+1 EIP-712 signatures; not auditor majority",
    // The MEASURED counterpart of the sentence above. `recomputedBytesEqualCommitted`
    // is routinely false: tfhe-rs evaluates in parallel, so ciphertext bytes do not
    // reproduce across processes while the equality bit does. That is precisely why
    // the settlement rule is FHE.eq and not a byte comparison.
    leafDecision: dishonest.fhevmResolution
      ? {
          decidedBy: dishonest.fhevmResolution.decidedBy ?? null,
          operatorValid: dishonest.fhevmResolution.operatorValid ?? null,
          challengerValid: dishonest.fhevmResolution.challengerValid ?? null,
          eqDetail: dishonest.fhevmResolution.eqDetail ?? null
        }
      : null,
    leafDecisionAttestation: hardhatResult.leafDecisionAttestation ?? null
  },
  transactionCount: transactions.length,
  totalGasUsed: transactions.reduce((acc, tx) => acc + BigInt(tx.gasUsed ?? 0), 0n).toString(),
  transactions: transactions.map((tx, txIndex) => ({
    txIndex,
    label: tx.label ?? "",
    hash: tx.hash ?? "",
    blockNumber: tx.blockNumber ?? null,
    gasUsed: tx.gasUsed ?? "",
    status: tx.status ?? null
  }))
};

// The search has to land on the leaf that was corrupted. The driver already
// asserts the DECISION (it throws unless the dishonest task is slashed), but
// nothing asserted WHERE bisection stopped -- and a search that settled the
// right way on the wrong leaf would be a silent protocol fault, not a demo
// nicety. This is the claim the narrator's act-7 drawing makes, checked against
// what the chain actually did.
if (record.dispute.isolatedLeaf !== manipulatedLeafIndex) {
  throw new Error(
    `bisection ended on leaf ${record.dispute.isolatedLeaf} but leaf ${manipulatedLeafIndex} `
    + `is the one that was corrupted; the rounds walked `
    + `${(record.dispute.bisectionRounds ?? []).map((r) => `[${r.disputeStart},${r.disputeEnd})`).join(" -> ")}`
  );
}

await fs.mkdir(evaluationsDir, { recursive: true });
const recordPath = path.join(evaluationsDir, `${runName}.json`);
const latestPath = path.join(evaluationsDir, "latest_arithmetic_teaching_example.json");
await writeJson(recordPath, record);
await writeJson(latestPath, record);

step("Settlement", [
  `honest task:    ${record.settlement.honestDecisionName}`,
  `dishonest task: ${record.settlement.dishonestDecisionName}`,
  `isolated leaf:  ${manipulatedLeafIndex} (operatorValid=${record.settlement.leafDecision?.operatorValid}, challengerValid=${record.settlement.leafDecision?.challengerValid})`,
  `decided by:     ${record.settlement.leafDecision?.decidedBy}`,
  `ciphertext bytes reproduced: ${record.settlement.leafDecision?.eqDetail?.recomputedBytesEqualCommitted} `
    + "(false is expected, and is why the rule is FHE.eq)",
  // `bisectionRounds` is an ARRAY of round records; interpolating it printed
  // "[object Object],[object Object]". The count and the intervals it walked are
  // what a reader wants, and the last interval is the isolated leaf.
  `bisection rounds: ${record.dispute.bisectionRounds?.length ?? "?"}`
    + ` (${(record.dispute.bisectionRounds ?? [])
        .map((r) => `[${r.disputeStart},${r.disputeEnd})`).join(" -> ")})`,
  `transactions: ${record.transactionCount}, total gas: ${record.totalGasUsed}`,
  `operator slashed: ${record.settlement.dishonestOperatorSlashWei} wei`
]);

step("Records written", [
  path.relative(projectRoot, recordPath),
  path.relative(projectRoot, latestPath),
  "these paths are one directory below artifacts/evaluations/, where no collector,",
  "table generator or plotter globs for them"
]);

title("Arithmetic teaching example complete");
console.log();
console.log("  Say it plainly: every number above was invented to explain the process.");
console.log("  Two leaves are not evidence about scale.");
console.log();
