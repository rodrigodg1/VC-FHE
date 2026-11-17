/**
 * Runner for the SIMPLIFIED ANATEL RQUAL regulatory-seal demonstration.
 *
 * This is the teaching variant of ../anatel-rqual/. It drives the SAME pipeline
 * against the SAME contracts on the SAME validator network; the only difference
 * is the trace it drives, which is 28 useful leaves padded to 32 instead of 89
 * padded to 128, because IQS and IQP are supplied as pre-aggregated encrypted
 * indicators rather than computed from measurement panels, and F(.) uses three
 * band edges instead of four.
 *
 * The consequence, and it must be said whenever both are shown: NOTHING in this
 * variant is measured data, and the two demonstrations release different seals.
 *
 * WHAT IT DOES
 * ------------
 *   1. builds the demonstration inputs from declared parameters;
 *   2. lowers the RQUAL expression to a micro-ISA trace;
 *   3. writes the run artifacts the dispute demo consumes
 *      (micro_trace_bundle.json, application_workload.json,
 *      attestation_payload.json, summary.json, root.txt);
 *   4. spawns `npm run demo:hardhat`, which plays the whole pipeline against
 *      the configured chain: task creation, auditors, challenge, trace
 *      disclosure, bisection, objective leaf resolution and slashing;
 *   5. writes a self-contained evaluation record next to the run.
 *
 * WHAT IT IS NOT
 * --------------
 * It is NOT part of the implementation's evaluation. It does not import
 * `run-application-layer-evaluation.mjs`, it does not touch any canonical
 * artifact, and its workload is not a member of `allApplicationWorkloadSpecs()`.
 * Its output filenames live under `artifacts/evaluations/anatel-rqual-simplified-demo/`
 * precisely so that no downstream collector, table generator or plotter can
 * pick them up: `collect_results.py` copies `artifacts/evaluations/latest_*.json`
 * with a NON-recursive glob, so a file one directory deeper is invisible to it,
 * and every other consumer names its input file explicitly.
 *
 * WHAT THE NUMBERS MEAN
 * ---------------------
 * Only the STRUCTURE of the expression was verified against Res. 717/2019
 * (Art. 7 defines IQS, IQP and IR; Art. 11 assigns seals A to E). The
 * regulation does not publish F(.) or its band edges, so every threshold is a
 * declared deployment parameter in `anatel-rqual-simplified-params.json`. The seal this
 * demonstration releases is NOT an official ANATEL result.
 *
 * Usage:
 *   npm run demo:anatel-simplified
 *   node Anatel/anatel-rqual-simplificado/run-anatel-rqual-simplified-demo.mjs --dry-run
 *   node Anatel/anatel-rqual-simplificado/run-anatel-rqual-simplified-demo.mjs --manipulated-leaf-index 20
 */
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

import { simplifiedRqualInputs } from "./anatel-rqual-simplified-fixtures.mjs";
import { lowerSimplifiedRqual } from "./anatel-rqual-simplified-lowering.mjs";
import { evaluateLeaf } from "../../fhe-pod/scripts/micro-isa.mjs";
import { opcodeCounts } from "../../fhe-pod/scripts/application-lowering.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
// Same value as evm-lib's `projectRoot`, computed locally so that `--dry-run`
// needs no installed dependency tree (evm-lib pulls in ethers and solc).
//
// Resolve fhe-pod from the repository root, two levels above this directory.
// Generated traces, cached ciphertext manifests, run records and npm commands
// use the pod's existing paths.
const projectRoot = path.resolve(scriptDir, "..", "..", "fhe-pod");

const RUN_PREFIX = "anatel-rqual-simplified-demo";
const EVALUATION_SUBDIR = "anatel-rqual-simplified-demo";

// -------------------------------------------------------------- arguments --

function parseArgs(argv) {
  const parsed = {
    dryRun: false,
    manipulatedLeafIndex: null,
    refreshFhe: false,
    skipFhe: false
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--dry-run") {
      parsed.dryRun = true;
    } else if (arg === "--refresh-fhe") {
      parsed.refreshFhe = true;
    } else if (arg === "--skip-fhe") {
      parsed.skipFhe = true;
    } else if (arg === "--manipulated-leaf-index") {
      i += 1;
      if (i >= argv.length) throw new Error("--manipulated-leaf-index requires a value");
      const value = Number.parseInt(argv[i], 10);
      if (!Number.isInteger(value) || value < 0) {
        throw new Error(`--manipulated-leaf-index must be an integer >= 0; received ${argv[i]}`);
      }
      parsed.manipulatedLeafIndex = value;
    } else if (arg === "--help" || arg === "-h") {
      console.log(`Usage:
  node Anatel/anatel-rqual-simplificado/run-anatel-rqual-simplified-demo.mjs [options]

Options:
  --dry-run                      Build, verify and print the trace; spawn nothing, write nothing
  --manipulated-leaf-index <n>   Corrupt leaf n instead of the released seal leaf
  --refresh-fhe                  Re-run the TFHE executor even when a manifest for this trace exists
  --skip-fhe                     Register clear values instead of ciphertext handles. Degrades the
                                 demonstration and is refused unless VCFHE_ALLOW_CLEAR_DEMO=1
  --help                         This message`);
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return parsed;
}

const config = parseArgs(process.argv.slice(2));

// ------------------------------------------------------------- timestamps --

/**
 * Run stamp: `VCFHE_RUN_STAMP` when the caller sets one (so a wrapper script
 * can name the directory it is about to describe), otherwise the current time.
 * An unset variable is NOT an error. Sanitised to a filesystem-safe token
 * because an ISO string carries colons.
 */
function resolveRunStamp() {
  const raw = process.env.VCFHE_RUN_STAMP && process.env.VCFHE_RUN_STAMP.trim() !== ""
    ? process.env.VCFHE_RUN_STAMP.trim()
    : new Date().toISOString();
  const stamp = raw.replace(/[^0-9A-Za-z]+/g, "");
  if (stamp === "") {
    throw new Error(`VCFHE_RUN_STAMP=${raw} sanitises to an empty string`);
  }
  return stamp;
}

// ----------------------------------------------------------------- output --

function title(text) {
  console.log("");
  console.log("============================================================");
  console.log(text);
  console.log("============================================================");
}

function step(text, details = []) {
  console.log("");
  console.log(text);
  for (const detail of details) console.log(`  - ${detail}`);
}

// ------------------------------------------------------------ trace check --

/**
 * Re-evaluates every committed leaf against the reference implementation of the
 * on-chain validity predicate and requires the claimed value to match.
 */
function verifyTrace(witnesses) {
  for (const [index, w] of witnesses.entries()) {
    if (w.leaf_index !== index) {
      throw new Error(`leaf ${index} declares leaf_index ${w.leaf_index}`);
    }
    const verdict = evaluateLeaf(w.opcode_name, w.lhs, w.rhs);
    if (!verdict.valid) {
      throw new Error(`leaf ${index} (${w.opcode_name}) is invalid: ${verdict.reason}`);
    }
    if (Number(verdict.value) !== Number(w.claimed)) {
      throw new Error(
        `leaf ${index} (${w.opcode_name}) claims ${w.claimed} but the micro-ISA yields ${verdict.value}`
      );
    }
  }
  return witnesses.length;
}

function printTrace(witnesses, unpaddedLeafCount) {
  console.log("");
  console.log("  idx  opcode    lhs         rhs         claimed     note");
  console.log("  ---  --------  ----------  ----------  ----------  ----------------------------------");
  for (const w of witnesses) {
    const marker = w.leaf_index >= unpaddedLeafCount ? " (pad)" : "";
    console.log(
      `  ${String(w.leaf_index).padStart(3)}  ${w.opcode_name.padEnd(8)}  ` +
        `${String(w.lhs).padStart(10)}  ${String(w.rhs).padStart(10)}  ` +
        `${String(w.claimed).padStart(10)}  ${w.note}${marker}`
    );
  }
}

function printReferenceValues(workload) {
  const m = workload.model;
  const p = m.declaredParameters;
  step("Plaintext reference values (declared parameters, NOT ANATEL numbers)", [
    `IQS  supplied directly as ${m.iqsPermille} permille (no aggregation stage in this variant)`,
    `IQP  supplied directly as ${m.iqpPermille} permille (no aggregation stage in this variant)`,
    `IR   1000 * A_P(${p.complaintsAp}) / B_P(${p.accessBaseBp}) = ${m.irPermille} permille   [leaf ${m.leafIndex.ir}]`,
    `IRscore = 1000 - min(IR, 1000) = ${m.irScorePermille} permille   [leaf ${m.leafIndex.irScore}]`,
    `band edges (permille) = [${p.bandEdgesPermille.join(", ")}]  (three, against four in ../anatel-rqual/)`,
    `F(IQS) = ${m.bandIqs}   [leaf ${m.leafIndex.bandIqs}]`,
    `F(IQP) = ${m.bandIqp}   [leaf ${m.leafIndex.bandIqp}]`,
    `F(IR)  = ${m.bandIr}   [leaf ${m.leafIndex.bandIr}]`,
    `S = F(IQS) + F(IQP) + F(IR) = ${m.compositeScoreS} (range 0..${m.compositeScoreMax})   [leaf ${m.leafIndex.compositeScoreS}]`,
    `seal cut-offs = [${p.sealCutoffs.join(", ")}]  ->  seal index = ${m.sealIndex}` +
      `${m.sealLabel ? ` (band "${m.sealLabel}")` : ""}   [leaf ${m.leafIndex.sealIndex}, the released value]`
  ]);
}

// -------------------------------------------------------------- artifacts --

/**
 * Writes the five run artifacts the dispute demo reads.
 *
 * The shapes mirror `writeWorkloadArtifacts` of
 * `run-application-layer-evaluation.mjs`; they are reproduced inline rather
 * than imported so that this demonstration cannot perturb the evaluation.
 * `ethers` and `evm-lib` are imported dynamically because `--dry-run` must work
 * in a checkout with no installed dependencies.
 */
async function writeRunArtifacts(
  workload, runDir, manipulatedLeafIndex, sessionId, startedAt, fheHandles
) {
  // `ethers` comes THROUGH evm-lib rather than as a bare specifier: this file
  // lives outside fhe-pod/, and Node resolves bare specifiers by walking up
  // from the importing file, so `import("ethers")` from here would not find the
  // pod's node_modules. evm-lib re-exports it for exactly this reason.
  const { attachTraceHandles, buildMerkleTree, writeJson, ethers } = await import(
    "../../fhe-pod/scripts/evm-lib.mjs"
  );

  // The committed trace leaf is (opcode, lhsHandle, rhsHandle, claimedHandle),
  // so the root this run advertises has to be computed over the SAME ciphertext
  // handles the dispute registers on chain -- otherwise root.txt and the
  // attestation would name a commitment no on-chain object equals. This is why
  // the artifacts are written after the encrypted-execution stage: the handles
  // must exist first. With --skip-fhe there are no ciphertexts and the handles
  // degrade to the clear-value encoding, exactly as they do in the dispute.
  const tree = buildMerkleTree(
    attachTraceHandles(workload.witnesses, workload.witnesses, fheHandles)
  );

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
    proof_type: "POD_DISPUTE_GAME_ANATEL_RQUAL_SIMPLIFIED_DEMONSTRATION",
    session_id: sessionId,
    task_id_keccak256: ethers.keccak256(ethers.toUtf8Bytes(sessionId)),
    trace_root_keccak256: tree.root.slice(2),
    micro_trace_root_keccak256: tree.root.slice(2),
    result_hash_sha256: resultHash,
    metadata_hash_keccak256: metadataHash,
    content_uri_hint: runDir,
    content_uri_hash_keccak256: ethers.keccak256(ethers.toUtf8Bytes(runDir)),
    objective_verifier_hint:
      "ANATEL RQUAL simplified teaching demonstration lowered to supported deterministic micro-instructions; contested leaf uses local FHEVM objective verifier."
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

// ------------------------------------------------------------- the dispute --

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

function runHardhatDispute(runDir, workloadId, manipulatedLeafIndex) {
  return new Promise((resolve, reject) => {
    const command = resolveCommand("npm");
    const child = spawn(command, ["run", "demo:hardhat"], {
      cwd: projectRoot,
      env: {
        ...process.env,
        FHE_POD_RUN_DIR: runDir,
        DEMO_MANIPULATED_LEAF_INDEX: String(manipulatedLeafIndex),
        DEMO_FHE_WORKLOAD_ID: workloadId,
        // Protocol windows and chain selection are the caller's to set; an
        // unset variable keeps the demo's own default rather than becoming an
        // empty string, which parseIntegerEnv would have to reject.
        // Point the plan builder at the demonstration's own manifest and, unless
        // the caller explicitly opted out, forbid the clear-value fallback.
        // --skip-fhe must actually skip: pointing at a manifest that a previous
        // run left on disk would silently use ciphertext handles anyway, so the
        // flag would not mean what it says.
        VCFHE_CIPHERTEXT_MANIFEST: config.skipFhe
          ? path.join("artifacts", "fhe", "anatel-simplified-demo", "no-such-manifest.json")
          : path.relative(projectRoot, fheManifestPath),
        VCFHE_REQUIRE_FHE_HANDLES: config.skipFhe ? "0" : "1",
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
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`npm run demo:hardhat failed for ${runDir} with exit code ${code}`));
        return;
      }
      resolve();
    });
  });
}

// ------------------------------------------------------------------- main --

const startedAt = new Date();
const runStamp = resolveRunStamp();
const runName = `${RUN_PREFIX}-${runStamp}`;
const runDir = path.join(projectRoot, "artifacts", "runs", runName);
const evaluationsDir = path.join(projectRoot, "artifacts", "evaluations", EVALUATION_SUBDIR);

title("ANATEL RQUAL quality seal - SIMPLIFIED TEACHING DEMONSTRATION");
console.log("");
console.log("  DEMONSTRATION ONLY. Only the STRUCTURE of the expression was verified against");
console.log("  Res. 717/2019 (Art. 7 defines IQS, IQP and IR; Art. 11 assigns seals A to E).");
console.log("  The regulation does NOT publish the F(.) mapping or any numeric band edge, so");
console.log("  every threshold, band edge and cut-off used here is a DECLARED DEPLOYMENT");
console.log("  PARAMETER chosen in the range of such reference values - NOT an ANATEL value.");
console.log("  The seal released below is NOT an official RQUAL result.");
console.log("  TEACHING VARIANT: nothing here is measured data, and F(.) uses three band");
console.log("  edges against four in ../anatel-rqual/, so the two runs release different seals.");

const buildStart = performance.now();
const inputs = simplifiedRqualInputs();
const workload = lowerSimplifiedRqual(inputs);
const loweringDurationMs = Math.round(performance.now() - buildStart);

const manipulatedLeafIndex = config.manipulatedLeafIndex ?? workload.defaultManipulatedLeafIndex;
if (manipulatedLeafIndex >= workload.witnesses.length) {
  throw new Error(
    `manipulated leaf ${manipulatedLeafIndex} is outside the ${workload.witnesses.length}-leaf trace`
  );
}

step("Inputs (NONE of them measured; every value is a declared parameter)", [
  `IQS: ${inputs.iqsPermille} permille, supplied directly as an encrypted indicator`,
  `IQP: ${inputs.iqpPermille} permille, supplied directly as an encrypted indicator`,
  `IR:  A_P = ${inputs.complaintsAp} encrypted, B_P = ${inputs.accessBaseBp} public scalar divisor`,
  "the full demonstration in ../anatel-rqual/ derives IQS and IQP from measured panels;",
  "this teaching variant does not, so nothing here is evidence about real data",
  `relation to the full demonstration: ${inputs.provenance.relationToFullDemo ? "stated in the parameter file" : "unstated"}`
]);

const verifiedLeafCount = verifyTrace(workload.witnesses);
step("Micro-ISA trace", [
  `workload id: ${workload.id}`,
  `unpadded leaves: ${workload.lowering.unpaddedLeafCount}`,
  `padded leaves:   ${workload.lowering.paddedLeafCount}`,
  `opcode histogram: ${JSON.stringify(workload.lowering.opcodeHistogram)}`,
  `every leaf re-evaluated against the micro-ISA: OK ${verifiedLeafCount} leaves`,
  `manipulated leaf index: ${manipulatedLeafIndex} (${workload.witnesses[manipulatedLeafIndex].opcode_name})`,
  `lowering: ${loweringDurationMs} ms`
]);

printReferenceValues(workload);

if (config.dryRun) {
  printTrace(workload.witnesses, workload.lowering.unpaddedLeafCount);
  step("Dry run", [
    "no chain was contacted, no process was spawned and no file was written",
    `the live run would write ${path.relative(projectRoot, runDir)}/ and ` +
      `${path.relative(projectRoot, evaluationsDir)}/`
  ]);
  process.exit(0);
}

const sessionId = `${runName}-${workload.id}`;

// -------------------------------------------------- encrypted execution ----
// The dispute registers one ciphertext handle per operand. Those handles are
// keccak256 of the serialized TFHE ciphertext, produced by executing this very
// trace over FheUint64 values. Without this stage the plan would fall back to
// deriving a handle from the clear value, which is exactly the representation
// gap the evaluated workloads no longer have; the demonstration must not
// reintroduce it.
//
// The manifest is written under artifacts/fhe/anatel-simplified-demo/ and selected with
// VCFHE_CIPHERTEXT_MANIFEST, so it never touches the manifest the evaluation's
// measurements were produced with.
const fheDir = path.join(projectRoot, "artifacts", "fhe", "anatel-simplified-demo");
const fheTracesPath = path.join(fheDir, "traces.json");
const fheManifestPath = path.join(fheDir, "ciphertext-manifest.json");
const fheCiphertextDir = path.join(fheDir, "ciphertexts");

function runTool(command, args, extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(resolveCommand(command), args, {
      cwd: projectRoot,
      env: { ...process.env, ...extraEnv },
      stdio: ["ignore", "inherit", "inherit"],
      shell: process.platform === "win32" && resolveCommand(command).endsWith(".cmd")
    });
    child.on("error", reject);
    child.on("close", (code) => (code === 0
      ? resolve()
      : reject(new Error(`${command} ${args.join(" ")} exited with ${code}`))));
  });
}

/** True when the manifest already covers this exact trace, honest and corrupted. */
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
 * spent many minutes driving the chain through the whole dispute, and only then
 * died inside decideLeaf on a missing `result-<i>.ct`. The expensive work was
 * already done and thrown away.
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
      "this is the slow step; it is cached, so run it once before a live demonstration"
    ]);
    await runTool("node", [
      "scripts/export-traces-for-fhe.mjs",
      "--only-anatel-simplified",
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
    // before the chain is touched -- instead of many minutes later inside the
    // leaf decision. Note it returns an OBJECT: `!await manifestCoversTrace()`
    // would be permanently false.
    const after = await manifestCoversTrace();
    if (!after.ok) {
      throw new Error(
        `the TFHE executor finished but the cache is still not usable: ${after.reason}`
      );
    }
  }
}

// The run artifacts are written here, after the ciphertexts exist, because the
// trace root they publish is the handle-based commitment the chain will hold.
process.env.VCFHE_CIPHERTEXT_MANIFEST = path.relative(projectRoot, fheManifestPath);
const { fheHandlesForWorkload } = await import("../../fhe-pod/scripts/fhe-handles.mjs");
const honestFheHandles = config.skipFhe
  ? null
  : fheHandlesForWorkload(workload.id, workload.witnesses.length, "honest");
const { tree, writeJson } = await writeRunArtifacts(
  workload,
  runDir,
  manipulatedLeafIndex,
  sessionId,
  startedAt,
  honestFheHandles
);
step("Run artifacts written", [
  `dir: ${path.relative(projectRoot, runDir)}`,
  `micro trace root (over ciphertext handles): ${tree.root}`,
  "files: micro_trace_bundle.json, application_workload.json, attestation_payload.json, summary.json, root.txt"
]);

step("Dispute pipeline", [
  "spawning `npm run demo:hardhat`: task creation, auditors, challenge,",
  "trace disclosure, bisection, objective leaf resolution and settlement",
  `operand handles: ${fheMode}`
]);
const disputeStart = performance.now();
await runHardhatDispute(runDir, workload.id, manipulatedLeafIndex);
const disputeWallClockMs = Math.round(performance.now() - disputeStart);

const hardhatResultPath = path.join(runDir, "hardhat_dispute_result.json");
const hardhatResult = JSON.parse(await fs.readFile(hardhatResultPath, "utf8"));
const transactions = hardhatResult.transactions ?? [];
const dishonest = hardhatResult.dishonestNode ?? {};
const leafCheck = dishonest.leafCheck ?? {};

const decisionNames = { 0: "None", 1: "OperatorAccepted", 2: "OperatorSlashed", 3: "ChallengerSlashed" };

const record = {
  schema: "anatel-rqual-simplified-demonstration-v1",
  demonstrationOnly: true,
  notPartOfEvaluatedWorkloadSet: true,
  runId: runName,
  sessionId,
  workloadId: workload.id,
  startedAt: startedAt.toISOString(),
  finishedAt: new Date().toISOString(),
  disclaimer: workload.model.disclaimer,
  structureSource: inputs.params.structureSource,
  expression: inputs.params.expression,

  declaredParameters: workload.model.declaredParameters,
  declaredParameterNotes: workload.model.parameterNotes,
  inputProvenance: inputs.provenance,

  referenceValues: {
    iqsPermille: workload.model.iqsPermille,
    iqpPermille: workload.model.iqpPermille,
    irPermille: workload.model.irPermille,
    irScorePermille: workload.model.irScorePermille,
    bandIqs: workload.model.bandIqs,
    bandIqp: workload.model.bandIqp,
    bandIr: workload.model.bandIr,
    compositeScoreS: workload.model.compositeScoreS,
    compositeScoreMax: workload.model.compositeScoreMax,
    sealIndex: workload.model.sealIndex,
    sealLabel: workload.model.sealLabel,
    leafIndex: workload.model.leafIndex,
    indicator: workload.model.indicator
  },
  relationToFullDemo: workload.model.relationToFullDemo,

  trace: {
    microTraceRoot: tree.root,
    loweringEngine: workload.lowering.engineVersion,
    operationType: workload.lowering.operationType,
    unpaddedLeafCount: workload.lowering.unpaddedLeafCount,
    paddedLeafCount: workload.lowering.paddedLeafCount,
    leafCount: workload.witnesses.length,
    opcodeHistogram: workload.lowering.opcodeHistogram,
    microIsaSize: workload.lowering.microIsaSize,
    microIsaVerified: workload.lowering.microIsaVerified,
    everyLeafReEvaluated: true,
    loweringDurationMs
  },

  dispute: {
    network: hardhatResult.network ?? null,
    chainId: hardhatResult.chainId ?? null,
    contractAddress: hardhatResult.contractAddress ?? null,
    objectiveVerifier: hardhatResult.objectiveVerifier ?? null,
    config: hardhatResult.config ?? null,
    ciphertextHandles: hardhatResult.ciphertextHandles ?? null,
    manipulatedLeafIndex,
    manipulatedOpcode: workload.witnesses[manipulatedLeafIndex].opcode_name,
    honestLeaf: hardhatResult.honestLeaf ?? null,
    dishonestLeaf: hardhatResult.dishonestLeaf ?? null,
    bisectionRounds: dishonest.bisectionRounds?.length ?? 0,
    bisectionRoundDetail: dishonest.bisectionRounds ?? [],
    isolatedLeaf: {
      leafIndex: leafCheck.leafIndex ?? null,
      opcode: leafCheck.opcode ?? null,
      operatorValid: leafCheck.operatorValid ?? null,
      challengerValid: leafCheck.challengerValid ?? null,
      witness: workload.witnesses[leafCheck.leafIndex ?? manipulatedLeafIndex] ?? null
    },
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
    // The MEASURED counterpart of the sentence above, copied from the dispute
    // driver's own result so this record can show the property instead of
    // asserting it. `decidedBy` is "fhe-eq" when the leaf was recomputed
    // homomorphically and each claim compared with FHE.eq; the driver refuses to
    // settle any other way under VCFHE_REQUIRE_FHE_HANDLES=1. Watch
    // `recomputedBytesEqualCommitted`: it is routinely false, because tfhe-rs
    // evaluates in parallel and ciphertext bytes do not reproduce across
    // processes, while the equality bit does. That is the whole reason the rule
    // is FHE.eq and not byte comparison.
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
  totalGasUsed: transactions
    .reduce((total, tx) => total + BigInt(tx.gasUsed ?? 0), 0n)
    .toString(),
  transactions: transactions.map((tx, txIndex) => ({
    txIndex,
    label: tx.label ?? "",
    hash: tx.hash ?? "",
    blockNumber: tx.blockNumber ?? null,
    gasUsed: tx.gasUsed ?? "",
    status: tx.status ?? null,
    durationMs: tx.durationMs ?? null
  }))
};

const recordPath = path.join(evaluationsDir, `${runName}.json`);
const latestPath = path.join(evaluationsDir, "latest_anatel_rqual_simplified_demo.json");
await writeJson(recordPath, record);
await writeJson(latestPath, record);

step("Settlement", [
  `dishonest task decision: ${record.settlement.dishonestDecision} (${record.settlement.dishonestDecisionName})`,
  `honest task decision:    ${record.settlement.honestDecision} (${record.settlement.honestDecisionName})`,
  `isolated leaf: ${record.dispute.isolatedLeaf.leafIndex} ` +
    `(operatorValid=${record.dispute.isolatedLeaf.operatorValid}, challengerValid=${record.dispute.isolatedLeaf.challengerValid})`,
  `bisection rounds: ${record.dispute.bisectionRounds}`,
  `transactions: ${record.transactionCount}, total gas: ${record.totalGasUsed}`,
  `operator slashed: ${record.settlement.dishonestOperatorSlashWei} wei`,
  `challenger rewarded: ${record.settlement.challengerRewardWei} wei`
]);

step("Records written", [
  path.relative(projectRoot, recordPath),
  path.relative(projectRoot, latestPath),
  "these paths are deliberately one directory below artifacts/evaluations/, where no",
  "existing collector, table generator or plotter globs for them"
]);

title("ANATEL RQUAL simplified demonstration complete");
