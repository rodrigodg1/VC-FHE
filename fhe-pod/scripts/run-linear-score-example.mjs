import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { ethers } from "ethers";
import {
  buildMerkleTree,
  projectRoot,
  writeJson
} from "./evm-lib.mjs";
import { lowerWorkloadSpec } from "./application-lowering.mjs";

const startedAt = new Date();
const exampleId = `linear-score-${startedAt
  .toISOString()
  .replace(/[-:]/g, "")
  .replace(/\.\d{3}Z$/, "Z")}`;

const config = parseArgs(process.argv.slice(2));
const runDir = path.join(projectRoot, "artifacts", "runs", exampleId);

function resolveCommand(command) {
  if (process.platform === "win32" && command === "npm") {
    return "npm.cmd";
  }
  return command;
}

function parseArgs(args) {
  const parsed = {
    auditors: parseInteger(process.env.LINEAR_SCORE_AUDITORS, 4, "LINEAR_SCORE_AUDITORS", { min: 3 }),
    decryptors: parseInteger(process.env.LINEAR_SCORE_DECRYPTORS, 4, "LINEAR_SCORE_DECRYPTORS", { min: 3 }),
    manipulatedLeafIndex: parseInteger(
      process.env.LINEAR_SCORE_MANIPULATED_LEAF_INDEX,
      2,
      "LINEAR_SCORE_MANIPULATED_LEAF_INDEX",
      { min: 0 }
    )
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const nextValue = () => {
      index += 1;
      if (index >= args.length) {
        throw new Error(`${arg} requires a value`);
      }
      return args[index];
    };

    if (arg === "--auditors") {
      parsed.auditors = parseInteger(nextValue(), parsed.auditors, arg, { min: 3 });
    } else if (arg === "--decryptors") {
      parsed.decryptors = parseInteger(nextValue(), parsed.decryptors, arg, { min: 3 });
    } else if (arg === "--manipulated-leaf-index") {
      parsed.manipulatedLeafIndex = parseInteger(nextValue(), parsed.manipulatedLeafIndex, arg, { min: 0 });
    } else if (arg === "--help" || arg === "-h") {
      printUsageAndExit();
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return parsed;
}

function parseInteger(raw, fallback, label, { min = 0 } = {}) {
  if (raw === undefined || raw === null || raw === "") {
    return fallback;
  }
  const value = Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value < min) {
    throw new Error(`${label} must be an integer >= ${min}; received ${raw}`);
  }
  return value;
}

function printUsageAndExit() {
  console.log(`Usage:
  npm run example:linear-score -- [options]

Options:
  --auditors <n>                 Registered auditor pool size, minimum 3, default 4
  --decryptors <n>               Registered decryptor pool size, minimum 3, default 4
  --manipulated-leaf-index <n>   Leaf to corrupt before dispute, default 2`);
  process.exit(0);
}

function printTitle(title) {
  console.log("");
  console.log("============================================================");
  console.log(title);
  console.log("============================================================");
}

function printStep(index, title, details = []) {
  console.log("");
  console.log(`[${index}] ${title}`);
  for (const detail of details) {
    console.log(`    - ${detail}`);
  }
}

function buildLinearScoreWorkload() {
  const workload = lowerWorkloadSpec({
    id: "linear-score",
    domain: "ML inference",
    title: "Quantized linear score",
    applicability:
      "Fixed-point integer score for demonstrating how a model layer lowers into FHE micro-instructions.",
    limitation:
      "No sigmoid/softmax is proven here; the current layer supports deterministic integer thresholding.",
    defaultManipulatedLeafIndex: 2,
    operation: {
      type: "quantized_linear_classifier",
      features: [12, 7],
      weights: [5, 3],
      bias: 10,
      scaleShift: 1,
      threshold: 40,
      expectedClass: 1
    }
  });
  const model = {
    type: "quantized-linear-score",
    description:
      "Fixed-point integer score lowered by the canonical application-lowering engine.",
    features: workload.model.x,
    weights: workload.model.w,
    bias: workload.model.bias,
    scaleShift: workload.model.scaleShift,
    threshold: workload.model.threshold,
    expectedScore: workload.model.score,
    expectedClass: workload.model.expectedClass,
    lowering: workload.lowering,
    semantics: {
      score: "((x0*w0) + (x1*w1) + bias) >> scaleShift",
      class: "score > threshold ? 1 : 0",
      integerDomain: "uint64",
      overflowPolicy: "PoC assumes values fit uint64; production must define overflow explicitly."
    }
  };
  const witnesses = workload.witnesses;

  if (model.expectedScore !== 45 || witnesses.at(-1).claimed !== 1) {
    throw new Error("Internal linear-score example is inconsistent");
  }

  return { model, witnesses, workload };
}

async function writeWorkloadArtifacts() {
  const { model, witnesses, workload } = buildLinearScoreWorkload();
  if (config.manipulatedLeafIndex >= witnesses.length) {
    throw new Error(
      `--manipulated-leaf-index=${config.manipulatedLeafIndex} is outside the ${witnesses.length}-leaf workload`
    );
  }

  const tree = buildMerkleTree(witnesses);
  const resultPayload = {
    model,
    finalAccepted: witnesses.at(-1).claimed,
    finalScore: model.expectedScore,
    generatedAt: startedAt.toISOString()
  };
  const resultHash = ethers.sha256(ethers.toUtf8Bytes(JSON.stringify(resultPayload)));
  const metadataHash = ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(model)));

  const microTraceBundle = {
    session_id: exampleId,
    workload: "linear-score",
    micro_trace_root: tree.root.slice(2),
    leaf_count: witnesses.length,
    lowering: workload.lowering,
    witnesses,
    note:
      "Application-layer linear score lowered to deterministic FHE micro-instructions for the decentralized verification layer."
  };
  const attestationPayload = {
    version: "pod-evm-v2",
    domain_name: "VerifiableFHEDisputeGame",
    domain_version: "2",
    primary_type: "TaskClaim",
    chain_family: "evm",
    proof_type: "POD_DISPUTE_GAME_LINEAR_SCORE_EXAMPLE",
    session_id: exampleId,
    task_id_keccak256: ethers.keccak256(ethers.toUtf8Bytes(exampleId)),
    trace_root_keccak256: tree.root.slice(2),
    micro_trace_root_keccak256: tree.root.slice(2),
    result_hash_sha256: resultHash,
    metadata_hash_keccak256: metadataHash,
    content_uri_hint: runDir,
    content_uri_hash_keccak256: ethers.keccak256(ethers.toUtf8Bytes(runDir)),
    objective_verifier_hint:
      "Linear-score model layer lowered to micro-trace; dispute finality uses local FHEVM objective verifier."
  };
  const summary = {
    session_id: exampleId,
    output_dir: runDir,
    workload: "linear-score",
    micro_trace_root: tree.root.slice(2),
    micro_steps: witnesses.length,
    final_score: model.expectedScore,
    final_class: model.expectedClass,
    final_accepted: witnesses.at(-1).claimed,
    lowering_engine: workload.lowering.engineVersion,
    operation_type: workload.lowering.operationType,
    trace_hash_algorithm: "keccak256",
    result_hash_algorithm: "sha256",
    note:
      "This run demonstrates the application/model layer above the decentralized verification layer."
  };

  await fs.mkdir(runDir, { recursive: true });
  await Promise.all([
    writeJson(path.join(runDir, "linear_score_model.json"), model),
    writeJson(path.join(runDir, "micro_trace_bundle.json"), microTraceBundle),
    writeJson(path.join(runDir, "attestation_payload.json"), attestationPayload),
    writeJson(path.join(runDir, "summary.json"), summary),
    fs.writeFile(path.join(runDir, "root.txt"), `${tree.root}\n`)
  ]);

  return { model, witnesses, tree, resultHash };
}

function runHardhatDispute() {
  return new Promise((resolve, reject) => {
    const env = {
      ...process.env,
      FHE_POD_RUN_DIR: runDir,
      DEMO_AUDITOR_COUNT: String(config.auditors),
      DEMO_DECRYPTOR_COUNT: String(config.decryptors),
      DEMO_MANIPULATED_LEAF_INDEX: String(config.manipulatedLeafIndex)
    };
    const command = resolveCommand("npm");
    const child = spawn(command, ["run", "demo:hardhat"], {
      cwd: projectRoot,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      shell: process.platform === "win32" && command.endsWith(".cmd")
    });

    child.stdout.on("data", (chunk) => process.stdout.write(chunk));
    child.stderr.on("data", (chunk) => process.stderr.write(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`npm run demo:hardhat failed with exit code ${code}`));
        return;
      }
      resolve();
    });
  });
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

async function validateResult() {
  const resultPath = path.join(runDir, "hardhat_dispute_result.json");
  const result = await readJson(resultPath);
  const dishonestDecision = result.dishonestNode?.decision;
  const leafCheck = result.dishonestNode?.leafCheck;
  if (dishonestDecision !== 2) {
    throw new Error(`Expected dishonest operator to be slashed, got decision=${dishonestDecision}`);
  }
  if (!leafCheck || leafCheck.operatorValid !== false || leafCheck.challengerValid !== true) {
    throw new Error(`Unexpected leaf check: ${JSON.stringify(leafCheck)}`);
  }

  const exampleResult = {
    exampleId,
    runDir,
    modelPath: path.join(runDir, "linear_score_model.json"),
    microTracePath: path.join(runDir, "micro_trace_bundle.json"),
    hardhatResultPath: resultPath,
    manipulatedLeafIndex: config.manipulatedLeafIndex,
    manipulatedOperation: result.honestLeaf?.opcode_name,
    transactionCount: result.transactions?.length ?? 0,
    dishonestDecision,
    leafCheck,
    finalClaim:
      "A quantized model workload can use the verification layer if it lowers to supported deterministic micro-instructions."
  };
  await writeJson(path.join(runDir, "linear_score_example_result.json"), exampleResult);
  return exampleResult;
}

printTitle("Linear-score application-layer example");
printStep("1", "Lower model/function to a micro-trace", [
  "model=((x0*w0)+(x1*w1)+bias)>>scaleShift",
  "class=score>threshold",
  `outputRunDir=${runDir}`
]);
const { model, witnesses, tree } = await writeWorkloadArtifacts();
printStep("2", "Generated deterministic workload artifacts", [
  `features=${JSON.stringify(model.features)}`,
  `weights=${JSON.stringify(model.weights)}`,
  `bias=${model.bias}`,
  `score=${model.expectedScore}`,
  `leafCount=${witnesses.length}`,
  `microTraceRoot=${tree.root}`,
  `manipulatedLeafIndex=${config.manipulatedLeafIndex}`,
  `manipulatedOperation=${witnesses[config.manipulatedLeafIndex].opcode_name}`
]);
printStep("3", "Run decentralized verification layer", [
  "The Hardhat demo registers operators, auditors and decryptors.",
  "One auditor challenges a corrupted model micro-instruction.",
  "The dispute game bisects to the corrupted leaf.",
  "The local FHEVM verifier decides the leaf on-chain and slashes the dishonest operator."
]);
await runHardhatDispute();
const result = await validateResult();
printStep("4", "Example passed", [
  `dishonestDecision=${result.dishonestDecision} (OperatorSlashed)`,
  `leafCheck=${JSON.stringify(result.leafCheck)}`,
  `artifact=${path.join(runDir, "linear_score_example_result.json")}`
]);
