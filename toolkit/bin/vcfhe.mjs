#!/usr/bin/env node
/**
 * Command-line front end for the toolkit.
 *
 *   vcfhe inspect "x1 + x2 + x3"
 *   vcfhe compile "3*x1 + 2*x2 - x3" --inputs x1=4,x2=5,x3=2
 *   vcfhe compile "x1 + x2" --out task.json
 *
 * Exit codes: 0 accepted, 1 rejected (with reason), 2 usage error.
 */
import fs from "node:fs";
import { defineComputation, inspectExpression, CompilationError, ExpressionError, SUPPORTED_OPERATIONS } from "../src/index.mjs";

const argv = process.argv.slice(2);
const cmd = argv[0];

function usage(code = 2) {
  console.log(`vcfhe -- high-level interface to the verifiable FHE pipelines

  vcfhe inspect <expression>
      Parse and classify an expression. No inputs required.

  vcfhe compile <expression> [--inputs k=v,...] [--out file.json] [--tag name]
                             [--pipeline linear|non-linear] [--deploy]
      Compile to a task definition and print the generated instructions.
      With --deploy, also derive the on-chain statement (roots / constructor args).

  vcfhe run <expression> [--inputs k=v,...] [--out file.json] [--tag name]
      Do everything: parse, classify, validate, lower, bind the on-chain
      statement, and report the remaining deployment actions, showing each step.

  vcfhe ops
      List the supported operations.

Examples:
  vcfhe inspect "x1 + x2 + x3"
  vcfhe compile "3*x1 + 2*x2 - x3" --inputs x1=4,x2=5,x3=2
  vcfhe compile "gt(x1, 3)" --inputs x1=5 --out task.json`);
  process.exit(code);
}

function parseFlags(args) {
  const out = { inputs: null, outFile: null, tag: null, pipeline: null, deploy: false };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--inputs") {
      out.inputs = {};
      for (const pair of (args[++i] ?? "").split(",")) {
        const [k, v] = pair.split("=");
        if (!k || v === undefined) usage();
        out.inputs[k.trim()] = Number(v);
      }
    } else if (a === "--out") out.outFile = args[++i];
    else if (a === "--tag") out.tag = args[++i];
    else if (a === "--pipeline") out.pipeline = args[++i];
    else if (a === "--deploy") out.deploy = true;
    else usage();
  }
  return out;
}

function fail(err) {
  console.error(`\nREJECTED  [${err.code ?? "E_ERROR"}]  ${err.message}`);
  if (err.hint) console.error(`hint: ${err.hint}`);
  process.exit(1);
}

try {
  if (!cmd || cmd === "-h" || cmd === "--help") usage(0);

  if (cmd === "ops") {
    console.log("Linear pipeline (deterministic, constant-cost):");
    for (const p of SUPPORTED_OPERATIONS.linearPipeline) console.log(`  - ${p}`);
    console.log("\nMicro-ISA (non-linear pipeline, optimistic + dispute):");
    console.log("  infix        :", Object.keys(SUPPORTED_OPERATIONS.microISA.infix).join("  "));
    console.log("  binary calls :", Object.keys(SUPPORTED_OPERATIONS.microISA.binaryCalls).join("  "));
    console.log("  unary calls  :", Object.keys(SUPPORTED_OPERATIONS.microISA.unaryCalls).join("  "));
    process.exit(0);
  }

  const expression = argv[1];
  if (!expression) usage();
  const flags = parseFlags(argv.slice(2));

  if (cmd === "inspect") {
    const r = inspectExpression(expression);
    console.log(`expression : ${r.expression}`);
    console.log(`variables  : ${r.variables.join(", ")}`);
    console.log(`depth      : ${r.depth}`);
    console.log(`pipeline   : ${r.pipeline}${r.operation ? ` (${r.operation})` : ""}`);
    console.log(`reason     : ${r.reason}`);
    process.exit(0);
  }

  if (cmd === "run") {
    const { prepareComputation, renderSteps } = await import("../src/pipeline.mjs");
    const result = await prepareComputation(expression, {
      inputs: flags.inputs, datasetTag: flags.tag, taskLabel: flags.tag ?? undefined,
      forcePipeline: flags.pipeline,
    });
    console.log(renderSteps(result));
    if (!result.ok) process.exit(1);
    if (flags.outFile) {
      fs.writeFileSync(flags.outFile, JSON.stringify(result.artifact, null, 2) + "\n");
      console.log(`\ndeployment artefact written to ${flags.outFile}`);
    }
    process.exit(0);
  }

  if (cmd === "compile") {
    const task = await defineComputation(expression, {
      inputs: flags.inputs, datasetTag: flags.tag, forcePipeline: flags.pipeline,
    });
    console.log(task.explain());

    if (flags.deploy) {
      const { buildDeploymentArtifact } = await import("../src/deployment.mjs");
      const artifact = await buildDeploymentArtifact(task, { taskLabel: flags.tag ?? undefined });
      console.log("\n--- deployment artefact ---");
      console.log(`contract   : ${artifact.contract}`);
      console.log(`taskId     : ${artifact.taskId}`);
      if (artifact.pipeline === "linear") {
        console.log(`constructor: ${JSON.stringify(artifact.constructorArgs)}`);
      } else {
        console.log(`inputRoot     : ${artifact.statement.inputRoot}`);
        console.log(`programRoot   : ${artifact.statement.programRoot}`);
        console.log(`provenanceRoot: ${artifact.statement.provenanceRoot}`);
      }
      console.log(`verification: ${artifact.verification}`);
      if (flags.outFile) {
        fs.writeFileSync(flags.outFile, JSON.stringify(artifact, null, 2) + "\n");
        console.log(`\ndeployment artefact written to ${flags.outFile}`);
      }
      process.exit(0);
    }

    if (flags.outFile) {
      fs.writeFileSync(flags.outFile, JSON.stringify(task.toConfig(), null, 2) + "\n");
      console.log(`\nconfiguration written to ${flags.outFile}`);
    }
    process.exit(0);
  }

  usage();
} catch (err) {
  if (err instanceof CompilationError || err instanceof ExpressionError) fail(err);
  throw err;
}
