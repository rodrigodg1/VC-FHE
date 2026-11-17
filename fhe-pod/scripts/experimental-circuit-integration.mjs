// Isolated laboratory evidence. Never writes latest_experiment_evaluation artifacts.
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { compileComplianceCircuit, evaluateCircuitReference } from "./compliance-circuit.mjs";
import { validatePublicExecution } from "./experimental-public-replay.mjs";

const run = promisify(execFile), here = path.dirname(fileURLToPath(import.meta.url));
const binary = process.env.VCFHE_CIRCUIT_EXECUTOR;
if (!binary) throw new Error("set VCFHE_CIRCUIT_EXECUTOR to the experimental release binary");
const artifact = process.argv[2];
if (!artifact) throw new Error("supply a new experiment summary path");
await fs.access(artifact).then(() => { throw new Error("summary already exists"); }, error => { if (error.code !== "ENOENT") throw error; });
const workDir = await fs.mkdtemp(path.join(os.tmpdir(), "tops-explicit-circuit-"));
const execute = async args => JSON.parse((await run(binary, args, { maxBuffer: 8 * 1024 * 1024 })).stdout);
const audit = async (publicDir, operatorDir, replayDir) => JSON.parse((await run(process.execPath,
  [path.join(here, "experimental-public-replay.mjs"), binary, publicDir, operatorDir, replayDir],
  { maxBuffer: 8 * 1024 * 1024 })).stdout);
const options = { recordCount: 3, poorThresholdMilli: 2000, targetPermille: 950, targetCell: 7 };
const report = { status: "running", workDir, cases: [], honestReplays: [], faultReplays: [],
  boundary: "Public replay experiment; not a detector soundness proof, privacy proof, KMS evaluation or experiment campaign." };
const save = () => fs.writeFile(artifact, JSON.stringify(report, null, 2));
await save();
try {
  for (const [id, regional, values] of [
    ["regulatory-positive", false, [3000, 3000, 3000]],
    ["regulatory-negative", false, [1000, 3000, 3000]],
    ["regional-positive", true, [3000, 1000, 1000, 7, 8, 8]],
    ["regional-empty", true, [3000, 3000, 3000, 8, 8, 8]]
  ]) {
    const program = compileComplianceCircuit({ ...options, regional });
    const expected = evaluateCircuitReference(program, values).value;
    const fixture = path.join(workDir, id);
    await fs.mkdir(fixture);
    await fs.writeFile(path.join(fixture, "program.json"), JSON.stringify(program));
    await fs.writeFile(path.join(fixture, "owner-values.json"), JSON.stringify(values));
    await execute(["setup", path.join(fixture, "program.json"), path.join(fixture, "owner-values.json"), fixture]);
    const publicDir = path.join(fixture, "public"), honest = path.join(fixture, "honest");
    const manifest = await execute(["execute", publicDir, honest]);
    assert.equal(manifest.profile.fixedFFT, true, "this experiment requires the explicit feature flag");
    await validatePublicExecution(publicDir, honest);
    const owner = await execute(["owner-check", path.join(fixture, "owner/client-key.bin"), honest, String(expected)]);
    report.cases.push({ id, expected: Number(expected), leaves: program.instructions.length, elapsedMs: manifest.elapsedMs, owner, profile: manifest.profile });
    console.log(`${id}: owner check passed (${program.instructions.length} leaves)`);
    if (id === "regulatory-positive") {
      for (let repetition = 0; repetition < 3; repetition++) {
        const replay = await audit(publicDir, honest, path.join(fixture, `honest-replay-${repetition}`));
        report.honestReplays.push(replay); await save();
        assert.equal(replay.status, "byte-identical-replay");
      }
      const last = program.instructions.length - 1;
      for (const [name, faults] of [["early", [0, 7]], ["middle", [Math.floor(last / 2), 7]],
        ["terminal", [last, 7]], ["multiple", [0, 7, last, 8]]]) {
        const operatorDir = path.join(fixture, `fault-${name}`);
        await execute(["execute", publicDir, operatorDir, ...faults.map(String)]);
        // The auditor process receives none of the `faults` array or expected
        // owner values, and creates its own trace from the public bundle.
        const replay = await audit(publicDir, operatorDir, path.join(fixture, `fault-replay-${name}`));
        report.faultReplays.push({ name, injectedIndices: faults.filter((_, i) => i % 2 === 0), ...replay }); await save();
        assert.equal(replay.index, faults[0]);
        assert.equal(replay.settlementVerdict, null);
      }
      const corruptDir = path.join(fixture, "missing-result");
      await fs.mkdir(corruptDir);
      await fs.copyFile(path.join(honest, "manifest.json"), path.join(corruptDir, "manifest.json"));
      await assert.rejects(validatePublicExecution(publicDir, corruptDir), /ENOENT/);
      report.missingDataRejected = true;
    }
    await save();
  }
  report.status = "passed";
} catch (error) {
  report.status = "failed"; report.error = String(error); throw error;
} finally { await save(); }
console.log(`Experiment passed; summary: ${artifact}`);
