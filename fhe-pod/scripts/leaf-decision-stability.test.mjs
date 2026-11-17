#!/usr/bin/env node
/**
 * The leaf decision is stable across evaluation schedules; the ciphertext bytes
 * are not.
 *
 * WHAT THIS TEST ESTABLISHES, and why it is the test that matters.
 *
 * The protocol used to settle a disputed leaf by comparing ciphertext handles:
 *
 *     operatorValid := (operatorHandle == referenceHandle)
 *
 * with `handle = keccak256(safe_serialize(ciphertext))`. That rule is unsound,
 * because tfhe-rs evaluates in parallel and the resulting ciphertext depends on
 * the schedule the process happened to take. An operator that executed the
 * declared operation correctly can produce a different -- equally valid --
 * result ciphertext, and a byte comparison would slash it.
 *
 * The settlement rule is now `FHE.eq(recomputed, claimed)`, evaluated
 * homomorphically, of which only the bit is decrypted. This test re-executes a
 * workload in N INDEPENDENT PROCESSES, under CPU load chosen to perturb the
 * schedule, and asserts:
 *
 *   1. every replay decrypts to the committed values (the computation is right);
 *   2. every replay's leaf DECISION is `true` against the committed result --
 *      including in replays whose result BYTES differ from the committed ones;
 *   3. a wrong claim is still rejected, so the decision has not been weakened
 *      into "always accept";
 *   4. it reports how many replays reproduced the bytes, which is the property
 *      the protocol no longer depends on.
 *
 * The test does not REQUIRE a byte divergence to occur -- divergence is a race
 * and a run may not hit one -- but when one occurs it is the strongest evidence
 * available, so the test prints it and still requires the decision to hold.
 *
 * Fixtures: an ephemeral executor run over one small workload, written under
 * `artifacts/fhe/stability-test/` (or $VCFHE_STABILITY_DIR). Set
 * VCFHE_STABILITY_REPLAYS / VCFHE_STABILITY_LOAD to change the sampling.
 *
 *   node --test scripts/leaf-decision-stability.test.mjs
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  canonicalEvaluationEnv,
  decideLeaf,
  ensureCtInspect,
  ensureFheExecutor,
  replayWithDecisions,
  resultCiphertextPath,
  startCpuLoad
} from "./leaf-decision.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const podRoot = path.resolve(scriptDir, "..");

const WORKLOAD = process.env.VCFHE_STABILITY_WORKLOAD ?? "qoe_mos_degradation_alarm";
const CORRUPTED = `${WORKLOAD}#corrupted`;
const REPLAYS = Number(process.env.VCFHE_STABILITY_REPLAYS ?? 6);
const LOAD = Number(process.env.VCFHE_STABILITY_LOAD ?? Math.max(2, os.cpus().length - 2));
/**
 * VCFHE_CANONICAL=1 runs the fixture and every replay under the SINGLE-THREAD
 * profile (one rayon thread, see `canonicalEvaluationEnv`) and additionally
 * prices it against one parallel replay. It is a measurement arm only: byte
 * reproduction is REPORTED in both arms and REQUIRED in neither. On
 * 2026-09-02 the single-thread arm reproduced 256/384 leaves and the divergent
 * handles recurred in a small set, the same set the parallel profile produces,
 * so single-threading is not a determinism device for this library. The
 * fixture lives in its own directory so the two arms are never mixed.
 */
const CANONICAL = process.env.VCFHE_CANONICAL === "1";
const workDir = path.resolve(
  podRoot,
  process.env.VCFHE_STABILITY_DIR ??
    (CANONICAL ? "artifacts/fhe/stability-test-canonical" : "artifacts/fhe/stability-test")
);
const summaryPath = path.join(workDir, "summary.json");
const tracesPath = path.join(workDir, "traces.json");
const ciphertextDir = path.join(workDir, "ciphertexts");
const manifestPath = path.join(workDir, "ciphertext-manifest.json");

/** Build the fixture once: execute the honest and corrupted variants under FHE. */
function buildFixture() {
  fs.mkdirSync(workDir, { recursive: true });
  const exported = spawnSync(process.execPath,
    [path.join(scriptDir, "export-traces-for-fhe.mjs"),
      "--workloads", WORKLOAD, "--out", tracesPath],
    { cwd: podRoot, encoding: "utf8" });
  assert.equal(exported.status, 0, `fixture export failed: ${exported.stderr}`);
  if (fs.existsSync(manifestPath)) {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const covered = manifest.workloads?.map((w) => w.workloadId) ?? [];
    const requiredFiles = [
      path.join(ciphertextDir, "keys", "server-key.bin"),
      path.join(ciphertextDir, "keys", "client-key.bin")
    ];
    for (const w of manifest.workloads ?? []) {
      if (w.workloadId !== WORKLOAD && w.workloadId !== CORRUPTED) continue;
      for (const leaf of w.leaves ?? []) {
        requiredFiles.push(resultCiphertextPath(ciphertextDir, w.workloadId, leaf.index));
      }
      for (const input of w.inputs ?? []) {
        requiredFiles.push(path.join(ciphertextDir, w.workloadId, `input-${input.leafIndex}-${input.side}.ct`));
      }
    }
    // The JSON is tracked but the ciphertext/key files are not. A fresh local
    // checkout must regenerate the fixture instead of reusing an empty cache.
    if (covered.includes(WORKLOAD) && covered.includes(CORRUPTED) &&
        requiredFiles.every((file) => fs.existsSync(file))) return manifest;
  }
  const executor = ensureFheExecutor();
  fs.mkdirSync(workDir, { recursive: true });
  const run = spawnSync(
    executor,
    [
      "--traces", tracesPath,
      "--out", manifestPath,
      "--ciphertext-dir", ciphertextDir,
      "--workloads", `${WORKLOAD},${CORRUPTED}`
    ],
    {
      cwd: podRoot,
      encoding: "utf8",
      maxBuffer: 256 * 1024 * 1024,
      env: CANONICAL ? canonicalEvaluationEnv() : process.env
    }
  );
  assert.equal(run.status, 0, `fhe-executor failed: ${String(run.stderr).slice(-2000)}`);
  return JSON.parse(fs.readFileSync(manifestPath, "utf8"));
}

test(
  CANONICAL
    ? "single-thread profile: the leaf decision holds in every replay; byte reproduction is measured"
    : "a disputed leaf is decided by FHE.eq, not by ciphertext bytes",
  async (t) => {
  ensureCtInspect();
  const manifest = buildFixture();
  const honest = manifest.workloads.find((w) => w.workloadId === WORKLOAD);
  const corrupted = manifest.workloads.find((w) => w.workloadId === CORRUPTED);
  assert.ok(honest && corrupted, "fixture must cover both variants");

  // The disputed leaf: the first one where the corrupted trace differs.
  const disputedLeaf = honest.leaves.findIndex(
    (leaf, index) => String(leaf.claimed) !== String(corrupted.leaves[index].claimed)
  );
  assert.ok(disputedLeaf >= 0, "the corrupted variant must differ somewhere");
  t.diagnostic(
    `workload ${WORKLOAD}, ${honest.leaves.length} leaves, disputed leaf ${disputedLeaf} ` +
      `(${honest.leaves[disputedLeaf].opcode}); ${REPLAYS} replays under ${LOAD} busy cores; ` +
      `profile ${CANONICAL ? "single-thread (RAYON_NUM_THREADS=1)" : "parallel"}`
  );

  // --- 1. replay in independent processes, under load ----------------------
  const load = startCpuLoad(LOAD);
  const replays = [];
  try {
    for (let i = 0; i < REPLAYS; i += 1) {
      replays.push(
        replayWithDecisions({
          ciphertextDir,
          tracesPath,
          workloadId: WORKLOAD,
          decide: true,
          canonical: CANONICAL
        })
      );
    }
  } finally {
    load.stop();
  }

  let byteMatches = 0;
  let byteDivergences = 0;
  for (const [replayIndex, replay] of replays.entries()) {
    for (const leaf of replay.leaves) {
      const committed = honest.leaves.find((l) => l.index === leaf.index);

      // (1) the computation is right in every replay
      assert.equal(
        String(leaf.decrypted),
        String(committed.claimed),
        `replay ${replayIndex} leaf ${leaf.index} decrypted ${leaf.decrypted}, expected ${committed.claimed}`
      );

      // (2) the DECISION holds in every replay, byte-identical or not
      assert.equal(
        leaf.decisionBit,
        true,
        `replay ${replayIndex} leaf ${leaf.index}: FHE.eq against the committed result was false`
      );

      if (String(leaf.resultHandle).toLowerCase() === String(committed.resultHandle).toLowerCase()) {
        byteMatches += 1;
      } else {
        byteDivergences += 1;
        t.diagnostic(
          `replay ${replayIndex} leaf ${leaf.index} ${leaf.opcode}: BYTES DIVERGED ` +
            `(${leaf.resultHandle.slice(0, 12)}… vs committed ${committed.resultHandle.slice(0, 12)}…) ` +
            `-- decrypts to ${leaf.decrypted}, FHE.eq decision still ${leaf.decisionBit}`
        );
      }
    }
  }
  const total = byteMatches + byteDivergences;
  t.diagnostic(
    `byte reproducibility: ${byteMatches}/${total} replayed leaves reproduced the committed ` +
      `handle, ${byteDivergences} did not. Decision agreement: ${total}/${total}.`
  );

  // --- 1b. price the single-thread profile (measurement arm only) ----------
  const replayMs = replays.map((replay) => replay.elapsedMs ?? null).filter((v) => v !== null);
  const meanMs = replayMs.length ? replayMs.reduce((a, b) => a + b, 0) / replayMs.length : null;
  let parallelMs = null;
  if (CANONICAL) {
    // One replay under the parallel profile, decisions off, against the same
    // single-thread fixture: the cost of the profile is the ratio of the two.
    const parallel = replayWithDecisions({
      ciphertextDir,
      tracesPath,
      workloadId: WORKLOAD,
      decide: false,
      canonical: false
    });
    parallelMs = parallel.elapsedMs ?? null;
    t.diagnostic(
      `canonical replay ${meanMs === null ? "n/a" : Math.round(meanMs)} ms mean over ${replayMs.length}; ` +
        `parallel replay ${parallelMs === null ? "n/a" : Math.round(parallelMs)} ms; ` +
        `ratio ${meanMs !== null && parallelMs ? (meanMs / parallelMs).toFixed(2) : "n/a"}`
    );
  }
  fs.writeFileSync(
    summaryPath,
    JSON.stringify(
      {
        profile: CANONICAL ? "single-thread" : "parallel",
        rayonThreads: CANONICAL ? 1 : null,
        workload: WORKLOAD,
        leaves: honest.leaves.length,
        replays: REPLAYS,
        busyCores: LOAD,
        hostCores: os.cpus().length,
        replayedLeaves: total,
        byteMatches,
        byteDivergences,
        decisionAgreement: total,
        replayMs,
        replayMsMean: meanMs,
        parallelReplayMs: parallelMs,
        canonicalOverParallel: meanMs !== null && parallelMs ? meanMs / parallelMs : null,
        recordedAt: new Date().toISOString()
      },
      null,
      2
    ) + "\n"
  );
  t.diagnostic(`summary written to ${path.relative(podRoot, summaryPath)}`);

  // --- 2. the decision still rejects a wrong claim -------------------------
  // Same leaf, adjudicated the way `settleLeafViaAttestedDecision` gets its
  // bits: recompute from the committed operands, FHE.eq against each claim.
  const decision = decideLeaf({
    ciphertextDir,
    manifest,
    referenceKey: WORKLOAD,
    leafIndex: disputedLeaf,
    rhsScalar: 0,
    claims: [
      {
        label: "challenger",
        ciphertextPath: resultCiphertextPath(ciphertextDir, WORKLOAD, disputedLeaf),
        expectedHandle: honest.leaves[disputedLeaf].resultHandle
      },
      {
        label: "operator",
        ciphertextPath: resultCiphertextPath(ciphertextDir, CORRUPTED, disputedLeaf),
        expectedHandle: corrupted.leaves[disputedLeaf].resultHandle
      }
    ]
  });

  assert.equal(decision.byLabel.challenger, true, "the honest claim must be accepted");
  assert.equal(decision.byLabel.operator, false, "the corrupted claim must be rejected");

  const recomputedMatchedCommitted =
    String(decision.recomputedHandle).toLowerCase() ===
    String(honest.leaves[disputedLeaf].resultHandle).toLowerCase();
  t.diagnostic(
    `leaf ${disputedLeaf} adjudicated: challenger=true operator=false; the recomputation's own ` +
      `bytes ${recomputedMatchedCommitted ? "matched" : "did NOT match"} the committed result ` +
      `handle, which did not change the decision`
  );

  // --- 3. the property being asserted, stated as a number ------------------
  assert.equal(
    replays.length,
    REPLAYS,
    "every replay must have produced a result"
  );
});
