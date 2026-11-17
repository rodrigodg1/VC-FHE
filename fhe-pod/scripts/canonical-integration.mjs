// Real TFHE + independent public signer processes + deployed EVM contracts.
// Only final-output key management is a locally held-key simulation.
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import assert from "node:assert/strict";
import ganache from "ganache";
import { ethers } from "ethers";
import { compileComplianceCircuit, evaluateCircuitReference } from "./compliance-circuit.mjs";
import { createExecutionContext, runCanonicalBinary, detectCanonicalFault, canonicalTrace, hashJson } from "./canonical-protocol.mjs";
import { createCanonicalGame } from "./canonical-game-driver.mjs";
import { canonicalFinalityAdapter, publicTracePlan, checkCanonicalTerminal } from "./canonical-chain.mjs";
import { OutputReleasePolicy } from "./output-release-policy.mjs";
import { SimulatedOutputKms } from "./simulated-output-kms.mjs";
const binary = process.env.VCFHE_CIRCUIT_EXECUTOR;
if (!binary) throw new Error("set VCFHE_CIRCUIT_EXECUTOR to the pinned canonical binary");
const reportFile = process.argv[2]; if (!reportFile) throw new Error("supply a new report path");
await fs.access(reportFile).then(() => { throw new Error("report already exists"); }, e => { if (e.code !== "ENOENT") throw e; });
const workDir = await fs.mkdtemp(path.join(os.tmpdir(), "tops-canonical-integration-"));
const report = { status: "running", classification: "canonical-integration-validation", workDir,
  kms: "local-full-key-simulation; not threshold cryptography or MPC latency", cases: [], receipts: [] };
const save = () => fs.writeFile(reportFile, JSON.stringify(report, null, 2));
await save();
const server = ganache.server({ logging: { quiet: true }, wallet: { totalAccounts: 20 },
  chain: { chainId: 31337, time: new Date("2025-01-01T00:00:00Z") }, miner: { timestampIncrement: 0 } });
await server.listen(0, "127.0.0.1");
const rpcUrl = `http://127.0.0.1:${server.address().port}`;
const provider = new ethers.JsonRpcProvider(rpcUrl, undefined, { cacheTimeout: -1, pollingInterval: 20 });
const signers = Object.values(server.provider.getInitialAccounts()).slice(0, 12).map(a => new ethers.Wallet(a.secretKey, provider));
const advanceSeconds = async seconds => { await provider.send("evm_increaseTime", [seconds]); await provider.send("evm_mine", []); };
try {
  const program = compileComplianceCircuit({ recordCount: 2, poorThresholdMilli: 2000, targetPermille: 950 });
  const values = [3000, 3000];
  await fs.writeFile(path.join(workDir, "program.json"), JSON.stringify(program));
  await fs.writeFile(path.join(workDir, "owner-values.json"), JSON.stringify(values));
  await runCanonicalBinary(binary, ["setup", path.join(workDir, "program.json"), path.join(workDir, "owner-values.json"), workDir]);
  const publicDir = path.join(workDir, "public");
  const context = await createExecutionContext({ binary, publicDir, keyEpoch: "fixture-epoch-1", policyDomain: "canonical-integration",
    inputBounds: values.map(() => ({ min: "0", max: "5000" })),
    records: values.map((_, i) => ({ id: `rating:${i}`, protectedId: ethers.id(`record-${i}`), owner: signers[8 + i].address })) });
  const honestDir = path.join(workDir, "honest");
  const game = await createCanonicalGame({ provider, signers, context, binary, publicDir, workDir, rpcUrl, advanceSeconds,
    receipt: r => report.receipts.push(r) });
  report.runtimeBytes = game.runtimeBytes;
  const honestTask = ethers.id("canonical-honest");
  // One final output slot, approved by every selected input owner.
  const recipient = ethers.Wallet.createRandom(), domain = context.policyDomain;
  const sign = (w, body) => w.signMessage(ethers.getBytes(hashJson(body)));
  let kmsCalls = 0;
  const policy = new OutputReleasePolicy({ ledgerFile: path.join(workDir, "release-ledger.json"), domain,
    resolveFinalized: canonicalFinalityAdapter({ ...game, context, publicDir, operatorDir: honestDir }),
    kms: new SimulatedOutputKms({ decryptExact: async request => {
      kmsCalls++;
      // Called only after finality, exact digest/consent checks and durable reservation.
      return runCanonicalBinary(binary, ["release-output", path.join(workDir, "owner/client-key.bin"),
        path.join(honestDir, `result-${program.instructions.length - 1}.ct`), request.outputDigest]);
    } }) });
  for (const r of context.inputs) {
    const owner = signers.find(w => w.address === r.owner), record = { id: r.protectedId, owner: r.owner, releaseLimit: 1 };
    await policy.registerProtectedRecord(record, await sign(owner, { kind: "protected-record-v1", domain, ...record }));
  }
  const c = { kind: "final-output-consent-v1", domain, slot: ethers.id("approved-compliance-output"),
    contextDigest: hashJson(context), programDigest: context.programDigest, keyEpoch: context.keyEpoch,
    game: game.game.target, chainId: "31337", recordIds: context.inputs.map(r => r.protectedId),
    outputType: "bool", recipients: [recipient.address] };
  const signatures = Object.fromEntries(await Promise.all(context.inputs.map(async r =>
    [r.owner.toLowerCase(), await sign(signers.find(w => w.address === r.owner), c)])));
  const consentId = await policy.registerConsent(c, signatures);
  // The supported workflow obtains owner consent before encrypted execution.
  // Public computation can be performed outside this workflow; only the
  // policy service may authorize a final decryption.
  assert.ok(consentId); await assert.rejects(fs.access(honestDir));
  await runCanonicalBinary(binary, ["execute-canonical", publicDir, honestDir]);
  await runCanonicalBinary(binary, ["owner-check", path.join(workDir, "owner/client-key.bin"), honestDir, String(evaluateCircuitReference(program, values).value)]);
  await game.createTask(honestTask, honestDir);
  const honestReplay = await detectCanonicalFault({ context, binary, publicDir, operatorDir: honestDir, replayDir: path.join(workDir, "honest-auditor") });
  assert.equal(honestReplay.index, null);
  report.cases.push({ name: "independent-honest-replay", ...honestReplay }); await save();
  const manifest = JSON.parse(await fs.readFile(path.join(honestDir, "manifest.json"), "utf8"));
  const request = { kind: "final-output-release-v1", domain, requestId: ethers.id("output-request"), taskId: honestTask,
    slot: c.slot, consentId, contextDigest: c.contextDigest, keyEpoch: c.keyEpoch,
    game: c.game, chainId: c.chainId, outputDigest: manifest.terminalHandle, recipient: recipient.address };
  const release = async r => policy.release(r, await sign(recipient, r));
  await assert.rejects(release(request), /finalized/); assert.equal(kmsCalls, 0);
  await game.acceptHonest(honestTask);
  const output = await release(request); assert.equal(output.value, "1");
  await assert.rejects(release(request), /consumed/); assert.equal(kmsCalls, 1);
  for (const kind of ["leaf-equality", "audit-verdict"]) await assert.rejects(release({ ...request, kind }));
  report.cases.push({ name: "authorized-final-output", output, kmsCalls, ledger: policy.inspectLedger(), unauthorizedKmsCalls: 0 }); await save();
  // The fault positions are retained here only, never passed to detector or signer.
  for (const [name, faults] of [["early", [0, 7]], ["middle", [3, 7]], ["terminal", [7, 7]], ["multiple", [0, 7, 7, 8]]]) {
    const operatorDir = path.join(workDir, `operator-${name}`), replayDir = path.join(workDir, `auditor-${name}`);
    await runCanonicalBinary(binary, ["execute-canonical-fault-fixture", publicDir, operatorDir, ...faults.map(String)]);
    const taskId = ethers.id(`canonical-${name}`);
    // Replenish the same operator's collateral after prior task penalties.
    if (await game.game.getParticipantStake(signers[1].address) < ethers.parseEther("2")) {
      await game.record("operatorTopup", game.game.connect(signers[1]).registerOperator({ value: ethers.parseEther("2") }));
    }
    await game.createTask(taskId, operatorDir);
    const detection = await detectCanonicalFault({ context, binary, publicDir, operatorDir, replayDir });
    assert.equal(detection.index, faults[0]);
    const settlement = await game.auditAndChallenge(taskId, detection, replayDir, { afterAdmission: async ({ game: chainGame }) => {
      const stake = await chainGame.getParticipantStake(signers[1].address);
      await advanceSeconds(500);
      await assert.rejects(chainGame.timeoutDispute.staticCall(taskId));
      await assert.rejects(chainGame.finalizeUnchallenged.staticCall(taskId));
      assert.equal(await chainGame.getParticipantStake(signers[1].address), stake);
      assert.equal(Number((await chainGame.getTaskStatus(taskId))[0]), 2);
    } });
    assert.equal(settlement.state[0], 3); assert.equal(settlement.state[1], 2);
    assert.equal(settlement.certificates[0].evidence.operatorValid, false);
    assert.equal(settlement.certificates[0].evidence.challengerValid, true);
    report.cases.push({ name, injectedIndices: faults.filter((_, i) => i % 2 === 0), detection, settlement }); await save();
    console.log(`${name}: independently detected and slashed at leaf ${detection.index}`);
  }
  // Malicious accusation against the real honest FHE trace. Withhold the
  // complete candidate directory after its terminal opening is authenticated.
  const falseTask = ethers.id("canonical-false-challenger-withholding");
  await game.record("operatorTopup",game.game.connect(signers[1]).registerOperator({value:ethers.parseEther("2")}));
  for(const auditor of signers.slice(2,5))
    await game.record("auditorTopup",game.game.connect(auditor).registerAuditor({value:ethers.parseEther("1")}));
  const candidateDir = path.join(workDir,"operator-early");
  const candidate = await canonicalTrace(context,publicDir,candidateDir);
  const honest = await canonicalTrace(context,publicDir,honestDir);
  await game.createTask(falseTask,honestDir);
  const allegation = {index:0,operatorRoot:honest.tree.root,replayRoot:candidate.tree.root};
  const challenged = await game.auditAndChallenge(falseTask,allegation,candidateDir,{afterAdmission:async ({claimArgs})=>{
    const opLeaf=publicTracePlan(falseTask,context,honest.manifest).leaves[0];
    await assert.rejects(checkCanonicalTerminal({...game,taskId:falseTask,leafIndex:0,operatorLeaf:opLeaf,
      challengerLeaf:{...claimArgs[2],claimedHandle:ethers.id("invented-terminal-opening")}}),/uncommitted/);
    await fs.rename(candidateDir,path.join(workDir,"withheld-candidate"));
    await assert.rejects(fs.access(candidateDir));
  }});
  assert.equal(challenged.certificates[0].evidence.operatorValid,true);
  assert.equal(challenged.certificates[0].evidence.challengerValid,false);
  assert.equal(challenged.state[0],1); // A rejected accusation reopens auditing.
  await game.acceptHonest(falseTask);
  report.cases.push({name:"withheld-challenger-trace-real-fhe",candidateUnavailable:true,
    forgedOpeningRejected:true,settlement:challenged,finalState:Array.from(await game.game.getTaskStatus(falseTask),v=>typeof v==="bigint"?Number(v):v)});
  await save();
  report.status = "passed"; report.auditPlaintextOpenings = 0;
} catch (e) { report.status = "failed"; report.error = String(e.stack ?? e); throw e; }
finally { await save(); provider.destroy(); await server.close(); }
console.log(JSON.stringify({ status: report.status, reportFile, workDir }));
