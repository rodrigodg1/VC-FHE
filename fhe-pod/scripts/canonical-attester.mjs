// Standalone public-computation signer. The request has no client key or values.
// Each invocation fetches the committed statement from the chain itself.
import fs from "node:fs/promises";
import { ethers } from "ethers";
import { checkExecutionContext, adjudicateCanonicalLeaf, detectCanonicalFault, hashJson } from "./canonical-protocol.mjs";
import { checkCanonicalTask, checkCanonicalTerminal, publicTracePlan, CONTEXT_TYPES, RESULT_TYPES, FULL_TYPES, canonicalDomain } from "./canonical-chain.mjs";
let raw = ""; for await (const chunk of process.stdin) raw += chunk;
const request = JSON.parse(raw);
const provider = new ethers.JsonRpcProvider(request.rpcUrl, undefined, { cacheTimeout: -1 });
try {
  const artifact = async name => JSON.parse(await fs.readFile(new URL(`../contracts/out/${name}.json`, import.meta.url), "utf8"));
  const game = new ethers.Contract(request.game, (await artifact("VerifiableFHEDisputeGame")).abi, provider);
  const availability = new ethers.Contract(await game.availabilityModule(), (await artifact("AuthenticatedTraceAvailability")).abi, provider);
  const verifier = new ethers.Contract(await game.leafDecisionVerifier(), (await artifact("CanonicalLeafVerifier")).abi, provider);
  const context = JSON.parse(await fs.readFile(request.contextFile, "utf8"));
  await checkExecutionContext(context, request.binary, request.publicDir);
  const trace = await checkCanonicalTask({ game, availability, verifier, taskId: request.taskId, context,
    publicDir: request.publicDir, operatorDir: request.operatorDir, requireRegistered: request.mode !== "context" });
  const signer = new ethers.Wallet((await fs.readFile(request.identityFile, "utf8")).trim());
  if (!(await verifier.isSigner(signer.address))) throw new Error("unregistered signer identity");
  const domain = canonicalDomain((await provider.getNetwork()).chainId, verifier.target);
  let signature, evidence;
  if (request.mode === "context") {
    evidence = { taskId: request.taskId, contextDigest: hashJson(context) };
    signature = await signer.signTypedData(domain, CONTEXT_TYPES, evidence);
  } else if (request.mode === "full") {
    const baseline = new ethers.Contract(request.baseline, (await artifact("CanonicalExecutionBaseline")).abi, provider);
    if ((await baseline.registry()).toLowerCase() !== verifier.target.toLowerCase()) throw new Error("wrong baseline registry");
    evidence = await detectCanonicalFault({ ...request, context });
    if (evidence.index !== null) throw new Error("full recomputation rejects operator trace");
    const binding = await game.getTaskResultBinding(request.taskId);
    signature = await signer.signTypedData({name:"VCFHE-Full-Execution",version:"1",chainId:domain.chainId,
      verifyingContract:baseline.target},FULL_TYPES,{taskId:request.taskId,contextDigest:hashJson(context),
      traceRoot:binding.operatorTraceRoot,resultHash:binding.resultHash});
  } else if (request.mode === "leaf") {
    const operatorLeaf = publicTracePlan(request.taskId, context, trace.manifest).leaves[request.leafIndex];
    if (!operatorLeaf) throw new Error("invalid terminal index");
    const challengerLeaf = await checkCanonicalTerminal({ game, availability, taskId: request.taskId,
      leafIndex: request.leafIndex, operatorLeaf, challengerLeaf: request.challengerLeaf });
    evidence = await adjudicateCanonicalLeaf({ ...request, context, challengerLeaf });
    const binding = await game.leafDecisionBinding(request.taskId, request.leafIndex, operatorLeaf.opcode);
    signature = await signer.signTypedData(domain, RESULT_TYPES, {
      profileDigest: hashJson(context.profile), contextDigest: hashJson(context),
      leafBinding: ethers.keccak256(binding), resultHandle: evidence.recomputedHandle
    });
  } else throw new Error("unsupported attestation request");
  console.log(JSON.stringify({ signer: signer.address, signature, evidence, plaintextOpenings: 0 }));
} finally { provider.destroy(); }
