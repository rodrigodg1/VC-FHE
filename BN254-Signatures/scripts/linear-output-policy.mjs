import fs from "node:fs/promises";
import L from "./mklhs-lib.js";
import { ethers } from "ethers";
import { hashJson } from "../../fhe-pod/scripts/canonical-protocol.mjs";
export const PUBLIC_LINEAR_PARAMETERS = "VCFHE-LWE-PUBLIC-v2;k=1289;q=2^64;messageBits=10;delta=2^54;sigma=1.3847362925087773e-9;zeros=82816;margin=16;Nmax=33;BN254;OB_LHS_GEN_;balanced-reduction";
const LINEAR_DIMENSIONS = new Map([
  [ethers.id(PUBLIC_LINEAR_PARAMETERS),1290],
  [ethers.id("VCFHE-LWE-v1;k=742;q=2^64;messageBits=10;delta=2^54;sigma=0.000007069849454709433;BN254;OB_LHS_GEN_;balanced-reduction"),743]
]);

export function admitLinearBounds(op, bounds) {
  const n=bounds?.length;
  if(!Number.isInteger(n)||n<1||n>33||![0,1].includes(op))throw new Error("unsupported linear regime");
  let minimum=0n,maximum=0n;
  for(const [i,b] of bounds.entries()) {
    if(!/^(0|[1-9][0-9]*)$/.test(b.min)||!/^(0|[1-9][0-9]*)$/.test(b.max))throw new Error("invalid linear bounds");
    const lo=BigInt(b.min),hi=BigInt(b.max);
    if(lo>hi||hi>=512n)throw new Error("input outside linear message regime");
    if(op===1&&i>0){minimum-=hi;maximum-=lo;}else{minimum+=lo;maximum+=hi;}
  }
  if(minimum<0n||maximum>=512n)throw new Error("linear output outside unsigned message regime");
  return{minimum,maximum};
}

// A trusted service adapter, never a caller-supplied accepted:true predicate.
// The contract's digest alone is insufficient: recompute P(A) over the exact
// delivered canonical vector before permitting its balanced reduction/decrypt.
export function linearFinalityAdapter({ contract, context, liftedFile }) {
  return async request => {
    if (request.game.toLowerCase() !== contract.target.toLowerCase() ||
        request.chainId !== String((await contract.runner.provider.getNetwork()).chainId) ||
        await contract.datasetTag() !== context.datasetTag || await contract.keyEpoch() !== context.keyEpoch ||
        await contract.PARAMETER_DIGEST() !== context.parameterDigest) return null;
    const n=Number(await contract.totalItems()),op=Number(await contract.allowedOperation()),scale=Number(await contract.scale());
    const dimension=LINEAR_DIMENSIONS.get(context.parameterDigest);
    if(!dimension)return null;
    if(context.records.length!==n||context.inputBounds.length!==n||
      context.programDigest!==hashJson({op:op===0?"SUM":"SUB",n,scale}))return null;
    // Consent identities must be the immutable owners of these admitted slots,
    // not identities supplied in an alternative off-chain context.
    for(let i=0;i<n;i++) {
      if(!ethers.isAddress(context.records[i].owner)||
        (await contract.recordOwner(i)).toLowerCase()!==context.records[i].owner.toLowerCase())return null;
    }
    try{admitLinearBounds(op,context.inputBounds);}catch{return null;}
    const result = await contract.getBoundResult(request.taskId);
    if (!result.accepted) return null;
    const strings = JSON.parse(await fs.readFile(liftedFile,"utf8"));
    if (!Array.isArray(strings) || strings.length !== dimension ||
      strings.some(s => typeof s !== "string" || !/^(0|[1-9][0-9]*)$/.test(s) || BigInt(s) >= L.R)) return null;
    const coordinates = strings.map(BigInt), digest = L.coordsDigest(coordinates);
    if (digest !== result.outputDigest || digest !== request.outputDigest) return null;
    const point = L.g1ToContract(L.commit(coordinates,L.commitGenerators(dimension)));
    if (point.some((v,i)=>BigInt(v)!==result.outputCommitment[i])) return null;
    return {contextDigest:hashJson(context),programDigest:context.programDigest,outputDigest:digest,
      outputType:"uint64",recordIds:context.records.map(r=>r.protectedId),
      recordOwners:Object.fromEntries(context.records.map(r=>[r.protectedId,r.owner.toLowerCase()]))};
  };
}
