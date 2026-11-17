// LOCAL FUNCTIONAL SIMULATION ONLY. Four logical approvals and one full-key
// decryptor; these are NOT threshold-FHE shares, DKG or an MPC implementation.
// Construct only inside the trusted output-policy boundary. No public raw
// decryption endpoint is exposed by the revised service.
import { ethers } from "ethers";
import { hashJson } from "./canonical-protocol.mjs";
export class SimulatedOutputKms {
  #identities; #threshold; #decrypt; #faults; #audit = [];
  constructor({ decryptExact, participants = 4, approvals = 3, faults = {} }) {
    if (typeof decryptExact !== "function" || approvals < 1 || approvals > participants) throw new Error("invalid simulator");
    this.#identities = Array.from({ length: participants }, () => ethers.Wallet.createRandom());
    this.#threshold = approvals; this.#decrypt = decryptExact; this.#faults = faults;
  }
  async decryptAuthorized(request) {
    if (request.kind !== "final-output-release-v1") throw new Error("unsupported KMS purpose");
    const body = { purpose: "simulated-final-output-approval-v1", request };
    const digest = hashJson(body), accepted = new Set();
    for (const [i, identity] of this.#identities.entries()) {
      const fault = this.#faults[i]; if (fault === "missing") continue;
      const signer = fault === "duplicate" ? this.#identities[0] : identity;
      const signature = fault === "malformed" ? "0x00" : await signer.signMessage(ethers.getBytes(fault === "wrong-output" ? ethers.id("other-output") : digest));
      try {
        const address = ethers.verifyMessage(ethers.getBytes(digest), signature);
        if (this.#identities.some(w => w.address === address)) accepted.add(address);
      } catch { /* malformed public approval supplies no authorization */ }
    }
    this.#audit.push({ digest, approvals: accepted.size, required: this.#threshold, fheSharesProduced: 0 });
    if (accepted.size < this.#threshold) throw new Error("simulated KMS unavailable");
    const output = await this.#decrypt(request);
    return { ...output, kmsSimulation: "four logical approvals; one local full key; no MPC" };
  }
  auditLog() { return structuredClone(this.#audit); }
}
