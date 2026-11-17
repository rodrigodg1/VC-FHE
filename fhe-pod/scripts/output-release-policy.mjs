// Trusted authorization boundary. KMS cryptography is injected separately;
// neither the requester nor an attester can pass a caller-chosen finality bit.
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { ethers } from "ethers";
import { hashJson } from "./canonical-protocol.mjs";

const signedBy = (body, signature, owner) => {
  if (ethers.verifyMessage(ethers.getBytes(hashJson(body)), signature).toLowerCase() !== owner.toLowerCase()) {
    throw new Error("invalid authorization signature");
  }
};
export class OutputReleasePolicy {
  #file; #domain; #resolveFinalized; #kms;
  constructor({ ledgerFile, domain, resolveFinalized, kms }) {
    if (!domain || typeof resolveFinalized !== "function" || typeof kms?.decryptAuthorized !== "function") throw new Error("invalid release service");
    this.#file = ledgerFile; this.#domain = domain; this.#resolveFinalized = resolveFinalized; this.#kms = kms;
    fs.mkdirSync(path.dirname(path.resolve(ledgerFile)), { recursive: true });
    if (!fs.existsSync(ledgerFile)) fs.writeFileSync(ledgerFile, JSON.stringify({ version: 1, domain, records: {}, consents: {}, consumed: {}, requests: {} }), { flag: "wx", mode: 0o600 });
  }
  async #transaction(fn) {
    const lock = `${this.#file}.lock`;
    const fd = fs.openSync(lock, "wx", 0o600);
    try {
      const state = JSON.parse(fs.readFileSync(this.#file, "utf8"));
      if (state.version !== 1 || state.domain !== this.#domain) throw new Error("ledger domain mismatch");
      const save = () => {
        const tmp = `${this.#file}.${randomUUID()}.tmp`;
        const f = fs.openSync(tmp, "wx", 0o600);
        try { fs.writeFileSync(f, JSON.stringify(state)); fs.fsyncSync(f); } finally { fs.closeSync(f); }
        fs.renameSync(tmp, this.#file);
        const directory = fs.openSync(path.dirname(path.resolve(this.#file)), "r");
        try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
      };
      return await fn(state, save);
    } finally { fs.closeSync(fd); fs.unlinkSync(lock); }
  }
  async registerProtectedRecord(record, signature) {
    const body = { kind: "protected-record-v1", domain: this.#domain, ...record };
    if (body.kind !== "protected-record-v1" || body.domain !== this.#domain || !ethers.isHexString(record.id, 32) ||
        !ethers.isAddress(record.owner) || !Number.isSafeInteger(record.releaseLimit) || record.releaseLimit < 1) throw new Error("invalid record policy");
    signedBy(body, signature, record.owner);
    return this.#transaction((state, save) => {
      if (Object.hasOwn(state.records, record.id)) throw new Error("record policy already registered; epoch changes do not reset it");
      state.records[record.id] = { owner: record.owner.toLowerCase(), limit: record.releaseLimit, spent: 0 };
      save(); return hashJson(body);
    });
  }
  async registerConsent(consent, signatures) {
    if (consent.kind !== "final-output-consent-v1" || consent.domain !== this.#domain ||
        !ethers.isHexString(consent.slot, 32) || !ethers.isHexString(consent.contextDigest, 32) || !ethers.isHexString(consent.programDigest, 32) || !consent.keyEpoch ||
        !ethers.isAddress(consent.game) || !/^[1-9][0-9]*$/.test(consent.chainId) ||
        !["bool", "uint64"].includes(consent.outputType) || !Array.isArray(consent.recordIds) ||
        !consent.recordIds.length || consent.recordIds.some(id => !ethers.isHexString(id, 32)) || new Set(consent.recordIds).size !== consent.recordIds.length ||
        !Array.isArray(consent.recipients) || !consent.recipients.length || consent.recipients.some(a => !ethers.isAddress(a))) throw new Error("invalid consent");
    const consentId = hashJson(consent);
    return this.#transaction((state, save) => {
      if (Object.hasOwn(state.consents, consent.slot)) throw new Error("output slot already registered");
      for (const id of consent.recordIds) {
        const record = state.records[id]; if (!record) throw new Error("unknown protected record");
        signedBy(consent, signatures[record.owner], record.owner);
      }
      state.consents[consent.slot] = { consentId, consent }; save(); return consentId;
    });
  }
  async release(request, recipientSignature) {
    if (request.kind !== "final-output-release-v1" || request.domain !== this.#domain ||
        !ethers.isHexString(request.requestId, 32) || !ethers.isHexString(request.taskId, 32) || !ethers.isHexString(request.outputDigest, 32) || !ethers.isAddress(request.recipient)) throw new Error("unsupported release interface");
    signedBy(request, recipientSignature, request.recipient);
    return this.#transaction(async (state, save) => {
      const registered = state.consents[request.slot];
      if (!registered) throw new Error("unapproved output slot");
      const c = registered.consent;
      if (request.consentId !== registered.consentId || request.contextDigest !== c.contextDigest ||
          request.keyEpoch !== c.keyEpoch || request.game !== c.game || request.chainId !== c.chainId ||
          !c.recipients.some(a => a.toLowerCase() === request.recipient.toLowerCase())) throw new Error("request outside owner consent");
      if (Object.hasOwn(state.consumed, c.slot) || Object.hasOwn(state.requests, request.requestId)) throw new Error("release already consumed");
      // This adapter independently reads finalized contract state and delivery
      // bindings. A request field such as accepted:true has no authority here.
      const accepted = await this.#resolveFinalized(request);
      if (!accepted || accepted.contextDigest !== c.contextDigest || accepted.outputDigest !== request.outputDigest ||
          accepted.programDigest !== c.programDigest || accepted.outputType !== c.outputType ||
          hashJson([...accepted.recordIds].sort()) !== hashJson([...c.recordIds].sort())) throw new Error("no matching finalized output");
      for (const id of c.recordIds) {
        const r = state.records[id];
        if (!r || accepted.recordOwners?.[id]?.toLowerCase() !== r.owner) throw new Error("protected-record owner mismatch");
        if (r.spent >= r.limit) throw new Error("cumulative record budget exhausted");
      }
      // Reservation is durable BEFORE contacting any KMS node. Failure burns
      // this slot; it is not refunded under a new task, identity or key epoch.
      for (const id of c.recordIds) state.records[id].spent++;
      state.consumed[c.slot] = { requestId: request.requestId, outputDigest: request.outputDigest, state: "reserved" };
      state.requests[request.requestId] = c.slot; save();
      const response = await this.#kms.decryptAuthorized({ ...request, outputType: c.outputType });
      if (typeof response?.value !== "string" || !/^(0|[1-9][0-9]*)$/.test(response.value) ||
          BigInt(response.value) > (c.outputType === "bool" ? 1n : (1n << 64n)-1n)) throw new Error("KMS response outside approved output type");
      state.consumed[c.slot].state = "released"; save();
      return response;
    });
  }
  inspectLedger() { return JSON.parse(fs.readFileSync(this.#file, "utf8")); }
}
