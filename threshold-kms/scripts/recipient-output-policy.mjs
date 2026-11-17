// Authorization component for recipient-encrypted KMS responses. This does not
// expose a plaintext callback or by itself restrict access to upstream cores.
// The trusted deployment supplies the request decoder, finalized-state resolver
// and private core transport. The diagnostic native pilot does not yet wire it.
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {createRequire} from 'node:module';
const require = createRequire(new URL('../../BN254-Signatures/package.json', import.meta.url));
const {ethers} = require('ethers');
const canonical = value => {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])]));
  if (value === null || ['string', 'boolean'].includes(typeof value) || Number.isSafeInteger(value)) return value;
  throw Error('noncanonical signed data');
};
export const policyHash = value => ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(canonical(value))));
const hash = x => typeof x === 'string' && /^0x[0-9a-f]{64}$/.test(x);
const address = x => typeof x === 'string' && ethers.isAddress(x);
const fields = (object, required) => {
  if (!object || Object.keys(object).length !== required.length || !required.every(k => Object.hasOwn(object,k))) throw Error('unexpected policy fields');
};
const signed = (body, signature, signer) => {
  if (!address(signer) || ethers.verifyMessage(ethers.getBytes(policyHash(body)), signature).toLowerCase() !== signer.toLowerCase()) throw Error('invalid policy signature');
};
const equal = (a, b, names) => names.every(k => a[k] === b[k]);
const contextFields = ['chainId','game','contextDigest','programDigest','keyId','keyEpoch','profileDigest','keysetDigest','mpcContext'];

export class RecipientOutputPolicy {
  #file; #domain; #resolve; #inspect; #submit;
  constructor({ledgerFile, domain, resolveFinalized, inspectRequest, submitUserDecrypt}) {
    if (!hash(domain) || ![resolveFinalized,inspectRequest,submitUserDecrypt].every(f => typeof f === 'function')) throw Error('invalid trusted policy configuration');
    this.#file = path.resolve(ledgerFile); this.#domain = domain;
    this.#resolve = resolveFinalized; this.#inspect = inspectRequest; this.#submit = submitUserDecrypt;
    fs.mkdirSync(path.dirname(this.#file), {recursive:true});
    if (!fs.existsSync(this.#file)) fs.writeFileSync(this.#file, JSON.stringify({version:2,domain,records:{},consents:{},slots:{},requests:{}}), {flag:'wx',mode:0o600});
  }
  async #transaction(callback) {
    const lock = `${this.#file}.lock`, fd = fs.openSync(lock, 'wx', 0o600);
    try {
      const state = JSON.parse(fs.readFileSync(this.#file, 'utf8'));
      if (state.version !== 2 || state.domain !== this.#domain) throw Error('ledger domain/version mismatch');
      const save = () => {
        const temp = `${this.#file}.${randomUUID()}.tmp`, out = fs.openSync(temp, 'wx', 0o600);
        try {fs.writeFileSync(out, JSON.stringify(state)); fs.fsyncSync(out);} finally {fs.closeSync(out);}
        fs.renameSync(temp, this.#file);
        const dir = fs.openSync(path.dirname(this.#file), 'r');
        try {fs.fsyncSync(dir);} finally {fs.closeSync(dir);}
      };
      return await callback(state, save);
    } finally {fs.closeSync(fd); fs.unlinkSync(lock);}
  }
  async registerRecord(record, signature) {
    fields(record, ['kind','domain','id','owner','releaseLimit']);
    if (record.kind !== 'kms-protected-record-v2' || record.domain !== this.#domain || !hash(record.id) ||
        !address(record.owner) || !Number.isSafeInteger(record.releaseLimit) || record.releaseLimit < 1) throw Error('invalid protected record');
    signed(record, signature, record.owner);
    return this.#transaction((state, save) => {
      if (Object.hasOwn(state.records,record.id)) throw Error('record budget already registered');
      state.records[record.id] = {owner:record.owner.toLowerCase(),limit:record.releaseLimit,spent:0}; save();
    });
  }
  async registerConsent(consent, signatures) {
    fields(consent, ['kind','domain','slot',...contextFields,'outputType','recordIds','recipients']);
    if (consent.kind !== 'kms-final-consent-v2' || consent.domain !== this.#domain || !hash(consent.slot) ||
        !['contextDigest','programDigest','keyId','keyEpoch','profileDigest','keysetDigest','mpcContext'].every(k => hash(consent[k])) ||
        !address(consent.game) || !/^[1-9][0-9]*$/.test(consent.chainId) || !['bool','uint16','uint64'].includes(consent.outputType) ||
        !Array.isArray(consent.recordIds) || !consent.recordIds.length || !consent.recordIds.every(hash) ||
        new Set(consent.recordIds).size !== consent.recordIds.length || !Array.isArray(consent.recipients) ||
        !consent.recipients.length || !consent.recipients.every(address)) throw Error('invalid final-output consent');
    return this.#transaction((state, save) => {
      if (Object.hasOwn(state.consents,consent.slot)) throw Error('output slot already registered');
      for (const id of consent.recordIds) {
        const record = state.records[id]; if (!record) throw Error('unknown protected record');
        signed(consent, signatures[record.owner], record.owner);
      }
      const id = policyHash(consent); state.consents[consent.slot] = {id,consent}; save(); return id;
    });
  }
  async release(request, recipientSignature, wireBytes) {
    fields(request, ['kind','domain','slot','consentId',...contextFields,'requestId','taskId','aggregateDigest',
      'outputDigest','outputType','recipient','encKeyDigest','kmsRequestDigest']);
    if (request.kind !== 'kms-recipient-release-v2' || request.domain !== this.#domain || !address(request.recipient) ||
        !['slot','consentId','requestId','taskId','aggregateDigest','outputDigest','encKeyDigest','kmsRequestDigest'].every(k => hash(request[k])) ||
        !(wireBytes instanceof Uint8Array) || !wireBytes.length || ethers.keccak256(wireBytes) !== request.kmsRequestDigest) throw Error('invalid recipient request');
    signed(request, recipientSignature, request.recipient);
    // Copy attacker-supplied data before awaiting anything; the signed request
    // and wire bytes used for reservation/transport must be the same snapshot.
    const r = Object.freeze(structuredClone(request)), wire = Uint8Array.from(wireBytes);
    return this.#transaction(async (state, save) => {
      const registered = state.consents[r.slot], c = registered?.consent;
      if (!c || registered.id !== r.consentId || !equal(r,c,contextFields.concat('outputType')) ||
          !c.recipients.some(a => a.toLowerCase() === r.recipient.toLowerCase())) throw Error('outside owner consent');
      if (Object.hasOwn(state.slots,r.slot) || Object.hasOwn(state.requests,r.requestId)) throw Error('release consumed');
      // Trusted decoder inspects the actual protobuf request. Caller-provided
      // hashes/metadata are not a substitute for these derived fields.
      const decoded = await this.#inspect(Uint8Array.from(wire));
      if (!decoded || !equal(decoded,r,[...contextFields,'slot','consentId','requestId','taskId','aggregateDigest',
          'outputDigest','outputType','recipient','encKeyDigest']) || decoded.ciphertextCount !== 1) throw Error('wire request does not match authorization');
      // Trusted resolver reads finalized chain state and independently verifies
      // the exact original aggregate plus the prescribed public conversion.
      const final = await this.#resolve(r);
      if (!final || !equal(final,r,[...contextFields,'taskId','aggregateDigest','outputDigest','outputType']) ||
          policyHash([...final.recordIds].sort()) !== policyHash([...c.recordIds].sort())) throw Error('no matching finalized conversion');
      for (const id of c.recordIds) {
        const record = state.records[id];
        if (!record || final.recordOwners?.[id]?.toLowerCase() !== record.owner) throw Error('record owner mismatch');
        if (!Number.isSafeInteger(record.spent) || record.spent < 0 || !Number.isSafeInteger(record.limit) || record.limit < 1) throw Error('invalid durable record counter');
        if (record.spent >= record.limit) throw Error('cumulative record budget exhausted');
      }
      for (const id of c.recordIds) state.records[id].spent++;
      state.slots[r.slot] = {requestId:r.requestId,kmsRequestDigest:r.kmsRequestDigest,state:'reserved'};
      state.requests[r.requestId] = r.slot; save();
      // The only KMS contact follows durable reservation. No failure refunds
      // the record budget or permits a different ciphertext under this slot.
      const encryptedResponse = await this.#submit(wire);
      if (!(encryptedResponse instanceof Uint8Array) || !encryptedResponse.length) throw Error('expected opaque recipient-encrypted response');
      state.slots[r.slot].state = 'released'; save();
      return Uint8Array.from(encryptedResponse);
    });
  }
  inspectLedger() {return JSON.parse(fs.readFileSync(this.#file,'utf8'));}
}
