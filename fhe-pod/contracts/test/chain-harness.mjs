/**
 * Test harness that runs the contract suites either on the in-process EVM or
 * on a real consensus network (Hyperledger Besu QBFT).
 *
 * The suites were originally written for an auto-mining in-process EVM, which
 * differs from a real chain in two ways that matter:
 *
 *   1. Time. The in-process EVM exposes `evm_increaseTime`/`evm_mine`, so a
 *      protocol deadline can be crossed instantly. A BFT chain does not expose
 *      them: time only advances as blocks are produced. `advanceTime()` below
 *      hides that difference, waiting out real chain time when the RPC has no
 *      time-travel support.
 *
 *   2. Confirmation. On an auto-mining EVM `await tx` is indistinguishable from
 *      confirmation. With ethers v6 on a real chain it resolves on submission,
 *      so a dependent call can race ahead of the state it needs. `confirm()`
 *      makes the distinction explicit.
 *
 * Selecting the target:
 *
 *   (default)                      in-process EVM (ganache), instant blocks
 *   VCFHE_TEST_RPC_URL=<url>       external chain over JSON-RPC
 *
 * Optional overrides:
 *   VCFHE_TEST_CHAIN_ID            expected chain id of the external chain
 *   VCFHE_TEST_MNEMONIC            signer mnemonic (dev networks only)
 *   VCFHE_TEST_WINDOW_SECONDS      protocol window used by the fixtures
 *
 * Protocol windows must be long enough to hold every transaction a test sends
 * inside one phase. On the in-process EVM the clock only moves on demand, so
 * 20 seconds suffice. On a 2-second-block chain each transaction costs a block,
 * so the default grows accordingly.
 */

import { ethers } from "ethers";
// ganache is imported lazily, inside the in-process branch of createChain().
// A static import loads its native uWebSockets binary at module load, which
// prints a compatibility warning on Node builds it was not published for, and
// does so even when the suites run against a real chain and never use it.

export const DEFAULT_MNEMONIC =
  "test test test test test test test test test test test junk";

export const EXTERNAL_RPC_URL = process.env.VCFHE_TEST_RPC_URL || "";
export const onExternalChain = Boolean(EXTERNAL_RPC_URL);

/** Protocol window (commit, open, challenge, availability) used by fixtures. */
export const WINDOW_SECONDS = Number(
  process.env.VCFHE_TEST_WINDOW_SECONDS || (onExternalChain ? 90 : 20)
);

/** Amount by which a test advances the clock to cross a window boundary. */
export const PAST_WINDOW_SECONDS = WINDOW_SECONDS + 1;

/**
 * Window for suites that send many transactions inside a single phase (full
 * challenged-trace disclosure in batches, then every bisection round). On a
 * 2-second-block chain that work costs real time, and a phase that expires
 * mid-sequence fails with WrongPhase for reasons unrelated to the protocol.
 * The in-process EVM does not advance the clock on its own, so the base value
 * is kept there.
 */
export const HEAVY_WINDOW_SECONDS = onExternalChain ? WINDOW_SECONDS * 2 : WINDOW_SECONDS;
export const PAST_HEAVY_WINDOW_SECONDS = HEAVY_WINDOW_SECONDS + 1;

/**
 * Mocha-style timeout for a whole suite. Real chains need far more: every
 * confirmation costs at least one block, and crossing a window costs the
 * window itself.
 */
export const SUITE_TIMEOUT_MS = onExternalChain ? 90 * 60_000 : 5 * 60_000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Build a provider plus an indexed signer accessor for the configured target.
 * The returned shape is identical for both targets, so the suites do not need
 * to know which one they are running against.
 */
export async function createChain({ totalAccounts = 12, chainId = 31337 } = {}) {
  if (!onExternalChain) {
    const { default: ganache } = await import("ganache");
    const provider = new ethers.BrowserProvider(
      ganache.provider({
        logging: { quiet: true },
        // Pinned genesis time and frozen block time keep the derived seeds and
        // checkpoints identical across runs, so a loaded host cannot consume a
        // protocol window between two sequential transactions.
        chain: { chainId, time: new Date("2025-01-01T00:00:00.000Z") },
        miner: { timestampIncrement: 0 },
        wallet: { mnemonic: DEFAULT_MNEMONIC, totalAccounts }
      })
    );
    return {
      provider,
      external: false,
      signerAt: (index) => provider.getSigner(index),
      async dispose() {}
    };
  }

  const provider = new ethers.JsonRpcProvider(EXTERNAL_RPC_URL, undefined, {
    // Deadline arithmetic reads the latest block repeatedly; a cached "latest"
    // makes a test believe the chain is behind and overshoot its window.
    cacheTimeout: -1,
    // Receipts are discovered by polling, and ethers defaults to 4000 ms, which
    // on a 2-second-block chain roughly doubles the observed cost of every
    // confirmation. This is a measurement-harness cost, not a protocol one, and
    // it lengthens a suite that already takes hours under consensus.
    // network/deploy-contracts.mjs sets the same value for the same reason.
    pollingInterval: 500
  });
  const network = await provider.getNetwork();
  const expected = process.env.VCFHE_TEST_CHAIN_ID;
  if (expected && String(network.chainId) !== String(expected)) {
    throw new Error(
      `chain id mismatch: RPC reports ${network.chainId}, expected ${expected}`
    );
  }
  const cache = new Map();
  const signerAt = (index) => {
    if (!cache.has(index)) {
      cache.set(index, walletAtIndex(index).connect(provider));
    }
    return cache.get(index);
  };
  // Fail early and clearly when the genesis does not fund the accounts the
  // suite needs, instead of failing later inside an unrelated assertion.
  const balance = await provider.getBalance(await signerAt(totalAccounts - 1).getAddress());
  if (balance === 0n) {
    throw new Error(
      `account ${totalAccounts - 1} of the test mnemonic has no balance on ` +
        `${EXTERNAL_RPC_URL}; the genesis must prefund at least ${totalAccounts} accounts`
    );
  }
  return {
    provider,
    external: true,
    signerAt,
    async dispose() {
      provider.destroy();
    }
  };
}

/**
 * Provider for a fixture, matching the target selected by the environment.
 * Returns the provider only; use `signerFor(provider, i)` for signers.
 */
export async function createProvider(options = {}) {
  const chain = await createChain(options);
  return chain.provider;
}

/**
 * Account `index` of the test mnemonic on the standard Ethereum path.
 * `fromPhrase` already descends to m/44'/60'/0'/0/0, so the full path has to
 * be given to `fromMnemonic` rather than derived from that node.
 */
function walletAtIndex(index) {
  const phrase = process.env.VCFHE_TEST_MNEMONIC || DEFAULT_MNEMONIC;
  return ethers.HDNodeWallet.fromMnemonic(
    ethers.Mnemonic.fromPhrase(phrase),
    `m/44'/60'/0'/0/${index}`
  );
}

const signerCache = new WeakMap();

/**
 * Indexed signer for either target, so a fixture does not need to know which
 * one it runs against. The in-process EVM exposes unlocked accounts; a real
 * node does not, so signers are derived locally from the test mnemonic.
 */
export function signerFor(provider, index) {
  if (typeof provider.getSigner === "function" && !onExternalChain) {
    return provider.getSigner(index);
  }
  let cache = signerCache.get(provider);
  if (!cache) {
    cache = new Map();
    signerCache.set(provider, cache);
  }
  if (!cache.has(index)) {
    cache.set(index, walletAtIndex(index).connect(provider));
  }
  return cache.get(index);
}

/**
 * Latest block timestamp, read without provider-side caching.
 * A node under concurrent load can answer `null` for the head between blocks,
 * so retry briefly rather than propagating a spurious failure into a test.
 */
export async function chainTimestamp(provider) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const block = await provider.send("eth_getBlockByNumber", ["latest", false]);
    if (block && block.timestamp !== undefined) {
      return Number(BigInt(block.timestamp));
    }
    await sleep(500);
  }
  throw new Error("chain did not return a latest block after repeated attempts");
}

/**
 * Advance the chain clock by at least `seconds` relative to now.
 *
 * On the in-process EVM this is instantaneous. On a consensus network there is
 * no way to move the clock, so this waits for blocks to carry it forward. The
 * semantics are identical in both cases: on return, the chain timestamp is at
 * least `seconds` beyond what it was on entry.
 */
export async function advanceTime(provider, seconds) {
  try {
    await provider.send("evm_increaseTime", [seconds]);
    await provider.send("evm_mine", []);
    return;
  } catch {
    // No time-travel RPC: this is a real chain, so wait it out.
  }
  const target = (await chainTimestamp(provider)) + seconds;
  await advanceToTimestamp(provider, target, seconds + 120);
}

/**
 * Advance the chain clock until it is at least `target` (an absolute unix
 * timestamp). On the in-process EVM the jump is exact; on a consensus network
 * it waits for blocks to carry the clock forward.
 *
 * Advancing to an on-chain deadline plus a small margin (rather than by a fixed
 * delta from "now") is what keeps a multi-transaction phase inside its window
 * on a slow-block chain: a fixed `advanceTime(window + 1)` measured from the
 * moment the helper happens to run can land far past the deadline, leaving too
 * little of the next window for the transactions that phase must send.
 */
export async function advanceToTimestamp(provider, target, maxWaitSeconds) {
  const now = await chainTimestamp(provider);
  if (now >= target) return;
  try {
    await provider.send("evm_increaseTime", [target - now]);
    await provider.send("evm_mine", []);
    return;
  } catch {
    // No time-travel RPC: this is a real chain, so wait it out.
  }
  const budgetSeconds = maxWaitSeconds ?? target - now + 120;
  // Generous bound: block production can stall briefly during a view change.
  const deadline = Date.now() + budgetSeconds * 1000;
  for (;;) {
    if ((await chainTimestamp(provider)) >= target) return;
    if (Date.now() > deadline) {
      throw new Error(
        `chain clock did not reach ${target} within ${budgetSeconds}s; is the network producing blocks?`
      );
    }
    await sleep(1000);
  }
}

/** Mine or wait for `count` blocks, whichever the target supports. */
export async function advanceBlocks(provider, count = 1) {
  try {
    for (let i = 0; i < count; i += 1) {
      await provider.send("evm_mine", []);
    }
    return;
  } catch {
    // Real chain: wait for the block height to grow.
  }
  const start = await provider.getBlockNumber();
  const deadline = Date.now() + (count * 30 + 60) * 1000;
  for (;;) {
    if ((await provider.getBlockNumber()) >= start + count) return;
    if (Date.now() > deadline) {
      throw new Error(`chain did not produce ${count} block(s) in time`);
    }
    await sleep(500);
  }
}

/**
 * Await a transaction to CONFIRMATION, not merely to submission.
 * Accepts either a transaction response or a promise of one.
 */
export async function confirm(txOrPromise) {
  const tx = await txOrPromise;
  return tx.wait();
}

/**
 * Matcher for a revert with a specific custom error, valid on both targets.
 *
 * Providers report custom errors differently: some decode the name, some
 * report only "missing revert data", and a real node typically returns the
 * raw four-byte selector (`execution reverted (unknown custom error) ...
 * data="0x1234abcd"`). Matching the selector as well keeps the assertion
 * specific: it still identifies WHICH error was raised, rather than accepting
 * any revert.
 */
export function revertMatcher(contract, ...errorNames) {
  const alternatives = [...errorNames, "missing revert data"];
  for (const name of errorNames) {
    try {
      alternatives.push(contract.interface.getError(name).selector);
    } catch {
      // Error not present in this ABI: name matching still applies.
    }
  }
  return new RegExp(alternatives.join("|"));
}

/**
 * True when `receipt` contains `eventName` emitted by `contract`.
 * Used instead of chai's `.to.emit`, which reads the receipt without waiting
 * for a block and therefore cannot see a transaction that is still pending.
 */
export function receiptHasEvent(receipt, contract, eventName) {
  const topic = contract.interface.getEvent(eventName).topicHash;
  const address = String(contract.target).toLowerCase();
  return receipt.logs.some(
    (log) => log.address.toLowerCase() === address && log.topics[0] === topic
  );
}
