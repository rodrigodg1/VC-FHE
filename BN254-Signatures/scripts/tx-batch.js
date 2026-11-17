/**
 * Signer-grouped transaction batching for measurements on a real chain.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The measurement scripts submit their setup transactions strictly one at a
 * time: `await (await c.f()).wait()` in a loop. On an in-process EVM that costs
 * nothing, because blocks are mined on demand. On the QBFT validator network it
 * costs a full submit/include/receipt round trip per transaction -- measured at
 * 7 transactions per minute, about 8.6 s each on a 2 s-block chain. The gas
 * sweep at N = 200 alone is ~800 transactions, so the sequential loop turns a
 * two-hour campaign into a six-hour one.
 *
 * Nothing about the protocol requires that serialisation. Owner registrations
 * and record admissions are independent: each index is enrolled to its own
 * account, and the on-chain accumulator is updated by commutative point
 * addition, so admission order does not affect the result. What DOES require
 * ordering is the nonce sequence WITHIN one account.
 *
 * `sendGroupedBySigner` exploits exactly that distinction. It groups the work by
 * sending account and proceeds in rounds: round k submits the k-th transaction
 * of every account at once and then awaits all of their receipts. Within an
 * account the order is unchanged and strictly sequential, so nonces are never
 * raced; across accounts the round trips overlap. With the 18 distinct owner
 * accounts of the evaluated deployment this replaces N sequential round trips
 * with ceil(N/18) of them.
 *
 * Every receipt is still returned individually, so per-transaction gas stays
 * attributable -- the MapToGroup trial-count fit depends on that.
 *
 * WHAT THIS DOES NOT CHANGE
 * -------------------------
 * Gas is protocol-defined and independent of submission order, so batching
 * cannot move a reported figure. The gas table is byte-identical to the
 * sequential run; `scripts/check_linear_artifacts.py` cross-checks it.
 */
"use strict";

/** Receipt wait bound, so a dropped transaction fails loudly instead of hanging. */
const WAIT_TIMEOUT_MS = Number(process.env.TX_BATCH_TIMEOUT_MS || 180_000);

/**
 * Submits independent transactions grouped by sending account.
 *
 * @param {Array<T>} items            work items, in their original order
 * @param {(item: T) => object} signerOf  the signer each item must be sent from
 * @param {(item: T) => Promise<object>} send  submits the transaction, returns it
 * @param {(item: T, receipt: object) => void} [onReceipt]  per-item callback,
 *        called in the ORIGINAL item order once every receipt is in
 * @returns {Promise<Array<object>>} receipts, in the original item order
 */
async function sendGroupedBySigner(items, signerOf, send, onReceipt) {
  // Group by sender, preserving each group's relative order.
  const groups = new Map();
  items.forEach((item, index) => {
    const address = signerOf(item).address;
    if (!groups.has(address)) groups.set(address, []);
    groups.get(address).push({ item, index });
  });

  const receipts = new Array(items.length);
  const queues = [...groups.values()];
  const deepest = Math.max(0, ...queues.map((q) => q.length));

  for (let round = 0; round < deepest; round++) {
    // One transaction per account: distinct accounts, distinct nonce spaces.
    const wave = queues.map((q) => q[round]).filter(Boolean);
    const sent = await Promise.all(
      wave.map(async (entry) => ({ entry, tx: await send(entry.item) }))
    );
    const mined = await Promise.all(
      sent.map(async ({ entry, tx }) => {
        const receipt = await tx.wait(1, WAIT_TIMEOUT_MS);
        if (receipt === null) {
          throw new Error(
            `timed out after ${WAIT_TIMEOUT_MS} ms waiting for tx ${tx.hash}. ` +
              "Is another process sending from the same accounts?"
          );
        }
        return { entry, receipt };
      })
    );
    for (const { entry, receipt } of mined) receipts[entry.index] = receipt;
  }

  if (onReceipt) items.forEach((item, index) => onReceipt(item, receipts[index]));
  return receipts;
}

module.exports = { sendGroupedBySigner, WAIT_TIMEOUT_MS };
