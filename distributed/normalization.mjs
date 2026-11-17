// Both the operator and owners run the original public conversion locally.
import assert from 'node:assert/strict';
import {runPublicWorker} from '../threshold-kms/scripts/kms-public-worker.mjs';

export async function normalizeLocally(binary,job,directory){
  assert.equal(job.action,'normalize');
  await runPublicWorker(binary,job,directory);
  return {status:'completed',action:'normalize'};
}
