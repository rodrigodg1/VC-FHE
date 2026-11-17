import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {evaluateCommitteeAvailability} from '../../scripts/evaluate-committee-availability.mjs';

test('paired local availability controls preserve quorum requirements and expose the audit-coverage boundary',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'vcfhe-availability-test-'));
  const report=await evaluateCommitteeAvailability({outputDir:path.join(root,'evaluation')});
  assert.equal(report.status,'passed');assert.equal(report.checks.length,9);
  assert.ok(report.checks.every(c=>c.status==='passed'));
  assert.equal(report.realFheExecutions,0);assert.equal(report.kmsReleases,0);
  assert.equal(report.externalChain,false);assert.equal(report.sourceUnchanged,true);
  await assert.rejects(evaluateCommitteeAvailability({outputDir:path.join(root,'evaluation')}),e=>e.code==='EEXIST');
});
