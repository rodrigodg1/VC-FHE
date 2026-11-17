import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {measuredJsonCommand, summarizeAdjudicatorWork, ROLE_PROCESS_SCHEMA} from './adjudicator-metrics.mjs';

const outputDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vcfhe-resource-tests-'));
const base = {command:process.execPath, outputDir, role:'adjudicator', purpose:'leaf-result-certification'};
const observation = (id, purpose, cpu = 4) => ({
  schema:ROLE_PROCESS_SCHEMA, measurementId:id, role:'adjudicator', purpose, status:'completed',
  executionScope:'controller-only-remote-fhe-excluded',
  elapsedMs:10, resources:{userCpuMs:cpu,systemCpuMs:cpu === null ? null : 0,
    totalCpuMs:cpu,maxRssBytes:null}, nativeFheElapsedMs:null,
});

test('isolated command records CPU and elapsed separately and preserves JSON stdin/stdout', async () => {
  const {value,measurement} = await measuredJsonCommand({...base,measurementId:'json-roundtrip',input:{message:'public'},
    args:['-e',"let s='';process.stdin.on('data',b=>s+=b);process.stdin.on('end',()=>{const t=Date.now();while(Date.now()-t<30){};console.log(s)})"]});
  assert.deepEqual(value,{message:'public'});
  assert.equal(measurement.status,'completed');
  assert.ok(measurement.elapsedMs > 0);
  assert.ok(measurement.resources.totalCpuMs > 0);
  assert.equal(measurement.resources.totalCpuMs,
    measurement.resources.userCpuMs + measurement.resources.systemCpuMs);
  assert.equal(measurement.nativeFheElapsedMs,null);
  assert.equal(measurement.executionScope,'unclassified-command');
  assert.equal(measurement.resources.maxRssScope,'process-high-water-not-simultaneous-tree-peak');
});

test('waited nested command contributes resource usage without reporting native FHE timings', async () => {
  const code = "require('node:child_process').execFileSync(process.execPath,['-e','const t=Date.now();while(Date.now()-t<40){}']);console.log('{}')";
  const {measurement} = await measuredJsonCommand({...base,measurementId:'nested-worker',args:['-e',code]});
  assert.ok(measurement.resources.totalCpuMs > 0);
  assert.equal(measurement.resources.scope,'command-and-waited-descendants');
  assert.equal(measurement.nativeFheElapsedMs,null);
});

test('failed worker retains measured resources and never becomes a completed certificate worker', async () => {
  await assert.rejects(measuredJsonCommand({...base,measurementId:'failed-worker',args:['-e',"console.error('fixture failure');process.exit(7)"]}),
    error => error.measurement?.status === 'failed' && error.measurement.exitCode === 7 &&
      error.measurement.resources.totalCpuMs >= 0);
});

test('a command that cannot start reports unavailable resources rather than zero CPU', async () => {
  await assert.rejects(measuredJsonCommand({...base,command:path.join(outputDir,'absent-executable'),
    measurementId:'missing-command'}),error=>error.measurement?.status==='failed' &&
      error.measurement.resources.totalCpuMs===null &&
      error.measurement.resources.maxRssBytes===null &&
      error.measurement.resources.unavailableReason==='command-did-not-start');
});

test('invalid JSON fails the job even when its process exit status is zero', async () => {
  await assert.rejects(measuredJsonCommand({...base,measurementId:'invalid-json',args:['-e',"console.log('not json')"]}),
    error => error.measurement?.status === 'failed' && error.measurement.exitCode === 0);
});

test('resource output cannot overwrite an earlier observation or execute the colliding command', async () => {
  const marker=path.join(outputDir,'must-not-exist');
  await measuredJsonCommand({...base,measurementId:'unique',args:['-e',"console.log('{}')"]});
  await assert.rejects(measuredJsonCommand({...base,measurementId:'unique',args:['-e',`require('node:fs').writeFileSync(${JSON.stringify(marker)},'bad');console.log('{}')`]}));
  await assert.rejects(fs.stat(marker),error=>error.code==='ENOENT');
});

test('summary separates initial context work from full and leaf-result workers', () => {
  const rows=[observation('c0','context-certification'),observation('c1','context-certification'),
    observation('f0','full-execution-certification'),observation('f1','full-execution-certification'),
    observation('l0','leaf-result-certification'),observation('l1','leaf-result-certification')];
  const summary=summarizeAdjudicatorWork(rows);
  assert.equal(summary.completedContextWorkers,2);
  assert.equal(summary.completedFullExecutionWorkers,2);
  assert.equal(summary.completedLeafResultWorkers,2);
  assert.equal(summary.byPurpose['full-execution-certification'].completeCpuMs,8);
  assert.equal(summary.byPurpose['full-execution-certification'].summedWorkerElapsedMs,20);
  assert.equal(summary.fullProtocolCpuMs,null);
  assert.equal(summary.simultaneousTreePeakRssBytes,null);
  assert.equal(summary.independentAdministrationEstablished,false);
  assert.deepEqual(summary.executionScopes,['controller-only-remote-fhe-excluded']);
  assert.equal(summary.fheCpuMs,null);
});

test('missing CPU stays missing instead of becoming a zero-cost computation', () => {
  const summary=summarizeAdjudicatorWork([observation('unknown','leaf-result-certification',null)]);
  const leaf=summary.byPurpose['leaf-result-certification'];
  assert.equal(leaf.completeCpuMs,null);
  assert.equal(leaf.measuredCpuMs,null);
  assert.equal(leaf.cpuMeasuredWorkers,0);
  const mixed=summarizeAdjudicatorWork([observation('known','leaf-result-certification'),observation('unknown','leaf-result-certification',null)]);
  assert.equal(mixed.byPurpose['leaf-result-certification'].completeCpuMs,null);
  assert.equal(mixed.byPurpose['leaf-result-certification'].measuredCpuMs,4);
});

test('duplicate jobs and absent resource fields cannot silently contaminate totals', () => {
  const row=observation('duplicate','context-certification');
  assert.throws(()=>summarizeAdjudicatorWork([row,row]),/duplicate/);
  assert.throws(()=>summarizeAdjudicatorWork([{...row,resources:{}}]),/absent/);
  assert.throws(()=>summarizeAdjudicatorWork([{...row,elapsedMs:-1}]),/invalid/);
  assert.throws(()=>summarizeAdjudicatorWork([{...row,executionScope:undefined}]),/invalid/);
});

test('remote FHE stays outside local controller CPU even when the worker completes', async () => {
  const {measurement}=await measuredJsonCommand({...base,measurementId:'remote-controller',
    executionScope:'controller-only-remote-fhe-excluded',args:['-e',"console.log('{}')"]});
  const summary=summarizeAdjudicatorWork([measurement]);
  assert.ok(summary.byPurpose['leaf-result-certification'].completeCpuMs>=0);
  assert.deepEqual(summary.byPurpose['leaf-result-certification'].executionScopes,
    ['controller-only-remote-fhe-excluded']);
  assert.equal(summary.fheCpuMs,null);
  assert.equal(summary.fullProtocolCpuMs,null);
});
