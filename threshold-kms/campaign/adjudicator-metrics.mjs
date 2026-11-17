// Resource observations support cost accounting, not proof of independent work.
// Context checks, complete recomputations and leaf decisions are distinct jobs.
import fs from 'node:fs/promises';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';

export const ROLE_PROCESS_SCHEMA = 'role-process-resources-v1';
export const WORKER_PURPOSES = Object.freeze([
  'context-certification', 'full-execution-certification', 'leaf-result-certification',
  'auditor-full-recomputation', 'operator-execution',
]);
const roles = new Set(['adjudicator', 'auditor', 'operator']);
const executionScopes = new Set(['unclassified-command', 'controller-only-remote-fhe-excluded',
  'local-command-with-waited-fhe-descendants']);
const helper = fileURLToPath(new URL('./measure-process.py', import.meta.url));
const finite = v => typeof v === 'number' && Number.isFinite(v) && v >= 0;

export async function measuredJsonCommand({command, args = [], input, cwd, env = process.env,
  outputDir, measurementId, role, purpose, python = 'python3', executionScope = 'unclassified-command'}) {
  if (typeof command !== 'string' || !command || !Array.isArray(args) || args.some(a => typeof a !== 'string'))
    throw new Error('a command and string argument array are required');
  if (typeof measurementId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(measurementId))
    throw new Error('invalid measurement identifier');
  if (!roles.has(role) || !WORKER_PURPOSES.includes(purpose)) throw new Error('invalid worker role or purpose');
  if (!executionScopes.has(executionScope)) throw new Error('invalid worker execution scope');
  if (!outputDir || !path.isAbsolute(outputDir)) throw new Error('an absolute resource-output directory is required');
  await fs.mkdir(outputDir, {recursive:true});
  const rawFile = path.join(outputDir, `${measurementId}.resources.json`);
  const result = await new Promise((resolve, reject) => {
    const child = spawn(python, [helper, '--report', rawFile, '--', command, ...args],
      {cwd, env, stdio:['pipe','pipe','pipe']});
    let stdout = '', stderr = '';
    child.stdout.on('data', b => { stdout += b; });
    child.stderr.on('data', b => { stderr += b; });
    child.on('error', reject);
    child.stdin.on('error', error => { if (error.code !== 'EPIPE') reject(error); });
    child.on('close', (code, signal) => resolve({code, signal, stdout, stderr}));
    child.stdin.end(input === undefined ? '' : JSON.stringify(input));
  });
  let raw;
  try { raw = JSON.parse(await fs.readFile(rawFile, 'utf8')); }
  catch (cause) { throw new Error(`resource report unavailable for ${measurementId}: ${result.stderr.slice(-1000)}`, {cause}); }
  const measurement = {
    schema:ROLE_PROCESS_SCHEMA, measurementId, role, purpose, executionScope,
    status:result.code === 0 && raw.exitCode === 0 ? 'completed' : 'failed',
    exitCode:raw.exitCode, signal:raw.signal, startedAt:raw.startedAt, finishedAt:raw.finishedAt,
    elapsedMs:raw.elapsedMs, resources:raw.resources, nativeFheElapsedMs:null,
  };
  if (measurement.status !== 'completed') {
    const error = new Error(`measured worker ${measurementId} failed: ${result.stderr.slice(-3000)}`);
    error.measurement = measurement;
    throw error;
  }
  let value;
  try { value = JSON.parse(result.stdout); }
  catch (cause) {
    measurement.status = 'failed';
    const error = new Error(`measured worker ${measurementId} returned invalid JSON`, {cause});
    error.measurement = measurement;
    throw error;
  }
  return {value, measurement};
}

// Sums cover recorded workers, excluding the outer campaign orchestrator, chain,
// separate remote FHE workers, owner/KMS work and uninstrumented tasks. Elapsed sums are not an
// end-to-end timer. RSS high-water values cannot be summed into peak memory.
export function summarizeAdjudicatorWork(rows) {
  if (!Array.isArray(rows)) throw new Error('worker observations must be an array');
  const ids = new Set(), byPurpose = {};
  for (const row of rows) {
    if (row.schema !== ROLE_PROCESS_SCHEMA || !roles.has(row.role) || !WORKER_PURPOSES.includes(row.purpose) ||
        !executionScopes.has(row.executionScope) || !['completed','failed'].includes(row.status) ||
        !row.measurementId || ids.has(row.measurementId) ||
        !finite(row.elapsedMs)) throw new Error('invalid or duplicate worker observation');
    ids.add(row.measurementId);
    for (const key of ['userCpuMs','systemCpuMs','totalCpuMs','maxRssBytes']) {
      if (row.resources?.[key] !== null && !finite(row.resources?.[key]))
        throw new Error(`invalid or absent ${key}`);
    }
    const group = byPurpose[row.purpose] ??= {workerInvocations:0, completedWorkers:0, failedWorkers:0,
      summedWorkerElapsedMs:0, cpuMeasuredWorkers:0, measuredCpuMs:0, completeCpuMs:null,
      maxObservedWorkerRssBytes:null, nativeFheElapsedMs:null,executionScopes:[]};
    if(!group.executionScopes.includes(row.executionScope))group.executionScopes.push(row.executionScope);
    group.workerInvocations++;
    group[row.status === 'completed' ? 'completedWorkers' : 'failedWorkers']++;
    group.summedWorkerElapsedMs += row.elapsedMs;
    if (row.resources.totalCpuMs !== null) { group.cpuMeasuredWorkers++; group.measuredCpuMs += row.resources.totalCpuMs; }
    if (row.resources.maxRssBytes !== null)
      group.maxObservedWorkerRssBytes = Math.max(group.maxObservedWorkerRssBytes ?? 0, row.resources.maxRssBytes);
  }
  for (const group of Object.values(byPurpose)) {
    group.completeCpuMs = group.cpuMeasuredWorkers === group.workerInvocations ? group.measuredCpuMs : null;
    if (group.cpuMeasuredWorkers === 0) group.measuredCpuMs = null;
  }
  return {schema:ROLE_PROCESS_SCHEMA, recordedWorkers:rows.length, byPurpose,
    executionScopes:[...new Set(rows.map(r=>r.executionScope))],fheCpuMs:null,
    completedContextWorkers:byPurpose['context-certification']?.completedWorkers ?? 0,
    completedFullExecutionWorkers:byPurpose['full-execution-certification']?.completedWorkers ?? 0,
    completedLeafResultWorkers:byPurpose['leaf-result-certification']?.completedWorkers ?? 0,
    scope:'recorded-workers-only', independentAdministrationEstablished:false,
    fullProtocolCpuMs:null, simultaneousTreePeakRssBytes:null};
}
