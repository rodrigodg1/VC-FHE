import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {rpc} from './client.mjs';
const retained=JSON.parse(await fs.readFile('/reports/restart-request.json','utf8'));
await assert.rejects(rpc(retained.target,'task',retained.body,{id:retained.id}),/Reconcile/);
await fs.writeFile('/reports/restart-check.json',JSON.stringify({status:'passed',failedActionReexecuted:false}));
console.log('DOCKER_RESTART_REPLAY_REJECTED');
