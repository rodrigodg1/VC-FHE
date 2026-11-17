// Host launcher for the combined PoC. All options go to the existing controller.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const command=fileURLToPath(new URL('../run-poc.sh',import.meta.url));
const result=spawnSync('bash',[command,...process.argv.slice(2)],{stdio:'inherit',env:process.env});
process.exit(result.status ?? 1);
