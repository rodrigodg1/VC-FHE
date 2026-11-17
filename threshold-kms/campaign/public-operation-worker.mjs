// Keep the campaign's networkless public-worker dispatch unchanged. The Rust
// executable is a test-harness adapter, not a direct canonical CLI binary.
import {runCanonicalBinary} from './runtime/scripts/canonical-protocol.mjs';
let raw = '';
for await (const chunk of process.stdin) raw += chunk;
const {binary,args} = JSON.parse(raw);
console.log(JSON.stringify(await runCanonicalBinary(binary,args)));
