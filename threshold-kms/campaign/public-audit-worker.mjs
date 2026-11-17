// Measurement boundary around the unchanged public detector. No signing or
// decryption key is supplied. The caller records resources in a separate file.
import {detectCanonicalFault} from './runtime/scripts/canonical-protocol.mjs';
let raw = '';
for await (const chunk of process.stdin) raw += chunk;
const request = JSON.parse(raw);
console.log(JSON.stringify(await detectCanonicalFault(request)));
