# QoE component examples

Run `node ../../../datasets/download/download-stav360.mjs` from this directory
only after reviewing the input terms in `../../../datasets/README.md`.
`npm run cases:generate` prepares the linear cases. `npm run emit:tfhe` generates
the ciphertext/signature payload before the linear demo. Inputs and payloads are
not bundled. They must be generated with matching source versions.

These component examples have their own package scripts and contract settings.
They do not execute the complete current threshold campaign. For the supported full experiment, return to the repository root and run
`./run-poc.sh`.
