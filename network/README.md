# Network helpers

The current campaign uses `validators-besu/docker-compose.besu.yml`. Its one-shot
genesis service generates validator identities and QBFT configuration into Docker
volumes. Node 1 exposes local RPC at port 8550, with chain ID 46853. The campaign
starts and checks the required services. Use the root launchers for reproduction.

Keep validator volumes, policy state and identities together. Deleting the chain
would also remove the consumed-slot and budget history. Do not reset it to repair
a failed workflow. The local network uses public development accounts and must
remain isolated from untrusted users.

`verify-network.mjs` and `deploy-contracts.mjs` are component maintenance tools.
`run-all.mjs` dispatches to `run-poc.sh`. Other Compose/evaluator templates are
legacy component examples. They require separately generated local credentials
and are not the supported threshold experiment launcher. No pre-generated
validator secret files are supplied.
