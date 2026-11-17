import { compileContracts, contractsOutDir, logStep } from "./evm-lib.mjs";

const artifacts = await compileContracts();
for (const [name, artifact] of Object.entries(artifacts)) {
  logStep("contract compiled", {
    contract: name,
    artifact: `${contractsOutDir}\\${name}.json`,
    abi_items: artifact.abi.length
  });
}
