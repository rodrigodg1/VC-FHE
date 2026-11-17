# External components

[LICENSE](LICENSE) covers this repository's project code. It does not replace
licenses of dependencies or datasets. Retain upstream notices when redistributing
built images or dependency sources.

- Zama threshold KMS and TFHE-rs are fetched at the revisions pinned by
  `threshold-kms/campaign/run.py`, its build scripts and Cargo locks.
- Hyperledger Besu provides QBFT and the EVM. Local Compose fixes its version;
  cloud execution records immutable image digests.
- Solidity, ethers and other JavaScript dependencies use the component npm locks.
- Terraform's Google provider version and hashes are retained in
  `distributed/terraform.lock.hcl`.
- Matplotlib and analysis dependencies use
  `threshold-kms/postprocess/requirements.txt`.
- Input datasets are obtained separately. See [dataset provenance](datasets/README.md).

The older output-binding component uses its own TFHE-rs lock. Its results must
not be relabeled as results from the current grouped-radix threshold profile.
