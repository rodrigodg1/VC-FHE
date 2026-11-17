// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./MKLHS-Verification.sol";

/// @notice Deployment-bound linear admission. Legacy V1 remains for archived
/// measurements; revised deployments and signatures use this constructor.
contract MKLHSVerificationV2 is MKLHSVerification {
    bytes32 public constant PARAMETER_DIGEST = keccak256(
        "VCFHE-LWE-v1;k=742;q=2^64;messageBits=10;delta=2^54;sigma=0.000007069849454709433;BN254;OB_LHS_GEN_;balanced-reduction"
    );
    bytes32 public immutable keyEpoch;
    constructor(string memory ref_, uint64 scale_, uint64 n_, uint8 op_, bytes32 epoch_, address[] memory owners_)
        payable MKLHSVerification(ref_, scale_, n_, op_, epoch_, owners_)
    {
        keyEpoch = epoch_;
        // Read datasetTag from the deployed contract before signing. In an
        // offline workflow the sender must first reserve its CREATE address.
        datasetTag = keccak256(abi.encode("VCFHE-LINEAR-DEPLOYMENT-V2", block.chainid,
            address(this), epoch_, PARAMETER_DIGEST, scale_, n_, op_));
    }
}
