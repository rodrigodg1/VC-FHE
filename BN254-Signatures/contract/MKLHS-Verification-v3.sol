// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./MKLHS-Verification.sol";

/// Public-owner encryption profile. V1/V2 deployments remain regression-only.
contract MKLHSVerificationV3 is MKLHSVerification {
    bytes32 public constant PARAMETER_DIGEST = keccak256(
        "VCFHE-LWE-PUBLIC-v2;k=1289;q=2^64;messageBits=10;delta=2^54;sigma=1.3847362925087773e-9;zeros=82816;margin=16;Nmax=33;BN254;OB_LHS_GEN_;balanced-reduction"
    );
    bytes32 public immutable keyEpoch;
    constructor(string memory ref_, uint64 scale_, uint64 n_, uint8 op_, bytes32 epoch_, address[] memory owners_)
        payable MKLHSVerification(ref_, scale_, n_, op_, epoch_, owners_)
    {
        require(n_ > 0 && n_ <= 33, "unsupported public encryption regime");
        keyEpoch = epoch_;
        datasetTag = keccak256(abi.encode("VCFHE-LINEAR-DEPLOYMENT-V3", block.chainid,
            address(this), epoch_, PARAMETER_DIGEST, scale_, n_, op_));
    }
}
