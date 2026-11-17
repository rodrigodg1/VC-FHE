// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "MKLHS-Verification.sol";

/// Separate domain for the experimental grouped-radix profile; never a V3 payload.
contract GroupedLinearVerification is MKLHSVerification {
    bytes32 public immutable profileDigest;
    bytes32 public immutable keysetDigest;
    mapping(uint64 => bytes32) public protectedRecordId;
    mapping(uint64 => bytes32) public protectedCiphertextDigest;
    mapping(uint64 => bool) public protectedRecordBound;
    mapping(bytes32 => bool) private protectedIdUsed;

    event ProtectedRecordBound(
        uint64 indexed index,
        bytes32 indexed protectedId,
        bytes32 indexed ciphertextDigest,
        address ownerAddr
    );

    constructor(uint64 n_, uint8 op_, bytes32 epoch_, bytes32 profile_, bytes32 keys_, address[] memory owners_)
        payable MKLHSVerification("kms-grouped-radix-v1", 1, n_, op_, epoch_, owners_)
    {
        require(n_ > 0 && n_ <= 33 && profile_ != bytes32(0) && keys_ != bytes32(0), "invalid grouped profile");
        profileDigest = profile_;
        keysetDigest = keys_;
        datasetTag = keccak256(abi.encode("VCFHE-LINEAR-GROUPED-V1", block.chainid,
            address(this), epoch_, profile_, keys_, n_, op_));
    }

    /// The enrolled owner binds its stable policy record ID to the digest of
    /// the grouped ciphertext vector. The binding is immutable and independent
    /// of the relayer that later submits the owner's BLS admission.
    function bindProtectedRecord(uint64 index, bytes32 protectedId, bytes32 ciphertextDigest) external {
        if (index >= totalItems) revert InvalidIndex();
        if (msg.sender != recordOwner[index]) revert Unauthorized();
        require(protectedId != bytes32(0) && ciphertextDigest != bytes32(0), "empty protected binding");
        require(!protectedRecordBound[index] && !protectedIdUsed[protectedId], "protected binding fixed");
        protectedRecordId[index] = protectedId;
        protectedCiphertextDigest[index] = ciphertextDigest;
        protectedRecordBound[index] = true;
        protectedIdUsed[protectedId] = true;
        emit ProtectedRecordBound(index, protectedId, ciphertextDigest, msg.sender);
    }

    function getProtectedRecordBinding(uint64 index)
        external
        view
        returns (bytes32 protectedId, bytes32 ciphertextDigest, bool bound)
    {
        if (index >= totalItems) revert InvalidIndex();
        return (protectedRecordId[index], protectedCiphertextDigest[index], protectedRecordBound[index]);
    }
}
