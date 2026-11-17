// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice On-chain verifier for threshold public-decryption results produced
/// by the open-source Zama Key Management System (zama-ai/kms, pinned tag
/// v0.13.20). Each KMS core signs the EIP-712 struct
///
///     PublicDecryptVerification(bytes32[] ctHandles,bytes decryptedResult,bytes extraData)
///
/// with its party identity key (k256), under an EIP-712 domain that the
/// decryption REQUEST supplies verbatim (kms.v1.Eip712DomainMsg: name,
/// version, chain_id, verifying_contract). Source of truth in the pinned
/// KMS release:
///   - struct + typehash: core/grpc/src/solidity_types.rs (PublicDecryptVerification)
///   - message construction: core/service/src/engine/base.rs
///     (compute_public_decryption_message: handles are left-padded to
///     bytes32; decryptedResult = abi-encoded tuple of uint256 plaintexts)
///   - signing: core/service/src/cryptography/signatures.rs
///     (compute_eip712_signature -> eip712_signing_hash(domain))
///   - domain intake: core/grpc/proto/kms.v1.proto (Eip712DomainMsg) parsed by
///     protobuf_to_alloy_domain (core/grpc/src/rpc_types.rs)
///
/// A decryption result is accepted when at least `threshold` distinct
/// registered core identities produced valid signatures over the digest.
/// For the Noah's Ark threshold deployment (n >= 3t+1) the correct value is
/// threshold = t + 1 (`num_majority` in the kms-core-client configuration):
/// honest-majority agreement on the plaintext.
///
/// The function signature `verifyDecryptionEIP712KMSSignatures` mirrors the
/// fhevm host-contract KMSVerifier ABI and the repository's local stand-in
/// (`LocalFhevmKMSVerifier`), so it is a drop-in backend for
/// `FHE.checkSignatures`-style flows. NOTE: `decryptionProof` here is
/// abi.encode(bytes[] signatures, bytes extraData); this transport packing is
/// defined by this repository (the cryptographic payload each core signs is
/// exactly the production one).
contract ZamaKMSVerdictVerifier {
    /// keccak256("PublicDecryptVerification(bytes32[] ctHandles,bytes decryptedResult,bytes extraData)")
    bytes32 public constant PUBLIC_DECRYPT_VERIFICATION_TYPEHASH =
        keccak256(
            "PublicDecryptVerification(bytes32[] ctHandles,bytes decryptedResult,bytes extraData)"
        );
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    error BadThreshold();
    error NoSigners();
    error BadSignatureLength();

    address public immutable owner;
    string public domainName;
    string public domainVersion;
    uint256 public immutable domainChainId;
    address public immutable domainVerifyingContract;
    bytes32 public immutable domainSeparator;

    address[] private signers;
    mapping(address => bool) public isSigner;
    uint256 public threshold;

    event SignersConfigured(address[] signers, uint256 threshold);

    /// @param name_ EIP-712 domain name; must equal the `name` field the
    ///        relayer places in the decryption request's Eip712DomainMsg.
    /// @param version_ EIP-712 domain version (same correspondence).
    /// @param chainIdOverride 0 => use block.chainid (recommended); a nonzero
    ///        value pins a foreign chain id (e.g. to verify signatures made
    ///        for the stock kms-core-client `dummy_domain`, chain id 8006).
    /// @param verifyingContractOverride address(0) => address(this)
    ///        (recommended); nonzero pins a foreign verifying contract.
    /// @param signers_ the KMS cores' Ethereum-style identity addresses
    ///        (`VerfAddress/<key-id>` public objects of each core).
    /// @param threshold_ minimum distinct valid core signatures
    ///        (= t+1 = `num_majority`).
    constructor(
        string memory name_,
        string memory version_,
        uint256 chainIdOverride,
        address verifyingContractOverride,
        address[] memory signers_,
        uint256 threshold_
    ) {
        if (signers_.length == 0) revert NoSigners();
        if (threshold_ == 0 || threshold_ > signers_.length) revert BadThreshold();
        owner = msg.sender;
        domainName = name_;
        domainVersion = version_;
        domainChainId = chainIdOverride == 0 ? block.chainid : chainIdOverride;
        domainVerifyingContract = verifyingContractOverride == address(0)
            ? address(this)
            : verifyingContractOverride;
        domainSeparator = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name_)),
                keccak256(bytes(version_)),
                chainIdOverride == 0 ? block.chainid : chainIdOverride,
                verifyingContractOverride == address(0)
                    ? address(this)
                    : verifyingContractOverride
            )
        );
        _setSigners(signers_, threshold_);
    }

    function setSigners(address[] calldata signers_, uint256 threshold_) external {
        require(msg.sender == owner, "not owner");
        if (signers_.length == 0) revert NoSigners();
        if (threshold_ == 0 || threshold_ > signers_.length) revert BadThreshold();
        for (uint256 i = 0; i < signers.length; i++) {
            isSigner[signers[i]] = false;
        }
        delete signers;
        _setSigners(signers_, threshold_);
    }

    function _setSigners(address[] memory signers_, uint256 threshold_) private {
        for (uint256 i = 0; i < signers_.length; i++) {
            require(signers_[i] != address(0), "zero signer");
            require(!isSigner[signers_[i]], "duplicate signer");
            isSigner[signers_[i]] = true;
            signers.push(signers_[i]);
        }
        threshold = threshold_;
        emit SignersConfigured(signers_, threshold_);
    }

    /// @notice EIP-712 digest each KMS core signs for a public decryption.
    function publicDecryptionDigest(
        bytes32[] memory handlesList,
        bytes memory decryptedResult,
        bytes memory extraData
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                PUBLIC_DECRYPT_VERIFICATION_TYPEHASH,
                keccak256(abi.encodePacked(handlesList)),
                keccak256(decryptedResult),
                keccak256(extraData)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /// @notice Verifies that >= `threshold` distinct registered KMS cores
    /// signed (handlesList, decryptedResult, extraData) under this domain.
    /// @param decryptionProof abi.encode(bytes[] signatures, bytes extraData);
    ///        each signature is the 65-byte r||s||v `external_signature`
    ///        returned in the core's PublicDecryptionResponsePayload.
    function verifyDecryptionEIP712KMSSignatures(
        bytes32[] memory handlesList,
        bytes memory decryptedResult,
        bytes memory decryptionProof
    ) public view returns (bool) {
        (bytes[] memory signatures, bytes memory extraData) = abi.decode(
            decryptionProof,
            (bytes[], bytes)
        );
        if (signatures.length == 0) return false;
        bytes32 digest = publicDecryptionDigest(
            handlesList,
            decryptedResult,
            extraData
        );

        address[] memory seen = new address[](signatures.length);
        uint256 validCount = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address recovered = _recover(digest, signatures[i]);
            if (recovered == address(0) || !isSigner[recovered]) continue;
            bool duplicate = false;
            for (uint256 j = 0; j < validCount; j++) {
                if (seen[j] == recovered) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;
            seen[validCount] = recovered;
            validCount += 1;
            if (validCount >= threshold) return true;
        }
        return false;
    }

    function _recover(
        bytes32 digest,
        bytes memory signature
    ) private pure returns (address) {
        if (signature.length != 65) revert BadSignatureLength();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        // Reject malleable high-s signatures (EIP-2 upper bound).
        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) return address(0);
        return ecrecover(digest, v, r, s);
    }

    // --- Introspection parity with LocalFhevmKMSVerifier -------------------

    function getKmsSigners() external view returns (address[] memory) {
        return signers;
    }

    function getThreshold() external view returns (uint256) {
        return threshold;
    }

    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        return (
            0x0f,
            domainName,
            domainVersion,
            domainChainId,
            domainVerifyingContract,
            bytes32(0),
            new uint256[](0)
        );
    }
}
