// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Certificates of PUBLIC canonical recomputation, never decryption.
/// @dev The legacy method name preserves the dispute-game ABI. Its payload and
/// domain are distinct from KMS certificates. Identities and threshold are immutable.
contract CanonicalLeafVerifier {
    bytes32 private constant DOMAIN_TYPE = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant CONTEXT_TYPE = keccak256("CanonicalContext(bytes32 taskId,bytes32 contextDigest)");
    bytes32 public constant RESULT_TYPE = keccak256("CanonicalLeafResult(bytes32 profileDigest,bytes32 contextDigest,bytes32 leafBinding,bytes32 resultHandle)");
    bytes32 public immutable domainSeparator;
    bytes32 public immutable profileDigest;
    address public immutable game;
    uint256 public immutable threshold;
    mapping(address => bool) public isSigner;
    mapping(bytes32 => bytes32) public contexts;

    constructor(address game_, bytes32 profileDigest_, address[] memory signers, uint256 threshold_) {
        require(game_ != address(0) && profileDigest_ != bytes32(0), "bad context");
        require(threshold_ > 0 && threshold_ <= signers.length, "bad threshold");
        game = game_; profileDigest = profileDigest_; threshold = threshold_;
        for (uint256 i; i < signers.length; ++i) {
            require(signers[i] != address(0) && !isSigner[signers[i]], "bad signer");
            isSigner[signers[i]] = true;
        }
        domainSeparator = keccak256(abi.encode(DOMAIN_TYPE, keccak256("VCFHE-Canonical-Execution"),
            keccak256("1"), block.chainid, address(this)));
    }
    function registerContext(bytes32 taskId, bytes32 contextDigest, bytes[] calldata signatures) external {
        require(contexts[taskId] == bytes32(0) && contextDigest != bytes32(0), "context fixed");
        require(_quorum(_digest(keccak256(abi.encode(CONTEXT_TYPE, taskId, contextDigest))), signatures, 0), "bad context certificate");
        contexts[taskId] = contextDigest;
    }
    function verifyDecryptionEIP712KMSSignatures(bytes32[] memory handles, bytes memory decisions, bytes memory proof)
        external view returns (bool)
    {
        require(msg.sender == game && handles.length == 2 && decisions.length == 64, "wrong caller or shape");
        (bytes[] memory signatures, bytes memory binding) = abi.decode(proof, (bytes[], bytes));
        require(signatures.length > 1 && signatures[0].length == 32, "missing public recomputation");
        (bytes32 tag, address boundGame, uint256 chain, bytes32 taskId, uint32 index, uint8 opcode) =
            abi.decode(binding, (bytes32,address,uint256,bytes32,uint32,uint8));
        // The game additionally checks the exact binding against its isolated leaf.
        index; opcode;
        require(boundGame == game && chain == block.chainid &&
            tag == keccak256("FHE_POD_LEAF_DECISION_V1"), "wrong leaf domain");
        bytes32 context = contexts[taskId]; require(context != bytes32(0), "unregistered context");
        bytes32 result = abi.decode(signatures[0], (bytes32));
        (bool operatorValid, bool challengerValid) = abi.decode(decisions, (bool,bool));
        if (operatorValid != (handles[0] == result) || challengerValid != (handles[1] == result)) return false;
        return _quorum(_digest(keccak256(abi.encode(RESULT_TYPE, profileDigest, context, keccak256(binding), result))), signatures, 1);
    }
    function _digest(bytes32 body) private view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, body));
    }
    function _quorum(bytes32 digest, bytes[] memory signatures, uint256 start) private view returns (bool) {
        address[] memory seen = new address[](signatures.length); uint256 count;
        for (uint256 i = start; i < signatures.length; ++i) {
            bytes memory sig = signatures[i]; if (sig.length != 65) continue;
            bytes32 r; bytes32 s; uint8 v;
            assembly { r := mload(add(sig,32)) s := mload(add(sig,64)) v := byte(0,mload(add(sig,96))) }
            if (v < 27) v += 27;
            if ((v != 27 && v != 28) || uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) continue;
            address signer = ecrecover(digest,v,r,s);
            if (!isSigner[signer]) continue;
            bool duplicate; for (uint256 j; j < count; ++j) if (seen[j] == signer) duplicate = true;
            if (duplicate) continue; seen[count++] = signer;
            if (count >= threshold) return true;
        }
        return false;
    }
}
