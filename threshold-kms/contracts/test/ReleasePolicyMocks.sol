// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockCanonicalVerifier {
    address public immutable game;
    bytes32 public profileDigest;
    mapping(bytes32 => bytes32) public contexts;

    constructor(address game_) { game = game_; }
    function setProfileDigest(bytes32 value) external { profileDigest = value; }
    function setContext(bytes32 taskId, bytes32 value) external { contexts[taskId] = value; }
}

contract MockAvailability {
    struct TaskAuthorization {
        address requester;
        address operator;
        bytes32 traceRoot;
        bytes32 resultHash;
        bytes32 inputRoot;
        bytes32 programRoot;
        bytes32 provenanceRoot;
        bytes32 outputAttestationHash;
        uint32 inputCount;
        uint32 leafCount;
        uint64 deadline;
        bool consumed;
    }

    address public immutable game;
    bool public cleared;
    mapping(bytes32 => TaskAuthorization) private authorizations;

    constructor(address game_) { game = game_; }
    function setCleared(bool value) external { cleared = value; }
    function isCleared(bytes32) external view returns (bool) { return cleared; }
    function setTaskAuthorization(bytes32 taskId, TaskAuthorization calldata value) external {
        authorizations[taskId] = value;
    }
    function getTaskAuthorization(bytes32 taskId) external view returns (TaskAuthorization memory) {
        return authorizations[taskId];
    }
}

contract MockNonlinearGame {
    bool public secureTraceMode = true;
    address public availabilityModule;
    address public leafDecisionVerifier;
    address public fhevmVerifier;
    address public kmsVerdictVerifier;
    uint8 public status;
    uint8 public decision;
    bool public challengeTriggered;
    bytes32 public resultHash;
    bytes32 public operatorTraceRoot;
    uint32 public leafCount;

    function setModules(address availability, address verifier) external {
        availabilityModule = availability;
        leafDecisionVerifier = verifier;
    }
    function setLegacyVerifiers(address fhevm, address kmsVerdict) external {
        fhevmVerifier = fhevm;
        kmsVerdictVerifier = kmsVerdict;
    }
    function setSecureTraceMode(bool value) external { secureTraceMode = value; }
    function setStatus(uint8 status_, uint8 decision_, bool challenged_) external {
        status = status_; decision = decision_; challengeTriggered = challenged_;
    }
    function setResultBinding(bytes32 resultHash_, bytes32 traceRoot_, uint32 leafCount_) external {
        resultHash = resultHash_; operatorTraceRoot = traceRoot_; leafCount = leafCount_;
    }
    function getTaskStatus(bytes32)
        external
        view
        returns (uint8, uint8, bool, address, address)
    {
        return (status, decision, challengeTriggered, address(0x1111), address(0));
    }
    function getTaskResultBinding(bytes32)
        external
        view
        returns (bytes32, bytes32, uint32)
    {
        return (resultHash, operatorTraceRoot, leafCount);
    }
}

contract MockGroupedLinear {
    bytes32 public profileDigest;
    bytes32 public keysetDigest;
    uint64 public totalItems;
    uint64 public admittedCount;

    struct Binding { bytes32 protectedId; bytes32 ciphertextDigest; bool bound; }
    struct Result { uint256[2] commitment; bytes32 digest; address operator; bool accepted; }
    mapping(uint64 => address) public recordOwner;
    mapping(uint64 => Binding) private bindings;
    mapping(bytes32 => Result) private results;

    function configure(bytes32 profile, bytes32 keyset, uint64 count) external {
        profileDigest = profile; keysetDigest = keyset; totalItems = count; admittedCount = count;
    }
    function setAdmittedCount(uint64 count) external { admittedCount = count; }
    function setRecord(uint64 index, address owner, bytes32 protectedId, bytes32 ciphertextDigest) external {
        recordOwner[index] = owner;
        bindings[index] = Binding(protectedId, ciphertextDigest, true);
    }
    function setBoundResult(bytes32 taskId, bytes32 digest, bool accepted) external {
        results[taskId] = Result([uint256(1), uint256(2)], digest, address(0x2222), accepted);
    }
    function getProtectedRecordBinding(uint64 index)
        external
        view
        returns (bytes32 protectedId, bytes32 ciphertextDigest, bool bound)
    {
        Binding storage binding = bindings[index];
        return (binding.protectedId, binding.ciphertextDigest, binding.bound);
    }
    function getBoundResult(bytes32 taskId)
        external
        view
        returns (uint256[2] memory outputCommitment, bytes32 outputDigest, address operator, bool accepted)
    {
        Result storage result = results[taskId];
        return (result.commitment, result.digest, result.operator, result.accepted);
    }
}
