// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IReleasePolicyGame {
    function secureTraceMode() external view returns (bool);
    function availabilityModule() external view returns (address);
    function leafDecisionVerifier() external view returns (address);
    function fhevmVerifier() external view returns (address);
    function kmsVerdictVerifier() external view returns (address);
    function getTaskStatus(bytes32 taskId)
        external
        view
        returns (uint8 status, uint8 decision, bool challengeTriggered, address operator, address challenger);
    function getTaskResultBinding(bytes32 taskId)
        external
        view
        returns (bytes32 resultHash, bytes32 operatorTraceRoot, uint32 leafCount);
}

interface IReleasePolicyAvailability {
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

    function game() external view returns (address);
    function isCleared(bytes32 taskId) external view returns (bool);
    function getTaskAuthorization(bytes32 taskId) external view returns (TaskAuthorization memory);
}

interface IReleasePolicyCanonicalVerifier {
    function game() external view returns (address);
    function profileDigest() external view returns (bytes32);
    function contexts(bytes32 taskId) external view returns (bytes32);
}

interface IReleasePolicyGroupedLinear {
    function profileDigest() external view returns (bytes32);
    function keysetDigest() external view returns (bytes32);
    function totalItems() external view returns (uint64);
    function admittedCount() external view returns (uint64);
    function recordOwner(uint64 index) external view returns (address);
    function getProtectedRecordBinding(uint64 index)
        external
        view
        returns (bytes32 protectedId, bytes32 ciphertextDigest, bool bound);
    function getBoundResult(bytes32 taskId)
        external
        view
        returns (uint256[2] memory outputCommitment, bytes32 outputDigest, address operator, bool accepted);
}

/// @notice Owner consent and one-use final-output release authorization recorded on chain.
/// @dev KMS participants read the submit/result authorization views independently. A reservation consumes
///      every protected-record budget before any off-chain KMS request is submitted. There
///      is deliberately no refund path: a failed or abandoned KMS request remains consumed.
contract ReleasePolicyRegistry {
    enum WorkflowKind {
        None,
        GroupedLinear,
        CanonicalNonlinear
    }

    struct ProtectedRecord {
        address owner;
        bytes32 recordReference;
        uint64 releaseLimit;
        uint64 spent;
    }

    struct ConsentTerms {
        bytes32 domain;
        uint256 chainId;
        WorkflowKind workflowKind;
        address workflow;
        bytes32 taskId;
        bytes32 contextDigest;
        bytes32 programDigest;
        bytes32 programRoot;
        bytes32 profileDigest;
        bytes32 keysetDigest;
        bytes32 keyId;
        bytes32 keyEpoch;
        bytes32 mpcContext;
        bytes32 outputType;
        address recipient;
        bytes32 slot;
        bytes32[] protectedRecordIds;
        // Empty for the grouped-linear workflow. For the canonical nonlinear
        // workflow, one protected-record id appears for every input, in public
        // input-index order. Repeated ids are permitted.
        bytes32[] inputProtectedRecordIds;
        // Linear: one grouped-ciphertext digest per unique protected record.
        // Nonlinear: one exact ciphertext handle per ordered input.
        bytes32[] inputBindings;
    }

    struct ConsentState {
        bytes32 domain;
        uint256 chainId;
        WorkflowKind workflowKind;
        address workflow;
        bytes32 taskId;
        bytes32 contextDigest;
        bytes32 programDigest;
        bytes32 programRoot;
        bytes32 profileDigest;
        bytes32 keysetDigest;
        bytes32 keyId;
        bytes32 keyEpoch;
        bytes32 mpcContext;
        bytes32 outputType;
        address recipient;
        bytes32 slot;
        bytes32 inputRoot;
        bytes32 inputBindingsDigest;
        uint32 recordCount;
        uint32 actualInputCount;
        uint32 paddedInputCount;
        uint32 requiredOwnerCount;
        uint32 approvalCount;
        bool exists;
    }

    /// `requestKey` is keccak256 over the canonical serialized protobuf RequestId JSON.
    struct ReleaseRequest {
        bytes32 consentId;
        bytes32 requestId;
        bytes32 requestKey;
        bytes32 submitWireDigest;
        bytes32 resultQueryDigest;
        bytes32 finalOutputDigest;
        bytes32 aggregateDigest;
        bytes32 recipientEncryptionKeyDigest;
        address recipient;
    }

    struct ReleaseState {
        bytes32 consentId;
        bytes32 requestId;
        bytes32 requestKey;
        bytes32 submitWireDigest;
        bytes32 resultQueryDigest;
        bytes32 finalOutputDigest;
        bytes32 aggregateDigest;
        bytes32 recipientEncryptionKeyDigest;
        address recipient;
        bytes32 releaseDigest;
        uint32 approvalCount;
        uint64 reservedBlock;
        bool exists;
        bool reserved;
    }

    /// @notice Static, ABI-stable facts parsed independently from a KMS submit request.
    /// @dev The tuple has no dynamic members. Its selector is pinned by the KMS cores.
    struct KmsSubmitAuthorization {
        bytes32 requestId;
        bytes32 requestKey;
        bytes32 submitWireDigest;
        bytes32 consentId;
        bytes32 finalOutputDigest;
        bytes32 aggregateDigest;
        bytes32 recipientEncryptionKeyDigest;
        address recipient;
        bytes32 keyId;
        bytes32 keyEpoch;
        bytes32 mpcContext;
        bytes32 outputType;
        address workflow;
        uint256 chainId;
        bytes32 policyDomain;
        address policy;
        bytes32 slot;
        uint8 workflowKind;
        bytes32 taskId;
        bytes32 contextDigest;
        bytes32 programDigest;
        bytes32 programRoot;
        bytes32 profileDigest;
        bytes32 keysetDigest;
        bytes32 inputBindingsDigest;
    }

    error InvalidValue();
    error AlreadyRegistered();
    error UnknownRecord();
    error DuplicateRecord();
    error UnknownConsent();
    error ConsentNotApproved();
    error NotRecordOwner();
    error AlreadyApproved();
    error UnknownRelease();
    error ReleaseNotApproved();
    error RequestAlreadyUsed();
    error SlotAlreadyUsed();
    error BudgetExhausted();
    error InvalidRecipientSignature();
    error InvalidFinality();
    error RequestMismatch();

    uint256 public constant POLICY_VERSION = 3;
    bytes32 public immutable policyDomain;
    uint256 public immutable deploymentChainId;
    bytes32 public immutable DOMAIN_SEPARATOR;

    uint256 public constant MAX_RECORDS = 64;
    uint256 public constant MAX_INPUTS = 128;

    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant PROTECTED_RECORD_TYPEHASH = keccak256(
        "VCFHE_PROTECTED_RECORD_V2(uint256 chainId,address registry,address owner,bytes32 recordReference)"
    );
    bytes32 public constant CONSENT_TYPEHASH = keccak256(
        "ReleaseConsent(uint256 policyVersion,address policy,bytes32 domain,uint256 chainId,bytes32 executionDigest,bytes32 keyDigest,bytes32 outputType,address recipient,bytes32 slot,bytes32 protectedRecordsDigest,bytes32 inputProtectedRecordsDigest,bytes32 inputBindingsDigest)"
    );
    bytes32 public constant RELEASE_TYPEHASH = keccak256(
        "ReleaseRequest(bytes32 consentId,bytes32 requestId,bytes32 requestKey,bytes32 submitWireDigest,bytes32 resultQueryDigest,bytes32 finalOutputDigest,bytes32 aggregateDigest,bytes32 recipientEncryptionKeyDigest,address recipient)"
    );
    bytes32 public constant OUTPUT_BINDING_V2_TYPEHASH = keccak256(
        "FHE_POD_OUTPUT_BINDING_V2(bytes32 taskId,bytes32 operatorTraceRoot,uint32 leafCount,bytes32 terminalOutputHandle,bytes32 outputAttestationHash)"
    );
    bytes32 public constant INPUT_RECORD_TYPEHASH = keccak256(
        "FHE_POD_INPUT_RECORD_V1(address owner,bytes32 ciphertextHandle,bytes32 metadataHash)"
    );

    // secp256k1n / 2. Rejecting high-s signatures removes ECDSA malleability.
    uint256 private constant SECP256K1_HALF_N =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    mapping(bytes32 => ProtectedRecord) public protectedRecords;
    mapping(bytes32 => ConsentState) private consentStates;
    mapping(bytes32 => bytes32[]) private consentRecordIds;
    mapping(bytes32 => bytes32[]) private consentInputProtectedRecordIds;
    mapping(bytes32 => bytes32[]) private consentInputBindings;
    mapping(bytes32 => mapping(address => bool)) public isConsentOwner;
    mapping(bytes32 => mapping(address => bool)) public consentApprovedBy;

    mapping(bytes32 => ReleaseState) private releaseStates;
    mapping(bytes32 => mapping(address => bool)) public releaseApprovedBy;
    mapping(bytes32 => bytes32) public requestByKey;
    mapping(bytes32 => bytes32) public requestBySlot;

    event ProtectedRecordRegistered(
        bytes32 indexed protectedId,
        address indexed owner,
        bytes32 indexed recordReference,
        uint64 releaseLimit,
        uint64 initialSpent
    );
    event ConsentCreated(
        bytes32 indexed consentId,
        bytes32 indexed taskId,
        address indexed recipient,
        WorkflowKind workflowKind,
        address workflow,
        bytes32 slot,
        uint32 recordCount,
        uint32 requiredOwnerCount
    );
    event ConsentApproved(bytes32 indexed consentId, address indexed owner, uint32 approvalCount);
    event ReleaseProposed(
        bytes32 indexed requestId,
        bytes32 indexed consentId,
        bytes32 indexed requestKey,
        bytes32 releaseDigest
    );
    event ReleaseApproved(
        bytes32 indexed requestId,
        address indexed owner,
        uint32 approvalCount,
        bytes32 releaseDigest
    );
    event ReleaseReserved(
        bytes32 indexed requestId,
        bytes32 indexed consentId,
        bytes32 indexed requestKey,
        bytes32 submitWireDigest,
        bytes32 resultQueryDigest,
        bytes32 finalOutputDigest,
        bytes32 aggregateDigest,
        bytes32 recipientEncryptionKeyDigest,
        address recipient,
        bytes32 slot
    );

    constructor() {
        deploymentChainId = block.chainid;
        policyDomain = keccak256(
            abi.encode("VCFHE_RELEASE_POLICY_DOMAIN_V3", block.chainid, address(this))
        );
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256("VCFHE-Onchain-Release-Policy"),
                keccak256("3"),
                block.chainid,
                address(this)
            )
        );
    }

    function registerProtectedRecord(
        bytes32 protectedId,
        address recordOwner,
        bytes32 recordReference,
        uint64 releaseLimit,
        uint64 initialSpent
    ) external {
        if (
            protectedId == bytes32(0) ||
            recordOwner == address(0) ||
            recordReference == bytes32(0) ||
            msg.sender != recordOwner ||
            protectedId != deriveProtectedId(recordOwner, recordReference) ||
            releaseLimit == 0 ||
            initialSpent > releaseLimit
        ) revert InvalidValue();
        if (protectedRecords[protectedId].owner != address(0)) revert AlreadyRegistered();
        protectedRecords[protectedId] = ProtectedRecord(
            recordOwner,
            recordReference,
            releaseLimit,
            initialSpent
        );
        emit ProtectedRecordRegistered(
            protectedId,
            recordOwner,
            recordReference,
            releaseLimit,
            initialSpent
        );
    }

    function deriveProtectedId(address recordOwner, bytes32 recordReference)
        public
        view
        returns (bytes32)
    {
        if (recordOwner == address(0) || recordReference == bytes32(0)) revert InvalidValue();
        return keccak256(
            abi.encode(
                PROTECTED_RECORD_TYPEHASH,
                deploymentChainId,
                address(this),
                recordOwner,
                recordReference
            )
        );
    }

    function computeConsentId(ConsentTerms calldata terms) public view returns (bytes32) {
        bytes32 executionDigest = keccak256(
            abi.encode(
                terms.workflowKind,
                terms.workflow,
                terms.taskId,
                terms.contextDigest,
                terms.programDigest,
                terms.programRoot,
                terms.profileDigest,
                terms.keysetDigest
            )
        );
        bytes32 keyDigest = keccak256(
            abi.encode(terms.keyId, terms.keyEpoch, terms.mpcContext)
        );
        return keccak256(
            abi.encode(
                CONSENT_TYPEHASH,
                POLICY_VERSION,
                address(this),
                terms.domain,
                terms.chainId,
                executionDigest,
                keyDigest,
                terms.outputType,
                terms.recipient,
                terms.slot,
                keccak256(abi.encode(terms.protectedRecordIds)),
                keccak256(abi.encode(terms.inputProtectedRecordIds)),
                keccak256(abi.encode(terms.inputBindings))
            )
        );
    }

    function createConsent(ConsentTerms calldata terms) external returns (bytes32 consentId) {
        uint256 count = terms.protectedRecordIds.length;
        if (
            terms.domain != policyDomain ||
            terms.chainId != deploymentChainId ||
            terms.workflowKind == WorkflowKind.None ||
            uint8(terms.workflowKind) > uint8(WorkflowKind.CanonicalNonlinear) ||
            terms.workflow == address(0) ||
            terms.workflow.code.length == 0 ||
            terms.taskId == bytes32(0) ||
            terms.contextDigest == bytes32(0) ||
            terms.programDigest == bytes32(0) ||
            terms.programRoot == bytes32(0) ||
            terms.profileDigest == bytes32(0) ||
            terms.keysetDigest == bytes32(0) ||
            terms.keyId == bytes32(0) ||
            terms.keyEpoch == bytes32(0) ||
            terms.mpcContext == bytes32(0) ||
            terms.outputType == bytes32(0) ||
            terms.recipient == address(0) ||
            terms.slot == bytes32(0) ||
            count == 0 ||
            count > MAX_RECORDS
        ) revert InvalidValue();
        if (terms.workflowKind == WorkflowKind.GroupedLinear) {
            if (
                terms.inputProtectedRecordIds.length != 0 ||
                terms.inputBindings.length != count
            ) revert InvalidValue();
        } else {
            uint256 inputCount = terms.inputBindings.length;
            if (
                inputCount == 0 ||
                inputCount > MAX_INPUTS ||
                terms.inputProtectedRecordIds.length != inputCount
            ) revert InvalidValue();
        }

        consentId = computeConsentId(terms);
        if (consentStates[consentId].exists) revert AlreadyRegistered();

        ConsentState storage consent = consentStates[consentId];
        consent.domain = terms.domain;
        consent.chainId = terms.chainId;
        consent.workflowKind = terms.workflowKind;
        consent.workflow = terms.workflow;
        consent.taskId = terms.taskId;
        consent.contextDigest = terms.contextDigest;
        consent.programDigest = terms.programDigest;
        consent.programRoot = terms.programRoot;
        consent.profileDigest = terms.profileDigest;
        consent.keysetDigest = terms.keysetDigest;
        consent.keyId = terms.keyId;
        consent.keyEpoch = terms.keyEpoch;
        consent.mpcContext = terms.mpcContext;
        consent.outputType = terms.outputType;
        consent.recipient = terms.recipient;
        consent.slot = terms.slot;
        consent.inputBindingsDigest = keccak256(abi.encode(terms.inputBindings));
        consent.recordCount = uint32(count);

        for (uint256 i; i < count; ++i) {
            bytes32 protectedId = terms.protectedRecordIds[i];
            ProtectedRecord storage record = protectedRecords[protectedId];
            if (record.owner == address(0)) revert UnknownRecord();
            for (uint256 j; j < i; ++j) {
                if (terms.protectedRecordIds[j] == protectedId) revert DuplicateRecord();
            }
            consentRecordIds[consentId].push(protectedId);
            if (!isConsentOwner[consentId][record.owner]) {
                isConsentOwner[consentId][record.owner] = true;
                consent.requiredOwnerCount += 1;
            }
        }

        if (terms.workflowKind == WorkflowKind.GroupedLinear) {
            for (uint256 i; i < count; ++i) {
                bytes32 inputBinding = terms.inputBindings[i];
                if (inputBinding == bytes32(0)) revert InvalidValue();
                consentInputBindings[consentId].push(inputBinding);
            }
        } else {
            _storeCanonicalInputs(consentId, consent, terms);
        }
        consent.exists = true;

        emit ConsentCreated(
            consentId,
            terms.taskId,
            terms.recipient,
            terms.workflowKind,
            terms.workflow,
            terms.slot,
            uint32(count),
            consent.requiredOwnerCount
        );
    }

    function approveConsent(bytes32 consentId) external {
        ConsentState storage consent = consentStates[consentId];
        if (!consent.exists) revert UnknownConsent();
        if (!isConsentOwner[consentId][msg.sender]) revert NotRecordOwner();
        if (consentApprovedBy[consentId][msg.sender]) revert AlreadyApproved();
        consentApprovedBy[consentId][msg.sender] = true;
        consent.approvalCount += 1;
        emit ConsentApproved(consentId, msg.sender, consent.approvalCount);
    }

    function getConsent(bytes32 consentId) external view returns (ConsentState memory) {
        return consentStates[consentId];
    }

    function getConsentRecord(bytes32 consentId, uint256 index)
        external
        view
        returns (bytes32 protectedId, bytes32 inputBinding, address owner)
    {
        ConsentState storage consent = consentStates[consentId];
        if (!consent.exists || index >= consent.recordCount) revert InvalidValue();
        protectedId = consentRecordIds[consentId][index];
        if (consent.workflowKind == WorkflowKind.GroupedLinear) {
            inputBinding = consentInputBindings[consentId][index];
        }
        owner = protectedRecords[protectedId].owner;
    }

    function getConsentInput(bytes32 consentId, uint256 index)
        external
        view
        returns (bytes32 protectedId, bytes32 inputBinding, address owner)
    {
        ConsentState storage consent = consentStates[consentId];
        if (
            !consent.exists ||
            consent.workflowKind != WorkflowKind.CanonicalNonlinear ||
            index >= consent.actualInputCount
        ) revert InvalidValue();
        protectedId = consentInputProtectedRecordIds[consentId][index];
        inputBinding = consentInputBindings[consentId][index];
        owner = protectedRecords[protectedId].owner;
    }

    function _storeCanonicalInputs(
        bytes32 consentId,
        ConsentState storage consent,
        ConsentTerms calldata terms
    ) private {
        uint256 actualCount = terms.inputBindings.length;
        uint256 paddedCount = 1;
        while (paddedCount < actualCount) paddedCount <<= 1;

        bool[] memory usedRecords = new bool[](terms.protectedRecordIds.length);
        bytes32[] memory level = new bytes32[](paddedCount);
        address paddingOwner;
        for (uint256 i; i < actualCount; ++i) {
            bytes32 protectedId = terms.inputProtectedRecordIds[i];
            bytes32 inputBinding = terms.inputBindings[i];
            if (inputBinding == bytes32(0)) revert InvalidValue();

            (uint256 recordIndex, address owner) =
                _consentedRecordOwner(terms.protectedRecordIds, protectedId);
            usedRecords[recordIndex] = true;
            if (i == 0) paddingOwner = owner;
            consentInputProtectedRecordIds[consentId].push(protectedId);
            consentInputBindings[consentId].push(inputBinding);
            level[i] = _inputRecordHash(owner, inputBinding, terms.taskId, uint32(i), "record");
        }
        for (uint256 i; i < usedRecords.length; ++i) {
            if (!usedRecords[i]) revert InvalidValue();
        }
        for (uint256 i = actualCount; i < paddedCount; ++i) {
            bytes32 paddingHandle = keccak256(
                abi.encodePacked("VCFHE_INPUT_TREE_PADDING", terms.taskId, uint32(i))
            );
            level[i] = _inputRecordHash(
                paddingOwner,
                paddingHandle,
                terms.taskId,
                uint32(i),
                "padding"
            );
        }
        for (uint256 width = paddedCount; width > 1; width >>= 1) {
            for (uint256 i; i < width; i += 2) {
                level[i >> 1] = keccak256(abi.encodePacked(level[i], level[i + 1]));
            }
        }
        consent.inputRoot = level[0];
        consent.actualInputCount = uint32(actualCount);
        consent.paddedInputCount = uint32(paddedCount);
    }

    function _consentedRecordOwner(bytes32[] calldata protectedRecordIds, bytes32 target)
        private
        view
        returns (uint256 index, address owner)
    {
        for (uint256 i; i < protectedRecordIds.length; ++i) {
            if (protectedRecordIds[i] == target) {
                return (i, protectedRecords[target].owner);
            }
        }
        revert UnknownRecord();
    }

    function _inputRecordHash(
        address owner,
        bytes32 ciphertextHandle,
        bytes32 taskId,
        uint32 inputIndex,
        string memory kind
    ) private pure returns (bytes32) {
        bytes32 metadataHash = keccak256(abi.encode(taskId, inputIndex, kind));
        return keccak256(
            abi.encode(INPUT_RECORD_TYPEHASH, owner, ciphertextHandle, metadataHash)
        );
    }

    function releaseStructHash(ReleaseRequest calldata request) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                RELEASE_TYPEHASH,
                request.consentId,
                request.requestId,
                request.requestKey,
                request.submitWireDigest,
                request.resultQueryDigest,
                request.finalOutputDigest,
                request.aggregateDigest,
                request.recipientEncryptionKeyDigest,
                request.recipient
            )
        );
    }

    function releaseAuthorizationDigest(ReleaseRequest calldata request) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, releaseStructHash(request)));
    }

    /// @notice Records the exact post-execution output request that owners will review.
    /// @dev A relayer may submit it, but only with the designated recipient's EIP-712 signature.
    function proposeRelease(ReleaseRequest calldata request, bytes calldata recipientSignature) external {
        _validateReleaseRequest(request);
        ConsentState storage consent = consentStates[request.consentId];
        if (consent.approvalCount != consent.requiredOwnerCount) revert ConsentNotApproved();
        if (releaseStates[request.requestId].exists) revert AlreadyRegistered();
        if (_recover(releaseAuthorizationDigest(request), recipientSignature) != consent.recipient) {
            revert InvalidRecipientSignature();
        }
        if (!_hasFinality(request.consentId, consent, request)) revert InvalidFinality();

        bytes32 digest = releaseStructHash(request);
        ReleaseState storage release = releaseStates[request.requestId];
        release.consentId = request.consentId;
        release.requestId = request.requestId;
        release.requestKey = request.requestKey;
        release.submitWireDigest = request.submitWireDigest;
        release.resultQueryDigest = request.resultQueryDigest;
        release.finalOutputDigest = request.finalOutputDigest;
        release.aggregateDigest = request.aggregateDigest;
        release.recipientEncryptionKeyDigest = request.recipientEncryptionKeyDigest;
        release.recipient = request.recipient;
        release.releaseDigest = digest;
        release.exists = true;

        emit ReleaseProposed(request.requestId, request.consentId, request.requestKey, digest);
    }

    function approveRelease(bytes32 requestId, bytes32 expectedReleaseDigest) external {
        ReleaseState storage release = releaseStates[requestId];
        if (!release.exists) revert UnknownRelease();
        if (release.reserved) revert RequestAlreadyUsed();
        if (release.releaseDigest != expectedReleaseDigest) revert RequestMismatch();
        if (!isConsentOwner[release.consentId][msg.sender]) revert NotRecordOwner();
        if (releaseApprovedBy[requestId][msg.sender]) revert AlreadyApproved();
        releaseApprovedBy[requestId][msg.sender] = true;
        release.approvalCount += 1;
        emit ReleaseApproved(requestId, msg.sender, release.approvalCount, release.releaseDigest);
    }

    function getRelease(bytes32 requestId) external view returns (ReleaseState memory) {
        return releaseStates[requestId];
    }

    /// @notice Atomically consumes the slot and every cumulative record budget.
    /// @dev Finality is checked before the state transition. After a successful transaction,
    ///      no KMS outcome can refund the slot or counters.
    function reserveRelease(ReleaseRequest calldata request, bytes calldata recipientSignature) external {
        _validateReleaseRequest(request);
        ConsentState storage consent = consentStates[request.consentId];
        ReleaseState storage release = releaseStates[request.requestId];
        bytes32 digest = releaseStructHash(request);
        if (!release.exists) revert UnknownRelease();
        if (release.reserved) revert RequestAlreadyUsed();
        if (release.releaseDigest != digest) revert RequestMismatch();
        if (release.approvalCount != consent.requiredOwnerCount) revert ReleaseNotApproved();
        if (_recover(releaseAuthorizationDigest(request), recipientSignature) != consent.recipient) {
            revert InvalidRecipientSignature();
        }
        if (requestByKey[request.requestKey] != bytes32(0)) revert RequestAlreadyUsed();
        if (requestBySlot[consent.slot] != bytes32(0)) revert SlotAlreadyUsed();
        if (!_hasFinality(request.consentId, consent, request)) revert InvalidFinality();

        uint256 count = consent.recordCount;
        for (uint256 i; i < count; ++i) {
            ProtectedRecord storage record = protectedRecords[consentRecordIds[request.consentId][i]];
            if (record.spent >= record.releaseLimit) revert BudgetExhausted();
        }

        // No external call follows these writes. A mined reservation is the irrevocable
        // authorization point observed independently by the threshold participants.
        requestByKey[request.requestKey] = request.requestId;
        requestBySlot[consent.slot] = request.requestId;
        release.reserved = true;
        release.reservedBlock = uint64(block.number);
        for (uint256 i; i < count; ++i) {
            protectedRecords[consentRecordIds[request.consentId][i]].spent += 1;
        }

        emit ReleaseReserved(
            request.requestId,
            request.consentId,
            request.requestKey,
            request.submitWireDigest,
            request.resultQueryDigest,
            request.finalOutputDigest,
            request.aggregateDigest,
            request.recipientEncryptionKeyDigest,
            request.recipient,
            consent.slot
        );
    }

    /// @notice Core-facing authorization query for a parsed user-decryption request.
    /// @dev Every field is derived from the received wire or pinned local policy config.
    function isSubmitAuthorized(KmsSubmitAuthorization calldata authorization)
        external
        view
        returns (bool)
    {
        ReleaseState storage release = releaseStates[authorization.requestId];
        if (
            !release.reserved ||
            requestByKey[authorization.requestKey] != authorization.requestId ||
            release.requestId != authorization.requestId ||
            release.requestKey != authorization.requestKey ||
            release.submitWireDigest != authorization.submitWireDigest ||
            release.consentId != authorization.consentId ||
            release.finalOutputDigest != authorization.finalOutputDigest ||
            release.aggregateDigest != authorization.aggregateDigest ||
            release.recipientEncryptionKeyDigest != authorization.recipientEncryptionKeyDigest ||
            release.recipient != authorization.recipient
        ) return false;

        ConsentState storage consent = consentStates[release.consentId];
        return
            consent.exists &&
            consent.keyId == authorization.keyId &&
            consent.keyEpoch == authorization.keyEpoch &&
            consent.mpcContext == authorization.mpcContext &&
            consent.outputType == authorization.outputType &&
            consent.workflow == authorization.workflow &&
            consent.chainId == authorization.chainId &&
            consent.domain == authorization.policyDomain &&
            authorization.policy == address(this) &&
            consent.slot == authorization.slot &&
            uint8(consent.workflowKind) == authorization.workflowKind &&
            consent.taskId == authorization.taskId &&
            consent.contextDigest == authorization.contextDigest &&
            consent.programDigest == authorization.programDigest &&
            consent.programRoot == authorization.programRoot &&
            consent.profileDigest == authorization.profileDigest &&
            consent.keysetDigest == authorization.keysetDigest &&
            consent.inputBindingsDigest == authorization.inputBindingsDigest;
    }

    /// @notice Core-facing authorization query for the exact result RequestId wire.
    function isResultAuthorized(
        bytes32 requestId,
        bytes32 requestKey,
        bytes32 resultQueryDigest
    ) external view returns (bool) {
        ReleaseState storage release = releaseStates[requestId];
        return
            release.reserved &&
            requestByKey[requestKey] == requestId &&
            release.requestId == requestId &&
            release.requestKey == requestKey &&
            release.resultQueryDigest == resultQueryDigest;
    }

    function _validateReleaseRequest(ReleaseRequest calldata request) private view {
        ConsentState storage consent = consentStates[request.consentId];
        if (!consent.exists) revert UnknownConsent();
        if (
            request.requestId == bytes32(0) ||
            request.requestKey == bytes32(0) ||
            request.submitWireDigest == bytes32(0) ||
            request.resultQueryDigest != request.requestKey ||
            request.finalOutputDigest == bytes32(0) ||
            request.aggregateDigest == bytes32(0) ||
            request.recipientEncryptionKeyDigest == bytes32(0) ||
            request.recipient != consent.recipient
        ) revert InvalidValue();
    }

    function _hasFinality(
        bytes32 consentId,
        ConsentState storage consent,
        ReleaseRequest calldata request
    )
        private
        view
        returns (bool)
    {
        if (consent.workflowKind == WorkflowKind.GroupedLinear) {
            return _hasLinearFinality(consentId, consent, request);
        }
        if (consent.workflowKind == WorkflowKind.CanonicalNonlinear) {
            return _hasNonlinearFinality(consent, request);
        }
        return false;
    }

    function _hasLinearFinality(
        bytes32 consentId,
        ConsentState storage consent,
        ReleaseRequest calldata request
    )
        private
        view
        returns (bool)
    {
        IReleasePolicyGroupedLinear workflow = IReleasePolicyGroupedLinear(consent.workflow);
        if (
            workflow.profileDigest() != consent.profileDigest ||
            workflow.keysetDigest() != consent.keysetDigest ||
            workflow.totalItems() != consent.recordCount ||
            workflow.admittedCount() != consent.recordCount
        ) return false;

        (uint256[2] memory commitment, bytes32 aggregateDigest, , bool accepted) =
            workflow.getBoundResult(consent.taskId);
        if (
            !accepted ||
            aggregateDigest != request.aggregateDigest ||
            (commitment[0] == 0 && commitment[1] == 0)
        ) return false;

        for (uint64 i; i < consent.recordCount; ++i) {
            bytes32 protectedId = consentRecordIds[consentId][i];
            (bytes32 boundId, bytes32 ciphertextDigest, bool bound) = workflow.getProtectedRecordBinding(i);
            if (
                !bound ||
                boundId != protectedId ||
                ciphertextDigest != consentInputBindings[consentId][i] ||
                workflow.recordOwner(i) != protectedRecords[protectedId].owner
            ) return false;
        }
        return true;
    }

    function _hasNonlinearFinality(ConsentState storage consent, ReleaseRequest calldata request)
        private
        view
        returns (bool)
    {
        IReleasePolicyGame game = IReleasePolicyGame(consent.workflow);
        if (
            !game.secureTraceMode() ||
            game.fhevmVerifier() != address(0) ||
            game.kmsVerdictVerifier() != address(0) ||
            !_isAcceptedNonlinearTask(game, consent.taskId)
        ) return false;
        address availabilityAddress = game.availabilityModule();
        address verifierAddress = game.leafDecisionVerifier();
        if (availabilityAddress.code.length == 0 || verifierAddress.code.length == 0) return false;
        IReleasePolicyAvailability availability = IReleasePolicyAvailability(availabilityAddress);
        IReleasePolicyCanonicalVerifier verifier = IReleasePolicyCanonicalVerifier(verifierAddress);
        if (
            availability.game() != consent.workflow ||
            !availability.isCleared(consent.taskId) ||
            verifier.game() != consent.workflow ||
            verifier.profileDigest() != consent.profileDigest ||
            verifier.contexts(consent.taskId) != consent.contextDigest
        ) return false;

        return _matchesNonlinearBinding(consent, request, game, availability);
    }

    function _isAcceptedNonlinearTask(IReleasePolicyGame game, bytes32 taskId)
        private
        view
        returns (bool)
    {
        (uint8 status, uint8 decision, bool challengeTriggered, , ) = game.getTaskStatus(taskId);
        return status == 3 && decision == 1 && !challengeTriggered;
    }

    function _matchesNonlinearBinding(
        ConsentState storage consent,
        ReleaseRequest calldata request,
        IReleasePolicyGame game,
        IReleasePolicyAvailability availability
    ) private view returns (bool) {
        IReleasePolicyAvailability.TaskAuthorization memory authorization =
            availability.getTaskAuthorization(consent.taskId);
        (bytes32 resultHash, bytes32 traceRoot, uint32 leafCount) = game.getTaskResultBinding(consent.taskId);
        if (
            !authorization.consumed ||
            authorization.resultHash != resultHash ||
            authorization.traceRoot != traceRoot ||
            authorization.programRoot != consent.programRoot ||
            authorization.inputRoot != consent.inputRoot ||
            authorization.inputCount != consent.paddedInputCount ||
            authorization.leafCount != leafCount ||
            authorization.provenanceRoot == bytes32(0) ||
            authorization.outputAttestationHash == bytes32(0) ||
            request.aggregateDigest != request.finalOutputDigest
        ) return false;

        bytes32 expectedResultHash = keccak256(
            abi.encode(
                OUTPUT_BINDING_V2_TYPEHASH,
                consent.taskId,
                traceRoot,
                leafCount,
                request.finalOutputDigest,
                authorization.outputAttestationHash
            )
        );
        return resultHash == expectedResultHash;
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address signer) {
        if (signature.length != 65) revert InvalidRecipientSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (v < 27) v += 27;
        if ((v != 27 && v != 28) || uint256(s) > SECP256K1_HALF_N) {
            revert InvalidRecipientSignature();
        }
        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert InvalidRecipientSignature();
    }
}
