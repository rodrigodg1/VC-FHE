// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Read/write surface used by the authenticated availability module.
interface IAuthenticatedDisputeGame {
    function getTaskStatus(bytes32 taskId)
        external
        view
        returns (uint8 status, uint8 decision, bool challengeTriggered, address operator, address challenger);

    function getTaskResultBinding(bytes32 taskId)
        external
        view
        returns (bytes32 resultHash, bytes32 operatorTraceRoot, uint32 leafCount);

    function slashOperatorForUnavailability(bytes32 taskId, address requester) external;

    function getTaskDeadlines(bytes32 taskId)
        external
        view
        returns (uint64 commitDeadline, uint64 openDeadline, uint64 challengeDeadline);

    function getAssignedAuditors(bytes32 taskId) external view returns (address[] memory);

    function extendDeadlinesForDisclosure(bytes32 taskId, uint64 extensionSeconds) external;
}

/**
 * @title AuthenticatedTraceAvailability
 * @notice Security module for authenticated non-linear task statements,
 *         ciphertext-origin records, and complete on-chain trace disclosure
 *         after a challenge.
 *
 * The requester authorizes the exact task commitments and the roots of three
 * trees: authenticated inputs, the deterministic program/source plan, and the
 * per-leaf provenance metadata. Data owners register ciphertext handles
 * directly, so the input root can contain only records attributable to an EVM
 * account. Once a challenge opens, the operator must publish every committed
 * trace/provenance leaf in order. Incremental Merkle frontiers reconstruct all
 * three roots using O(N) hashes. Calldata and events provide L1 availability.
 * Bisection is not allowed until disclosure is complete.
 *
 * This module proves origin and structural dataflow of ciphertext handles. The
 * FHEVM input verifier remains responsible for validating ciphertext proofs
 * and for checking that the encrypted values behind those handles satisfy the
 * disputed operation.
 */
contract AuthenticatedTraceAvailability {
    error InvalidParameter();
    error Unauthorized();
    error WrongState();
    error BadProof();
    error RootMismatch();

    uint8 public constant SOURCE_AUTHENTICATED_INPUT = 0;
    uint8 public constant SOURCE_PREVIOUS_OUTPUT = 1;
    uint8 public constant SOURCE_PUBLIC_CONSTANT = 2;
    uint8 private constant TASK_STATUS_AUDITING = 1;
    uint8 private constant TASK_STATUS_CHALLENGED = 2;

    /// Anti-griefing bond of a pre-challenge disclosure request. Off-chain
    /// delivery of the trace is the operator's cheap path; a request forces the
    /// O(N) on-chain disclosure instead, so the bond is credited to a compliant
    /// operator (as in the leaf-level module) and refunded to the requester when
    /// the operator fails to disclose.
    uint256 public constant DISCLOSURE_REQUEST_BOND_BASE_WEI = 0.02 ether;
    /// Per-leaf component: the compelled disclosure costs the operator O(N)
    /// gas (about 170k per leaf in the evaluated deployment), so a request on
    /// a long trace must post a bond of the same order, or a single cohort
    /// seat could impose that cost on a compliant operator for a flat fee.
    uint256 public constant DISCLOSURE_REQUEST_BOND_PER_LEAF_WEI = 0.002 ether;

    /// @notice Bond a pre-challenge disclosure request must post for `taskId`.
    function requiredDisclosureBond(bytes32 taskId) public view returns (uint256) {
        return DISCLOSURE_REQUEST_BOND_BASE_WEI +
            DISCLOSURE_REQUEST_BOND_PER_LEAF_WEI * uint256(authorizations[taskId].leafCount);
    }

    bytes32 public constant INPUT_RECORD_TYPEHASH = keccak256(
        "FHE_POD_INPUT_RECORD_V1(address owner,bytes32 ciphertextHandle,bytes32 metadataHash)"
    );
    bytes32 public constant PROGRAM_LEAF_TYPEHASH = keccak256(
        "FHE_POD_PROGRAM_LEAF_V1(bytes32 taskId,uint32 leafIndex,uint8 opcode,uint8 lhsSourceKind,uint32 lhsSourceIndex,uint8 rhsSourceKind,uint32 rhsSourceIndex,uint256 lhsConstant,uint256 rhsConstant)"
    );
    bytes32 public constant PROVENANCE_LEAF_TYPEHASH = keccak256(
        "FHE_POD_PROVENANCE_LEAF_V1(bytes32 taskId,uint32 leafIndex,bytes32 traceLeafHash,bytes32 lhsHandle,bytes32 rhsHandle,bytes32 claimedHandle,uint8 lhsSourceKind,uint32 lhsSourceIndex,bytes32 lhsInputRecord,uint8 rhsSourceKind,uint32 rhsSourceIndex,bytes32 rhsInputRecord)"
    );

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

    /// @notice One disclosed trace leaf: STRUCTURE ONLY.
    /// @dev The operator's disclosure obligation is over the shape of the
    /// computation -- which operation, over which committed ciphertexts, with
    /// each operand's origin (authenticated input / previous output / public
    /// constant) -- and no longer over anybody's data. There is no cleartext
    /// operand field, so publishing the whole trace, which a challenge forces,
    /// discloses no individual's value. Everything this module enforces (root
    /// reconstruction, source classes, previous-output handle continuity, the
    /// reveal-or-slash deadline) is a property of that structure and is
    /// unchanged.
    struct ProvenanceLeaf {
        uint8 opcode;
        bytes32 lhsHandle;
        bytes32 rhsHandle;
        bytes32 claimedHandle;
        uint8 lhsSourceKind;
        uint32 lhsSourceIndex;
        bytes32 lhsInputRecord;
        uint8 rhsSourceKind;
        uint32 rhsSourceIndex;
        bytes32 rhsInputRecord;
    }

    struct DisclosedHandles {
        bytes32 traceLeafHash;
        bytes32 lhsHandle;
        bytes32 rhsHandle;
        bytes32 claimedHandle;
        uint8 lhsSourceKind;
        uint8 rhsSourceKind;
    }

    IAuthenticatedDisputeGame public immutable game;
    uint64 public immutable disclosureWindowSeconds;

    mapping(bytes32 => bool) public registeredInputRecords;
    mapping(bytes32 => bytes32) public registeredInputHandles;
    // Reverse index handle -> registered, so the dispute game can refuse to let
    // an individual user's input ciphertext handle be committed as a verdict
    // (and thus be publicly decrypted through the verdict-opening path).
    mapping(bytes32 => bool) public inputHandleRegistered;
    mapping(bytes32 => address) public registeredInputOwners;
    mapping(bytes32 => TaskAuthorization) internal authorizations;
    mapping(bytes32 => uint64) public disclosureDeadline;
    mapping(bytes32 => uint32) public nextDisclosureIndex;
    mapping(bytes32 => bool) public disputeReady;
    mapping(bytes32 => bool) public unavailable;
    // Pre-challenge disclosure requests: the assigned auditor that forced the
    // disclosure (zero when the disclosure was opened by a challenge), and the
    // bond it posted. Bonds are settled by pull to keep disclosure completion
    // independent of the recipient's ability to receive ether.
    mapping(bytes32 => address) public disclosureRequester;
    mapping(bytes32 => uint256) private disclosureRequestBond;
    mapping(address => uint256) public claimableBond;
    mapping(bytes32 => mapping(uint32 => DisclosedHandles)) private disclosedHandles;
    mapping(bytes32 => bytes32[32]) private traceFrontiers;
    mapping(bytes32 => bytes32[32]) private programFrontiers;
    mapping(bytes32 => bytes32[32]) private provenanceFrontiers;

    event InputOriginRegistered(
        bytes32 indexed inputRecord,
        address indexed owner,
        bytes32 indexed ciphertextHandle,
        bytes32 metadataHash
    );
    event TaskStatementAuthorized(
        bytes32 indexed taskId,
        address indexed requester,
        address indexed operator,
        bytes32 inputRoot,
        bytes32 programRoot,
        bytes32 provenanceRoot
    );
    event TaskStatementConsumed(bytes32 indexed taskId, address indexed operator);
    event FullTraceDisclosureOpened(bytes32 indexed taskId, uint64 deadline, uint32 leafCount);
    event DisputedTraceLeafPublished(
        bytes32 indexed taskId,
        uint32 indexed leafIndex,
        bytes32 traceLeafHash,
        bytes32 lhsHandle,
        bytes32 rhsHandle,
        bytes32 claimedHandle
    );
    event FullTraceAvailable(bytes32 indexed taskId, uint32 leafCount);
    event FullTraceUnavailable(bytes32 indexed taskId, address indexed operator);
    event TraceDisclosureRequested(
        bytes32 indexed taskId,
        address indexed auditor,
        uint64 deadline,
        uint32 leafCount
    );
    event DisclosureRequestBondSettled(
        bytes32 indexed taskId,
        address indexed recipient,
        uint256 amount,
        bool operatorComplied
    );
    event BondWithdrawn(address indexed recipient, uint256 amount);

    constructor(address game_, uint64 disclosureWindowSeconds_) {
        if (game_ == address(0) || disclosureWindowSeconds_ == 0) revert InvalidParameter();
        game = IAuthenticatedDisputeGame(game_);
        disclosureWindowSeconds = disclosureWindowSeconds_;
    }

    modifier onlyGame() {
        if (msg.sender != address(game)) revert Unauthorized();
        _;
    }

    function inputRecordHash(
        address owner,
        bytes32 ciphertextHandle,
        bytes32 metadataHash
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(INPUT_RECORD_TYPEHASH, owner, ciphertextHandle, metadataHash));
    }

    /// @notice The data owner directly registers the ciphertext handle and
    /// metadata commitment. This authenticates origin, not plaintext truth.
    function registerInputOrigin(
        bytes32 ciphertextHandle,
        bytes32 metadataHash
    ) external returns (bytes32 recordHash) {
        if (metadataHash == bytes32(0)) revert InvalidParameter();
        recordHash = inputRecordHash(msg.sender, ciphertextHandle, metadataHash);
        if (registeredInputRecords[recordHash]) revert WrongState();
        registeredInputRecords[recordHash] = true;
        registeredInputHandles[recordHash] = ciphertextHandle;
        registeredInputOwners[recordHash] = msg.sender;
        inputHandleRegistered[ciphertextHandle] = true;
        emit InputOriginRegistered(recordHash, msg.sender, ciphertextHandle, metadataHash);
    }

    /// @notice Whether `handle` is a registered individual-input ciphertext
    /// handle. The dispute game consults this so an input handle can never be
    /// committed as a verdict and decrypted through the verdict-opening path.
    function isRegisteredInputHandle(bytes32 handle) external view returns (bool) {
        return inputHandleRegistered[handle];
    }

    function registerInputOrigins(
        bytes32[] calldata ciphertextHandles,
        bytes32[] calldata metadataHashes
    ) external returns (bytes32[] memory recordHashes) {
        if (
            ciphertextHandles.length == 0 ||
            ciphertextHandles.length != metadataHashes.length
        ) revert InvalidParameter();
        recordHashes = new bytes32[](ciphertextHandles.length);
        for (uint256 i = 0; i < ciphertextHandles.length; i++) {
            bytes32 metadataHash = metadataHashes[i];
            if (metadataHash == bytes32(0)) revert InvalidParameter();
            bytes32 recordHash = inputRecordHash(
                msg.sender,
                ciphertextHandles[i],
                metadataHash
            );
            if (registeredInputRecords[recordHash]) revert WrongState();
            registeredInputRecords[recordHash] = true;
            registeredInputHandles[recordHash] = ciphertextHandles[i];
            registeredInputOwners[recordHash] = msg.sender;
            inputHandleRegistered[ciphertextHandles[i]] = true;
            recordHashes[i] = recordHash;
            emit InputOriginRegistered(
                recordHash,
                msg.sender,
                ciphertextHandles[i],
                metadataHash
            );
        }
    }

    /// @notice The requester authorizes an exact task statement. Calling this
    /// function authenticates the statement under msg.sender's EVM account;
    /// it does not assert that the operator's result is correct.
    function authorizeTaskStatement(
        bytes32 taskId,
        address operator,
        bytes32 traceRoot,
        bytes32 resultHash,
        bytes32 inputRoot,
        uint32 inputCount,
        bytes32 programRoot,
        bytes32 provenanceRoot,
        uint32 leafCount,
        bytes32 outputAttestationHash,
        uint64 deadline
    ) external {
        if (
            taskId == bytes32(0) ||
            operator == address(0) ||
            traceRoot == bytes32(0) ||
            resultHash == bytes32(0) ||
            inputRoot == bytes32(0) ||
            programRoot == bytes32(0) ||
            provenanceRoot == bytes32(0) ||
            outputAttestationHash == bytes32(0) ||
            !_isPowerOfTwo(inputCount) ||
            !_isPowerOfTwo(leafCount) ||
            deadline <= block.timestamp ||
            authorizations[taskId].requester != address(0)
        ) revert InvalidParameter();

        authorizations[taskId] = TaskAuthorization({
            requester: msg.sender,
            operator: operator,
            traceRoot: traceRoot,
            resultHash: resultHash,
            inputRoot: inputRoot,
            programRoot: programRoot,
            provenanceRoot: provenanceRoot,
            outputAttestationHash: outputAttestationHash,
            inputCount: inputCount,
            leafCount: leafCount,
            deadline: deadline,
            consumed: false
        });
        emit TaskStatementAuthorized(
            taskId,
            msg.sender,
            operator,
            inputRoot,
            programRoot,
            provenanceRoot
        );
    }

    function consumeTaskAuthorization(
        bytes32 taskId,
        address operator,
        bytes32 traceRoot,
        bytes32 resultHash,
        uint32 leafCount,
        bytes32 outputAttestationHash
    ) external onlyGame {
        TaskAuthorization storage auth = authorizations[taskId];
        if (
            auth.requester == address(0) ||
            auth.consumed ||
            block.timestamp > auth.deadline ||
            auth.operator != operator ||
            auth.traceRoot != traceRoot ||
            auth.resultHash != resultHash ||
            auth.leafCount != leafCount ||
            auth.outputAttestationHash != outputAttestationHash
        ) revert Unauthorized();
        auth.consumed = true;
        emit TaskStatementConsumed(taskId, operator);
    }

    function openDisputeTrace(bytes32 taskId) external onlyGame {
        TaskAuthorization storage auth = authorizations[taskId];
        if (!auth.consumed || unavailable[taskId]) revert WrongState();
        // A pre-challenge request may already have opened (or completed) the
        // disclosure of this task; the challenge then reuses it as is.
        if (disclosureDeadline[taskId] != 0) return;
        disclosureDeadline[taskId] = uint64(block.timestamp + disclosureWindowSeconds);
        game.extendDeadlinesForDisclosure(taskId, disclosureWindowSeconds);
        emit FullTraceDisclosureOpened(taskId, disclosureDeadline[taskId], auth.leafCount);
    }

    /// @notice Bonded pre-challenge disclosure request by an assigned auditor.
    ///
    /// The protocol lets the operator deliver the committed trace off chain, but
    /// nothing forces it to. Without this entry point an operator that delivers
    /// the trace to no assigned auditor could never be challenged, so a faulty
    /// task would finalize optimistically at no cost: withholding was a free
    /// strategy. A request opens the same complete-disclosure obligation a
    /// challenge opens (every committed trace/provenance leaf, in order, within
    /// the disclosure window, or the operator is slashed for withholding), and
    /// the task's audit deadlines are pushed by the same window so that the
    /// auditors can still audit, commit, open, and challenge after disclosure.
    /// At most one request per task; only during the audit-commit window, so the
    /// disclosed trace can inform the verdict the auditor commits.
    function requestTraceDisclosure(bytes32 taskId) external payable {
        if (msg.value != requiredDisclosureBond(taskId)) revert InvalidParameter();
        TaskAuthorization storage auth = authorizations[taskId];
        if (!auth.consumed || disclosureDeadline[taskId] != 0 || unavailable[taskId]) {
            revert WrongState();
        }
        (uint8 status, , bool challengeTriggered, , ) = game.getTaskStatus(taskId);
        if (status != TASK_STATUS_AUDITING || challengeTriggered) revert WrongState();
        (uint64 commitDeadline, , ) = game.getTaskDeadlines(taskId);
        // commitDeadline == 0 means participants are not yet sampled.
        if (commitDeadline == 0 || block.timestamp > commitDeadline) revert WrongState();
        if (!_isAssignedAuditor(taskId, msg.sender)) revert Unauthorized();

        disclosureRequester[taskId] = msg.sender;
        disclosureRequestBond[taskId] = msg.value;
        uint64 deadline = uint64(block.timestamp + disclosureWindowSeconds);
        disclosureDeadline[taskId] = deadline;
        game.extendDeadlinesForDisclosure(taskId, disclosureWindowSeconds);
        emit TraceDisclosureRequested(taskId, msg.sender, deadline, auth.leafCount);
    }

    /// @notice Pull settlement of disclosure-request bonds (credited to the
    ///         operator when it complied, refunded to the requester otherwise).
    function withdrawBond() external {
        uint256 amount = claimableBond[msg.sender];
        if (amount == 0) revert WrongState();
        claimableBond[msg.sender] = 0;
        emit BondWithdrawn(msg.sender, amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert WrongState();
    }

    function _isAssignedAuditor(bytes32 taskId, address auditor) internal view returns (bool) {
        address[] memory assigned = game.getAssignedAuditors(taskId);
        for (uint256 i = 0; i < assigned.length; i++) {
            if (assigned[i] == auditor) return true;
        }
        return false;
    }

    function _settleDisclosureRequestBond(bytes32 taskId, bool operatorComplied) internal {
        address requester = disclosureRequester[taskId];
        uint256 bond = disclosureRequestBond[taskId];
        if (requester == address(0) || bond == 0) return;
        disclosureRequestBond[taskId] = 0;
        address recipient = requester;
        if (operatorComplied) {
            (, , , address operator, ) = game.getTaskStatus(taskId);
            recipient = operator;
        }
        claimableBond[recipient] += bond;
        emit DisclosureRequestBondSettled(taskId, recipient, bond, operatorComplied);
    }

    /// @notice Publishes one sequential trace leaf. Sequential publication
    /// lets the contract reconstruct roots with an incremental Merkle frontier
    /// and validate references to earlier ciphertext outputs.
    function publishDisputedTraceLeaf(
        bytes32 taskId,
        ProvenanceLeaf calldata leaf,
        bytes32[] calldata lhsInputProof,
        bytes32[] calldata rhsInputProof
    ) external virtual {
        _requireDisclosurePublisher(taskId);
        _publishOne(taskId, leaf, lhsInputProof, rhsInputProof);
    }

    /// @notice Publishes a sequential chunk in one transaction. Chunking is
    /// necessary for traces whose leaf count exceeds the disclosure window in
    /// blocks; callers must still size each chunk below the chain gas limit.
    function publishDisputedTraceBatch(
        bytes32 taskId,
        ProvenanceLeaf[] calldata leaves,
        bytes32[][] calldata lhsInputProofs,
        bytes32[][] calldata rhsInputProofs
    ) external virtual {
        if (
            leaves.length == 0 ||
            leaves.length != lhsInputProofs.length ||
            leaves.length != rhsInputProofs.length
        ) revert InvalidParameter();
        _requireDisclosurePublisher(taskId);
        for (uint256 i = 0; i < leaves.length; i++) {
            _publishOne(taskId, leaves[i], lhsInputProofs[i], rhsInputProofs[i]);
        }
    }

    function markDisputeTraceUnavailable(bytes32 taskId) external {
        if (
            disclosureDeadline[taskId] == 0 ||
            block.timestamp <= disclosureDeadline[taskId] ||
            disputeReady[taskId] ||
            unavailable[taskId]
        ) revert WrongState();
        unavailable[taskId] = true;
        (, , , address operator, address challenger) = game.getTaskStatus(taskId);
        // The slashed stake goes to the party the operator stonewalled: the
        // challenger of an open dispute, else the auditor whose pre-challenge
        // request went unanswered, else whoever reports the breach.
        address reporter = challenger;
        if (reporter == address(0)) reporter = disclosureRequester[taskId];
        if (reporter == address(0)) reporter = msg.sender;
        _settleDisclosureRequestBond(taskId, false);
        game.slashOperatorForUnavailability(taskId, reporter);
        emit FullTraceUnavailable(taskId, operator);
    }

    /// @notice True when optimistic finalization may proceed: the statement was
    ///         consumed, no withholding was recorded, and no disclosure
    ///         obligation is still open (a pre-challenge request must be
    ///         answered or expire into a slash before the task can finalize).
    function isCleared(bytes32 taskId) external view returns (bool) {
        return
            authorizations[taskId].consumed &&
            !unavailable[taskId] &&
            (disclosureDeadline[taskId] == 0 || disputeReady[taskId]);
    }

    function isDisputeReady(bytes32 taskId) external view returns (bool) {
        return disputeReady[taskId] && !unavailable[taskId];
    }

    function getTaskAuthorization(bytes32 taskId)
        external
        view
        returns (TaskAuthorization memory)
    {
        return authorizations[taskId];
    }

    function getDisclosedLeafHandles(bytes32 taskId, uint32 leafIndex)
        external
        view
        returns (
            bytes32 traceLeafHash,
            bytes32 lhsHandle,
            bytes32 rhsHandle,
            bytes32 claimedHandle,
            uint8 lhsSourceKind,
            uint8 rhsSourceKind
        )
    {
        if (!disputeReady[taskId]) revert WrongState();
        DisclosedHandles storage handles = disclosedHandles[taskId][leafIndex];
        return (
            handles.traceLeafHash,
            handles.lhsHandle,
            handles.rhsHandle,
            handles.claimedHandle,
            handles.lhsSourceKind,
            handles.rhsSourceKind
        );
    }

    function programLeafHash(
        bytes32 taskId,
        uint32 leafIndex,
        ProvenanceLeaf calldata leaf
    ) external pure returns (bytes32) {
        return _programLeafHash(taskId, leafIndex, leaf);
    }

    function provenanceLeafHash(
        bytes32 taskId,
        uint32 leafIndex,
        ProvenanceLeaf calldata leaf
    ) external pure returns (bytes32) {
        return _provenanceLeafHash(taskId, leafIndex, _traceLeafHash(leaf), leaf);
    }

    /// @notice The trace-leaf commitment, recomputed from the disclosed leaf.
    /// @dev Must stay byte-identical to `_leafHash` in
    /// VerifiableFHEDisputeGame.sol and to `leafHash` in scripts/evm-lib.mjs:
    /// the same commitment is what bisection walks and what the terminal round
    /// opens. It commits to handles, not values, which is why a disclosure can
    /// reconstruct the operator's committed trace root without publishing a
    /// single operand.
    function _traceLeafHash(
        ProvenanceLeaf calldata leaf
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                leaf.opcode,
                leaf.lhsHandle,
                leaf.rhsHandle,
                leaf.claimedHandle
            )
        );
    }

    function _programLeafHash(
        bytes32 taskId,
        uint32 leafIndex,
        ProvenanceLeaf calldata leaf
    ) internal pure returns (bytes32) {
        // A PUBLIC_CONSTANT operand's handle IS its 32-byte big-endian
        // encoding, so the program root still binds the constant itself with no
        // cleartext field on the leaf. Every other source kind contributes 0.
        uint256 lhsConstant = leaf.lhsSourceKind == SOURCE_PUBLIC_CONSTANT
            ? uint256(leaf.lhsHandle)
            : 0;
        uint256 rhsConstant = leaf.rhsSourceKind == SOURCE_PUBLIC_CONSTANT
            ? uint256(leaf.rhsHandle)
            : 0;
        return keccak256(
            abi.encode(
                PROGRAM_LEAF_TYPEHASH,
                taskId,
                leafIndex,
                leaf.opcode,
                leaf.lhsSourceKind,
                leaf.lhsSourceIndex,
                leaf.rhsSourceKind,
                leaf.rhsSourceIndex,
                lhsConstant,
                rhsConstant
            )
        );
    }

    function _commitPublishedLeaf(
        bytes32 taskId,
        uint32 index,
        ProvenanceLeaf calldata leaf
    ) internal {
        bytes32 traceLeafHash = _traceLeafHash(leaf);
        bytes32 programLeaf = _programLeafHash(taskId, index, leaf);
        bytes32 provenanceLeaf = _provenanceLeafHash(
            taskId,
            index,
            traceLeafHash,
            leaf
        );
        _append(traceFrontiers[taskId], index, traceLeafHash);
        _append(programFrontiers[taskId], index, programLeaf);
        _append(provenanceFrontiers[taskId], index, provenanceLeaf);
        disclosedHandles[taskId][index] = DisclosedHandles({
            traceLeafHash: traceLeafHash,
            lhsHandle: leaf.lhsHandle,
            rhsHandle: leaf.rhsHandle,
            claimedHandle: leaf.claimedHandle,
            lhsSourceKind: leaf.lhsSourceKind,
            rhsSourceKind: leaf.rhsSourceKind
        });
        nextDisclosureIndex[taskId] = index + 1;
        emit DisputedTraceLeafPublished(
            taskId,
            index,
            traceLeafHash,
            leaf.lhsHandle,
            leaf.rhsHandle,
            leaf.claimedHandle
        );

        TaskAuthorization storage auth = authorizations[taskId];
        if (index + 1 == auth.leafCount) {
            uint8 depth = _treeDepth(auth.leafCount);
            if (
                traceFrontiers[taskId][depth] != auth.traceRoot ||
                programFrontiers[taskId][depth] != auth.programRoot ||
                provenanceFrontiers[taskId][depth] != auth.provenanceRoot
            ) revert RootMismatch();
            disputeReady[taskId] = true;
            emit FullTraceAvailable(taskId, auth.leafCount);
            _settleDisclosureRequestBond(taskId, true);
        }
    }

    function _validateLeafSources(
        bytes32 taskId,
        uint32 index,
        ProvenanceLeaf calldata leaf,
        bytes32[] calldata lhsInputProof,
        bytes32[] calldata rhsInputProof
    ) internal view {
        TaskAuthorization storage auth = authorizations[taskId];
        _validateSource(
            taskId,
            index,
            leaf.lhsSourceKind,
            leaf.lhsSourceIndex,
            leaf.lhsHandle,
            leaf.lhsInputRecord,
            lhsInputProof,
            auth
        );
        _validateSource(
            taskId,
            index,
            leaf.rhsSourceKind,
            leaf.rhsSourceIndex,
            leaf.rhsHandle,
            leaf.rhsInputRecord,
            rhsInputProof,
            auth
        );
    }

    function _requireDisclosurePublisher(bytes32 taskId) internal view {
        (, , , address operator, ) = game.getTaskStatus(taskId);
        if (msg.sender != operator) revert Unauthorized();
        if (
            disclosureDeadline[taskId] == 0 ||
            block.timestamp > disclosureDeadline[taskId] ||
            disputeReady[taskId]
        ) revert WrongState();
    }

    function _publishOne(
        bytes32 taskId,
        ProvenanceLeaf calldata leaf,
        bytes32[] calldata lhsInputProof,
        bytes32[] calldata rhsInputProof
    ) internal {
        uint32 index = nextDisclosureIndex[taskId];
        if (index >= authorizations[taskId].leafCount) revert WrongState();
        _validateLeafSources(taskId, index, leaf, lhsInputProof, rhsInputProof);
        _commitPublishedLeaf(taskId, index, leaf);
    }

    function _provenanceLeafHash(
        bytes32 taskId,
        uint32 leafIndex,
        bytes32 traceLeafHash,
        ProvenanceLeaf calldata leaf
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                PROVENANCE_LEAF_TYPEHASH,
                taskId,
                leafIndex,
                traceLeafHash,
                leaf.lhsHandle,
                leaf.rhsHandle,
                leaf.claimedHandle,
                leaf.lhsSourceKind,
                leaf.lhsSourceIndex,
                leaf.lhsInputRecord,
                leaf.rhsSourceKind,
                leaf.rhsSourceIndex,
                leaf.rhsInputRecord
            )
        );
    }

    function _validateSource(
        bytes32 taskId,
        uint32 leafIndex,
        uint8 sourceKind,
        uint32 sourceIndex,
        bytes32 handle,
        bytes32 inputRecord,
        bytes32[] calldata inputProof,
        TaskAuthorization storage auth
    ) internal view {
        if (sourceKind == SOURCE_AUTHENTICATED_INPUT) {
            if (
                sourceIndex >= auth.inputCount ||
                !registeredInputRecords[inputRecord] ||
                registeredInputHandles[inputRecord] != handle ||
                !_verifyIndexedProof(auth.inputRoot, inputRecord, sourceIndex, auth.inputCount, inputProof)
            ) revert BadProof();
            return;
        }
        if (sourceKind == SOURCE_PREVIOUS_OUTPUT) {
            if (
                sourceIndex >= leafIndex ||
                inputRecord != bytes32(0) ||
                inputProof.length != 0 ||
                disclosedHandles[taskId][sourceIndex].claimedHandle != handle
            ) revert InvalidParameter();
            return;
        }
        if (sourceKind == SOURCE_PUBLIC_CONSTANT) {
            // The handle IS the constant here (a public scalar is not encrypted
            // by anyone), and the program root already binds it through
            // `lhsConstant`/`rhsConstant`, so there is no separate value to
            // cross-check: the equality this branch used to assert has become
            // an identity.
            if (
                sourceIndex != 0 ||
                inputRecord != bytes32(0) ||
                inputProof.length != 0
            ) revert InvalidParameter();
            return;
        }
        revert InvalidParameter();
    }

    function _verifyIndexedProof(
        bytes32 root,
        bytes32 node,
        uint32 index,
        uint32 leafCount,
        bytes32[] calldata proof
    ) internal pure returns (bool) {
        if (proof.length != _treeDepth(leafCount)) return false;
        for (uint256 i = 0; i < proof.length; i++) {
            node = (index & 1) == 1
                ? keccak256(abi.encodePacked(proof[i], node))
                : keccak256(abi.encodePacked(node, proof[i]));
            index >>= 1;
        }
        return node == root;
    }

    function _append(
        bytes32[32] storage frontier,
        uint32 index,
        bytes32 node
    ) internal {
        uint8 level = 0;
        uint32 cursor = index;
        while ((cursor & 1) == 1) {
            node = keccak256(abi.encodePacked(frontier[level], node));
            delete frontier[level];
            cursor >>= 1;
            level += 1;
        }
        frontier[level] = node;
    }

    function _treeDepth(uint32 leafCount) internal pure returns (uint8 depth) {
        while (leafCount > 1) {
            leafCount >>= 1;
            depth += 1;
        }
    }

    function _isPowerOfTwo(uint32 value) internal pure returns (bool) {
        return value > 0 && (value & (value - 1)) == 0;
    }
}
