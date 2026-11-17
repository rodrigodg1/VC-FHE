// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal read surface of the dispute game needed by this module.
interface IDisputeGameView {
    function getTaskStatus(bytes32 taskId)
        external
        view
        returns (uint8 status, uint8 decision, bool challengeTriggered, address operator, address challenger);

    function getTaskDeadlines(bytes32 taskId)
        external
        view
        returns (uint64 commitDeadline, uint64 openDeadline, uint64 challengeDeadline);

    function getTaskResultBinding(bytes32 taskId)
        external
        view
        returns (bytes32 resultHash, bytes32 operatorTraceRoot, uint32 leafCount);

    function isAuditorAssignedToLeaf(bytes32 taskId, address auditor, uint32 leafIndex)
        external
        view
        returns (bool);

    function slashOperatorForUnavailability(bytes32 taskId, address requester) external;
}

/**
 * @title TraceAvailability
 * @notice Reveal-or-reject enforcement for specifically requested committed
 *         trace leaves in the optimistic (non-linear) verification path.
 *
 *         Fraud-proof soundness remains conditional on off-chain availability
 *         of enough trace data to locate a suspect leaf and construct a
 *         challenge. This module enforces only request-triggered leaf evidence:
 *         an auditor assigned to a stage may post a bonded request for one
 *         indexed committed leaf; the operator must publish that preimage
 *         on-chain, with Merkle inclusion, within the reveal window. An
 *         unanswered request permanently blocks optimistic finalization. Full
 *         trace recovery requires one request per leaf (O(N) requests and
 *         O(N log N) proof hashes) and is neither provided nor claimed here.
 *
 *         Bond economics: the requester's bond compensates the operator's
 *         reveal gas when the operator complies (anti-griefing) and is
 *         refunded to the requester when the operator fails to reveal.
 */
contract TraceAvailability {
    error InvalidRequest();
    error NotAssignedAuditor();
    error NotOperator();
    error WrongWindow();
    error AlreadySettled();
    error BadBond();
    error BadProof();
    error TransferFailed();

    struct RevealRequest {
        address requester;
        uint64 revealDeadline;
        uint32 leafIndex;
        bool revealed;
        bool expired;
    }

    uint8 internal constant TASK_STATUS_AUDITING = 1;
    uint256 public constant REQUEST_BOND_WEI = 0.05 ether;

    IDisputeGameView public immutable game;
    uint64 public immutable revealWindowSeconds;

    mapping(bytes32 => RevealRequest[]) internal requests;
    mapping(bytes32 => uint32) public pendingRequests;
    mapping(bytes32 => bool) public unavailabilityRecorded;

    event StageRevealRequested(
        bytes32 indexed taskId,
        uint256 indexed requestId,
        address indexed requester,
        uint32 leafIndex,
        uint64 revealDeadline
    );
    /// @dev Structure only: the operation and the three ciphertext handles the
    /// committed leaf reads and writes. A stage reveal proves the operator can
    /// still produce the committed leaf; it is not a disclosure of anybody's
    /// operand, and cannot be, since the trace leaf commits to handles.
    event StageDataRevealed(
        bytes32 indexed taskId,
        uint256 indexed requestId,
        uint32 leafIndex,
        uint8 opcode,
        bytes32 lhsHandle,
        bytes32 rhsHandle,
        bytes32 claimedHandle
    );
    event TraceUnavailable(
        bytes32 indexed taskId,
        uint256 indexed requestId,
        uint32 leafIndex
    );

    constructor(address game_, uint64 revealWindowSeconds_) {
        if (game_ == address(0) || revealWindowSeconds_ == 0) revert InvalidRequest();
        game = IDisputeGameView(game_);
        revealWindowSeconds = revealWindowSeconds_;
    }

    /// @notice True when no requested-leaf obligation is outstanding or
    ///         breached. This says nothing about unrequested trace leaves.
    function isCleared(bytes32 taskId) external view returns (bool) {
        return pendingRequests[taskId] == 0 && !unavailabilityRecorded[taskId];
    }

    function requestCount(bytes32 taskId) external view returns (uint256) {
        return requests[taskId].length;
    }

    function getRequest(bytes32 taskId, uint256 requestId)
        external
        view
        returns (RevealRequest memory)
    {
        return requests[taskId][requestId];
    }

    /// @notice Bonded stage-scoped reveal request by an assigned auditor,
    ///         open during the whole optimistic phase of the task.
    function requestReveal(bytes32 taskId, uint32 leafIndex) external payable {
        if (msg.value != REQUEST_BOND_WEI) revert BadBond();
        (uint8 status, , , , ) = game.getTaskStatus(taskId);
        if (status != TASK_STATUS_AUDITING) revert WrongWindow();
        (, , uint64 challengeDeadline) = game.getTaskDeadlines(taskId);
        // challengeDeadline == 0 means participants are not yet sampled.
        if (challengeDeadline == 0 || block.timestamp > challengeDeadline) revert WrongWindow();
        if (!game.isAuditorAssignedToLeaf(taskId, msg.sender, leafIndex)) {
            revert NotAssignedAuditor();
        }

        requests[taskId].push(
            RevealRequest({
                requester: msg.sender,
                revealDeadline: uint64(block.timestamp + revealWindowSeconds),
                leafIndex: leafIndex,
                revealed: false,
                expired: false
            })
        );
        pendingRequests[taskId] += 1;
        uint256 requestId = requests[taskId].length - 1;
        emit StageRevealRequested(
            taskId,
            requestId,
            msg.sender,
            leafIndex,
            uint64(block.timestamp + revealWindowSeconds)
        );
    }

    /// @notice Operator publishes the requested committed leaf on-chain. The
    ///         calldata itself makes the stage structure publicly available;
    ///         the Merkle proof binds it to the committed trace root. The leaf
    ///         preimage is (opcode, lhsHandle, rhsHandle, claimedHandle) --
    ///         identical to `_leafHash` in VerifiableFHEDisputeGame.sol -- so
    ///         answering a reveal request costs the operator no operand.
    function reveal(
        bytes32 taskId,
        uint256 requestId,
        uint8 opcode,
        bytes32 lhsHandle,
        bytes32 rhsHandle,
        bytes32 claimedHandle,
        bytes32[] calldata proof
    ) external {
        _checkOperator(taskId);
        RevealRequest storage request = requests[taskId][requestId];
        if (request.revealed || request.expired) revert AlreadySettled();
        _checkProof(
            taskId,
            request.leafIndex,
            keccak256(abi.encode(opcode, lhsHandle, rhsHandle, claimedHandle)),
            proof
        );

        request.revealed = true;
        pendingRequests[taskId] -= 1;
        emit StageDataRevealed(
            taskId,
            requestId,
            request.leafIndex,
            opcode,
            lhsHandle,
            rhsHandle,
            claimedHandle
        );
        _payBond(msg.sender);
    }

    function _checkOperator(bytes32 taskId) internal view {
        (, , , address operator, ) = game.getTaskStatus(taskId);
        if (msg.sender != operator) revert NotOperator();
    }

    function _checkProof(
        bytes32 taskId,
        uint32 index,
        bytes32 node,
        bytes32[] calldata proof
    ) internal view {
        (, bytes32 traceRoot, uint32 leafCount) = game.getTaskResultBinding(taskId);
        if (index >= leafCount || (uint256(1) << proof.length) != leafCount) {
            revert BadProof();
        }
        for (uint256 i = 0; i < proof.length; i++) {
            node = (index & 1) == 1
                ? keccak256(abi.encodePacked(proof[i], node))
                : keccak256(abi.encodePacked(node, proof[i]));
            index >>= 1;
        }
        if (node != traceRoot) revert BadProof();
    }

    function _payBond(address to) internal {
        (bool okTransfer, ) = payable(to).call{value: REQUEST_BOND_WEI}("");
        if (!okTransfer) revert TransferFailed();
    }

    /// @notice Records a breached reveal obligation after the deadline. The
    ///         breach is objectively attributable (bonded request, elapsed
    ///         window, no Merkle-verified reveal), so the operator is slashed
    ///         in the dispute game with the reward paid to the requester; the
    ///         task is permanently excluded from optimistic finalization and
    ///         the requester's bond is refunded. Withholding is therefore
    ///         never cheaper than losing a dispute.
    function markUnavailable(bytes32 taskId, uint256 requestId) external {
        RevealRequest storage request = requests[taskId][requestId];
        if (request.revealed || request.expired) revert AlreadySettled();
        if (block.timestamp <= request.revealDeadline) revert WrongWindow();

        request.expired = true;
        pendingRequests[taskId] -= 1;
        unavailabilityRecorded[taskId] = true;
        game.slashOperatorForUnavailability(taskId, request.requester);
        emit TraceUnavailable(taskId, requestId, request.leafIndex);
        _payBond(request.requester);
    }
}
