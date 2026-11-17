// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CanonicalFHEDisputeGame} from "./CanonicalFHEDisputeGame.sol";
import {BountyTraceAvailability} from "./BountyTraceAvailability.sol";
import {InvalidParameter, NotEligible, StateConflict, ITraceAvailability} from "./VerifiableFHEDisputeGame.sol";

/// @notice Opt-in canonical game paying only a correct, precommitted challenge.
/// @dev Versioned independently of the historical canonical game. The existing
/// authenticated trace, bisection and canonical certificate relation are unchanged.
/// A bounty certifies a successful challenge, not physical independent full replay.
/// No administrator, withdrawal of burned funds, or reward for agreement exists.
contract CanonicalBountyFHEDisputeGame is CanonicalFHEDisputeGame {
    error LegacyAuditAPIUnavailable();
    error WithdrawalFailed();
    error ReentrantWithdrawal();

    bytes32 public constant SEALED_AUDIT_TYPEHASH = keccak256(
        "FHE_BOUNTY_AUDIT_V2(uint256 chainId,address game,bytes32 taskId,address auditor,uint32 leafIndex,bytes32 podRoot,bytes32 candidateTraceRoot,bool supportsOperator,bytes32 salt)"
    );
    uint256 public immutable OPERATOR_PENALTY_WEI;
    uint256 public immutable CHALLENGE_BOUNTY_WEI;
    uint256 public constant ECONOMICS_VERSION = 1;
    uint32 public immutable MAX_TRACE_LEAVES;
    uint256 public immutable CHALLENGE_COST_BUDGET_WEI;
    uint256 public immutable MAX_DISCLOSURE_FEE_WEI;
    uint256 public totalBurnedWei;
    mapping(bytes32 => uint256) private operatorReservations;
    mapping(bytes32 => mapping(address => uint256)) private auditReservations;
    mapping(bytes32 => mapping(address => bytes32)) private candidateTraceRoots;
    mapping(bytes32 => uint64) public taskFinalizedAt;
    bool private withdrawing;

    event SealedAuditSubmitted(bytes32 indexed taskId, address indexed auditor, bytes32 commitment, uint256 reservedWei);
    event SealedAuditRevealed(bytes32 indexed taskId, address indexed auditor, uint32 leafIndex, bytes32 podRoot, bytes32 candidateTraceRoot, bool supportsOperator);
    event OperatorBondReserved(bytes32 indexed taskId, address indexed operator, uint256 amountWei);
    event AuditBondReturned(bytes32 indexed taskId, address indexed auditor, uint256 amountWei);
    event AuditBondBurned(bytes32 indexed taskId, address indexed auditor, uint256 amountWei);
    event ChallengeBondSettlement(bytes32 indexed taskId, address indexed challenger, address indexed recipient, uint256 debitWei, uint256 compensationWei, uint256 burnedWei);
    event BountySettlement(bytes32 indexed taskId, address indexed operator, address indexed recipient, uint256 operatorDebitWei, uint256 bountyWei, uint256 burnedWei);
    event ProceduralTaskRejected(bytes32 indexed taskId, address indexed operator, address indexed reporter, uint256 burnedWei);
    event StakeWithdrawn(address indexed participant, address indexed recipient, uint256 amountWei);

    constructor(
        address objectiveVerifier_,
        uint64 commitWindowSeconds_,
        uint64 openWindowSeconds_,
        uint64 challengeWindowSeconds_,
        address availability_,
        address leafDecisionVerifier_,
        uint256 operatorPenaltyWei_,
        uint256 challengeBountyWei_,
        uint32 maxTraceLeaves_,
        uint256 challengeCostBudgetWei_
    ) CanonicalFHEDisputeGame(
        objectiveVerifier_, commitWindowSeconds_, openWindowSeconds_,
        challengeWindowSeconds_, availability_, leafDecisionVerifier_
    ) {
        if (BountyTraceAvailability(availability_).RELAY_VERSION() != 2) revert InvalidParameter();
        if (!_isPowerOfTwo(maxTraceLeaves_) || challengeCostBudgetWei_ == 0) revert InvalidParameter();
        uint256 disclosureFee = BountyTraceAvailability(availability_).DISCLOSURE_REQUEST_BOND_BASE_WEI()
            + BountyTraceAvailability(availability_).DISCLOSURE_REQUEST_BOND_PER_LEAF_WEI() * maxTraceLeaves_;
        // The cost budget is a deployment assumption, not a measured price.
        // Include the separate fee even when a third party relays publication.
        // Preserve a positive coalition loss after both possible receipts.
        if (challengeBountyWei_ <= disclosureFee + challengeCostBudgetWei_ ||
            operatorPenaltyWei_ <= challengeBountyWei_ + disclosureFee) revert InvalidParameter();
        OPERATOR_PENALTY_WEI = operatorPenaltyWei_;
        CHALLENGE_BOUNTY_WEI = challengeBountyWei_;
        MAX_TRACE_LEAVES = maxTraceLeaves_;
        CHALLENGE_COST_BUDGET_WEI = challengeCostBudgetWei_;
        MAX_DISCLOSURE_FEE_WEI = disclosureFee;
    }

    function createTask(
        bytes32 taskId,
        bytes32 operatorTraceRoot,
        bytes32 resultHash,
        uint32 leafCount,
        LeafClaim calldata terminalLeaf,
        bytes32[] calldata terminalLeafProof,
        bytes32 outputAttestationHash
    ) public override {
        if (leafCount > MAX_TRACE_LEAVES) revert InvalidParameter();
        super.createTask(taskId, operatorTraceRoot, resultHash, leafCount, terminalLeaf, terminalLeafProof, outputAttestationHash);
        // The aggregate lock protects all active tasks, including cross-role
        // audit commitments. Authorization consumption rolls back if unfunded.
        _lockChallengeBond(msg.sender, OPERATOR_PENALTY_WEI);
        operatorReservations[taskId] = OPERATOR_PENALTY_WEI;
        emit OperatorBondReserved(taskId, msg.sender, OPERATOR_PENALTY_WEI);
    }

    function computeSealedAuditCommitment(
        bytes32 taskId,
        address auditor,
        uint32 leafIndex,
        bytes32 podRoot,
        bytes32 candidateTraceRoot,
        bool supportsOperator,
        bytes32 salt
    ) public view returns (bytes32) {
        return keccak256(abi.encode(SEALED_AUDIT_TYPEHASH, block.chainid, address(this),
            taskId, auditor, leafIndex, podRoot, candidateTraceRoot, supportsOperator, salt));
    }

    /// @notice Participation is voluntary. Assignment alone creates no liability.
    /// The transaction and event expose only the salted commitment, never its index.
    function submitSealedAudit(bytes32 taskId, bytes32 commitment) external {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Auditing) revert TaskNotAuditing();
        if (!task.sampled || block.timestamp > task.commitDeadline) revert WrongPhase();
        AuditRecord storage record = audits[taskId][msg.sender];
        if (!record.assigned) revert AuditorNotAssigned();
        if (record.submitted) revert StateConflict();
        if (commitment == bytes32(0)) revert InvalidParameter();
        if (participants[msg.sender].stake < MIN_AUDITOR_STAKE_WEI) revert NotEligible();
        uint256 bondWei = _requiredChallengeBond(task.leafCount);
        _lockChallengeBond(msg.sender, bondWei);
        auditReservations[taskId][msg.sender] = bondWei;
        record.submitted = true;
        record.verdictCommit = commitment;
        emit SealedAuditSubmitted(taskId, msg.sender, commitment, bondWei);
    }

    /// @notice Anyone may relay the exact opening; its owner and any eventual
    /// bounty remain the committed auditor. No opening committee is involved.
    function revealSealedAudit(
        bytes32 taskId,
        address auditor,
        uint32 leafIndex,
        bytes32 podRoot,
        bytes32 candidateTraceRoot,
        bool supportsOperator,
        bytes32 salt
    ) external {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Auditing) revert TaskNotAuditing();
        if (block.timestamp <= task.commitDeadline || block.timestamp > task.openDeadline) revert WrongPhase();
        AuditRecord storage record = audits[taskId][auditor];
        if (!record.submitted) revert AuditNotSubmitted();
        if (record.opened) revert StateConflict();
        if (!_isAuditorAssignedToLeaf(taskId, auditor, leafIndex)) revert AuditorNotAssigned();
        if (podRoot == bytes32(0) || candidateTraceRoot == bytes32(0) || salt == bytes32(0)) revert InvalidParameter();
        if (supportsOperator != (candidateTraceRoot == task.operatorTraceRoot)) revert InvalidParameter();
        if (record.verdictCommit != computeSealedAuditCommitment(taskId, auditor, leafIndex, podRoot,
                candidateTraceRoot, supportsOperator, salt)) revert InvalidParameter();
        record.opened = true;
        record.auditedLeafIndex = leafIndex;
        record.podRoot = podRoot;
        record.verdictSupportsOperator = supportsOperator;
        candidateTraceRoots[taskId][auditor] = candidateTraceRoot;
        emit SealedAuditRevealed(taskId, auditor, leafIndex, podRoot, candidateTraceRoot, supportsOperator);
        emit VerdictOpened(taskId, auditor, leafIndex, supportsOperator, podRoot);
    }

    function openChallenge(
        bytes32 taskId,
        bytes32 challengerTraceRoot,
        uint32 challengeLeafHint,
        bytes32 challengeErrorDigest,
        AuditTraceLeaf calldata auditTraceLeaf,
        bytes32[] calldata auditTraceProof,
        bool[] calldata auditTraceProofSiblingOnLeft
    ) public override {
        if (candidateTraceRoots[taskId][msg.sender] != challengerTraceRoot) revert InvalidParameter();
        super.openChallenge(taskId, challengerTraceRoot, challengeLeafHint, challengeErrorDigest,
            auditTraceLeaf, auditTraceProof, auditTraceProofSiblingOnLeft);
    }

    /// @dev Activation changes the purpose of an existing lock, never locks twice.
    function _activateChallengeBond(bytes32 taskId, address challenger, uint256 bondWei) internal override {
        if (auditReservations[taskId][challenger] != bondWei) revert NotEligible();
    }

    function _releaseChallengeBond(bytes32 taskId, bool slashBond, address recipient) internal override {
        Task storage task = tasks[taskId];
        uint256 amount = task.activeChallengeBondWei;
        if (amount == 0) return;
        if (auditReservations[taskId][task.challenger] != amount) revert StateConflict();
        delete auditReservations[taskId][task.challenger];
        Participant storage challenger = participants[task.challenger];
        challenger.lockedChallengeBondWei -= amount;
        task.activeChallengeBondWei = 0;
        if (slashBond) {
            challenger.stake -= amount;
            // A correct operator receives bounded compensation, not the entire
            // bond: a self-controlled failed challenger cannot recycle its cost.
            uint256 compensation = recipient == address(0) ? 0 : amount / 2;
            if (compensation != 0) participants[recipient].stake += compensation;
            uint256 burned = amount - compensation;
            totalBurnedWei += burned;
            emit AuditBondBurned(taskId, task.challenger, burned);
            emit ChallengeBondSettlement(taskId, task.challenger, recipient, amount, compensation, burned);
        } else {
            emit ChallengeBondReleased(taskId, task.challenger, task.challenger, amount, false);
        }
    }

    function _applyLeafDecision(bytes32 taskId, uint32 leafIndex, uint8 opcode,
        bool operatorValid, bool challengerValid, address verifier) internal override
    {
        Task storage task = tasks[taskId];
        emit LeafCheckedOnChain(taskId, leafIndex, opcode, operatorValid, challengerValid, verifier);
        if (operatorValid) {
            _releaseChallengeBond(taskId, true, task.operator);
            _reopenAfterLostChallenge(taskId, leafIndex);
            return;
        }
        // A false candidate cannot exonerate the operator, collect a bounty, or
        // recover its challenge bond. Only a certified correct candidate wins.
        _releaseChallengeBond(taskId, !challengerValid, challengerValid ? task.challenger : address(0));
        _settleOperatorBond(taskId, challengerValid ? task.challenger : address(0), challengerValid ? CHALLENGE_BOUNTY_WEI : 0);
        task.status = TaskStatus.Finalized;
        task.decision = FinalDecision.OperatorSlashed;
        taskFinalizedAt[taskId] = uint64(block.timestamp);
        emit TaskResolved(taskId, task.decision, challengerValid ? task.challenger : address(0));
    }

    /// @dev The debit was reserved at creation. Its excess over the bounty is
    /// removed from all spendable balances and has no recovery/withdrawal route.
    function _settleOperatorBond(bytes32 taskId, address recipient, uint256 bountyWei) private {
        uint256 amount = operatorReservations[taskId];
        if (amount != OPERATOR_PENALTY_WEI || bountyWei > CHALLENGE_BOUNTY_WEI) revert StateConflict();
        delete operatorReservations[taskId];
        Participant storage operator = participants[tasks[taskId].operator];
        operator.lockedChallengeBondWei -= amount;
        operator.stake -= amount;
        if (bountyWei != 0) participants[recipient].stake += bountyWei;
        uint256 burned = amount - bountyWei;
        totalBurnedWei += burned;
        emit BountySettlement(taskId, tasks[taskId].operator, recipient, amount, bountyWei, burned);
    }

    /// @dev Procedural nonresponse rejects the task but earns no computation bounty.
    function _rejectOperatorForProcedure(bytes32 taskId) private {
        Task storage task = tasks[taskId];
        _releaseChallengeBond(taskId, false, task.challenger);
        _settleOperatorBond(taskId, address(0), 0);
        task.status = TaskStatus.Finalized;
        task.decision = FinalDecision.OperatorSlashed;
        taskFinalizedAt[taskId] = uint64(block.timestamp);
        delete pendingFhevmLeafResolutions[taskId];
        delete bisectionRounds[taskId];
    }

    function timeoutDispute(bytes32 taskId) external override {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Challenged) revert TaskNotChallenged();
        if (block.timestamp <= task.disputeProgressDeadline) revert WrongPhase();
        if (!ITraceAvailability(availabilityModule).isDisputeReady(taskId)) revert WrongPhase();
        if (task.disputeEnd - task.disputeStart <= 1) {
            // Certificate outage after authenticated admission is not evidence
            // against either party and cannot pay a computational bounty.
            if (pendingFhevmLeafResolutions[taskId].active) revert WrongPhase();
            _releaseChallengeBond(taskId, true, task.operator);
            emit DisputeTimedOut(taskId, task.challenger, FinalDecision.ChallengerSlashed);
            _reopenAfterLostChallenge(taskId, task.challengeLeafHint);
            return;
        }
        BisectionProposal storage proposal = bisectionRounds[taskId];
        if (proposal.operatorSubmitted && proposal.challengerSubmitted) revert WrongPhase();
        if (!proposal.challengerSubmitted) {
            _releaseChallengeBond(taskId, true, task.operator);
            emit DisputeTimedOut(taskId, task.challenger, FinalDecision.ChallengerSlashed);
            _reopenAfterLostChallenge(taskId, task.challengeLeafHint);
        } else {
            _rejectOperatorForProcedure(taskId);
            emit DisputeTimedOut(taskId, task.operator, FinalDecision.OperatorSlashed);
        }
        delete bisectionRounds[taskId];
    }

    function slashOperatorForUnavailability(bytes32 taskId, address requester) external override {
        if (msg.sender != availabilityModule) revert NotEligible();
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Auditing && task.status != TaskStatus.Challenged) revert StateConflict();
        _rejectOperatorForProcedure(taskId);
        emit ProceduralTaskRejected(taskId, task.operator, requester, OPERATOR_PENALTY_WEI);
        emit TaskResolved(taskId, task.decision, requester);
    }

    function finalizeUnchallenged(bytes32 taskId) public override {
        super.finalizeUnchallenged(taskId);
        uint256 amount = operatorReservations[taskId];
        if (amount != OPERATOR_PENALTY_WEI) revert StateConflict();
        delete operatorReservations[taskId];
        participants[tasks[taskId].operator].lockedChallengeBondWei -= amount;
        taskFinalizedAt[taskId] = uint64(block.timestamp);
    }

    /// @notice Releases a losing-race or unchallenged audit's own deposit only.
    /// Early operator rejection also releases unopened commitments because the
    /// task closed before their reveal opportunity ended.
    function claimAuditBond(bytes32 taskId) external {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Finalized) revert StateConflict();
        AuditRecord storage record = audits[taskId][msg.sender];
        if (!record.opened && taskFinalizedAt[taskId] > task.openDeadline) revert NotEligible();
        uint256 amount = auditReservations[taskId][msg.sender];
        if (amount == 0) revert NotEligible();
        delete auditReservations[taskId][msg.sender];
        participants[msg.sender].lockedChallengeBondWei -= amount;
        emit AuditBondReturned(taskId, msg.sender, amount);
    }

    /// @notice Only voluntarily committed, unfulfilled opening duties are penalized.
    /// Assignment alone, correct agreement and losing a race carry no penalty.
    function slashLazyAuditor(bytes32 taskId, address auditor) external override {
        Task storage task = tasks[taskId];
        if (block.timestamp <= task.openDeadline) revert WrongPhase();
        if (task.status == TaskStatus.Finalized && taskFinalizedAt[taskId] <= task.openDeadline) revert NotEligible();
        AuditRecord storage record = audits[taskId][auditor];
        uint256 amount = auditReservations[taskId][auditor];
        if (!record.submitted || record.opened || amount == 0) revert NotEligible();
        delete auditReservations[taskId][auditor];
        record.lazySlashed = true;
        participants[auditor].lockedChallengeBondWei -= amount;
        participants[auditor].stake -= amount;
        totalBurnedWei += amount;
        emit AuditBondBurned(taskId, auditor, amount);
        emit LazyAuditorSlashed(taskId, auditor, address(0), amount);
    }

    function getAuditReservation(bytes32 taskId, address auditor) external view returns (uint256) {
        return auditReservations[taskId][auditor];
    }

    function getOperatorReservation(bytes32 taskId) external view returns (uint256) {
        return operatorReservations[taskId];
    }

    /// @dev Full replay auditors can challenge any leaf. Sampling the task's
    /// cohort does not partition computation or reveal a narrow fault location.
    function _stageAuditorCohortSize(uint256 assignedAuditorCount, uint32)
        internal pure override returns (uint256)
    {
        return assignedAuditorCount;
    }

    function _requiresOpeningParticipants() internal pure override returns (bool) { return false; }
    function _assignDecryptors(bytes32, bytes32) internal pure override {}

    // Branches already authenticate against the current committed node. Relaying
    // either side cannot change its claim or the recorded bounty beneficiary.
    function _canSubmitBisection(bytes32, address, bool) internal pure override returns (bool) {
        return true;
    }

    /// @notice One forced disclosure leaves a complete commit/replay window
    /// after its latest permitted publication, even for a last-moment request.
    function extendDeadlinesForDisclosure(bytes32 taskId, uint64 extensionSeconds) external override {
        if (msg.sender != availabilityModule) revert NotEligible();
        Task storage task = tasks[taskId];
        if (!task.sampled) revert WrongPhase();
        if (task.status == TaskStatus.Challenged) {
            task.disputeProgressDeadline += extensionSeconds;
            return;
        }
        if (task.status != TaskStatus.Auditing || block.timestamp > task.commitDeadline) revert WrongPhase();
        uint256 windows = windowConfigPacked;
        task.commitDeadline = uint64(block.timestamp) + extensionSeconds + uint64(windows);
        task.openDeadline = task.commitDeadline + uint64(windows >> 64);
        task.challengeDeadline = task.openDeadline + uint64(windows >> 128);
        emit TaskDeadlinesExtended(taskId, extensionSeconds, task.challengeDeadline);
    }

    /// @notice Tops up a registered participant without changing its role(s).
    function depositStake() external payable {
        Participant storage participant = participants[msg.sender];
        if (msg.value == 0 || !(participant.isOperator || participant.isAuditor || participant.isDecryptor)) revert NotEligible();
        participant.stake += msg.value;
    }

    /// @notice Withdraws unreserved excess. The role-registration floor remains
    /// because immutable task candidate snapshots still contain this identity.
    /// This is not a full role-retirement or full-exit interface.
    function withdraw(uint256 amountWei, address payable recipient) external {
        if (withdrawing) revert ReentrantWithdrawal();
        Participant storage participant = participants[msg.sender];
        uint256 floor = participant.isOperator ? MIN_OPERATOR_STAKE_WEI :
            (participant.isAuditor || participant.isDecryptor ? MIN_AUDITOR_STAKE_WEI : 0);
        if (recipient == address(0) || amountWei == 0 || amountWei > _availableStake(participant) ||
            participant.stake - amountWei < floor) revert NotEligible();
        withdrawing = true;
        participant.stake -= amountWei;
        (bool sent, ) = recipient.call{value: amountWei}("");
        if (!sent) revert WithdrawalFailed();
        withdrawing = false;
        emit StakeWithdrawn(msg.sender, recipient, amountWei);
    }

    // Unsupported APIs are compile-time overrides, not alternative admission or
    // payment paths. This also removes their runtime code in this new version.
    function registerDecryptor() external payable override { revert LegacyAuditAPIUnavailable(); }
    function submitAudit(bytes32, uint32, bytes32, bytes32) external pure override { revert LegacyAuditAPIUnavailable(); }
    function openVerdict(bytes32, address, bool, bytes32, bytes32) external pure override { revert LegacyAuditAPIUnavailable(); }
    function openVerdictViaKMS(bytes32, address, bytes32, bytes calldata, bytes calldata) external pure override { revert LegacyAuditAPIUnavailable(); }
    function claimDiligenceReward(bytes32, AuditDiligenceCheckpoint calldata, bytes32[] calldata, bool[] calldata) external pure override { revert LegacyAuditAPIUnavailable(); }
    function resolveLeafDispute(bytes32, LeafClaim calldata, LeafClaim calldata) external pure override { revert InvalidFhevmVerifierMode(); }
    function requestFhevmLeafResolution(bytes32, LeafClaim calldata, LeafClaim calldata, CiphertextLeafWitness calldata) external pure override { revert InvalidFhevmVerifierMode(); }
    function finalizeFhevmLeafResolution(bytes32, bool, bool, bytes calldata) external pure override { revert InvalidFhevmVerifierMode(); }
    function _slashWrongVerdictAuditors(bytes32, uint32, bool, address, address) internal pure override {}
}
