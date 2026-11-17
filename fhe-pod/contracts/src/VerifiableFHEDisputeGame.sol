// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UniformParticipantSampler} from "./UniformParticipantSampler.sol";

interface ITraceAvailability {
    function isCleared(bytes32 taskId) external view returns (bool);

    function isRegisteredInputHandle(bytes32 handle) external view returns (bool);

    function consumeTaskAuthorization(
        bytes32 taskId,
        address operator,
        bytes32 traceRoot,
        bytes32 resultHash,
        uint32 leafCount,
        bytes32 outputAttestationHash
    ) external;

    function openDisputeTrace(bytes32 taskId) external;

    function isDisputeReady(bytes32 taskId) external view returns (bool);

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
        );
}

error InvalidParameter();
error StateConflict();
error NotEligible();

/// @notice Threshold-KMS decryption verifier (see ZamaKMSVerdictVerifier.sol):
/// accepts when >= t+1 distinct registered KMS core identities signed the
/// EIP-712 struct PublicDecryptVerification(ctHandles, decryptedResult,
/// extraData) produced by a real Zama KMS public decryption.
interface IKMSVerdictVerifier {
    function verifyDecryptionEIP712KMSSignatures(
        bytes32[] memory handlesList,
        bytes memory decryptedResult,
        bytes memory decryptionProof
    ) external view returns (bool);
}

interface IObjectiveMicroVerifier {
    function verifyLeaf(
        uint8 opcode,
        uint256 lhs,
        uint256 rhs,
        uint256 claimed
    ) external view returns (bool);

    function verifyTerminalOutputBinding(
        bytes32 taskId,
        bytes32 operatorTraceRoot,
        bytes32 resultHash,
        uint32 leafCount,
        uint8 terminalOpcode,
        bytes32 terminalLhsHandle,
        bytes32 terminalRhsHandle,
        bytes32 terminalClaimedHandle,
        bytes32[] calldata terminalLeafProof,
        bytes32 outputAttestationHash
    ) external pure returns (bytes32 terminalLeafHash);
}

interface IFhevmObjectiveMicroVerifier {
    /// @dev Handles only. Nothing in this struct is a cleartext operand: the
    /// backend loads each operand from its ciphertext handle and recomputes the
    /// leaf homomorphically.
    struct LeafPair {
        uint8 opcode;
        bytes32 lhsHandle;
        bytes32 rhsHandle;
        bytes32 operatorClaimedHandle;
        bytes32 challengerClaimedHandle;
        uint8 lhsSourceKind;
        uint8 rhsSourceKind;
        bytes lhsInputProof;
        bytes rhsInputProof;
        bytes operatorClaimedProof;
        bytes challengerClaimedProof;
    }

    function requestLeafCheck(
        bytes32 taskId,
        uint32 leafIndex,
        LeafPair calldata pair
    ) external returns (bytes32 operatorValidHandle, bytes32 challengerValidHandle);

    function finalizeLeafCheck(
        bytes32 taskId,
        uint32 leafIndex,
        bytes32 operatorValidHandle,
        bytes32 challengerValidHandle,
        bool operatorValid,
        bool challengerValid,
        bytes calldata decryptionProof
    ) external returns (bool, bool);
}

/// @notice PoC deterministic micro-verifier.
/// @dev This verifier intentionally checks only one disputed micro-instruction,
/// and it is the CLEAR-ARITHMETIC fallback: it re-executes the opcode natively
/// in the EVM. It is reachable only when no FHEVM backend is configured and
/// secure-trace mode is off (see `resolveLeafDispute`), i.e. exactly the
/// deployment where handles are the legacy clear-value encoding and no
/// confidentiality is claimed.
contract ObjectiveMicroVerifier is IObjectiveMicroVerifier {
    error OutputBindingInvalid();

    /// @notice Domain-separated derivation of an output-bound result commitment.
    /// @dev V2 binds the terminal output HANDLE. The trace leaf commits to
    /// ciphertext handles, so the terminal leaf carries no clear value to bind;
    /// and a chain adjudicating encrypted execution cannot read the plaintext
    /// output in any case. A consumer verifies that the ciphertext it received
    /// hashes to this handle and decrypts it under its own authorization.
    bytes32 public constant OUTPUT_BINDING_TYPEHASH =
        keccak256(
            "FHE_POD_OUTPUT_BINDING_V2(bytes32 taskId,bytes32 operatorTraceRoot,uint32 leafCount,bytes32 terminalOutputHandle,bytes32 outputAttestationHash)"
        );

    /// @notice Canonical output-bound result commitment. Consumers recompute
    /// this from the published output handle and the on-chain trace root to
    /// verify that a published result matches the committed execution trace.
    function computeBoundResultHash(
        bytes32 taskId,
        bytes32 operatorTraceRoot,
        uint32 leafCount,
        bytes32 terminalOutputHandle,
        bytes32 outputAttestationHash
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    OUTPUT_BINDING_TYPEHASH,
                    taskId,
                    operatorTraceRoot,
                    leafCount,
                    terminalOutputHandle,
                    outputAttestationHash
                )
            );
    }

    /// @notice Objective check that a published result commitment is bound to
    /// the terminal leaf of the committed trace.
    /// @dev The terminal leaf must be proven to be the LAST leaf of
    /// `operatorTraceRoot`. The proof shape pins the position: for leaf index
    /// leafCount-1 every Merkle sibling lies on the left, so a
    /// fixed-orientation fold of length log2(leafCount) can only verify the
    /// terminal leaf. Reverts with OutputBindingInvalid on any mismatch.
    function verifyTerminalOutputBinding(
        bytes32 taskId,
        bytes32 operatorTraceRoot,
        bytes32 resultHash,
        uint32 leafCount,
        uint8 terminalOpcode,
        bytes32 terminalLhsHandle,
        bytes32 terminalRhsHandle,
        bytes32 terminalClaimedHandle,
        bytes32[] calldata terminalLeafProof,
        bytes32 outputAttestationHash
    ) external pure override returns (bytes32 terminalLeafHash) {
        uint256 expectedDepth = 0;
        uint32 width = leafCount;
        while (width > 1) {
            width >>= 1;
            expectedDepth += 1;
        }
        if (
            outputAttestationHash == bytes32(0) ||
            terminalLeafProof.length != expectedDepth
        ) {
            revert OutputBindingInvalid();
        }

        terminalLeafHash = keccak256(
            abi.encode(
                terminalOpcode,
                terminalLhsHandle,
                terminalRhsHandle,
                terminalClaimedHandle
            )
        );
        bytes32 computed = terminalLeafHash;
        for (uint256 i = 0; i < terminalLeafProof.length; i++) {
            // Sibling always on the left pins the leaf to index leafCount-1.
            computed = keccak256(abi.encodePacked(terminalLeafProof[i], computed));
        }
        if (
            computed != operatorTraceRoot ||
            resultHash !=
            computeBoundResultHash(
                taskId,
                operatorTraceRoot,
                leafCount,
                terminalClaimedHandle,
                outputAttestationHash
            )
        ) {
            revert OutputBindingInvalid();
        }
    }

    uint8 public constant OPCODE_MUL = 1;
    uint8 public constant OPCODE_SHR = 2;
    uint8 public constant OPCODE_CAST_U8 = 3;
    uint8 public constant OPCODE_MIN = 4;
    uint8 public constant OPCODE_BITAND = 5;
    uint8 public constant OPCODE_ADD = 6;
    uint8 public constant OPCODE_SUB = 7;
    uint8 public constant OPCODE_DIV = 8;
    uint8 public constant OPCODE_MOD = 9;
    uint8 public constant OPCODE_EQ = 10;
    uint8 public constant OPCODE_LT = 11;
    uint8 public constant OPCODE_GT = 12;
    uint8 public constant OPCODE_BITOR = 13;
    uint8 public constant OPCODE_BITXOR = 14;
    uint8 public constant OPCODE_ADD_CHAIN = 15;
    uint256 public constant MAX_COMPOUND_OPS = 8;

    function verifyLeaf(
        uint8 opcode,
        uint256 lhs,
        uint256 rhs,
        uint256 claimed
    ) external pure override returns (bool) {
        if (
            lhs > type(uint64).max ||
            rhs > type(uint64).max ||
            claimed > type(uint64).max
        ) return false;
        if (opcode == OPCODE_MUL) {
            if (rhs != 0 && lhs > type(uint64).max / rhs) return false;
            return claimed == lhs * rhs;
        }
        if (opcode == OPCODE_SHR) {
            if (rhs >= 64) return false;
            return claimed == (lhs >> rhs);
        }
        if (opcode == OPCODE_CAST_U8) {
            return claimed == uint256(uint8(lhs));
        }
        if (opcode == OPCODE_MIN) {
            return claimed == (lhs < rhs ? lhs : rhs);
        }
        if (opcode == OPCODE_BITAND) {
            return claimed == (lhs & rhs);
        }
        if (opcode == OPCODE_ADD) {
            if (lhs > type(uint64).max - rhs) return false;
            return claimed == lhs + rhs;
        }
        if (opcode == OPCODE_SUB) {
            return lhs >= rhs && claimed == lhs - rhs;
        }
        if (opcode == OPCODE_DIV) {
            return rhs != 0 && claimed == lhs / rhs;
        }
        if (opcode == OPCODE_MOD) {
            return rhs != 0 && claimed == lhs % rhs;
        }
        if (opcode == OPCODE_EQ) {
            return claimed == (lhs == rhs ? 1 : 0);
        }
        if (opcode == OPCODE_LT) {
            return claimed == (lhs < rhs ? 1 : 0);
        }
        if (opcode == OPCODE_GT) {
            return claimed == (lhs > rhs ? 1 : 0);
        }
        if (opcode == OPCODE_BITOR) {
            return claimed == (lhs | rhs);
        }
        if (opcode == OPCODE_BITXOR) {
            return claimed == (lhs ^ rhs);
        }
        if (opcode == OPCODE_ADD_CHAIN) {
            if (
                rhs == 0 ||
                rhs > MAX_COMPOUND_OPS ||
                lhs > type(uint64).max - rhs
            ) return false;
            uint256 expected = lhs;
            for (uint256 i = 0; i < rhs; i++) {
                expected += 1;
            }
            return claimed == expected;
        }
        return false;
    }
}

/// @notice PoD + dispute game + on-chain objective finality for FHE auditing.
/// @dev Auditors provide diligence artifacts and can trigger disputes, but the
/// final decision does not depend on majority voting.
abstract contract VerifiableFHEDisputeGame {
    error InvalidFhevmVerifierMode();
    // Compact custom errors keep the runtime under the EIP-170 limit while
    // preserving distinguishable revert causes for tooling.
    error TaskNotAuditing();
    error TaskNotChallenged();
    error WrongPhase();
    error AuditorNotAssigned();
    error AuditNotSubmitted();
    error LeafStageReached();
    error DiligenceRandomnessMissing();

    enum TaskStatus {
        None,
        Auditing,
        Challenged,
        Finalized
    }

    enum FinalDecision {
        None,
        OperatorAccepted,
        OperatorSlashed,
        ChallengerSlashed
    }

    struct Participant {
        uint256 stake;
        uint256 lockedChallengeBondWei;
        bool isOperator;
        bool isAuditor;
        bool isDecryptor;
    }

    struct Task {
        address operator;
        address challenger;
        bytes32 resultHash;
        bytes32 operatorTraceRoot;
        bytes32 challengerTraceRoot;
        bytes32 currentOperatorNode;
        bytes32 currentChallengerNode;
        bytes32 challengeErrorDigest;
        bytes32 challengePodRoot;
        bytes32 diligenceSeed;
        uint32 leafCount;
        uint32 disputeStart;
        uint32 disputeEnd;
        uint32 challengeLeafHint;
        bytes32 challengeAuditLeafHash;
        uint64 commitDeadline;
        uint64 openDeadline;
        uint64 challengeDeadline;
        uint32 threshold;
        uint256 activeChallengeBondWei;
        TaskStatus status;
        FinalDecision decision;
        bool challengeTriggered;
        uint64 sampleBlock;
        bool sampled;
        /// Number of times the seed block was rescheduled (bounded by
        /// MAX_SEED_RESCHEDULES so the cohort cannot be redrawn indefinitely).
        uint8 seedReschedules;
        uint64 disputeProgressDeadline;
        // Set when a challenge was lost and the task returned to Auditing:
        // dissenting verdicts at that leaf are slashed only if the task then
        // finalizes as accepted, so a sham challenge cannot slash a diligent
        // dissenter that has not challenged yet.
        bool hasLostChallenge;
        uint32 lostChallengeLeaf;
        // The pools only append. These lengths fix the eligible prefixes for
        // the lifetime of the task, including expired-block rescheduling.
        uint256 auditorPoolSizeAtCommit;
        uint256 decryptorPoolSizeAtCommit;
    }

    struct AuditRecord {
        bool assigned;
        bool submitted;
        bool opened;
        bool diligenceProven;
        bool diligenceRewardClaimed;
        bool verdictSupportsOperator;
        bool lazySlashed;
        bool wrongVerdictSlashed;
        bool challengeSpent;
        uint32 auditedLeafIndex;
        uint32 diligenceLeafIndex;
        bytes32 podRoot;
        bytes32 verdictCommit;
        bytes32 diligenceCheckpointHash;
        bytes32 diligenceOperatorLeafHash;
        bytes32 diligenceRecomputedLeafHash;
    }

    struct BisectionProposal {
        bytes32 operatorLeft;
        bytes32 operatorRight;
        bool operatorSubmitted;
        bytes32 challengerLeft;
        bytes32 challengerRight;
        bool challengerSubmitted;
    }

    /// @notice One trace leaf as the protocol commits to it: the operation and
    /// the three ciphertext handles it reads and writes.
    /// @dev No cleartext operand. The trace root is what bisection walks, so
    /// whatever this tuple contains is what the terminal round must publish;
    /// while it carried (lhs, rhs, claimed) the end of every dispute leaked the
    /// disputed operands. The FHEVM backend re-executes the leaf from these
    /// handles, so the loss of the openings costs the adjudication nothing.
    struct LeafClaim {
        uint8 opcode;
        bytes32 lhsHandle;
        bytes32 rhsHandle;
        bytes32 claimedHandle;
    }

    /// @dev Ciphertext input proofs for the four handles of a terminal leaf.
    /// The challenger's claimed handle is not repeated here: it is part of the
    /// challenger's own LeafClaim, which the bisection has already pinned to
    /// its committed trace root.
    struct CiphertextLeafWitness {
        bytes lhsInputProof;
        bytes rhsInputProof;
        bytes operatorClaimedProof;
        bytes challengerClaimedProof;
    }

    struct AuditTraceLeaf {
        uint32 leafIndex;
        bytes32 operatorLeafHash;
        bytes32 recomputedLeafHash;
        bytes32 errorDigest;
    }

    struct AuditDiligenceCheckpoint {
        uint32 leafIndex;
        uint32 checkpointIndex;
        bytes32 operatorLeafHash;
        bytes32 recomputedLeafHash;
        bytes32 previousCheckpointHash;
        bytes32 nextCheckpointHash;
        bytes32 transcriptDigest;
    }

    struct PendingFhevmLeafResolution {
        bool active;
        address verifier;
        uint8 opcode;
        uint32 leafIndex;
        // A request that is not finalized by this timestamp may be replaced by
        // the other party, so no single request can pin the terminal round.
        uint64 replaceableAfter;
        bytes32 operatorValidHandle;
        bytes32 challengerValidHandle;
    }

    uint256 public constant MIN_OPERATOR_STAKE_WEI = 2 ether;
    uint256 public constant MIN_AUDITOR_STAKE_WEI = 1 ether;
    uint256 public constant MIN_DECRYPTOR_STAKE_WEI = 1 ether;
    uint256 public constant SLASH_AMOUNT_WEI = 0.5 ether;
    uint256 public constant DILIGENCE_REWARD_WEI = 0.05 ether;
    uint256 public constant DISPUTE_BOND_BASE_WEI = 0.2 ether;
    /// @notice Maximum number of times the sampling seed block may be
    /// rescheduled after ageing out of the EVM's 256-block hash horizon.
    uint8 public constant MAX_SEED_RESCHEDULES = 3;
    uint256 public constant DISPUTE_BOND_PER_ROUND_WEI = 0.1 ether;
    // Packed deployment configuration keeps the runtime below EIP-170's
    // 24,576-byte limit while allowing chain-specific timing windows.
    uint256 internal windowConfigPacked;
    uint32 public constant THRESHOLD_SHARES = 2;
    uint32 public constant AUDITOR_SAMPLE_SIZE = 3;
    uint32 public constant STAGE_AUDITOR_SAMPLE_SIZE = 2;
    uint32 public constant DECRYPTOR_SAMPLE_SIZE = 3;
    uint32 public constant DILIGENCE_CHECKPOINT_SPACE = 7;
    /// @dev V3 states the accusation over ciphertext handles: which leaf, and
    /// the two competing result ciphertexts. Still binding (a handle is a
    /// collision-resistant commitment to a ciphertext) and still recomputed
    /// here from the terminal LeafClaim pair, but an auditor no longer has to
    /// publish anybody's data to accuse.
    bytes32 public constant CHALLENGE_ERROR_TYPEHASH =
        keccak256(
            "FHE_POD_CHALLENGE_V3(bytes32 taskId,uint32 leafIndex,uint8 opcode,bytes32 operatorLhsHandle,bytes32 operatorRhsHandle,bytes32 operatorClaimedHandle,bytes32 challengerLhsHandle,bytes32 challengerRhsHandle,bytes32 challengerClaimedHandle)"
        );
    bytes32 public constant DILIGENCE_CHECKPOINT_TYPEHASH =
        keccak256(
            "FHE_POD_DILIGENCE_CHECKPOINT_V1(bytes32 taskId,address auditor,bytes32 operatorTraceRoot,uint32 leafIndex,uint32 checkpointIndex,bytes32 operatorLeafHash,bytes32 recomputedLeafHash,bytes32 previousCheckpointHash,bytes32 nextCheckpointHash,bytes32 transcriptDigest)"
        );
    UniformParticipantSampler public immutable participantSampler;
    bool public immutable secureTraceMode;
    address public availabilityModule;
    IObjectiveMicroVerifier public immutable objectiveVerifier;
    IFhevmObjectiveMicroVerifier public fhevmVerifier;
    /// @notice Optional threshold-KMS backend for verdict opening. When set,
    /// an audit whose `verdictCommit` is the bytes32 handle of a TFHE `ebool`
    /// ciphertext (encrypted under the KMS threshold key) can be opened by
    /// anyone through `openVerdictViaKMS` with the KMS cores' EIP-712
    /// signatures over the public-decryption result, instead of the
    /// commit-reveal committee path of `openVerdict`.
    address public kmsVerdictVerifier;
    /// @notice Threshold-KMS backend that attests LEAF DECISIONS. Same contract
    /// type and same t+1 rule as `kmsVerdictVerifier`; a separate slot because
    /// the two roles are configured independently (verdict opening keeps a
    /// commit-reveal fallback, leaf settlement over real ciphertext handles
    /// does not).
    address public leafDecisionVerifier;

    mapping(address => Participant) internal participants;
    address[] public auditorPool;
    address[] public decryptorPool;

    mapping(bytes32 => Task) internal tasks;
    mapping(bytes32 => address[]) private taskAuditors;
    mapping(bytes32 => address[]) private taskDecryptors;
    mapping(bytes32 => mapping(address => AuditRecord)) internal audits;
    mapping(bytes32 => mapping(address => bool)) private decryptorAssignedToTask;
    mapping(bytes32 => mapping(address => mapping(address => bool)))
        private decryptorOpenedAudit;
    mapping(bytes32 => uint256) private openingCounts;
    mapping(bytes32 => BisectionProposal) internal bisectionRounds;
    mapping(bytes32 => PendingFhevmLeafResolution) internal pendingFhevmLeafResolutions;

    event FhevmLeafResolutionRequested(
        bytes32 indexed taskId,
        uint32 indexed leafIndex,
        uint8 opcode,
        bytes32 operatorValidHandle,
        bytes32 challengerValidHandle
    );
    event FhevmLeafResolutionFinalized(
        bytes32 indexed taskId,
        uint32 indexed leafIndex,
        uint8 opcode,
        bool operatorValid,
        bool challengerValid
    );
    event OperatorRegistered(address indexed operator, uint256 stake);
    event AuditorRegistered(address indexed auditor, uint256 stake);
    event DecryptorRegistered(address indexed decryptor, uint256 stake);
    event TaskCreated(
        bytes32 indexed taskId,
        address indexed operator,
        bytes32 operatorTraceRoot,
        uint32 leafCount
    );
    event TerminalOutputBound(
        bytes32 indexed taskId,
        bytes32 terminalLeafHash,
        bytes32 terminalOutputHandle,
        bytes32 outputAttestationHash,
        bytes32 resultHash
    );
    event AuditSubmitted(
        bytes32 indexed taskId,
        address indexed auditor,
        uint32 indexed auditedLeafIndex,
        bytes32 podRoot,
        bytes32 verdictCommit
    );
    event VerdictOpened(
        bytes32 indexed taskId,
        address indexed auditor,
        uint32 indexed auditedLeafIndex,
        bool verdictSupportsOperator,
        bytes32 podRoot
    );
    event AuditDiligenceProven(
        bytes32 indexed taskId,
        address indexed auditor,
        uint32 indexed auditedLeafIndex,
        uint32 checkpointIndex,
        bytes32 checkpointHash
    );
    event DiligenceRewardClaimed(
        bytes32 indexed taskId,
        address indexed auditor,
        uint32 indexed auditedLeafIndex,
        uint256 amount
    );
    event DiligenceRandomnessSealed(
        bytes32 indexed taskId,
        bytes32 diligenceSeed
    );
    event ChallengeOpened(
        bytes32 indexed taskId,
        address indexed challenger,
        bytes32 challengerTraceRoot,
        uint32 challengeLeafHint,
        bytes32 challengeErrorDigest,
        bytes32 challengePodRoot
    );
    event ChallengeBondLocked(
        bytes32 indexed taskId,
        address indexed challenger,
        uint256 bondWei
    );
    event ChallengeBondReleased(
        bytes32 indexed taskId,
        address indexed challenger,
        address indexed recipient,
        uint256 bondWei,
        bool slashed
    );
    event DisputeBisected(
        bytes32 indexed taskId,
        uint32 nextStart,
        uint32 nextEnd,
        bytes32 operatorNode,
        bytes32 challengerNode
    );
    event TraceWithholdingSlashed(
        bytes32 indexed taskId,
        address indexed operator,
        address indexed requester,
        uint256 amount
    );
    event TaskDeadlinesExtended(bytes32 indexed taskId, uint64 extensionSeconds, uint64 challengeDeadline);
    event ChallengeLost(bytes32 indexed taskId, address indexed challenger, uint32 leafIndex);
    event DisputeTimedOut(
        bytes32 indexed taskId,
        address indexed defaulter,
        FinalDecision decision
    );
    event ParticipantsSampled(
        bytes32 indexed taskId,
        bytes32 seed,
        uint64 sampleBlock
    );
    event TaskResolved(
        bytes32 indexed taskId,
        FinalDecision decision,
        address indexed winner
    );
    event LazyAuditorSlashed(
        bytes32 indexed taskId,
        address indexed auditor,
        address indexed reporter,
        uint256 amount
    );
    event WrongVerdictAuditorSlashed(
        bytes32 indexed taskId,
        address indexed auditor,
        address indexed reporter,
        uint256 amount
    );
    event LeafCheckedOnChain(
        bytes32 indexed taskId,
        uint32 indexed leafIndex,
        uint8 opcode,
        bool operatorValid,
        bool challengerValid,
        address verifier
    );

    /// @dev The experiment's security claims apply only when `secureTraceMode_` is
    /// true. The false value is retained solely for legacy regression tests and
    /// must not be used for a security-critical deployment.
    constructor(
        address objectiveVerifier_,
        uint64 commitWindowSeconds_,
        uint64 openWindowSeconds_,
        uint64 challengeWindowSeconds_,
        bool secureTraceMode_
    ) {
        require(objectiveVerifier_ != address(0), "bad verifier");
        require(commitWindowSeconds_ > 0, "bad commit window");
        require(openWindowSeconds_ > 0, "bad open window");
        require(challengeWindowSeconds_ > 0, "bad challenge window");
        participantSampler = new UniformParticipantSampler();
        secureTraceMode = secureTraceMode_;
        objectiveVerifier = IObjectiveMicroVerifier(objectiveVerifier_);
        windowConfigPacked =
            uint256(commitWindowSeconds_) |
            (uint256(openWindowSeconds_) << 64) |
            (uint256(challengeWindowSeconds_) << 128);
    }

    function COMMIT_WINDOW_SECONDS() external view returns (uint64) {
        return uint64(windowConfigPacked);
    }

    function OPEN_WINDOW_SECONDS() external view returns (uint64) {
        return uint64(windowConfigPacked >> 64);
    }

    function CHALLENGE_WINDOW_SECONDS() external view returns (uint64) {
        return uint64(windowConfigPacked >> 128);
    }

    function registerOperator() external payable {
        if (!(msg.value >= MIN_OPERATOR_STAKE_WEI)) revert NotEligible(); // was: operator stake too low
        Participant storage participant = participants[msg.sender];
        participant.stake += msg.value;
        participant.isOperator = true;
        emit OperatorRegistered(msg.sender, participant.stake);
    }

    function registerAuditor() external payable {
        if (!(msg.value >= MIN_AUDITOR_STAKE_WEI)) revert NotEligible(); // was: auditor stake too low
        Participant storage participant = participants[msg.sender];
        bool newAuditor = !participant.isAuditor;
        participant.stake += msg.value;
        participant.isAuditor = true;
        if (newAuditor) {
            auditorPool.push(msg.sender);
        }
        emit AuditorRegistered(msg.sender, participant.stake);
    }

    function registerDecryptor() external payable virtual {
        if (!(msg.value >= MIN_DECRYPTOR_STAKE_WEI)) revert NotEligible(); // was: decryptor stake too low
        Participant storage participant = participants[msg.sender];
        bool newDecryptor = !participant.isDecryptor;
        participant.stake += msg.value;
        participant.isDecryptor = true;
        if (newDecryptor) {
            decryptorPool.push(msg.sender);
        }
        emit DecryptorRegistered(msg.sender, participant.stake);
    }

    /// @notice Creates a task and cryptographically binds the published result
    /// commitment to the terminal leaf of the committed trace.
    /// @dev `resultHash` is not a free operator claim: it must equal the
    /// domain-separated hash of (taskId, operatorTraceRoot, leafCount,
    /// terminalLeaf.claimedHandle, outputAttestationHash), and `terminalLeaf` must be
    /// proven to be the LAST leaf of `operatorTraceRoot`. The proof shape pins
    /// the position: for leaf index leafCount-1 every Merkle sibling lies on
    /// the left, so a fixed-orientation fold of length log2(leafCount) can
    /// only verify the terminal leaf. Output substitution relative to the
    /// committed trace is therefore rejected deterministically at creation,
    /// mirroring the reject-not-slash policy of the linear path. Trace-internal
    /// corruption remains the dispute path's task: a successful leaf challenge
    /// now also impeaches the published output, because the output commitment
    /// is bound to the slashed trace root.
    function createTask(
        bytes32 taskId,
        bytes32 operatorTraceRoot,
        bytes32 resultHash,
        uint32 leafCount,
        LeafClaim calldata terminalLeaf,
        bytes32[] calldata terminalLeafProof,
        bytes32 outputAttestationHash
    ) public virtual {
        if (!(taskId != bytes32(0))) revert InvalidParameter(); // was: bad task
        if (!(operatorTraceRoot != bytes32(0))) revert InvalidParameter(); // was: bad trace root
        if (!(resultHash != bytes32(0))) revert InvalidParameter(); // was: bad result
        if (!(_isPowerOfTwo(leafCount))) revert InvalidParameter(); // was: leaf count must be power of two
        if (!(tasks[taskId].status == TaskStatus.None)) revert StateConflict(); // was: task exists
        Participant storage operator = participants[msg.sender];
        if (!(operator.isOperator)) revert NotEligible(); // was: not operator
        if (!(operator.stake >= MIN_OPERATOR_STAKE_WEI)) revert StateConflict(); // was: operator inactive
        if (!(auditorPool.length >= AUDITOR_SAMPLE_SIZE)) revert NotEligible(); // was: not enough auditors
        if (_requiresOpeningParticipants() && decryptorPool.length < DECRYPTOR_SAMPLE_SIZE) revert NotEligible();

        bytes32 terminalLeafHash = objectiveVerifier.verifyTerminalOutputBinding(
            taskId,
            operatorTraceRoot,
            resultHash,
            leafCount,
            terminalLeaf.opcode,
            terminalLeaf.lhsHandle,
            terminalLeaf.rhsHandle,
            terminalLeaf.claimedHandle,
            terminalLeafProof,
            outputAttestationHash
        );

        if (secureTraceMode) {
            if (
                availabilityModule == address(0) ||
                (address(fhevmVerifier) == address(0) && leafDecisionVerifier == address(0))
            ) revert StateConflict();
            ITraceAvailability(availabilityModule).consumeTaskAuthorization(
                taskId,
                msg.sender,
                operatorTraceRoot,
                resultHash,
                leafCount,
                outputAttestationHash
            );
        }

        Task storage task = tasks[taskId];
        _initializeTask(task, msg.sender, operatorTraceRoot, resultHash, leafCount);
        task.auditorPoolSizeAtCommit = auditorPool.length;
        task.decryptorPoolSizeAtCommit = decryptorPool.length;

        // Commit-then-sample: auditor and decryptor assignment is derived
        // from randomness fixed AFTER this commitment transaction, so the
        // operator cannot grind taskId or trace root against a known seed.
        task.sampleBlock = uint64(block.number + 1);

        emit TaskCreated(taskId, msg.sender, operatorTraceRoot, leafCount);
        emit TerminalOutputBound(
            taskId,
            terminalLeafHash,
            terminalLeaf.claimedHandle,
            outputAttestationHash,
            resultHash
        );
    }

    /// @notice Exposes the stored output binding for auditability. Consumers
    /// recompute the bound result hash via the objective verifier's
    /// `computeBoundResultHash` from the published output and attestation and
    /// compare it with `resultHash`; the `TerminalOutputBound` event logs the
    /// bound terminal output and attestation at creation time.
    function getTaskResultBinding(
        bytes32 taskId
    )
        external
        view
        returns (
            bytes32 resultHash,
            bytes32 operatorTraceRoot,
            uint32 leafCount
        )
    {
        Task storage task = tasks[taskId];
        if (!(task.status != TaskStatus.None)) revert NotEligible(); // was: unknown task
        return (task.resultHash, task.operatorTraceRoot, task.leafCount);
    }

    function submitAudit(
        bytes32 taskId,
        uint32 auditedLeafIndex,
        bytes32 podRoot,
        bytes32 verdictCommit
    ) external virtual {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Auditing) revert TaskNotAuditing();
        if (block.timestamp > task.commitDeadline) revert WrongPhase();
        if (!(auditedLeafIndex < task.leafCount)) revert InvalidParameter(); // was: bad audited leaf

        AuditRecord storage record = audits[taskId][msg.sender];
        if (!record.assigned) revert AuditorNotAssigned();
        if (!_isAuditorAssignedToLeaf(taskId, msg.sender, auditedLeafIndex)) {
            revert AuditorNotAssigned();
        }
        if (!(!record.submitted)) revert StateConflict(); // was: audit already submitted
        if (!(podRoot != bytes32(0))) revert InvalidParameter(); // was: bad pod
        if (!(verdictCommit != bytes32(0))) revert InvalidParameter(); // was: bad verdict commit
        // Individual-privacy guard: the verdict handle must not be a registered
        // individual-input ciphertext handle. Without this, an assigned auditor
        // could commit a user's input handle as its verdict and have it
        // publicly decrypted through openVerdictViaKMS.
        //
        // The input-handle registry is an OPTIONAL extension of the
        // availability module: only the authenticated module keeps one. A
        // module without it (the plain TraceAvailability) registers no input
        // origins at all, so it has no individual-input handle to protect. The
        // registry is therefore PROBED, not assumed: a module that does not
        // answer the probe is treated as "no registry, nothing to guard"
        // instead of making every audit submission revert. A direct interface
        // call would revert with empty returndata against such a module.
        if (availabilityModule != address(0)) {
            (bool probed, bytes memory answer) = availabilityModule.staticcall(
                abi.encodeWithSelector(
                    ITraceAvailability.isRegisteredInputHandle.selector,
                    verdictCommit
                )
            );
            if (probed && answer.length == 32 && abi.decode(answer, (bool))) {
                revert InvalidParameter(); // input handle cannot be a verdict commitment
            }
        }

        record.submitted = true;
        record.auditedLeafIndex = auditedLeafIndex;
        record.podRoot = podRoot;
        record.verdictCommit = verdictCommit;

        emit AuditSubmitted(taskId, msg.sender, auditedLeafIndex, podRoot, verdictCommit);
    }

    function openVerdict(
        bytes32 taskId,
        address auditor,
        bool verdictSupportsOperator,
        bytes32 salt,
        bytes32 podRoot
    ) external virtual {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Auditing) revert TaskNotAuditing();
        if (block.timestamp <= task.commitDeadline) revert WrongPhase();
        if (block.timestamp > task.openDeadline) revert WrongPhase();
        if (!(decryptorAssignedToTask[taskId][msg.sender])) revert NotEligible(); // was: decryptor not assigned

        AuditRecord storage record = audits[taskId][auditor];
        if (!(record.assigned)) revert InvalidParameter(); // was: bad auditor
        if (!record.submitted) revert AuditNotSubmitted();
        if (!(!record.opened)) revert StateConflict(); // was: already opened
        if (!(!decryptorOpenedAudit[taskId][auditor][msg.sender])) revert NotEligible(); // was: decryptor reused
        if (!(record.podRoot == podRoot)) revert InvalidParameter(); // was: pod mismatch

        bytes32 openingCommit = secureTraceMode && address(fhevmVerifier) == address(0)
            ? _openingKey(taskId, auditor, verdictSupportsOperator, salt, podRoot)
            : _verdictCommit(verdictSupportsOperator, salt, podRoot);
        if (!(openingCommit == record.verdictCommit)) revert InvalidParameter(); // was: bad opening

        decryptorOpenedAudit[taskId][auditor][msg.sender] = true;

        bytes32 openingKey = _openingKey(
            taskId,
            auditor,
            verdictSupportsOperator,
            salt,
            podRoot
        );
        openingCounts[openingKey] += 1;

        if (openingCounts[openingKey] >= task.threshold) {
            record.opened = true;
            record.verdictSupportsOperator = verdictSupportsOperator;
            emit VerdictOpened(
                taskId,
                auditor,
                record.auditedLeafIndex,
                verdictSupportsOperator,
                podRoot
            );
        }
    }

    /// @notice Opens an audit verdict from a REAL threshold-FHE public
    /// decryption instead of the commit-reveal committee. In this mode the
    /// auditor's `verdictCommit` submitted in `submitAudit` is the bytes32
    /// handle of its verdict bit encrypted as a TFHE `ebool` under the KMS
    /// threshold key (handle = keccak256 of the ciphertext bytes, also used
    /// as `external_handle` in the KMS decryption request). The KMS cores
    /// jointly decrypt via the maliciously secure MPC protocol and each core
    /// signs (ctHandles, decryptedResult, extraData) under EIP-712; the
    /// configured `kmsVerdictVerifier` accepts t+1 distinct core signatures.
    /// The caller is untrusted: validity comes from the KMS signatures, and
    /// the signed handle equals the auditor's committed handle, so a
    /// decryption of any other ciphertext cannot open this audit.
    ///
    /// Execution binding (anti-replay). The KMS public-decryption struct signs
    /// (ctHandles, decryptedResult, extraData) but NOT the task or the auditor,
    /// so a bundle valid for one (taskId, auditor) would otherwise open any
    /// other audit record that carries the same verdict handle, in this game or
    /// in any other game wired to the same verifier. This function therefore
    /// requires the signed `extraData` to equal the execution binding
    /// keccak256(abi.encode(taskId, auditor, address(this))). Because the KMS
    /// cores sign `extraData`, a captured bundle cannot be replayed to a
    /// different task, a different auditor, or a different game: changing any of
    /// them changes the required binding, and no valid signatures exist over the
    /// new binding. See `verdictOpeningBinding(taskId, auditor)`.
    function openVerdictViaKMS(
        bytes32 taskId,
        address auditor,
        bytes32 podRoot,
        bytes calldata decryptedResult,
        bytes calldata decryptionProof
    ) external virtual {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Auditing) revert TaskNotAuditing();
        if (block.timestamp <= task.commitDeadline) revert WrongPhase();
        if (block.timestamp > task.openDeadline) revert WrongPhase();
        if (kmsVerdictVerifier == address(0)) revert StateConflict();

        AuditRecord storage record = audits[taskId][auditor];
        if (!(record.assigned)) revert InvalidParameter(); // was: bad auditor
        if (!record.submitted) revert AuditNotSubmitted();
        if (!(!record.opened)) revert StateConflict(); // was: already opened
        if (!(record.podRoot == podRoot)) revert InvalidParameter(); // was: pod mismatch
        // One ebool plaintext = one abi-encoded uint256 word.
        if (!(decryptedResult.length == 32)) revert InvalidParameter();

        // The signed extraData must bind this opening to (taskId, auditor,
        // game). The verifier folds extraData into the EIP-712 digest, so this
        // check makes the KMS signatures valid for exactly this execution.
        (, bytes memory boundExtraData) = abi.decode(
            decryptionProof,
            (bytes[], bytes)
        );
        if (
            keccak256(boundExtraData) !=
            keccak256(abi.encode(taskId, auditor, address(this)))
        ) revert NotEligible(); // was: opening not bound to this execution

        bytes32[] memory handles = new bytes32[](1);
        handles[0] = record.verdictCommit;
        if (
            !IKMSVerdictVerifier(kmsVerdictVerifier)
                .verifyDecryptionEIP712KMSSignatures(
                    handles,
                    decryptedResult,
                    decryptionProof
                )
        ) revert NotEligible(); // was: bad KMS decryption proof

        bool verdictSupportsOperator = abi.decode(decryptedResult, (bool));
        record.opened = true;
        record.verdictSupportsOperator = verdictSupportsOperator;
        emit VerdictOpened(
            taskId,
            auditor,
            record.auditedLeafIndex,
            verdictSupportsOperator,
            podRoot
        );
    }

    /// @notice The `extraData` a KMS public-decryption opening for this
    /// (taskId, auditor) must be signed over. The KMS cores sign this exact
    /// value so the resulting bundle is usable only for this task, this auditor,
    /// and this game instance (`openVerdictViaKMS` enforces the equality).
    function verdictOpeningBinding(bytes32 taskId, address auditor)
        external
        view
        returns (bytes memory)
    {
        return abi.encode(taskId, auditor, address(this));
    }

    function sealDiligenceRandomness(bytes32 taskId) external {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Auditing) revert TaskNotAuditing();
        if (!task.sampled) revert WrongPhase();
        if (block.timestamp <= task.commitDeadline) revert WrongPhase();
        if (!(task.diligenceSeed == bytes32(0))) revert StateConflict(); // was: diligence randomness sealed

        task.diligenceSeed = keccak256(
            abi.encodePacked(
                taskId,
                task.operatorTraceRoot,
                block.prevrandao,
                blockhash(block.number - 1),
                address(this)
            )
        );
        emit DiligenceRandomnessSealed(taskId, task.diligenceSeed);
    }

    function proveAuditDiligence(
        bytes32 taskId,
        AuditDiligenceCheckpoint calldata checkpoint,
        bytes32[] calldata checkpointProof,
        bool[] calldata checkpointProofSiblingOnLeft
    ) external {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Auditing) revert TaskNotAuditing();
        if (block.timestamp <= task.commitDeadline) revert WrongPhase();

        AuditRecord storage record = audits[taskId][msg.sender];
        if (!record.assigned) revert AuditorNotAssigned();
        if (!record.submitted) revert AuditNotSubmitted();
        if (!(!record.diligenceProven)) revert StateConflict(); // was: diligence already proven
        _proveAuditDiligence(
            taskId,
            task,
            record,
            msg.sender,
            checkpoint,
            checkpointProof,
            checkpointProofSiblingOnLeft
        );
    }

    function claimDiligenceReward(
        bytes32 taskId,
        AuditDiligenceCheckpoint calldata checkpoint,
        bytes32[] calldata checkpointProof,
        bool[] calldata checkpointProofSiblingOnLeft
    ) external virtual {
        Task storage task = tasks[taskId];
        if (!(task.status == TaskStatus.Finalized)) revert StateConflict(); // was: task not finalized

        AuditRecord storage record = audits[taskId][msg.sender];
        if (!record.assigned) revert AuditorNotAssigned();
        if (!record.submitted) revert AuditNotSubmitted();
        if (!(record.opened)) revert NotEligible(); // was: verdict not opened
        if (!(!record.lazySlashed)) revert StateConflict(); // was: auditor lazy slashed
        if (!(!record.wrongVerdictSlashed)) revert StateConflict(); // was: auditor verdict slashed
        if (!(!record.diligenceRewardClaimed)) revert StateConflict(); // was: diligence reward claimed

        if (record.diligenceProven) {
            bytes32 checkpointHash = _auditDiligenceCheckpointHash(
                taskId,
                msg.sender,
                task.operatorTraceRoot,
                checkpoint
            );
            if (!(checkpointHash == record.diligenceCheckpointHash)) revert InvalidParameter(); // was: diligence checkpoint mismatch
        } else {
            _proveAuditDiligence(
                taskId,
                task,
                record,
                msg.sender,
                checkpoint,
                checkpointProof,
                checkpointProofSiblingOnLeft
            );
        }

        if (!(_isDiligenceRewardEligible(task, record))) revert NotEligible(); // was: verdict not reward eligible

        record.diligenceRewardClaimed = true;
        _transferStake(task.operator, msg.sender, DILIGENCE_REWARD_WEI);
        emit DiligenceRewardClaimed(
            taskId,
            msg.sender,
            record.auditedLeafIndex,
            DILIGENCE_REWARD_WEI
        );
    }

    function openChallenge(
        bytes32 taskId,
        bytes32 challengerTraceRoot,
        uint32 challengeLeafHint,
        bytes32 challengeErrorDigest,
        AuditTraceLeaf calldata auditTraceLeaf,
        bytes32[] calldata auditTraceProof,
        bool[] calldata auditTraceProofSiblingOnLeft
    ) public virtual {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Auditing) revert TaskNotAuditing();
        if (block.timestamp <= task.openDeadline) revert WrongPhase();
        if (block.timestamp > task.challengeDeadline) revert WrongPhase();
        if (!(!task.challengeTriggered)) revert StateConflict(); // was: challenge exists
        if (challengerTraceRoot == bytes32(0) || challengerTraceRoot == task.operatorTraceRoot) revert InvalidParameter();
        if (!(challengeLeafHint < task.leafCount)) revert InvalidParameter(); // was: bad leaf hint
        if (!(challengeErrorDigest != bytes32(0))) revert InvalidParameter(); // was: bad error digest

        AuditRecord storage record = audits[taskId][msg.sender];
        if (!record.assigned) revert AuditorNotAssigned();
        if (!(record.opened)) revert NotEligible(); // was: verdict not opened
        if (!(record.diligenceProven)) revert NotEligible(); // was: diligence not proven
        if (!(!record.verdictSupportsOperator)) revert NotEligible(); // was: no dissent
        if (record.challengeSpent) revert NotEligible(); // one challenge per assigned auditor
        if (!(record.auditedLeafIndex == challengeLeafHint)) revert NotEligible(); // was: auditor not scoped to leaf
        if (!(record.diligenceLeafIndex == challengeLeafHint)) revert InvalidParameter(); // was: diligence scope mismatch
        if (!(auditTraceLeaf.leafIndex == challengeLeafHint)) revert InvalidParameter(); // was: audit leaf mismatch
        if (!(auditTraceLeaf.errorDigest == challengeErrorDigest)) revert InvalidParameter(); // was: audit error mismatch
        if (!(record.diligenceOperatorLeafHash == auditTraceLeaf.operatorLeafHash &&
                record.diligenceRecomputedLeafHash == auditTraceLeaf.recomputedLeafHash)) revert InvalidParameter(); // was: diligence hash mismatch
        if (!(auditTraceLeaf.operatorLeafHash != bytes32(0) &&
                auditTraceLeaf.recomputedLeafHash != bytes32(0))) revert InvalidParameter(); // was: bad audit leaf

        bytes32 auditLeafHash = _auditTraceLeafHash(
            taskId,
            msg.sender,
            auditTraceLeaf
        );
        if (!(_verifyMerkleProof(
                record.podRoot,
                auditLeafHash,
                auditTraceProof,
                auditTraceProofSiblingOnLeft
            ))) revert InvalidParameter(); // was: bad audit proof

        uint256 challengeBond = _requiredChallengeBond(task.leafCount);
        _activateChallengeBond(taskId, msg.sender, challengeBond);

        task.challengeTriggered = true;
        task.status = TaskStatus.Challenged;
        task.disputeProgressDeadline = uint64(
            block.timestamp + uint64(windowConfigPacked >> 128)
        );
        task.challenger = msg.sender;
        task.challengerTraceRoot = challengerTraceRoot;
        task.currentChallengerNode = challengerTraceRoot;
        task.challengeLeafHint = challengeLeafHint;
        task.challengeErrorDigest = challengeErrorDigest;
        task.challengePodRoot = record.podRoot;
        task.challengeAuditLeafHash = auditLeafHash;
        task.activeChallengeBondWei = challengeBond;

        if (secureTraceMode) {
            ITraceAvailability(availabilityModule).openDisputeTrace(taskId);
        }

        emit ChallengeOpened(
            taskId,
            msg.sender,
            challengerTraceRoot,
            challengeLeafHint,
            challengeErrorDigest,
            record.podRoot
        );
        emit ChallengeBondLocked(taskId, msg.sender, challengeBond);
    }

    function submitBisection(
        bytes32 taskId,
        bool operatorSide,
        bytes32 left,
        bytes32 right
    ) external {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Challenged) revert TaskNotChallenged();
        if (task.disputeEnd - task.disputeStart <= 1) revert LeafStageReached();
        if (
            secureTraceMode &&
            !ITraceAvailability(availabilityModule).isDisputeReady(taskId)
        ) revert WrongPhase();

        if (operatorSide) {
            if (!(_canSubmitBisection(taskId, msg.sender, true))) revert NotEligible(); // was: not operator-side defender
            if (!(keccak256(abi.encodePacked(left, right)) == task.currentOperatorNode)) revert InvalidParameter(); // was: bad operator branch
            BisectionProposal storage proposal = bisectionRounds[taskId];
            proposal.operatorLeft = left;
            proposal.operatorRight = right;
            proposal.operatorSubmitted = true;
        } else {
            if (!(_canSubmitBisection(taskId, msg.sender, false))) revert NotEligible(); // was: not challenger-side defender
            if (!(keccak256(abi.encodePacked(left, right)) == task.currentChallengerNode)) revert InvalidParameter(); // was: bad challenger branch
            BisectionProposal storage proposal = bisectionRounds[taskId];
            proposal.challengerLeft = left;
            proposal.challengerRight = right;
            proposal.challengerSubmitted = true;
        }
    }

    /// @notice Default judgment for a stalled bisection round. Silence past
    /// the per-round window is an objectively attributable fault under the
    /// timing model (an honest participant is included within Delta). The
    /// side that failed to post its branch loses by default. A timeout is
    /// an economic settlement, not a correctness verdict: in neither
    /// outcome is the operator's result marked accepted. Losing challengers
    /// reopen the challenge window before any later optimistic finalization.
    function timeoutDispute(bytes32 taskId) external virtual {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Challenged) revert TaskNotChallenged();
        if (block.timestamp <= task.disputeProgressDeadline) revert WrongPhase();
        // Disclosure has its own reveal-or-slash deadline. In particular a
        // one-leaf task must not charge the challenger for missing operator data.
        if (secureTraceMode && !ITraceAvailability(availabilityModule).isDisputeReady(taskId)) {
            revert WrongPhase();
        }
        if (task.disputeEnd - task.disputeStart <= 1) {
            // Certificate-only mode: authenticated admission separates a
            // backend outage from either party's missing evidence. Keep the
            // task challenged (and its output unavailable) until a certificate
            // arrives. Silence is not evidence of an incorrect computation.
            if (secureTraceMode && address(fhevmVerifier) == address(0) &&
                pendingFhevmLeafResolutions[taskId].active) revert WrongPhase();
            // Until a structurally valid request has authenticated all ciphertext
            // handles, the challenger still bears the submission burden. The
            // attested backend admits and settles atomically, so it cannot leave
            // an admitted request pending. A fabricated or withheld challenger
            // leaf must never turn into a reward via an operator timeout.
            if (secureTraceMode && !pendingFhevmLeafResolutions[taskId].active) {
                _releaseChallengeBond(taskId, true, task.operator);
                emit DisputeTimedOut(taskId, task.challenger, FinalDecision.ChallengerSlashed);
                _reopenAfterLostChallenge(taskId, task.challengeLeafHint);
                return;
            }
            // In secure mode a request has already authenticated the terminal
            // claims. The operator can finalize the pending decision itself;
            // failure within the fresh decision window loses by default.
            // Legacy mode retains its original terminal-timeout policy.
            task.status = TaskStatus.Finalized;
            task.decision = FinalDecision.OperatorSlashed;
            _slashAndReward(task.operator, task.challenger, SLASH_AMOUNT_WEI);
            _releaseChallengeBond(taskId, false, task.challenger);
            delete pendingFhevmLeafResolutions[taskId];
            emit DisputeTimedOut(taskId, task.operator, task.decision);
            delete bisectionRounds[taskId];
            return;
        }
        BisectionProposal storage proposal = bisectionRounds[taskId];
        if (proposal.operatorSubmitted && proposal.challengerSubmitted) {
            revert WrongPhase(); // round complete: call advanceDispute
        }
        if (!proposal.challengerSubmitted) {
            // The dissent side bears the prosecution burden: abandoning a
            // round forfeits the bond to the operator. The result is not
            // accepted here; the task returns to Auditing so that another
            // eligible dissenter can still challenge (a sham challenge must
            // not consume the only challenge of the task).
            _releaseChallengeBond(taskId, true, task.operator);
            emit DisputeTimedOut(taskId, task.challenger, FinalDecision.ChallengerSlashed);
            _reopenAfterLostChallenge(taskId, task.challengeLeafHint);
        } else {
            task.status = TaskStatus.Finalized;
            // The operator side (operator plus supporting auditors) went
            // silent: the operator is slashed and the challenger is
            // compensated, exactly as for a lost dispute.
            task.decision = FinalDecision.OperatorSlashed;
            _slashAndReward(task.operator, task.challenger, SLASH_AMOUNT_WEI);
            _releaseChallengeBond(taskId, false, task.challenger);
            emit DisputeTimedOut(taskId, task.operator, task.decision);
        }
        delete bisectionRounds[taskId];
    }

    /// @notice Called by the availability module when a bonded stage-reveal
    /// request expires unanswered. The breach is objectively attributable
    /// (bonded request, elapsed window, no Merkle-verified reveal), so the
    /// operator is slashed and the requester rewarded; the module has
    /// already excluded the task from optimistic finalization.
    function slashOperatorForUnavailability(
        bytes32 taskId,
        address requester
    ) external virtual {
        if (msg.sender != availabilityModule) revert NotEligible();
        Task storage task = tasks[taskId];
        if (task.status == TaskStatus.None) revert InvalidParameter();
        Participant storage operatorParticipant = participants[task.operator];
        uint256 effectiveSlash = SLASH_AMOUNT_WEI;
        uint256 availableStake = _availableStake(operatorParticipant);
        if (availableStake < effectiveSlash) {
            effectiveSlash = availableStake;
        }
        if (effectiveSlash > 0) {
            operatorParticipant.stake -= effectiveSlash;
            participants[requester].stake += effectiveSlash;
        }
        emit TraceWithholdingSlashed(
            taskId,
            task.operator,
            requester,
            effectiveSlash
        );
        if (task.status == TaskStatus.Challenged) {
            _releaseChallengeBond(taskId, false, task.challenger);
            task.status = TaskStatus.Finalized;
            task.decision = FinalDecision.OperatorSlashed;
            emit TaskResolved(taskId, task.decision, requester);
        } else if (task.status == TaskStatus.Auditing) {
            // Pre-challenge disclosure request left unanswered: the task closes
            // against the operator. The result is never accepted, exactly as
            // for withholding after a challenge.
            task.status = TaskStatus.Finalized;
            task.decision = FinalDecision.OperatorSlashed;
            emit TaskResolved(taskId, task.decision, requester);
        }
    }

    /// @notice Pushes the audit-commit, verdict-opening, and challenge
    ///         deadlines of a task still in its optimistic phase by
    ///         `extensionSeconds`. Callable only by the availability module,
    ///         when an assigned auditor forces on-chain trace disclosure before
    ///         any challenge: the auditors must be able to audit the disclosed
    ///         trace, commit, open, and challenge after the disclosure window.
    ///         The module admits one request per task, so the delay an
    ///         auditor can impose on finalization is bounded by one window.
    ///         A challenge-triggered disclosure instead extends its first
    ///         response deadline, so disclosure cannot consume that window.
    function extendDeadlinesForDisclosure(bytes32 taskId, uint64 extensionSeconds) external virtual {
        if (msg.sender != availabilityModule) revert NotEligible();
        Task storage task = tasks[taskId];
        if (!task.sampled) revert WrongPhase();
        if (task.status == TaskStatus.Challenged) {
            // Reserve a full response window after the latest timely disclosure,
            // including a one-leaf trace with no intervening bisection round.
            task.disputeProgressDeadline += extensionSeconds;
            return;
        }
        if (task.status != TaskStatus.Auditing) revert WrongPhase();
        task.commitDeadline += extensionSeconds;
        task.openDeadline += extensionSeconds;
        task.challengeDeadline += extensionSeconds;
        emit TaskDeadlinesExtended(taskId, extensionSeconds, task.challengeDeadline);
    }

    function advanceDispute(bytes32 taskId) external {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Challenged) revert TaskNotChallenged();
        if (task.disputeEnd - task.disputeStart <= 1) revert LeafStageReached();

        BisectionProposal storage proposal = bisectionRounds[taskId];
        if (!(proposal.operatorSubmitted)) revert NotEligible(); // was: operator branch missing
        if (!(proposal.challengerSubmitted)) revert NotEligible(); // was: challenger branch missing

        uint32 mid = uint32((uint256(task.disputeStart) + uint256(task.disputeEnd)) / 2);

        if (proposal.operatorLeft != proposal.challengerLeft) {
            task.disputeEnd = mid;
            task.currentOperatorNode = proposal.operatorLeft;
            task.currentChallengerNode = proposal.challengerLeft;
        } else if (proposal.operatorRight != proposal.challengerRight) {
            task.disputeStart = mid;
            task.currentOperatorNode = proposal.operatorRight;
            task.currentChallengerNode = proposal.challengerRight;
        } else {
            revert("no differing branch");
        }

        task.disputeProgressDeadline = uint64(
            block.timestamp + uint64(windowConfigPacked >> 128)
        );

        emit DisputeBisected(
            taskId,
            task.disputeStart,
            task.disputeEnd,
            task.currentOperatorNode,
            task.currentChallengerNode
        );

        delete bisectionRounds[taskId];
    }

    function resolveLeafDispute(
        bytes32 taskId,
        LeafClaim calldata operatorLeaf,
        LeafClaim calldata challengerLeaf
    ) external virtual {
        // The clear verifier is a deployment fallback, not a competing
        // settlement route. Once the FHEVM backend is configured, allowing
        // both paths would let a caller race two potentially different
        // arithmetic semantics for the same dispute.
        if (secureTraceMode || address(fhevmVerifier) != address(0)) {
            revert InvalidFhevmVerifierMode();
        }
        (uint32 leafIndex, bool admissible) = _validateLeafResolution(
            taskId,
            operatorLeaf,
            challengerLeaf
        );
        if (!admissible) return;
        if (
            operatorLeaf.lhsHandle != challengerLeaf.lhsHandle ||
            operatorLeaf.rhsHandle != challengerLeaf.rhsHandle
        ) revert InvalidParameter();
        bool operatorValid = _isValidLeaf(operatorLeaf);
        bool challengerValid = _isValidLeaf(challengerLeaf);
        _applyLeafDecision(
            taskId,
            leafIndex,
            operatorLeaf.opcode,
            operatorValid,
            challengerValid,
            address(objectiveVerifier)
        );
    }

    function requestFhevmLeafResolution(
        bytes32 taskId,
        LeafClaim calldata operatorLeaf,
        LeafClaim calldata challengerLeaf,
        CiphertextLeafWitness calldata witness
    ) external virtual {
        if (address(fhevmVerifier) == address(0)) {
            revert InvalidFhevmVerifierMode();
        }
        Task storage requesting = tasks[taskId];
        // Only the two parties to the dispute may drive the terminal decision.
        // A permissionless request lets a third party pin the slot with a
        // witness of its choosing; the parties themselves are already bonded
        // and are settled by the terminal-round timeout if they stall.
        if (msg.sender != requesting.operator && msg.sender != requesting.challenger) {
            revert NotEligible();
        }
        PendingFhevmLeafResolution storage pending = pendingFhevmLeafResolutions[taskId];
        // A pending request that is not finalized before its own deadline may
        // be replaced, so a request that cannot settle (for example one carrying
        // a witness the verifier cannot decide) never blocks the dispute.
        if (pending.active && block.timestamp <= pending.replaceableAfter) {
            revert NotEligible();
        }

        (uint32 leafIndex, bool admissible) = _validateLeafResolution(
            taskId,
            operatorLeaf,
            challengerLeaf
        );
        if (!admissible) return;
        IFhevmObjectiveMicroVerifier.LeafPair memory pair;
        pair.opcode = operatorLeaf.opcode;
        pair.lhsHandle = operatorLeaf.lhsHandle;
        pair.rhsHandle = operatorLeaf.rhsHandle;
        pair.operatorClaimedHandle = operatorLeaf.claimedHandle;
        pair.challengerClaimedHandle = challengerLeaf.claimedHandle;
        if (secureTraceMode) {
            bytes32 disclosedLeafHash;
            (
                disclosedLeafHash,
                pair.lhsHandle,
                pair.rhsHandle,
                pair.operatorClaimedHandle,
                pair.lhsSourceKind,
                pair.rhsSourceKind
            ) = ITraceAvailability(availabilityModule).getDisclosedLeafHandles(taskId, leafIndex);
            if (disclosedLeafHash != _leafHash(operatorLeaf)) revert InvalidParameter();
        }
        pair.lhsInputProof = witness.lhsInputProof;
        pair.rhsInputProof = witness.rhsInputProof;
        pair.operatorClaimedProof = witness.operatorClaimedProof;
        pair.challengerClaimedProof = witness.challengerClaimedProof;
        IFhevmObjectiveMicroVerifier verifier = fhevmVerifier;
        (bytes32 operatorValidHandle, bytes32 challengerValidHandle) =
            verifier.requestLeafCheck(taskId, leafIndex, pair);

        // A successful request authenticates both claims and the operand
        // handles. Only now can failure to obtain the decision be attributed
        // to the operator. Retries must not extend the deadline indefinitely.
        if (secureTraceMode && !pending.active) {
            requesting.disputeProgressDeadline = uint64(block.timestamp + uint64(windowConfigPacked >> 128));
        }
        pendingFhevmLeafResolutions[taskId] = PendingFhevmLeafResolution({
            active: true,
            verifier: address(verifier),
            opcode: operatorLeaf.opcode,
            leafIndex: leafIndex,
            replaceableAfter: uint64(block.timestamp + uint64(windowConfigPacked >> 128)),
            operatorValidHandle: operatorValidHandle,
            challengerValidHandle: challengerValidHandle
        });

        emit FhevmLeafResolutionRequested(
            taskId,
            leafIndex,
            operatorLeaf.opcode,
            operatorValidHandle,
            challengerValidHandle
        );
    }

    function finalizeFhevmLeafResolution(
        bytes32 taskId,
        bool operatorValid,
        bool challengerValid,
        bytes calldata decryptionProof
    ) external virtual {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Challenged) revert TaskNotChallenged();

        PendingFhevmLeafResolution memory pending = pendingFhevmLeafResolutions[taskId];
        if (!(pending.active)) revert NotEligible(); // was: no fhevm resolution pending

        (bool provenOperatorValid, bool provenChallengerValid) = IFhevmObjectiveMicroVerifier(
            pending.verifier
        )
            .finalizeLeafCheck(
                taskId,
                pending.leafIndex,
                pending.operatorValidHandle,
                pending.challengerValidHandle,
                operatorValid,
                challengerValid,
                decryptionProof
            );

        delete pendingFhevmLeafResolutions[taskId];

        emit FhevmLeafResolutionFinalized(
            taskId,
            pending.leafIndex,
            pending.opcode,
            provenOperatorValid,
            provenChallengerValid
        );
        _applyLeafDecision(
            taskId,
            pending.leafIndex,
            pending.opcode,
            provenOperatorValid,
            provenChallengerValid,
            pending.verifier
        );
    }

    /// @notice Domain tag of the leaf-decision attestation. Named explicitly so
    /// that a bundle signed for a leaf decision can never be replayed as a
    /// verdict opening (whose `extraData` is
    /// `abi.encode(taskId, auditor, game)`), and vice versa.
    bytes32 public constant FHE_POD_LEAF_DECISION_V1 =
        keccak256("FHE_POD_LEAF_DECISION_V1");

    /// @notice The `extraData` a leaf-decision attestation must be signed over.
    /// Binds the decision to this game, this chain, this task, this leaf and
    /// this opcode. The remaining two required bindings -- the CLAIMED HANDLES
    /// and the DECISION BITS -- are the `ctHandles` and the `decryptedResult`
    /// of the same EIP-712 struct, so all six are covered by one digest.
    function leafDecisionBinding(
        bytes32 taskId,
        uint32 leafIndex,
        uint8 opcode
    ) public view returns (bytes memory) {
        return
            abi.encode(
                FHE_POD_LEAF_DECISION_V1,
                address(this),
                block.chainid,
                taskId,
                leafIndex,
                opcode
            );
    }

    /// @notice Settles the isolated leaf from a threshold-signed attestation of
    /// the two equality bits, carrying NO operand.
    ///
    /// WHY THIS EXISTS. The on-chain homomorphic route
    /// (`requestFhevmLeafResolution` -> `finalizeFhevmLeafResolution`) can only
    /// recompute the leaf if the backend can resolve a handle to its content.
    /// A production coprocessor does that from the ciphertext it holds; the
    /// local stand-in cannot, and the previous workaround was to TELL it the
    /// operands in a transaction, which published the disputed leaf's operands
    /// in the clear and defeated the handle-only design. That entry point is
    /// gone (see LocalFhevmRuntime.verifyInput). This function is the route a
    /// dispute over real ciphertext handles takes instead.
    ///
    /// WHAT IS MODELED AND WHAT WOULD BE REAL.
    ///  - REAL, and unchanged: the settlement rule, the bisection that isolates
    ///    the leaf, the per-round default judgment, reveal-or-slash, the leaf
    ///    hash / provenance checks in `_validateLeafResolution`, the EIP-712
    ///    signature verification (identical code path and t+1 rule as
    ///    `openVerdictViaKMS`, `ZamaKMSVerdictVerifier`), and the fact that no
    ///    operand value appears anywhere in this call.
    ///  - REAL, and the rule that decides the leaf: the two bits are
    ///    `FHE.eq(recomputed, claimed)` EVALUATED HOMOMORPHICALLY over the
    ///    ciphertexts, of which only the equality bit is ever decrypted. The
    ///    leaf is recomputed from its operand ciphertexts, so no stored result
    ///    is trusted as the reference (scripts/leaf-decision.mjs,
    ///    `ct-inspect leaf-decision`).
    ///
    ///    This is not an implementation detail. Deciding the leaf by comparing
    ///    ciphertext HANDLES would be unsound: a handle is
    ///    keccak256(serialized ciphertext), tfhe-rs evaluates in parallel, and
    ///    two correct evaluations of the same operation on the same operands
    ///    under the same key can serialize to different bytes. Byte equality
    ///    answers "was this the same EXECUTION?" and can slash an operator that
    ///    executed correctly under a different schedule; plaintext equality
    ///    under encryption answers "is the claim right?" and is insensitive to
    ///    scheduling. Measured, under CPU load, in
    ///    scripts/leaf-decision-stability.test.mjs.
    ///
    ///  - MODELED: in production the recomputation runs on the FHEVM
    ///    coprocessor and the two `ebool`s are THRESHOLD-DECRYPTED by the KMS,
    ///    whose cores sign the resulting `PublicDecryptVerification` struct.
    ///    Here both run in a local process holding the evaluation key pair, and
    ///    the signers are deterministic local identities. The same struct is
    ///    signed over the CLAIMED handles rather than over the two derived
    ///    `ebool` handles, because the claimed handles are what this contract
    ///    can bind the attestation to. The transport, the digest, the
    ///    threshold and the on-chain acceptance rule are the production ones;
    ///    what is modeled is who holds the decryption key.
    ///
    /// @param decisionProof abi.encode(bytes[] signatures, bytes extraData),
    ///        exactly as `openVerdictViaKMS` takes it. `extraData` must equal
    ///        `leafDecisionBinding(taskId, leafIndex, opcode)`.
    function settleLeafViaAttestedDecision(
        bytes32 taskId,
        LeafClaim calldata operatorLeaf,
        LeafClaim calldata challengerLeaf,
        bool operatorValid,
        bool challengerValid,
        bytes calldata decisionProof
    ) external {
        address attestor = leafDecisionVerifier;
        if (attestor == address(0)) revert StateConflict();
        (uint32 leafIndex, bool admissible) = _validateLeafResolution(
            taskId,
            operatorLeaf,
            challengerLeaf
        );
        if (!admissible) return;

        // Settlement keys on the OPERATOR's claim, so the operator handle the
        // attestation speaks about must be the one the operator is bound to:
        // the disclosed provenance record in secure-trace mode, its own
        // committed leaf otherwise. Same resolution as
        // `requestFhevmLeafResolution`.
        bytes32 operatorClaimedHandle = operatorLeaf.claimedHandle;
        if (secureTraceMode) {
            bytes32 disclosedLeafHash;
            (
                disclosedLeafHash,
                ,
                ,
                operatorClaimedHandle,
                ,

            ) = ITraceAvailability(availabilityModule).getDisclosedLeafHandles(
                taskId,
                leafIndex
            );
            if (disclosedLeafHash != _leafHash(operatorLeaf)) {
                revert InvalidParameter();
            }
        }

        // Empty proof admits BOTH authenticated openings in certificate-only
        // mode. It releases no value and decides no validity bit. A caller
        // cannot freeze a task with invented or malformed leaf calldata,
        // because _validateLeafResolution already authenticated both leaves.
        if (secureTraceMode && address(fhevmVerifier) == address(0) && decisionProof.length == 0) {
            pendingFhevmLeafResolutions[taskId].active = true;
            return;
        }
        (, bytes memory boundExtraData) = abi.decode(
            decisionProof,
            (bytes[], bytes)
        );
        if (
            keccak256(boundExtraData) !=
            keccak256(leafDecisionBinding(taskId, leafIndex, operatorLeaf.opcode))
        ) revert NotEligible(); // was: attestation not bound to this leaf

        bytes32[] memory handles = new bytes32[](2);
        handles[0] = operatorClaimedHandle;
        handles[1] = challengerLeaf.claimedHandle;
        if (
            !IKMSVerdictVerifier(attestor).verifyDecryptionEIP712KMSSignatures(
                handles,
                abi.encode(operatorValid, challengerValid),
                decisionProof
            )
        ) revert NotEligible(); // was: bad leaf-decision attestation

        _applyLeafDecision(
            taskId,
            leafIndex,
            operatorLeaf.opcode,
            operatorValid,
            challengerValid,
            attestor
        );
    }

    function finalizeUnchallenged(bytes32 taskId) public virtual {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Auditing) revert TaskNotAuditing();
        if (!task.sampled) revert WrongPhase();
        if (block.timestamp <= task.challengeDeadline) revert WrongPhase();
        if (!(!task.challengeTriggered)) revert StateConflict(); // was: challenge exists
        if (
            availabilityModule != address(0) &&
            !ITraceAvailability(availabilityModule).isCleared(taskId)
        ) {
            revert WrongPhase();
        }

        task.status = TaskStatus.Finalized;
        task.decision = FinalDecision.OperatorAccepted;
        if (task.hasLostChallenge) {
            _slashWrongVerdictAuditors(taskId, task.lostChallengeLeaf, true, task.operator, address(0));
        }
        emit TaskResolved(taskId, task.decision, task.operator);
    }

    function slashLazyAuditor(bytes32 taskId, address auditor) external virtual {
        Task storage task = tasks[taskId];
        if (block.timestamp <= task.openDeadline) revert WrongPhase();

        AuditRecord storage record = audits[taskId][auditor];
        if (!record.assigned) revert AuditorNotAssigned();
        if (!(!record.opened)) revert StateConflict(); // was: auditor already opened
        if (!(!record.lazySlashed)) revert StateConflict(); // was: auditor already slashed

        record.lazySlashed = true;
        uint256 paid = _slashAndReward(auditor, msg.sender, SLASH_AMOUNT_WEI);
        emit LazyAuditorSlashed(taskId, auditor, msg.sender, paid);
    }

    function getAssignedAuditors(bytes32 taskId) external view returns (address[] memory) {
        return taskAuditors[taskId];
    }

    function getAssignedAuditorsForLeaf(
        bytes32 taskId,
        uint32 leafIndex
    ) external view returns (address[] memory) {
        Task storage task = tasks[taskId];
        if (!(task.status != TaskStatus.None)) revert NotEligible(); // was: unknown task
        if (!(leafIndex < task.leafCount)) revert InvalidParameter(); // was: bad leaf

        address[] storage assignedAuditors = taskAuditors[taskId];
        uint256 cohortSize = _stageAuditorCohortSize(
            assignedAuditors.length,
            task.leafCount
        );
        address[] memory stageAuditors = new address[](cohortSize);
        uint256 start = _stageAuditorStart(taskId, leafIndex, assignedAuditors.length);

        for (uint256 i = 0; i < cohortSize; i++) {
            stageAuditors[i] = assignedAuditors[(start + i) % assignedAuditors.length];
        }

        return stageAuditors;
    }

    function isAuditorAssignedToLeaf(
        bytes32 taskId,
        address auditor,
        uint32 leafIndex
    ) external view returns (bool) {
        return _isAuditorAssignedToLeaf(taskId, auditor, leafIndex);
    }

    function getAssignedDecryptors(
        bytes32 taskId
    ) external view returns (address[] memory) {
        return taskDecryptors[taskId];
    }

    function getParticipantStake(address account) external view returns (uint256) {
        return participants[account].stake;
    }

    function getParticipantStakeBreakdown(
        address account
    )
        external
        view
        returns (
            uint256 totalStakeWei,
            uint256 lockedChallengeBondWei,
            uint256 availableStakeWei
        )
    {
        Participant storage participant = participants[account];
        totalStakeWei = participant.stake;
        lockedChallengeBondWei = participant.lockedChallengeBondWei;
        availableStakeWei = _availableStake(participant);
    }


    function getRequiredDiligenceCheckpointIndex(
        bytes32 taskId,
        address auditor
    ) external view returns (uint32) {
        return _requiredDiligenceCheckpointIndex(taskId, auditor);
    }

    function getTaskStatus(
        bytes32 taskId
    )
        external
        view
        returns (
            TaskStatus status,
            FinalDecision decision,
            bool challengeTriggered,
            address operator,
            address challenger
        )
    {
        Task storage task = tasks[taskId];
        return (
            task.status,
            task.decision,
            task.challengeTriggered,
            task.operator,
            task.challenger
        );
    }

    function getTaskDeadlines(
        bytes32 taskId
    ) external view returns (uint64 commitDeadline, uint64 openDeadline, uint64 challengeDeadline) {
        Task storage task = tasks[taskId];
        return (task.commitDeadline, task.openDeadline, task.challengeDeadline);
    }

    function getTaskDisputeState(
        bytes32 taskId
    )
        external
        view
        returns (
            uint32 disputeStart,
            uint32 disputeEnd,
            bytes32 currentOperatorNode,
            bytes32 currentChallengerNode
        )
    {
        Task storage task = tasks[taskId];
        return (
            task.disputeStart,
            task.disputeEnd,
            task.currentOperatorNode,
            task.currentChallengerNode
        );
    }

    function getChallengeClaim(
        bytes32 taskId
    )
        external
        view
        returns (
            address challenger,
            bytes32 challengerTraceRoot,
            uint32 challengeLeafHint,
            bytes32 challengeErrorDigest,
            bytes32 challengePodRoot,
            bytes32 challengeAuditLeafHash,
            bytes32 diligenceSeed
        )
    {
        Task storage task = tasks[taskId];
        return (
            task.challenger,
            task.challengerTraceRoot,
            task.challengeLeafHint,
            task.challengeErrorDigest,
            task.challengePodRoot,
            task.challengeAuditLeafHash,
            task.diligenceSeed
        );
    }

    function getPendingFhevmLeafResolution(
        bytes32 taskId
    )
        external
        view
        returns (
            bool active,
            address verifier,
            uint8 opcode,
            uint32 leafIndex,
            bytes32 operatorValidHandle,
            bytes32 challengerValidHandle
        )
    {
        PendingFhevmLeafResolution storage pending = pendingFhevmLeafResolutions[
            taskId
        ];
        return (
            pending.active,
            pending.verifier,
            pending.opcode,
            pending.leafIndex,
            pending.operatorValidHandle,
            pending.challengerValidHandle
        );
    }

    function getAuditStatus(
        bytes32 taskId,
        address auditor
    )
        external
        view
        returns (
            bool assigned,
            bool submitted,
            bool opened,
            bool diligenceProven,
            bool verdictSupportsOperator,
            bool lazySlashed,
            bool wrongVerdictSlashed,
            uint32 auditedLeafIndex,
            bytes32 diligenceCheckpointHash
        )
    {
        AuditRecord storage record = audits[taskId][auditor];
        return (
            record.assigned,
            record.submitted,
            record.opened,
            record.diligenceProven,
            record.verdictSupportsOperator,
            record.lazySlashed,
            record.wrongVerdictSlashed,
            record.auditedLeafIndex,
            record.diligenceCheckpointHash
        );
    }


    /// @notice Permissionless commit-then-sample assignment. The seed is the
    /// hash of the first block mined after the task commitment, so neither the
    /// operator (who committed earlier) nor the caller (the seed is fixed
    /// regardless of when this is called) can grind it. The producer of the
    /// seed block retains the usual block-production withholding bias.
    /// If the seed block ages beyond the 256-block hash horizon before
    /// anyone samples, the target is rescheduled instead of reverting.
    function sampleParticipants(bytes32 taskId) external {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Auditing) revert TaskNotAuditing();
        if (task.sampled) revert StateConflict();
        if (block.number <= task.sampleBlock) revert WrongPhase();
        bytes32 seed = blockhash(uint256(task.sampleBlock));
        if (seed == bytes32(0)) {
            // Rescheduling keeps the task alive when nobody sampled within the
            // 256-block hash horizon, but an unbounded number of reschedules
            // would let a party redraw the cohort for free until it is
            // captured. Bounding the count keeps Eq. (sybil-capture) a bound
            // over a fixed, small number of draws.
            if (task.seedReschedules >= MAX_SEED_RESCHEDULES) revert StateConflict();
            task.seedReschedules += 1;
            task.sampleBlock = uint64(block.number + 1);
            emit ParticipantsSampled(taskId, bytes32(0), task.sampleBlock);
            return;
        }
        task.sampled = true;
        _assignAuditors(taskId, seed);
        _assignDecryptors(taskId, seed);
        uint256 windows = windowConfigPacked;
        uint64 commitWindowSeconds = uint64(windows);
        uint64 openWindowSeconds = uint64(windows >> 64);
        uint64 challengeWindowSeconds = uint64(windows >> 128);
        task.commitDeadline = uint64(block.timestamp + commitWindowSeconds);
        task.openDeadline = uint64(block.timestamp + commitWindowSeconds + openWindowSeconds);
        task.challengeDeadline = uint64(
            block.timestamp +
                commitWindowSeconds +
                openWindowSeconds +
                challengeWindowSeconds
        );
        emit ParticipantsSampled(taskId, seed, task.sampleBlock);
    }

    function _assignAuditors(bytes32 taskId, bytes32 seed) internal {
        uint256[] memory indices = participantSampler.sampleIndices(
            tasks[taskId].auditorPoolSizeAtCommit,
            AUDITOR_SAMPLE_SIZE,
            keccak256(abi.encode(taskId, seed, "auditors"))
        );
        for (uint256 i = 0; i < AUDITOR_SAMPLE_SIZE; i++) {
            address auditor = auditorPool[indices[i]];
            audits[taskId][auditor].assigned = true;
            taskAuditors[taskId].push(auditor);
        }
    }

    function _requiresOpeningParticipants() internal pure virtual returns (bool) {
        return true;
    }

    function _assignDecryptors(bytes32 taskId, bytes32 seed) internal virtual {
        uint256[] memory indices = participantSampler.sampleIndices(
            tasks[taskId].decryptorPoolSizeAtCommit,
            DECRYPTOR_SAMPLE_SIZE,
            keccak256(abi.encode(taskId, seed, "decryptors"))
        );
        for (uint256 i = 0; i < DECRYPTOR_SAMPLE_SIZE; i++) {
            address decryptor = decryptorPool[indices[i]];
            decryptorAssignedToTask[taskId][decryptor] = true;
            taskDecryptors[taskId].push(decryptor);
        }
    }

    /// @notice Counts of candidates eligible for this task. Later registrations
    /// are eligible only for tasks created after their registration.
    function getTaskCandidateCounts(bytes32 taskId)
        external view returns (uint256 auditorCount, uint256 openingParticipantCount)
    {
        Task storage task = tasks[taskId];
        return (task.auditorPoolSizeAtCommit, task.decryptorPoolSizeAtCommit);
    }

    function _isAuditorAssignedToLeaf(
        bytes32 taskId,
        address auditor,
        uint32 leafIndex
    ) internal view returns (bool) {
        Task storage task = tasks[taskId];
        if (task.status == TaskStatus.None || leafIndex >= task.leafCount) {
            return false;
        }

        address[] storage assignedAuditors = taskAuditors[taskId];
        if (assignedAuditors.length == 0) {
            return false;
        }

        uint256 cohortSize = _stageAuditorCohortSize(
            assignedAuditors.length,
            task.leafCount
        );
        uint256 start = _stageAuditorStart(taskId, leafIndex, assignedAuditors.length);

        for (uint256 i = 0; i < cohortSize; i++) {
            if (assignedAuditors[(start + i) % assignedAuditors.length] == auditor) {
                return true;
            }
        }

        return false;
    }

    function _stageAuditorCohortSize(
        uint256 assignedAuditorCount,
        uint32 leafCount
    ) internal pure virtual returns (uint256) {
        uint256 minimumForFullAuditorCoverage =
            (assignedAuditorCount + leafCount - 1) / leafCount;
        uint256 desired = STAGE_AUDITOR_SAMPLE_SIZE >
            minimumForFullAuditorCoverage
            ? STAGE_AUDITOR_SAMPLE_SIZE
            : minimumForFullAuditorCoverage;
        return assignedAuditorCount < desired ? assignedAuditorCount : desired;
    }

    function _stageAuditorStart(
        bytes32 taskId,
        uint32 leafIndex,
        uint256 assignedAuditorCount
    ) internal view returns (uint256) {
        Task storage task = tasks[taskId];
        uint256 offset =
            uint256(
                keccak256(
                    abi.encodePacked(
                        taskId,
                        task.operatorTraceRoot,
                        "stage-auditors"
                    )
                )
            ) % assignedAuditorCount;
        return (offset + leafIndex) % assignedAuditorCount;
    }

    function _requiredDiligenceCheckpointIndex(
        bytes32 taskId,
        address auditor
    ) internal view returns (uint32) {
        Task storage task = tasks[taskId];
        if (!(task.status != TaskStatus.None)) revert NotEligible(); // was: task missing
        if (task.diligenceSeed == bytes32(0)) revert DiligenceRandomnessMissing();
        AuditRecord storage record = audits[taskId][auditor];
        if (!record.submitted) revert AuditNotSubmitted();
        return
            uint32(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            task.diligenceSeed,
                            auditor,
                            record.podRoot,
                            "diligence-checkpoint"
                        )
                    )
                ) % DILIGENCE_CHECKPOINT_SPACE
            );
    }

    function _slashAndReward(
        address loser,
        address winner,
        uint256 amount
    ) internal returns (uint256 effectiveSlash) {
        Participant storage loserParticipant = participants[loser];
        effectiveSlash = amount;
        uint256 availableStake = _availableStake(loserParticipant);
        if (availableStake < effectiveSlash) {
            effectiveSlash = availableStake;
        }
        // Concurrent tasks can exhaust unreserved collateral. That lowers the
        // economic penalty; it must not veto an otherwise valid settlement.
        loserParticipant.stake -= effectiveSlash;
        participants[winner].stake += effectiveSlash;
    }

    function _transferStake(
        address payer,
        address recipient,
        uint256 amount
    ) internal {
        Participant storage payerParticipant = participants[payer];
        if (!(_availableStake(payerParticipant) >= amount)) revert NotEligible(); // was: reward payer stake low
        payerParticipant.stake -= amount;
        participants[recipient].stake += amount;
    }

    function _proveAuditDiligence(
        bytes32 taskId,
        Task storage task,
        AuditRecord storage record,
        address auditor,
        AuditDiligenceCheckpoint calldata checkpoint,
        bytes32[] calldata checkpointProof,
        bool[] calldata checkpointProofSiblingOnLeft
    ) internal {
        if (task.diligenceSeed == bytes32(0)) revert DiligenceRandomnessMissing();
        if (!(checkpoint.checkpointIndex ==
                _requiredDiligenceCheckpointIndex(taskId, auditor))) revert NotEligible(); // was: wrong diligence checkpoint
        if (!(checkpoint.leafIndex == record.auditedLeafIndex)) revert InvalidParameter(); // was: diligence leaf mismatch
        if (!(checkpoint.operatorLeafHash != bytes32(0) &&
                checkpoint.recomputedLeafHash != bytes32(0) &&
                checkpoint.transcriptDigest != bytes32(0))) revert InvalidParameter(); // was: bad diligence checkpoint

        bytes32 checkpointHash = _auditDiligenceCheckpointHash(
            taskId,
            auditor,
            task.operatorTraceRoot,
            checkpoint
        );
        if (!(_verifyMerkleProof(
                record.podRoot,
                checkpointHash,
                checkpointProof,
                checkpointProofSiblingOnLeft
            ))) revert InvalidParameter(); // was: bad diligence proof

        record.diligenceProven = true;
        record.diligenceLeafIndex = checkpoint.leafIndex;
        record.diligenceCheckpointHash = checkpointHash;
        record.diligenceOperatorLeafHash = checkpoint.operatorLeafHash;
        record.diligenceRecomputedLeafHash = checkpoint.recomputedLeafHash;
        emit AuditDiligenceProven(
            taskId,
            auditor,
            record.auditedLeafIndex,
            checkpoint.checkpointIndex,
            checkpointHash
        );
    }

    function _isDiligenceRewardEligible(
        Task storage task,
        AuditRecord storage record
    ) internal view returns (bool) {
        if (!task.challengeTriggered) {
            return task.decision == FinalDecision.OperatorAccepted &&
                record.verdictSupportsOperator;
        }

        if (record.auditedLeafIndex != task.challengeLeafHint) {
            return false;
        }

        if (task.decision == FinalDecision.OperatorSlashed) {
            return !record.verdictSupportsOperator;
        }

        if (
            task.decision == FinalDecision.OperatorAccepted ||
            task.decision == FinalDecision.ChallengerSlashed
        ) {
            return record.verdictSupportsOperator;
        }

        return false;
    }

    function _slashWrongVerdictAuditors(
        bytes32 taskId,
        uint32 challengedLeafIndex,
        bool expectedSupportsOperator,
        address reporter,
        address excludedAuditor
    ) internal virtual {
        address[] storage assignedAuditors = taskAuditors[taskId];
        for (uint256 i = 0; i < assignedAuditors.length; i++) {
            address auditor = assignedAuditors[i];
            if (auditor == excludedAuditor) {
                continue;
            }

            AuditRecord storage record = audits[taskId][auditor];
            if (
                !record.opened ||
                record.wrongVerdictSlashed ||
                record.auditedLeafIndex != challengedLeafIndex ||
                record.verdictSupportsOperator == expectedSupportsOperator
            ) {
                continue;
            }

            record.wrongVerdictSlashed = true;
            uint256 paid = _slashAndReward(auditor, reporter, SLASH_AMOUNT_WEI);
            emit WrongVerdictAuditorSlashed(
                taskId,
                auditor,
                reporter,
                paid
            );
        }
    }

    function _validateLeafResolution(
        bytes32 taskId,
        LeafClaim calldata operatorLeaf,
        LeafClaim calldata challengerLeaf
    ) internal returns (uint32 leafIndex, bool admissible) {
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.Challenged) revert TaskNotChallenged();
        if (!(task.disputeEnd - task.disputeStart == 1)) revert NotEligible();
        if (secureTraceMode && !ITraceAvailability(availabilityModule).isDisputeReady(taskId)) {
            revert WrongPhase();
        }

        bytes32 operatorLeafHash = _leafHash(operatorLeaf);
        bytes32 challengerLeafHash = _leafHash(challengerLeaf);
        // Authenticate BOTH openings before attributing any fault: arbitrary
        // invalid calldata must only revert, never slash another participant.
        if (operatorLeafHash != task.currentOperatorNode || challengerLeafHash != task.currentChallengerNode) {
            revert InvalidParameter();
        }
        leafIndex = task.disputeStart;
        AuditRecord storage record = audits[taskId][task.challenger];
        bool malformed = operatorLeaf.opcode != challengerLeaf.opcode ||
            leafIndex != task.challengeLeafHint ||
            task.challengeErrorDigest != _challengeErrorDigest(taskId, leafIndex, operatorLeaf, challengerLeaf) ||
            (operatorLeaf.lhsHandle == challengerLeaf.lhsHandle &&
                operatorLeaf.rhsHandle == challengerLeaf.rhsHandle &&
                operatorLeaf.claimedHandle == challengerLeaf.claimedHandle);
        if (secureTraceMode) {
            // The operator's disclosed trace already passed requester-authorized
            // provenance checks. At the first divergent leaf an honest replay
            // therefore has the same operation and operand handles.
            malformed = malformed || operatorLeaf.lhsHandle != challengerLeaf.lhsHandle ||
                operatorLeaf.rhsHandle != challengerLeaf.rhsHandle ||
                record.diligenceOperatorLeafHash != operatorLeafHash ||
                record.diligenceRecomputedLeafHash != challengerLeafHash;
        }
        if (malformed) {
            if (!secureTraceMode) revert InvalidParameter(); // legacy regression surface
            _releaseChallengeBond(taskId, true, task.operator);
            _reopenAfterLostChallenge(taskId, task.challengeLeafHint);
            return (leafIndex, false);
        }
        return (leafIndex, true);
    }

    function _applyLeafDecision(
        bytes32 taskId,
        uint32 leafIndex,
        uint8 opcode,
        bool operatorValid,
        bool challengerValid,
        address verifier
    ) internal virtual {
        // The operator's terminal claim is what settlement depends on. When the
        // verifier invalidates it, the operator is slashed regardless of the
        // challenger's bit: an inconclusive or fabricated challenger witness
        // must not exonerate a claim the verifier already rejected.
        //
        // When BOTH claims validate, the two committed leaves differ as bytes
        // but decrypt to the same value: the challenger committed a
        // value-equal, byte-different result ciphertext (an independent
        // re-evaluation, or a deliberate re-encryption). The operator's claim
        // is correct, so the challenge is unsupported and settles against the
        // challenger. This case used to revert; a revert here left the terminal
        // round without a decision and `timeoutDispute` then slashed an
        // operator whose claim the verifier had just validated.
        Task storage task = tasks[taskId];
        emit LeafCheckedOnChain(
            taskId,
            leafIndex,
            opcode,
            operatorValid,
            challengerValid,
            verifier
        );

        // Settlement keys on the operator's claim, not on a vote or on the
        // challenger's witness: !operatorValid slashes the operator, whatever
        // the challenger's bit is.
        if (!operatorValid) {
            _releaseChallengeBond(taskId, false, task.challenger);
            _slashAndReward(task.operator, task.challenger, SLASH_AMOUNT_WEI);
            _slashWrongVerdictAuditors(
                taskId,
                leafIndex,
                false,
                task.challenger,
                address(0)
            );
            task.status = TaskStatus.Finalized;
            task.decision = FinalDecision.OperatorSlashed;
            emit TaskResolved(taskId, task.decision, task.challenger);
        } else {
            _releaseChallengeBond(taskId, true, task.operator);
            _reopenAfterLostChallenge(taskId, leafIndex);
        }
    }

    /// A lost challenge (leaf decided for the operator, or challenger
    /// abandonment) does not close the task: the losing challenger is barred
    /// from challenging again, the challenge window restarts, and the task
    /// returns to Auditing so that every other eligible dissenter keeps its
    /// challenge. Dissenting verdicts at the lost leaf are slashed only when
    /// the task finally finalizes as accepted. At most one challenge per
    /// assigned auditor bounds the number of disputes per task by the cohort.
    function _reopenAfterLostChallenge(bytes32 taskId, uint32 leafIndex) internal {
        Task storage task = tasks[taskId];
        AuditRecord storage loser = audits[taskId][task.challenger];
        loser.challengeSpent = true;
        loser.wrongVerdictSlashed = true; // the bond was its penalty
        task.hasLostChallenge = true;
        task.lostChallengeLeaf = leafIndex;
        task.challengeDeadline = uint64(block.timestamp) + (task.challengeDeadline - task.openDeadline);
        task.challengeTriggered = false;
        task.status = TaskStatus.Auditing;
        task.disputeStart = 0;
        task.disputeEnd = task.leafCount;
        task.currentOperatorNode = task.operatorTraceRoot;
        delete pendingFhevmLeafResolutions[taskId];
        delete bisectionRounds[taskId];
        emit ChallengeLost(taskId, task.challenger, leafIndex);
        task.challenger = address(0);
    }

    function _leafHash(LeafClaim calldata claim) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                claim.opcode,
                claim.lhsHandle,
                claim.rhsHandle,
                claim.claimedHandle
            )
        );
    }

    function _auditTraceLeafHash(
        bytes32 taskId,
        address auditor,
        AuditTraceLeaf calldata auditTraceLeaf
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    taskId,
                    auditor,
                    auditTraceLeaf.leafIndex,
                    auditTraceLeaf.operatorLeafHash,
                    auditTraceLeaf.recomputedLeafHash,
                    auditTraceLeaf.errorDigest
                )
            );
    }

    function _auditDiligenceCheckpointHash(
        bytes32 taskId,
        address auditor,
        bytes32 operatorTraceRoot,
        AuditDiligenceCheckpoint calldata checkpoint
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    DILIGENCE_CHECKPOINT_TYPEHASH,
                    taskId,
                    auditor,
                    operatorTraceRoot,
                    checkpoint.leafIndex,
                    checkpoint.checkpointIndex,
                    checkpoint.operatorLeafHash,
                    checkpoint.recomputedLeafHash,
                    checkpoint.previousCheckpointHash,
                    checkpoint.nextCheckpointHash,
                    checkpoint.transcriptDigest
                )
            );
    }

    function _verifyMerkleProof(
        bytes32 root,
        bytes32 leaf,
        bytes32[] calldata proof,
        bool[] calldata proofSiblingOnLeft
    ) internal pure returns (bool) {
        if (!(proof.length == proofSiblingOnLeft.length)) revert InvalidParameter(); // was: bad proof shape
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = proofSiblingOnLeft[i]
                ? keccak256(abi.encodePacked(proof[i], computed))
                : keccak256(abi.encodePacked(computed, proof[i]));
        }
        return computed == root;
    }

    function _challengeErrorDigest(
        bytes32 taskId,
        uint32 leafIndex,
        LeafClaim calldata operatorLeaf,
        LeafClaim calldata challengerLeaf
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                CHALLENGE_ERROR_TYPEHASH,
                taskId,
                leafIndex,
                operatorLeaf.opcode,
                operatorLeaf.lhsHandle,
                operatorLeaf.rhsHandle,
                operatorLeaf.claimedHandle,
                challengerLeaf.lhsHandle,
                challengerLeaf.rhsHandle,
                challengerLeaf.claimedHandle
            )
        );
    }

    /// @dev Clear-arithmetic fallback, reachable only from
    /// `resolveLeafDispute`, i.e. only when no FHEVM backend is configured and
    /// secure-trace mode is off. In that deployment a handle IS the 32-byte
    /// encoding of its value (`ciphertextHandleForClear` in scripts/evm-lib.mjs)
    /// and no confidentiality is claimed, so re-executing the opcode over
    /// uint256(handle) is exactly the check this path always performed. With an
    /// FHEVM backend the handles are keccak256 of real ciphertexts and this
    /// function is unreachable by construction.
    function _isValidLeaf(LeafClaim calldata claim) internal view returns (bool) {
        return objectiveVerifier.verifyLeaf(
            claim.opcode,
            uint256(claim.lhsHandle),
            uint256(claim.rhsHandle),
            uint256(claim.claimedHandle)
        );
    }

    function _verdictCommit(
        bool verdictSupportsOperator,
        bytes32 salt,
        bytes32 podRoot
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(verdictSupportsOperator, salt, podRoot));
    }

    function _openingKey(
        bytes32 taskId,
        address auditor,
        bool verdictSupportsOperator,
        bytes32 salt,
        bytes32 podRoot
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(taskId, auditor, verdictSupportsOperator, salt, podRoot)
        );
    }

    function _initializeTask(
        Task storage task,
        address operator,
        bytes32 operatorTraceRoot,
        bytes32 resultHash,
        uint32 leafCount
    ) internal {
        task.operator = operator;
        task.resultHash = resultHash;
        task.operatorTraceRoot = operatorTraceRoot;
        task.currentOperatorNode = operatorTraceRoot;
        task.leafCount = leafCount;
        task.disputeStart = 0;
        task.disputeEnd = leafCount;
        task.threshold = THRESHOLD_SHARES;
        task.status = TaskStatus.Auditing;
        // Audit windows start at sampling time (sampleParticipants), not at
        // creation, so the sampling delay never consumes the commit window.
    }

    function _availableStake(
        Participant storage participant
    ) internal view returns (uint256) {
        if (participant.stake <= participant.lockedChallengeBondWei) {
            return 0;
        }
        return participant.stake - participant.lockedChallengeBondWei;
    }

    function _lockChallengeBond(address challenger, uint256 bondWei) internal {
        Participant storage participant = participants[challenger];
        if (!(_availableStake(participant) >= bondWei)) revert NotEligible(); // was: challenge bond unavailable
        participant.lockedChallengeBondWei += bondWei;
    }

    /// @dev Extension seam for versions that reserve the bond at audit commitment.
    /// The historical games retain their original challenge-time reservation.
    function _activateChallengeBond(bytes32, address challenger, uint256 bondWei) internal virtual {
        _lockChallengeBond(challenger, bondWei);
    }

    function _releaseChallengeBond(
        bytes32 taskId,
        bool slashBond,
        address recipient
    ) internal virtual {
        Task storage task = tasks[taskId];
        uint256 bondWei = task.activeChallengeBondWei;
        if (bondWei == 0) {
            return;
        }

        Participant storage challengerParticipant = participants[task.challenger];
        if (!(challengerParticipant.lockedChallengeBondWei >= bondWei)) revert InvalidParameter(); // was: bond accounting mismatch
        challengerParticipant.lockedChallengeBondWei -= bondWei;
        task.activeChallengeBondWei = 0;

        if (!slashBond) {
            emit ChallengeBondReleased(
                taskId,
                task.challenger,
                task.challenger,
                bondWei,
                false
            );
            return;
        }

        uint256 transferableBond = bondWei;
        if (challengerParticipant.stake < transferableBond) {
            transferableBond = challengerParticipant.stake;
        }
        if (!(transferableBond > 0)) revert NotEligible(); // was: nothing to slash

        challengerParticipant.stake -= transferableBond;
        participants[recipient].stake += transferableBond;
        emit ChallengeBondReleased(
            taskId,
            task.challenger,
            recipient,
            transferableBond,
            true
        );
    }

    function _canSubmitBisection(
        bytes32 taskId,
        address actor,
        bool operatorSide
    ) internal view virtual returns (bool) {
        Task storage task = tasks[taskId];
        if (operatorSide && actor == task.operator) {
            return true;
        }
        if (!operatorSide && actor == task.challenger) {
            return true;
        }

        AuditRecord storage record = audits[taskId][actor];
        if (!record.assigned || !record.opened) {
            return false;
        }

        return record.verdictSupportsOperator == operatorSide;
    }

    function _requiredChallengeBond(
        uint32 leafCount
    ) internal pure returns (uint256) {
        uint256 bondWei =
            DISPUTE_BOND_BASE_WEI +
            (uint256(_maxBisectionRounds(leafCount)) * DISPUTE_BOND_PER_ROUND_WEI);
        if (bondWei < SLASH_AMOUNT_WEI) {
            return SLASH_AMOUNT_WEI;
        }
        return bondWei;
    }

    function _maxBisectionRounds(uint32 leafCount) internal pure returns (uint32) {
        uint32 rounds = 0;
        uint32 width = leafCount;
        while (width > 1) {
            width >>= 1;
            rounds += 1;
        }
        return rounds;
    }

    function _isPowerOfTwo(uint32 value) internal pure returns (bool) {
        return value > 0 && (value & (value - 1)) == 0;
    }
}
