// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    FHE,
    ebool,
    euint64,
    externalEuint64
} from "@fhevm/solidity/lib/FHE.sol";
import {CoprocessorConfig} from "@fhevm/solidity/lib/Impl.sol";

/// @notice FHEVM backend for one final disputed micro-instruction over the
/// ciphertext handles committed by the authenticated provenance trace.
/// @dev `FHE.fromExternal` validates every handle through the configured input
/// verifier. The disputed leaf is decided PURELY over handles: the operation is
/// recomputed homomorphically on the committed operand handles and each party's
/// claimed-output handle is compared to it under FHE, producing two encrypted
/// validity bits and nothing else. No cleartext operand enters this contract,
/// so a dispute reveals which operation was executed, never the data it ran on.
/// Structural origin and inter-leaf handle continuity are enforced by the
/// separate authenticated trace-availability module before this contract is
/// reachable.
///
/// MODEL LIMIT. The two validity bits are opened through the configured KMS
/// verifier (locally, `LocalFhevmKMSVerifier`, which reads the plaintexts the
/// local executor stored). That models threshold decryption of exactly two
/// booleans; it is the only decryption the dispute performs.
contract FhevmObjectiveMicroVerifier {
    uint8 public constant SOURCE_AUTHENTICATED_INPUT = 0;
    uint8 public constant SOURCE_PREVIOUS_OUTPUT = 1;
    uint8 public constant SOURCE_PUBLIC_CONSTANT = 2;
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
    uint64 public constant MAX_COMPOUND_OPS = 8;

    /// @notice The disputed leaf, as handles. There is deliberately no
    /// cleartext operand field: the only clear datum the backend uses is the
    /// PUBLIC control scalar of SHR/DIV/MOD/ADD_CHAIN, and that is read out of
    /// `rhsHandle` (see `_controlConstant`), so it cannot be chosen
    /// independently of the committed trace.
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

    event FhevmLeafCheckRequested(
        bytes32 indexed taskId,
        uint32 indexed leafIndex,
        bytes32 operatorValidHandle,
        bytes32 challengerValidHandle
    );
    event FhevmLeafCheckFinalized(
        bytes32 indexed taskId,
        uint32 indexed leafIndex,
        bool operatorValid,
        bool challengerValid
    );

    error UnsupportedOpcode(uint8 opcode);
    error InvalidCiphertextWitness();

    constructor(address acl, address executor, address kmsVerifier) {
        require(acl != address(0), "bad acl");
        require(executor != address(0), "bad executor");
        require(kmsVerifier != address(0), "bad kms");
        FHE.setCoprocessor(
            CoprocessorConfig({
                ACLAddress: acl,
                CoprocessorAddress: executor,
                KMSVerifierAddress: kmsVerifier
            })
        );
    }

    function requestLeafCheck(
        bytes32 taskId,
        uint32 leafIndex,
        LeafPair calldata pair
    )
        external
        returns (
            bytes32 operatorValidHandle,
            bytes32 challengerValidHandle
        )
    {
        if (
            pair.operatorClaimedProof.length == 0 ||
            pair.challengerClaimedProof.length == 0
        ) revert InvalidCiphertextWitness();

        euint64 lhsEncrypted = _loadOperand(
            pair.lhsSourceKind,
            pair.lhsHandle,
            pair.lhsInputProof
        );
        euint64 rhsEncrypted = _loadOperand(
            pair.rhsSourceKind,
            pair.rhsHandle,
            pair.rhsInputProof
        );
        euint64 operatorClaimedEncrypted = FHE.fromExternal(
            externalEuint64.wrap(pair.operatorClaimedHandle),
            pair.operatorClaimedProof
        );
        euint64 challengerClaimedEncrypted = FHE.fromExternal(
            externalEuint64.wrap(pair.challengerClaimedHandle),
            pair.challengerClaimedProof
        );
        // The leaf relation is recomputed ONCE, from the operand handles the
        // trace committed; each party's claim is then a handle-to-handle
        // comparison against it. Both parties are judged against the same
        // recomputation, which is what makes the decision objective.
        (ebool operatorValid, ebool challengerValid) = _verifyClaim(
            pair.opcode,
            lhsEncrypted,
            rhsEncrypted,
            operatorClaimedEncrypted,
            challengerClaimedEncrypted,
            pair.rhsHandle
        );

        operatorValid = FHE.makePubliclyDecryptable(operatorValid);
        challengerValid = FHE.makePubliclyDecryptable(challengerValid);
        operatorValidHandle = FHE.toBytes32(operatorValid);
        challengerValidHandle = FHE.toBytes32(challengerValid);

        emit FhevmLeafCheckRequested(
            taskId,
            leafIndex,
            operatorValidHandle,
            challengerValidHandle
        );
    }

    function finalizeLeafCheck(
        bytes32 taskId,
        uint32 leafIndex,
        bytes32 operatorValidHandle,
        bytes32 challengerValidHandle,
        bool operatorValid,
        bool challengerValid,
        bytes calldata decryptionProof
    ) external returns (bool, bool) {
        bytes32[] memory handles = new bytes32[](2);
        handles[0] = operatorValidHandle;
        handles[1] = challengerValidHandle;
        FHE.checkSignatures(
            handles,
            abi.encode(operatorValid, challengerValid),
            decryptionProof
        );
        emit FhevmLeafCheckFinalized(
            taskId,
            leafIndex,
            operatorValid,
            challengerValid
        );
        return (operatorValid, challengerValid);
    }

    /// @notice Decides both parties' claims for one leaf, over handles only.
    /// @dev Loads nothing in the clear: `expected` is the leaf operation
    /// recomputed homomorphically on the committed operand handles, and each
    /// party's bit is `FHE.eq(expected, itsClaimedHandle)` ANDed with the
    /// encrypted range guard. There is no opening to compare against, so there
    /// is nothing to reveal.
    function _verifyClaim(
        uint8 opcode,
        euint64 lhsEncrypted,
        euint64 rhsEncrypted,
        euint64 operatorClaimedEncrypted,
        euint64 challengerClaimedEncrypted,
        bytes32 rhsHandle
    ) internal returns (ebool operatorValid, ebool challengerValid) {
        (euint64 expected, ebool valid) = _expectedFromHandles(
            opcode,
            lhsEncrypted,
            rhsEncrypted,
            rhsHandle
        );
        operatorValid = FHE.and(valid, FHE.eq(expected, operatorClaimedEncrypted));
        challengerValid = FHE.and(valid, FHE.eq(expected, challengerClaimedEncrypted));
    }

    /// @notice The PUBLIC control scalar of an opcode whose second operand is
    /// fixed by the program tree rather than by user data.
    /// @dev SHR's shift amount, DIV's divisor, MOD's modulus and ADD_CHAIN's
    /// length are public by construction (a panel size, an SLA threshold, a
    /// fixed-point scale). Their handle is therefore the 32-byte big-endian
    /// encoding of the scalar itself, not an encryption of anything -- see
    /// `ciphertextHandleForClear` in scripts/evm-lib.mjs and the
    /// SOURCE_PUBLIC_CONSTANT branch of AuthenticatedTraceAvailability. Reading
    /// the scalar out of the committed handle (rather than accepting it as a
    /// separate argument) is what keeps it bound to the disputed leaf: a caller
    /// cannot swap in a different divisor without changing the leaf hash, and
    /// therefore without failing bisection.
    ///
    /// A handle that does not fit in uint64 is not such an encoding -- it is a
    /// real ciphertext handle in a position the ISA does not admit one -- and
    /// `outOfRange` reports it so the leaf resolves as invalid for BOTH parties
    /// instead of settling on an arbitrary scalar.
    function _controlConstant(
        bytes32 rhsHandle
    ) internal pure returns (uint64 control, bool outOfRange) {
        uint256 raw = uint256(rhsHandle);
        if (raw > type(uint64).max) return (0, true);
        return (uint64(raw), false);
    }

    /// Homomorphic recomputation of the leaf operation over operand handles,
    /// plus the encrypted validity guard.
    ///
    /// @dev Range guards. The micro-ISA rejects out-of-range leaves rather than
    /// wrapping, and that semantics is preserved here. The guards split in two:
    ///
    ///  (a) Guards on the ENCRYPTED operands -- MUL/ADD/ADD_CHAIN overflow and
    ///      SUB underflow. These cannot be decided with an `if`, because
    ///      nothing here can read an operand. They are computed as ENCRYPTED
    ///      predicates and ANDed into both validity bits, so an overflowing
    ///      leaf yields validity 0 for both parties, exactly as the clear
    ///      checker returned false for both. Wrap-around is detectable without
    ///      revealing anything: an unsigned sum wraps exactly when the result
    ///      is smaller than an addend, and a difference underflows exactly when
    ///      lhs < rhs.
    ///
    ///  (b) Guards on the PUBLIC control scalar -- shift >= 64, zero divisor or
    ///      modulus, chain length outside 1..MAX_COMPOUND_OPS. These stay
    ///      CLEAR, because the scalar is public by construction (see
    ///      `_controlConstant`); PUBLIC_SCALAR_RHS_OPCODES in
    ///      scripts/micro-isa.mjs is the same list. A violated guard sets the
    ///      validity bit to an encrypted false for both parties rather than
    ///      reverting, so an undecidable leaf still SETTLES (against the
    ///      operator, whose claim it is) instead of stalling the dispute.
    ///
    /// MUL overflow is detected by splitting both operands into 32-bit halves
    /// under FHE: with a = ah*2^32+al and b = bh*2^32+bl, the product fits in
    /// 64 bits exactly when ah*bh == 0, when the middle term ah*bl + al*bh is
    /// below 2^32, and when adding the low term to it does not wrap. That is
    /// three encrypted multiplications and four comparisons; it needs no
    /// 128-bit intermediate and no division by an encrypted operand, neither of
    /// which the euint64 surface offers.
    /// @return expected homomorphic result of the leaf relation
    /// @return valid   encrypted validity guard for this leaf
    function _expectedFromHandles(
        uint8 opcode,
        euint64 lhsEncrypted,
        euint64 rhsEncrypted,
        bytes32 rhsHandle
    ) internal returns (euint64 expected, ebool valid) {
        valid = FHE.asEbool(true);
        if (opcode == OPCODE_MUL) {
            return (
                FHE.mul(lhsEncrypted, rhsEncrypted),
                _mulFitsInU64(lhsEncrypted, rhsEncrypted)
            );
        } else if (opcode == OPCODE_CAST_U8) {
            // width-restrict to the low 8 bits, homomorphically; identical to
            // the `uint64(uint8(lhs))` truncation of the clear checker.
            return (FHE.and(lhsEncrypted, FHE.asEuint64(0xff)), valid);
        } else if (opcode == OPCODE_MIN) {
            return (FHE.min(lhsEncrypted, rhsEncrypted), valid);
        } else if (opcode == OPCODE_BITAND) {
            return (FHE.and(lhsEncrypted, rhsEncrypted), valid);
        } else if (opcode == OPCODE_ADD) {
            expected = FHE.add(lhsEncrypted, rhsEncrypted);
            // No wrap  <=>  lhs + rhs >= lhs  (unsigned).
            return (expected, FHE.ge(expected, lhsEncrypted));
        } else if (opcode == OPCODE_SUB) {
            // No underflow  <=>  rhs <= lhs.
            return (
                FHE.sub(lhsEncrypted, rhsEncrypted),
                FHE.le(rhsEncrypted, lhsEncrypted)
            );
        } else if (opcode == OPCODE_EQ) {
            return (FHE.asEuint64(FHE.eq(lhsEncrypted, rhsEncrypted)), valid);
        } else if (opcode == OPCODE_LT) {
            return (FHE.asEuint64(FHE.lt(lhsEncrypted, rhsEncrypted)), valid);
        } else if (opcode == OPCODE_GT) {
            return (FHE.asEuint64(FHE.gt(lhsEncrypted, rhsEncrypted)), valid);
        } else if (opcode == OPCODE_BITOR) {
            return (FHE.or(lhsEncrypted, rhsEncrypted), valid);
        } else if (opcode == OPCODE_BITXOR) {
            return (FHE.xor(lhsEncrypted, rhsEncrypted), valid);
        }

        // ----- opcodes controlled by a PUBLIC scalar (guards stay clear) -----
        (uint64 control, bool outOfRange) = _controlConstant(rhsHandle);
        ebool rejected = FHE.asEbool(false);
        if (opcode == OPCODE_SHR) {
            if (outOfRange || control >= 64) return (lhsEncrypted, rejected);
            return (FHE.shr(lhsEncrypted, uint8(control)), valid);
        } else if (opcode == OPCODE_DIV) {
            if (outOfRange || control == 0) return (lhsEncrypted, rejected);
            return (FHE.div(lhsEncrypted, control), valid);
        } else if (opcode == OPCODE_MOD) {
            if (outOfRange || control == 0) return (lhsEncrypted, rejected);
            return (FHE.rem(lhsEncrypted, control), valid);
        } else if (opcode == OPCODE_ADD_CHAIN) {
            if (outOfRange || control == 0 || control > MAX_COMPOUND_OPS) {
                return (lhsEncrypted, rejected);
            }
            euint64 one = FHE.asEuint64(1);
            euint64 acc = lhsEncrypted;
            for (uint64 i = 0; i < control; i++) {
                acc = FHE.add(acc, one);
            }
            // The whole chain adds `control`, so the same wrap test applies.
            return (acc, FHE.ge(acc, lhsEncrypted));
        }
        revert UnsupportedOpcode(opcode);
    }

    /// @notice Encrypted "a*b fits in 64 bits" predicate. See the overflow note
    /// on `_expectedFromHandles`.
    function _mulFitsInU64(
        euint64 a,
        euint64 b
    ) internal returns (ebool) {
        euint64 mask = FHE.asEuint64(0xffffffff);
        euint64 aHigh = FHE.shr(a, 32);
        euint64 aLow = FHE.and(a, mask);
        euint64 bHigh = FHE.shr(b, 32);
        euint64 bLow = FHE.and(b, mask);
        // Both halves high  =>  the product needs at least 2^64.
        ebool highProductZero = FHE.eq(FHE.mul(aHigh, bHigh), FHE.asEuint64(0));
        // Middle term; it cannot itself wrap unless highProductZero is already
        // false, and that case is rejected by the term above.
        euint64 middle = FHE.add(FHE.mul(aHigh, bLow), FHE.mul(aLow, bHigh));
        ebool middleFits = FHE.le(middle, mask);
        euint64 middleShifted = FHE.shl(middle, 32);
        euint64 total = FHE.add(middleShifted, FHE.mul(aLow, bLow));
        ebool lowFits = FHE.ge(total, middleShifted);
        return FHE.and(FHE.and(highProductZero, middleFits), lowFits);
    }

    /// @dev Loads one operand from its committed handle. A PUBLIC_CONSTANT
    /// operand's handle IS its value (that is what makes it public), so it is
    /// trivially encrypted here; every other operand is a real ciphertext and
    /// must come with an input proof the FHEVM input verifier accepts.
    function _loadOperand(
        uint8 sourceKind,
        bytes32 handle,
        bytes calldata inputProof
    ) internal returns (euint64) {
        if (sourceKind == SOURCE_PUBLIC_CONSTANT) {
            if (inputProof.length != 0 || uint256(handle) > type(uint64).max) {
                revert InvalidCiphertextWitness();
            }
            return FHE.asEuint64(uint64(uint256(handle)));
        }
        if (
            (sourceKind != SOURCE_AUTHENTICATED_INPUT &&
                sourceKind != SOURCE_PREVIOUS_OUTPUT) ||
            inputProof.length == 0
        ) revert InvalidCiphertextWitness();
        return FHE.fromExternal(externalEuint64.wrap(handle), inputProof);
    }
}
