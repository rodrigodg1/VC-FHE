// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MKLHSVerification
 * @notice Multi-key linearly homomorphic signature (MKLHS) verification for the
 *         linear path, in the style of Aranha--Pagnin (LATINCRYPT 2019),
 *         adapted so that on-chain result verification stays O(1).
 *
 *         Design. Each data owner i holds its own BLS key pair
 *         (sk_i, pk_i = sk_i * G2) and signs a context-bound message point that
 *         carries its OWN lifted LWE ciphertext commitment:
 *             M_i     = MapToGroup( ctx_i ),
 *             ctx_i   = DST || pk_i || tag || i || op || N || P(c_i),
 *             sigma_i = sk_i * M_i.
 *         The commitment sits inside the hash preimage, so the signature has no
 *         linear structure: no scalar multiple and no combination of signatures
 *         verifies against a different commitment. The homomorphism lives only
 *         in P. There is no data-curation authority: no single party can admit,
 *         substitute, or fabricate another owner's record.
 *
 *         Instead of verifying an O(N)-pairing product at result time, the
 *         contract verifies each admission ONCE (one 2-pair pairing check per
 *         record, paid by the admission transaction) and accumulates
 *             P_agg = sum_i w_i * P(c_i)
 *         on-chain. At result submission the check is a single G1 equality
 *             P(A_out) == P_agg,
 *         which is O(1) and requires no pairing. Under the DLR assumption the
 *         equality binds the delivered lifted accumulator A_out to the
 *         authorized linear combination of the owner-signed inputs.
 *
 *         Enrollment. The participant set is fixed at deployment as a list of
 *         owner addresses (the dataset schema, analogous to the fixed
 *         statement). Each owner self-registers its BLS G2 public key from its
 *         enrolled address; key substitution by third parties is impossible
 *         at the contract layer.
 *
 *         Liveness trade-off (documented, deliberate): a result can only be
 *         finalized after ALL N records are admitted, so a non-participating
 *         owner delays finalization. Omission of an admitted record by the
 *         aggregator is impossible (the accumulator is maintained by the
 *         contract, not by the operator).
 */
contract MKLHSVerification {
    // === Fixed dataset configuration ===
    string public datasetRef;
    uint64 public scale;
    uint64 public totalItems;
    uint8 public allowedOperation; // 0 = SUM, 1 = SUB
    bytes32 public datasetTag; // dataset/epoch tag bound into every signed context

    address public owner; // deployment admin: task assignment only

    error Unauthorized();
    error InvalidOperation();
    error InvalidDatasetTag();
    error InvalidG1Point();
    error InvalidPublicKey();
    error InvalidTask();
    error TaskAlreadyConsumed();
    error InvalidResult();
    error NotEnrolled();
    error KeyAlreadyRegistered();
    error KeyNotRegistered();
    error AlreadyAdmitted();
    error IncompleteAdmission();
    error InvalidSignature();
    error InvalidIndex();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // === Per-owner enrollment and keys ===
    // index i -> enrolled owner address (fixed at deployment)
    mapping(uint64 => address) public recordOwner;
    // index i -> registered BLS G2 public key [x0, x1, y0, y1]
    mapping(uint64 => uint256[4]) internal ownerKey;
    mapping(uint64 => bool) public keyRegistered;

    // === Admission state ===
    mapping(uint64 => bool) public admitted;
    // index i -> admitted ciphertext-vector commitment P(c_i)
    mapping(uint64 => uint256[2]) internal admittedCommitment;
    uint64 public admittedCount;
    // Running accumulator P_agg = sum_i w_i * P(c_i) over admitted records.
    uint256[2] public aggregateCommitment;
    bool internal aggregateInitialized;

    // === Economic security (same reject-not-slash policy as the LHS path) ===
    mapping(address => uint256) public stakes;
    uint256 public constant MIN_STAKE = 1 ether;

    // === One-shot task assignment ===
    mapping(bytes32 => address) public taskOperator;

    struct BoundResult {
        uint256[2] outputCommitment;
        bytes32 outputDigest;
        address operator;
        bool accepted;
    }
    mapping(bytes32 => BoundResult) private boundResults;

    event StakeDeposited(address indexed operator, uint256 amount);
    event OwnerKeyRegistered(uint64 indexed index, address indexed ownerAddr);
    event RecordAdmitted(
        uint64 indexed index,
        address indexed submitter,
        uint256[2] commitment
    );
    event TaskRegistered(bytes32 indexed taskId, address indexed operator);
    event ResultBound(
        bytes32 indexed taskId,
        bytes32 indexed outputDigest,
        uint256[2] outputCommitment,
        address indexed operator
    );

    /**
     * @param _datasetRef  Reference to dataset, e.g. "./Users_Ratings.csv"
     * @param _scale       Fixed-point scaling factor (e.g. 1000)
     * @param _totalItems  Number of records N in the fixed statement.
     *        The leveled-regime decryption budgets of the LHS path apply
     *        unchanged (enforced by operator/consumer tooling off-chain).
     * @param _allowedOperation 0 = SUM (all w_i = +1),
     *                          1 = SUB (w_0 = +1, w_{i>0} = -1)
     * @param _datasetTag  Mandatory non-zero dataset/epoch tag.
     * @param _owners      Enrolled owner address for each index 0..N-1.
     */
    constructor(
        string memory _datasetRef,
        uint64 _scale,
        uint64 _totalItems,
        uint8 _allowedOperation,
        bytes32 _datasetTag,
        address[] memory _owners
    ) payable {
        require(bytes(_datasetRef).length > 0, "empty datasetRef");
        require(_scale > 0 && _totalItems > 0, "invalid params");
        if (_allowedOperation > 1) revert InvalidOperation();
        if (_datasetTag == bytes32(0)) revert InvalidDatasetTag();
        require(_owners.length == _totalItems, "owners length mismatch");

        datasetRef = _datasetRef;
        scale = _scale;
        totalItems = _totalItems;
        allowedOperation = _allowedOperation;
        datasetTag = _datasetTag;
        owner = msg.sender;

        require(msg.value >= MIN_STAKE, "Insufficient setup stake");
        stakes[msg.sender] = msg.value;
        emit StakeDeposited(msg.sender, msg.value);

        for (uint64 i = 0; i < _totalItems; i++) {
            require(_owners[i] != address(0), "zero owner");
            recordOwner[i] = _owners[i];
        }
        // NOTE: no O(N) hash-to-curve loop here. The message point M_i is
        // derived per admission, and no aggregate message point is ever needed
        // on-chain because result verification is an accumulator equality, not
        // a pairing. Deployment cost drops accordingly.
    }

    function depositStake() external payable {
        require(msg.value > 0, "Deposit value must be > 0");
        stakes[msg.sender] += msg.value;
        emit StakeDeposited(msg.sender, msg.value);
    }

    /// @notice Owner i self-registers its BLS G2 public key. Only the enrolled
    ///         address for that index may register, and only once.
    function registerOwnerKey(uint64 index, uint256[4] memory pk) external {
        if (index >= totalItems) revert InvalidIndex();
        if (msg.sender != recordOwner[index]) revert NotEnrolled();
        if (keyRegistered[index]) revert KeyAlreadyRegistered();
        require(
            pk[0] != 0 || pk[1] != 0 || pk[2] != 0 || pk[3] != 0,
            "empty pubkey"
        );
        if (!_isValidG2Point(pk)) revert InvalidPublicKey();
        ownerKey[index] = pk;
        keyRegistered[index] = true;
        emit OwnerKeyRegistered(index, msg.sender);
    }

    function getOwnerKey(uint64 index)
        external
        view
        returns (uint256[4] memory)
    {
        if (!keyRegistered[index]) revert KeyNotRegistered();
        return ownerKey[index];
    }

    /// @notice Admit record i: verify the owner's MKLHS signature over the
    ///         ciphertext-vector commitment and fold it into the accumulator.
    /// @dev Verifies e(sigma, G2) * e(-M_i, pk_i) == 1 with M_i = H2C(ctx || P(c_i)).
    ///      Callable by anyone (owner or relayer); authenticity comes from the
    ///      signature, not from msg.sender.
    function admitRecord(
        uint64 index,
        uint256[2] memory commitment,
        uint256[2] memory signature
    ) external {
        if (index >= totalItems) revert InvalidIndex();
        if (!keyRegistered[index]) revert KeyNotRegistered();
        if (admitted[index]) revert AlreadyAdmitted();
        _requireCanonicalG1(commitment, false);
        _requireCanonicalG1(signature, false);
        // The commitment is folded into the accumulator, and the first fold
        // bypasses the point-add precompile, so validate the curve equation
        // here instead of relying on a precompile that may not be reached.
        _requireOnCurveG1(commitment);

        // M_i = H2C(context || P(c_i)): the commitment is inside the hash, so
        // the message point has no additive structure an attacker can exploit.
        uint256[2] memory message = hashContextToG1(index, commitment);
        if (!_pairingCheck(signature, ownerKey[index], message)) {
            revert InvalidSignature();
        }

        admitted[index] = true;
        admittedCommitment[index] = commitment;
        admittedCount += 1;

        // Fold w_i * P(c_i) into the accumulator.
        // SUM: w_i = +1. SUB: w_0 = +1, w_{i>0} = -1.
        uint256[2] memory term = commitment;
        if (allowedOperation == 1 && index != 0) {
            term = _negateG1(term);
        }
        if (!aggregateInitialized) {
            aggregateCommitment = term;
            aggregateInitialized = true;
        } else {
            aggregateCommitment = bn256PointAdd(aggregateCommitment, term);
        }

        emit RecordAdmitted(index, msg.sender, commitment);
    }

    function getAdmittedCommitment(uint64 index)
        external
        view
        returns (uint256[2] memory)
    {
        require(admitted[index], "not admitted");
        return admittedCommitment[index];
    }

    /// @notice Assign a unique computation task to an operator before submission.
    function registerTask(bytes32 taskId, address operator) external onlyOwner {
        if (taskId == bytes32(0) || operator == address(0)) revert InvalidTask();
        if (taskOperator[taskId] != address(0) || boundResults[taskId].accepted) {
            revert TaskAlreadyConsumed();
        }
        taskOperator[taskId] = operator;
        emit TaskRegistered(taskId, operator);
    }

    /// @notice O(1) verification of the delivered output commitment against
    ///         the on-chain accumulator of owner-signed admissions.
    function verifyBound(uint256[2] memory outputCommitment)
        public
        view
        returns (bool)
    {
        if (admittedCount != totalItems) revert IncompleteAdmission();
        _requireCanonicalG1(outputCommitment, false);
        return
            outputCommitment[0] == aggregateCommitment[0] &&
            outputCommitment[1] == aggregateCommitment[1];
    }

    /// @notice Submit an output-bound result for a pre-assigned, one-shot task.
    ///         Accepts only if P(A_out) equals the accumulated commitment of
    ///         all owner-signed records under the authorized weights.
    function submitResultBound(
        bytes32 taskId,
        bytes32 outputDigest,
        uint256[2] memory outputCommitment
    ) external {
        require(stakes[msg.sender] >= MIN_STAKE, "Insufficient Stake");
        if (taskId == bytes32(0) || outputDigest == bytes32(0)) revert InvalidTask();
        if (boundResults[taskId].accepted) revert TaskAlreadyConsumed();
        if (taskOperator[taskId] != msg.sender) revert Unauthorized();

        if (!verifyBound(outputCommitment)) revert InvalidResult();

        boundResults[taskId] = BoundResult({
            outputCommitment: outputCommitment,
            outputDigest: outputDigest,
            operator: msg.sender,
            accepted: true
        });
        delete taskOperator[taskId];
        emit ResultBound(taskId, outputDigest, outputCommitment, msg.sender);
    }

    function getBoundResult(bytes32 taskId)
        external
        view
        returns (
            uint256[2] memory outputCommitment,
            bytes32 outputDigest,
            address operator,
            bool accepted
        )
    {
        BoundResult storage result = boundResults[taskId];
        return (
            result.outputCommitment,
            result.outputDigest,
            result.operator,
            result.accepted
        );
    }

    // =========================================================================
    // Curve helpers (BN254), shared conventions with LHSVerification
    // =========================================================================

    uint256 constant BN254_BASE_FIELD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /// 2^256 mod p, used for the exact 512-bit reduction in `mapToG1`.
    uint256 constant TWO_POW_256_MOD_P =
        6350874878119819312338956282401532409788428879151445726012394534686998597021;

    /// MapToGroup trial bound, `I = 8` in the notation of Boneh-Lynn-Shacham.
    /// A preimage is unhashable with probability 2^-256.
    uint256 constant MAP_TRIALS = 256;

    /// @dev e(sig, G2) == e(message, pk)  <=>  e(sig, G2) * e(-message, pk) == 1
    function _pairingCheck(
        uint256[2] memory sig,
        uint256[4] memory pk,
        uint256[2] memory message
    ) internal view returns (bool) {
        uint256[2] memory negMessage = _negateG1(message);
        uint256[] memory input = new uint256[](12);

        input[0] = sig[0];
        input[1] = sig[1];
        input[
            2
        ] = 11559732032986387107991004021392285783925812861821192530917403151452391805634; // G2 x1
        input[
            3
        ] = 10857046999023057135944570762232829481370756359578518086990519993285655852781; // G2 x0
        input[
            4
        ] = 4082367875863433681332203403145435568316851327593401208105741076214120093531; // G2 y1
        input[
            5
        ] = 8495653923123431417604973247489272438418190587263600148770280649306958101930; // G2 y0

        input[6] = negMessage[0];
        input[7] = negMessage[1];
        input[8] = pk[1]; // x1
        input[9] = pk[0]; // x0
        input[10] = pk[3]; // y1
        input[11] = pk[2]; // y0

        uint256[1] memory out;
        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                0x08,
                add(input, 0x20),
                0x180,
                out,
                0x20
            )
        }
        require(success, "Pairing check failed");
        return out[0] == 1;
    }

    function bn256PointAdd(
        uint256[2] memory p1,
        uint256[2] memory p2
    ) internal view returns (uint256[2] memory r) {
        uint256[4] memory input;
        input[0] = p1[0];
        input[1] = p1[1];
        input[2] = p2[0];
        input[3] = p2[1];
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 0x06, input, 0x80, r, 0x40)
        }
        require(success, "Point add failed");
    }

    function _requireCanonicalG1(
        uint256[2] memory point,
        bool allowInfinity
    ) internal pure {
        if (point[0] >= BN254_BASE_FIELD || point[1] >= BN254_BASE_FIELD) {
            revert InvalidG1Point();
        }
        if (!allowInfinity && point[0] == 0 && point[1] == 0) {
            revert InvalidG1Point();
        }
    }

    /// @notice Curve-equation check y^2 == x^3 + 3 over the BN254 base field.
    /// @dev `_requireCanonicalG1` only bounds the coordinates. For the SIGNATURE
    ///      that is sufficient, because the pairing precompile (0x08) rejects a
    ///      point that is not on the curve. For the COMMITMENT it was NOT: the
    ///      commitment never reaches a pairing, and its only curve validation
    ///      came from the point-add precompile (0x06) -- which the accumulator
    ///      initialisation branch skips on the first admitted record. An owner
    ///      that signed an off-curve "commitment" for the first admitted index
    ///      therefore left `aggregateCommitment` off the curve, after which every
    ///      later `admitRecord` reverted inside 0x06 and the deployment could
    ///      never finalise (finalisation requires all N admissions).
    ///
    ///      This does not contradict the output-binding proposition, which
    ///      assumes honest owners, but it is a corrupted-owner denial of service
    ///      that costs one transaction. Checking the curve equation directly is
    ///      a few hundred gas and removes the branch-dependent validation.
    ///      G1 on BN254 has cofactor one, so on-curve implies prime-order
    ///      subgroup membership and no cofactor clearing is required.
    function _requireOnCurveG1(uint256[2] memory point) internal pure {
        uint256 x = point[0];
        uint256 y = point[1];
        uint256 lhs = mulmod(y, y, BN254_BASE_FIELD);
        uint256 rhs = addmod(
            mulmod(mulmod(x, x, BN254_BASE_FIELD), x, BN254_BASE_FIELD),
            3,
            BN254_BASE_FIELD
        );
        if (lhs != rhs) revert InvalidG1Point();
    }

    function _negateG1(
        uint256[2] memory point
    ) internal pure returns (uint256[2] memory negated) {
        if (point[0] == 0 && point[1] == 0) {
            return point;
        }
        negated[0] = point[0];
        negated[1] = BN254_BASE_FIELD - point[1];
    }

    /// Validate that a registered key is a canonical G2 subgroup point.
    function _isValidG2Point(
        uint256[4] memory pubkey
    ) internal view returns (bool) {
        uint256[] memory input = new uint256[](12);
        input[0] = 1;
        input[1] = 2;
        input[2] = pubkey[1];
        input[3] = pubkey[0];
        input[4] = pubkey[3];
        input[5] = pubkey[2];
        input[6] = 1;
        input[7] = BN254_BASE_FIELD - 2;
        input[8] = pubkey[1];
        input[9] = pubkey[0];
        input[10] = pubkey[3];
        input[11] = pubkey[2];

        uint256[1] memory out;
        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                0x08,
                add(input, 0x20),
                0x180,
                out,
                0x20
            )
        }
        return success && out[0] == 1;
    }

    /// @notice Context-bound message point for index `i`:
    ///   M_i = MapToGroup( DST || pk_i || tag || i || op || N || P(c_i) )
    /// @dev The commitment is inside the hash preimage, so the signature is not
    ///      linearly malleable: no scalar multiple and no combination of two
    ///      signatures under the same label yields a valid pair for a different
    ///      commitment. The owner key, authorized operation and input count are
    ///      bound as well, so admissions cannot be replayed into a deployment
    ///      with a different operation, size or enrolled key. The preimage uses
    ///      fixed-width fields only, so the encoding is injective.
    function hashContextToG1(
        uint64 index,
        uint256[2] memory commitment
    ) internal view returns (uint256[2] memory) {
        uint256[4] memory pk = ownerKey[index];
        bytes memory ctx = abi.encodePacked(
            "MKLHS_CTX_V1_",
            pk[0],
            pk[1],
            pk[2],
            pk[3],
            datasetTag,
            index,
            allowedOperation,
            totalItems,
            commitment[0],
            commitment[1]
        );
        return mapToG1(keccak256(ctx));
    }

    /// @notice MapToGroup of Boneh-Lynn-Shacham on BN254; must match the Rust
    ///         `hash_to_g1` and the JS tooling byte for byte.
    /// @dev The caller passes `seed = keccak256(preimage)`; every trial expands
    ///      that seed instead of rehashing the preimage. For each trial counter,
    ///      two Keccak256 blocks supply 512 bits that are reduced modulo the base
    ///      field, which bounds the reduction bias by about 2^-261, and a third
    ///      block supplies the root-selection bit. On failure the counter is
    ///      incremented and the blocks are recomputed, so the accepted
    ///      x-coordinate is uniform over the coordinates satisfying the curve
    ///      equation and the returned point is uniform over G1 \ {O}. With
    ///      MAP_TRIALS = 256 and success probability close to 1/2 per trial, a
    ///      preimage is unhashable with probability 2^-256. The cofactor of G1 on
    ///      BN254 is one, so no cofactor clearing is applied.
    function mapToG1(
        bytes32 seed
    ) internal view returns (uint256[2] memory) {
        for (uint256 trial = 0; trial < MAP_TRIALS; trial++) {
            uint8 t = uint8(trial);
            uint256 t0 = uint256(keccak256(abi.encodePacked(bytes1(0x00), t, seed)));
            uint256 t1 = uint256(keccak256(abi.encodePacked(bytes1(0x01), t, seed)));
            // x = (t0 * 2^256 + t1) mod p, an exact wide reduction of 512 bits.
            uint256 x = addmod(
                mulmod(t0, TWO_POW_256_MOD_P, BN254_BASE_FIELD),
                t1 % BN254_BASE_FIELD,
                BN254_BASE_FIELD
            );
            uint256 b = uint256(
                keccak256(abi.encodePacked(bytes1(0x02), t, seed))
            ) & 1;

            uint256 x_sq = mulmod(x, x, BN254_BASE_FIELD);
            uint256 x_cubed = mulmod(x_sq, x, BN254_BASE_FIELD);
            uint256 y_sq = addmod(x_cubed, 3, BN254_BASE_FIELD);
            uint256 y = modExpSqrt(y_sq);
            if (mulmod(y, y, BN254_BASE_FIELD) == y_sq) {
                uint256 negY = BN254_BASE_FIELD - y;
                uint256 y0 = y <= negY ? y : negY;
                return [x, b == 0 ? y0 : BN254_BASE_FIELD - y0];
            }
        }
        revert InvalidG1Point();
    }

    function modExpSqrt(uint256 base) internal view returns (uint256 result) {
        uint256 exponent =
            5472060717959818805561601436314318772174077789324455915672259473661306552146;

        bytes memory input = new bytes(192);
        assembly {
            mstore(add(input, 0x20), 32)
            mstore(add(input, 0x40), 32)
            mstore(add(input, 0x60), 32)
            mstore(add(input, 0x80), base)
            mstore(add(input, 0xa0), exponent)
            mstore(add(input, 0xc0), 21888242871839275222246405745257275088696311157297823662689037894645226208583)
        }

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                0x05,
                add(input, 0x20),
                0xc0,
                add(input, 0x20),
                0x20
            )
            result := mload(add(input, 0x20))
        }
        require(success, "modexp failed");
    }

    function getConfig()
        public
        view
        returns (
            string memory _datasetRef,
            uint64 _scale,
            uint64 _totalItems,
            uint8 _allowedOperation,
            uint64 _admittedCount
        )
    {
        return (datasetRef, scale, totalItems, allowedOperation, admittedCount);
    }
}
