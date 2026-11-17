// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {FheType} from "@fhevm/solidity/lib/FheType.sol";

interface ILocalFhevmPlaintextStore {
    function plaintextOf(bytes32 handle) external view returns (uint256);

    function typeOf(bytes32 handle) external view returns (FheType);
}

contract LocalFhevmACL {
    mapping(bytes32 => mapping(address => bool)) private allowed;
    mapping(bytes32 => mapping(address => bool)) private persistentAllowed;
    mapping(bytes32 => bool) private decryptable;

    function multicall(
        bytes[] calldata data
    ) external payable returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory result) = address(this).delegatecall(data[i]);
            require(ok, "acl multicall failed");
            results[i] = result;
        }
    }

    function allowTransient(bytes32 ciphertext, address account) external {
        allowed[ciphertext][account] = true;
    }

    function allow(bytes32 handle, address account) external {
        allowed[handle][account] = true;
        persistentAllowed[handle][account] = true;
    }

    function cleanTransientStorage() external {}

    function isAllowed(
        bytes32 handle,
        address account
    ) external view returns (bool) {
        return allowed[handle][account] || persistentAllowed[handle][account];
    }

    function allowForDecryption(bytes32[] memory handlesList) external {
        for (uint256 i = 0; i < handlesList.length; i++) {
            decryptable[handlesList[i]] = true;
        }
    }

    function isAllowedForDecryption(
        bytes32 handle
    ) external view returns (bool) {
        return decryptable[handle];
    }

    function persistAllowed(
        bytes32 handle,
        address account
    ) external view returns (bool) {
        return persistentAllowed[handle][account];
    }

    function isAccountAllowed(
        address account
    ) external pure returns (bool) {
        account;
        return true;
    }
}

contract LocalFhevmExecutor is ILocalFhevmPlaintextStore {
    uint256 private nextHandle = 1;
    address public immutable inputVerifierAddress;

    mapping(bytes32 => uint256) private plaintexts;
    mapping(bytes32 => FheType) private types;

    constructor() {
        inputVerifierAddress = address(this);
    }

    function plaintextOf(bytes32 handle) external view returns (uint256) {
        return plaintexts[handle];
    }

    function typeOf(bytes32 handle) external view returns (FheType) {
        return types[handle];
    }

    function fheAdd(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        return _store(_valueOf(lhs) + _rhsValue(rhs, scalarByte), _typeOf(lhs));
    }

    function fheSub(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        return _store(_valueOf(lhs) - _rhsValue(rhs, scalarByte), _typeOf(lhs));
    }

    function fheMul(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        return _store(_valueOf(lhs) * _rhsValue(rhs, scalarByte), _typeOf(lhs));
    }

    function fheDiv(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        uint256 divisor = _rhsValue(rhs, scalarByte);
        require(divisor != 0, "fhe div by zero");
        return _store(_valueOf(lhs) / divisor, _typeOf(lhs));
    }

    function fheRem(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        uint256 divisor = _rhsValue(rhs, scalarByte);
        require(divisor != 0, "fhe rem by zero");
        return _store(_valueOf(lhs) % divisor, _typeOf(lhs));
    }

    function fheBitAnd(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        return _store(_valueOf(lhs) & _rhsValue(rhs, scalarByte), _typeOf(lhs));
    }

    function fheBitOr(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        return _store(_valueOf(lhs) | _rhsValue(rhs, scalarByte), _typeOf(lhs));
    }

    function fheBitXor(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        return _store(_valueOf(lhs) ^ _rhsValue(rhs, scalarByte), _typeOf(lhs));
    }

    function fheShl(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        return _store(_valueOf(lhs) << _rhsValue(rhs, scalarByte), _typeOf(lhs));
    }

    function fheShr(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        return _store(_valueOf(lhs) >> _rhsValue(rhs, scalarByte), _typeOf(lhs));
    }

    function fheRotl(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        rhs;
        scalarByte;
        return _store(_valueOf(lhs), _typeOf(lhs));
    }

    function fheRotr(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        rhs;
        scalarByte;
        return _store(_valueOf(lhs), _typeOf(lhs));
    }

    function fheEq(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        return _store(_valueOf(lhs) == _rhsValue(rhs, scalarByte) ? 1 : 0, FheType.Bool);
    }

    function fheNe(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        return _store(_valueOf(lhs) != _rhsValue(rhs, scalarByte) ? 1 : 0, FheType.Bool);
    }

    function fheGe(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        return _store(_valueOf(lhs) >= _rhsValue(rhs, scalarByte) ? 1 : 0, FheType.Bool);
    }

    function fheGt(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        return _store(_valueOf(lhs) > _rhsValue(rhs, scalarByte) ? 1 : 0, FheType.Bool);
    }

    function fheLe(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        return _store(_valueOf(lhs) <= _rhsValue(rhs, scalarByte) ? 1 : 0, FheType.Bool);
    }

    function fheLt(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        return _store(_valueOf(lhs) < _rhsValue(rhs, scalarByte) ? 1 : 0, FheType.Bool);
    }

    function fheMin(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        uint256 left = _valueOf(lhs);
        uint256 right = _rhsValue(rhs, scalarByte);
        return _store(left < right ? left : right, _typeOf(lhs));
    }

    function fheMax(
        bytes32 lhs,
        bytes32 rhs,
        bytes1 scalarByte
    ) external returns (bytes32 result) {
        uint256 left = _valueOf(lhs);
        uint256 right = _rhsValue(rhs, scalarByte);
        return _store(left > right ? left : right, _typeOf(lhs));
    }

    function fheNeg(bytes32 ct) external returns (bytes32 result) {
        return _store(type(uint256).max - _valueOf(ct) + 1, _typeOf(ct));
    }

    function fheNot(bytes32 ct) external returns (bytes32 result) {
        return _store(~_valueOf(ct), _typeOf(ct));
    }

    /// @notice Resolves an external handle to an internal one.
    /// @dev MODEL LIMIT, STATED PLAINLY. A production coprocessor holds the
    /// ciphertext bytes and resolves a handle to its content by itself. This
    /// runtime holds no ciphertext and cannot decrypt, so the only content it
    /// can attribute to a handle is the handle itself. That is correct exactly
    /// for the CLEAR-VALUE handle regime (`ciphertextHandleForClear` in
    /// scripts/evm-lib.mjs), which the unit tests and the opcode-surface checks
    /// use, and it is meaningless for the keccak256-of-ciphertext handles a
    /// real TFHE execution produces.
    ///
    /// THERE IS DELIBERATELY NO WAY TO TELL THIS CONTRACT WHAT A HANDLE
    /// ENCRYPTS. An earlier revision had a handle-declaration entry point
    /// (handle, value, type) so that the homomorphic recomputation could also
    /// run over real ciphertext handles. Calling it meant putting the disputed
    /// leaf's operands in the clear in transaction calldata, which defeated the
    /// whole handle-only design. It was removed. Disputes over real ciphertext
    /// handles are settled instead by
    /// `VerifiableFHEDisputeGame.settleLeafViaAttestedDecision`, which verifies
    /// a t+1-signed attestation of the leaf equality bit and never carries an
    /// operand.
    function verifyInput(
        bytes32 inputHandle,
        address callerAddress,
        bytes memory inputProof,
        FheType inputType
    ) external returns (bytes32 result) {
        callerAddress;
        inputProof;
        return _store(uint256(inputHandle), inputType);
    }

    function cast(bytes32 ct, FheType toType) external returns (bytes32 result) {
        return _store(_castValue(_valueOf(ct), toType), toType);
    }

    function trivialEncrypt(
        uint256 ct,
        FheType toType
    ) external returns (bytes32 result) {
        return _store(_castValue(ct, toType), toType);
    }

    function fheIfThenElse(
        bytes32 control,
        bytes32 ifTrue,
        bytes32 ifFalse
    ) external returns (bytes32 result) {
        return _store(_valueOf(control) != 0 ? _valueOf(ifTrue) : _valueOf(ifFalse), _typeOf(ifTrue));
    }

    function fheRand(FheType randType) external returns (bytes32 result) {
        return _store(0, randType);
    }

    function fheRandBounded(
        uint256 upperBound,
        FheType randType
    ) external returns (bytes32 result) {
        return _store(upperBound == 0 ? 0 : uint256(keccak256(abi.encode(nextHandle))) % upperBound, randType);
    }

    function getInputVerifierAddress() external view returns (address) {
        return inputVerifierAddress;
    }

    function multicall(
        bytes[] calldata data
    ) external payable returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory result) = address(this).delegatecall(data[i]);
            require(ok, "executor multicall failed");
            results[i] = result;
        }
    }

    function cleanTransientStorage() external {}

    function _rhsValue(
        bytes32 rhs,
        bytes1 scalarByte
    ) internal view returns (uint256) {
        return scalarByte == 0x01 ? uint256(rhs) : _valueOf(rhs);
    }

    function _valueOf(bytes32 handle) internal view returns (uint256) {
        uint256 value = plaintexts[handle];
        require(handle != bytes32(0), "empty handle");
        return value;
    }

    function _typeOf(bytes32 handle) internal view returns (FheType) {
        return types[handle];
    }

    function _store(uint256 value, FheType fheType) internal returns (bytes32) {
        bytes32 handle = keccak256(
            abi.encodePacked(address(this), block.chainid, nextHandle++, value, fheType)
        );
        plaintexts[handle] = _castValue(value, fheType);
        types[handle] = fheType;
        return handle;
    }

    function _castValue(
        uint256 value,
        FheType fheType
    ) internal pure returns (uint256) {
        if (fheType == FheType.Bool) return value == 0 ? 0 : 1;
        if (fheType == FheType.Uint4) return value & 0x0f;
        if (fheType == FheType.Uint8) return value & type(uint8).max;
        if (fheType == FheType.Uint16) return value & type(uint16).max;
        if (fheType == FheType.Uint32) return value & type(uint32).max;
        if (fheType == FheType.Uint64) return value & type(uint64).max;
        return value;
    }
}

contract LocalFhevmKMSVerifier {
    LocalFhevmACL public immutable acl;
    ILocalFhevmPlaintextStore public immutable executor;
    address[] private signers;

    constructor(address acl_, address executor_) {
        acl = LocalFhevmACL(acl_);
        executor = ILocalFhevmPlaintextStore(executor_);
        signers.push(address(this));
    }

    function verifyDecryptionEIP712KMSSignatures(
        bytes32[] memory handlesList,
        bytes memory decryptedResult,
        bytes memory decryptionProof
    ) external view returns (bool) {
        require(decryptionProof.length != 0, "empty local proof");
        require(decryptedResult.length == handlesList.length * 32, "bad cleartext length");

        for (uint256 i = 0; i < handlesList.length; i++) {
            require(acl.isAllowedForDecryption(handlesList[i]), "handle not decryptable");
            require(executor.typeOf(handlesList[i]) == FheType.Bool, "expected bool handle");
            uint256 clearValue;
            assembly {
                clearValue := mload(add(add(decryptedResult, 0x20), mul(i, 0x20)))
            }
            if ((executor.plaintextOf(handlesList[i]) != 0) != (clearValue != 0)) {
                return false;
            }
        }

        return true;
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
            "LocalFhevmKMSVerifier",
            "1",
            block.chainid,
            address(this),
            bytes32(0),
            new uint256[](0)
        );
    }

    function getThreshold() external pure returns (uint256) {
        return 1;
    }

    function getKmsSigners() external view returns (address[] memory) {
        return signers;
    }
}
