// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    VerifiableFHEDisputeGame, IFhevmObjectiveMicroVerifier, NotEligible, StateConflict
} from "./VerifiableFHEDisputeGame.sol";

/// @notice Regression-only configurable adapter for historical FHEVM and KMS
/// verdict paths. It is not the current canonical protocol deployment.
contract LegacyConfigurableDisputeGame is VerifiableFHEDisputeGame {
    address public immutable owner;

    constructor(address objectiveVerifier_, uint64 commit_, uint64 open_, uint64 challenge_, bool secure_)
        VerifiableFHEDisputeGame(objectiveVerifier_, commit_, open_, challenge_, secure_)
    {
        owner = msg.sender;
    }

    function setFhevmVerifier(address verifier) external {
        if (
            msg.sender != owner || verifier == address(0) ||
            address(fhevmVerifier) != address(0) || auditorPool.length != 0 || decryptorPool.length != 0
        ) revert InvalidFhevmVerifierMode();
        fhevmVerifier = IFhevmObjectiveMicroVerifier(verifier);
    }

    function setKmsVerdictVerifier(address verifier) external {
        if (msg.sender != owner || verifier == address(0)) revert NotEligible();
        if (secureTraceMode) revert InvalidFhevmVerifierMode();
        if (kmsVerdictVerifier != address(0)) revert StateConflict();
        kmsVerdictVerifier = verifier;
    }

    function setLeafDecisionVerifier(address verifier) external {
        if (msg.sender != owner || verifier == address(0)) revert NotEligible();
        if (leafDecisionVerifier != address(0)) revert StateConflict();
        leafDecisionVerifier = verifier;
    }

    function setAvailabilityModule(address module) external {
        if (msg.sender != owner || module == address(0)) revert NotEligible();
        if (availabilityModule != address(0)) revert StateConflict();
        availabilityModule = module;
    }
}
