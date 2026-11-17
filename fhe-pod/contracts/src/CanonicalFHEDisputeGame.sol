// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {VerifiableFHEDisputeGame, InvalidParameter} from "./VerifiableFHEDisputeGame.sol";
import {AuthenticatedTraceAvailability} from "./AuthenticatedTraceAvailability.sol";
import {CanonicalLeafVerifier} from "./CanonicalLeafVerifier.sol";

/// @notice Canonical certificate-only game with constructor-fixed components.
/// No administrator approves participants or can change a task's verifier,
/// availability contract, sampler, or adjudicator identities after deployment.
contract CanonicalFHEDisputeGame is VerifiableFHEDisputeGame {
    constructor(
        address objectiveVerifier_,
        uint64 commitWindowSeconds_,
        uint64 openWindowSeconds_,
        uint64 challengeWindowSeconds_,
        address availability_,
        address leafDecisionVerifier_
    ) VerifiableFHEDisputeGame(
        objectiveVerifier_, commitWindowSeconds_, openWindowSeconds_,
        challengeWindowSeconds_, true
    ) {
        if (availability_.code.length == 0 || leafDecisionVerifier_.code.length == 0) {
            revert InvalidParameter();
        }
        if (
            address(AuthenticatedTraceAvailability(availability_).game()) != address(this) ||
            CanonicalLeafVerifier(leafDecisionVerifier_).game() != address(this) ||
            CanonicalLeafVerifier(leafDecisionVerifier_).threshold() < 2
        ) revert InvalidParameter();
        availabilityModule = availability_;
        leafDecisionVerifier = leafDecisionVerifier_;
    }
}
