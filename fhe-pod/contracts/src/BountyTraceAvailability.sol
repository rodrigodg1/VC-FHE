// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AuthenticatedTraceAvailability} from "./AuthenticatedTraceAvailability.sol";

/// @notice Authenticated, permissionless disclosure for the bounty game only.
/// Every accepted prefix is bound to all three task roots. This prevents an
/// untrusted publisher, including the operator, from poisoning partial state.
contract BountyTraceAvailability is AuthenticatedTraceAvailability {
    uint256 public constant RELAY_VERSION = 2;

    struct Subtree {
        bytes32[3] roots; // trace, program, provenance
        uint32 size;
    }
    struct Split {
        bytes32[3] left;
        bytes32[3] right;
    }
    mapping(bytes32 => Subtree[]) private pendingSubtrees;

    constructor(address game_, uint64 window_)
        AuthenticatedTraceAvailability(game_, window_) {}

    // The historical unproved entry points cannot bypass prefix authentication.
    function publishDisputedTraceLeaf(bytes32, ProvenanceLeaf calldata,
        bytes32[] calldata, bytes32[] calldata) external pure override { revert InvalidParameter(); }

    function publishDisputedTraceBatch(bytes32, ProvenanceLeaf[] calldata,
        bytes32[][] calldata, bytes32[][] calldata) external pure override { revert InvalidParameter(); }

    function getDisclosureFrontier(bytes32 taskId) external view returns (Subtree[] memory) {
        return pendingSubtrees[taskId];
    }

    /// @dev A depth-first frontier expands each internal node once. Across all
    /// batches there are N-1 splits, O(N) authentication data and O(log N) live
    /// frontier storage, rather than a separate O(log N) proof for every leaf.
    /// No split is stored without consuming an authenticated leaf in this call.
    function publishAuthenticatedTraceBatch(
        bytes32 taskId,
        ProvenanceLeaf[] calldata leaves,
        bytes32[][] calldata lhsInputProofs,
        bytes32[][] calldata rhsInputProofs,
        Split[] calldata splits
    ) external {
        if (leaves.length == 0 || leaves.length != lhsInputProofs.length ||
            leaves.length != rhsInputProofs.length) revert InvalidParameter();
        (uint8 status, , , , ) = game.getTaskStatus(taskId);
        if ((status != 1 && status != 2) || disclosureDeadline[taskId] == 0 ||
            block.timestamp > disclosureDeadline[taskId] || unavailable[taskId] ||
            disputeReady[taskId]) revert WrongState();
        TaskAuthorization storage auth = authorizations[taskId];
        Subtree[] storage frontier = pendingSubtrees[taskId];
        if (nextDisclosureIndex[taskId] == 0 && frontier.length == 0) {
            frontier.push(Subtree([auth.traceRoot, auth.programRoot, auth.provenanceRoot], auth.leafCount));
        }
        uint256 used;
        for (uint256 i; i < leaves.length; i++) {
            if (frontier.length == 0) revert InvalidParameter();
            while (frontier[frontier.length - 1].size > 1) {
                if (used == splits.length) revert InvalidParameter();
                Subtree memory parent = frontier[frontier.length - 1];
                Split calldata branch = splits[used++];
                for (uint256 j; j < 3; j++) {
                    if (keccak256(abi.encodePacked(branch.left[j], branch.right[j])) != parent.roots[j])
                        revert RootMismatch();
                }
                frontier.pop();
                frontier.push(Subtree(branch.right, parent.size / 2));
                frontier.push(Subtree(branch.left, parent.size / 2));
            }
            uint32 index = nextDisclosureIndex[taskId];
            bytes32 traceHash = _traceLeafHash(leaves[i]);
            bytes32[3] storage roots = frontier[frontier.length - 1].roots;
            if (traceHash != roots[0] || _programLeafHash(taskId, index, leaves[i]) != roots[1] ||
                _provenanceLeafHash(taskId, index, traceHash, leaves[i]) != roots[2]) revert RootMismatch();
            frontier.pop();
            _publishOne(taskId, leaves[i], lhsInputProofs[i], rhsInputProofs[i]);
        }
        if (used != splits.length) revert InvalidParameter();
    }
}
