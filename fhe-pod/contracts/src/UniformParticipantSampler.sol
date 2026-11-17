// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Stateless ordered sampling without replacement. No owner, registry,
/// approvals, callbacks, or caller-dependent randomness.
contract UniformParticipantSampler {
    error InvalidPopulation();

    function sampleIndices(uint256 population, uint256 sampleSize, bytes32 domain)
        external pure returns (uint256[] memory selected)
    {
        if (sampleSize == 0 || sampleSize > population) revert InvalidPopulation();
        selected = new uint256[](sampleSize);
        uint256 cutoff = type(uint256).max - (type(uint256).max % population);
        for (uint256 i; i < sampleSize; ++i) {
            for (uint256 attempt; ; ++attempt) {
                uint256 draw = uint256(keccak256(abi.encode(domain, i, attempt)));
                if (draw >= cutoff) continue;
                uint256 candidate = draw % population;
                bool duplicate;
                for (uint256 j; j < i; ++j) {
                    if (selected[j] == candidate) {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate) {
                    selected[i] = candidate;
                    break;
                }
            }
        }
    }
}
