// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FHEComputationRegistry
 * @notice Simplified version of the earlier FHEStageRegistry.
 *         Configuration is set once during deployment.
 *         Each stage can be recomputed or verified independently.
 */
contract FHEComputationRegistry {
    struct StageMeta {
        uint64 index;
        uint64 startInclusive;
        uint64 endExclusive;
        bytes32 partialSumCommit; // Commitment of local encrypted sum
        address submitter;
        uint64 submittedAt;
    }

    // === Fixed dataset configuration ===
    string public datasetRef;
    uint64 public scale;
    uint64 public chunkSize;
    uint64 public totalItems;
    uint64 public stageCount;

    // === Stage metadata ===
    mapping(uint64 => StageMeta) public stages;

    // === Global aggregation ===
    bytes32 public globalSumCommit;

    event StageRecorded(uint64 indexed index, bytes32 partialSumCommit, address submitter);
    event AggregationRecorded(bytes32 globalSumCommit, uint64 timestamp);

    /**
     * @param _datasetRef  Reference to dataset, e.g. "./Users_Ratings.csv"
     * @param _scale       Fixed-point scaling factor (e.g. 1000)
     * @param _chunkSize   Number of ratings per stage
     * @param _totalItems  Total number of ratings in dataset
     */
    constructor(
        string memory _datasetRef,
        uint64 _scale,
        uint64 _chunkSize,
        uint64 _totalItems
    ) {
        require(bytes(_datasetRef).length > 0, "empty datasetRef");
        require(_scale > 0 && _chunkSize > 0 && _totalItems > 0, "invalid params");

        datasetRef = _datasetRef;
        scale = _scale;
        chunkSize = _chunkSize;
        totalItems = _totalItems;

        // compute number of stages
        stageCount = (_totalItems + _chunkSize - 1) / _chunkSize;

        // prepopulate stage metadata ranges
        for (uint64 i = 0; i < stageCount; i++) {
            uint64 startIdx = i * _chunkSize;
            uint64 endIdx = startIdx + _chunkSize;
            if (endIdx > _totalItems) endIdx = _totalItems;
            stages[i + 1] = StageMeta({
                index: i + 1,
                startInclusive: startIdx,
                endExclusive: endIdx,
                partialSumCommit: bytes32(0),
                submitter: address(0),
                submittedAt: 0
            });
        }
    }

    /// @notice Record or update the commitment for a specific stage.
    function recordStageCommit(uint64 stageIndex, bytes32 commit) external {
        require(stageIndex >= 1 && stageIndex <= stageCount, "invalid stage index");
        require(commit != bytes32(0), "empty commit");

        StageMeta storage st = stages[stageIndex];
        st.partialSumCommit = commit;
        st.submitter = msg.sender;
        st.submittedAt = uint64(block.timestamp);

        emit StageRecorded(stageIndex, commit, msg.sender);
    }

    /// @notice Record final aggregation commitment after all stages are computed.
    function recordGlobalAggregation(bytes32 commit) external {
        require(commit != bytes32(0), "empty commit");
        globalSumCommit = commit;
        emit AggregationRecorded(commit, uint64(block.timestamp));
    }

    /// @notice Retrieve basic info for off-chain clients.
    function getConfig()
        external
        view
        returns (
            string memory _datasetRef,
            uint64 _scale,
            uint64 _chunkSize,
            uint64 _totalItems,
            uint64 _stageCount
        )
    {
        return (datasetRef, scale, chunkSize, totalItems, stageCount);
    }
}
