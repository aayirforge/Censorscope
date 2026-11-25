// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title EvidenceAnchor
 * @dev Anchors Merkle roots of off-chain measurement batches on Ethereum for tamper-evident verification.
 */
contract EvidenceAnchor {
    struct Batch {
        bytes32 merkleRoot;
        string ipfsCid;
        uint256 timestamp;
        uint256 recordCount;
    }

    address public owner;
    uint256 public batchCount;
    mapping(uint256 => Batch) public batches;

    event BatchAnchored(
        uint256 indexed batchId,
        bytes32 indexed merkleRoot,
        string ipfsCid,
        uint256 recordCount,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can anchor batches");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function anchorBatch(
        bytes32 _merkleRoot,
        string calldata _ipfsCid,
        uint256 _recordCount
    ) external onlyOwner returns (uint256) {
        require(_merkleRoot != bytes32(0), "Invalid Merkle root");
        require(bytes(_ipfsCid).length > 0, "Invalid IPFS CID");

        uint256 currentBatchId = batchCount;
        batches[currentBatchId] = Batch({
            merkleRoot: _merkleRoot,
            ipfsCid: _ipfsCid,
            timestamp: block.timestamp,
            recordCount: _recordCount
        });

        emit BatchAnchored(
            currentBatchId,
            _merkleRoot,
            _ipfsCid,
            _recordCount,
            block.timestamp
        );

        batchCount++;
        return currentBatchId;
    }

    function getBatch(uint256 _batchId) external view returns (Batch memory) {
        require(_batchId < batchCount, "Batch does not exist");
        return batches[_batchId];
    }
}
