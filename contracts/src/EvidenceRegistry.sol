// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title EvidenceRegistry
 * @notice Tamper-evident evidence registry for CensorScope censorship measurement batches.
 *
 * WHAT ANCHORING PROVES AND DOES NOT PROVE:
 * - Anchoring proves that our stored copy of a record has not changed since the batch was published.
 * - It does not prove the measurement was true, and for OONI data it does not prove OONI said it;
 *   it proves what we stored from OONI at the time.
 *
 * SECURITY & ACCESS CONTROL:
 * - AccessControl with DEFAULT_ADMIN_ROLE and PUBLISHER_ROLE.
 * - Pausable by admin to freeze submissions during operational emergencies.
 * - Non-upgradeable: no proxy patterns or hidden delegates.
 * - Rejects zero Merkle roots, zero counts, and duplicate roots.
 * - Double-leaf hashing (keccak256(abi.encode(leafHash))) defends against second-preimage attacks.
 */
contract EvidenceRegistry is AccessControl, Pausable {
    bytes32 public constant PUBLISHER_ROLE = keccak256("PUBLISHER_ROLE");

    struct Batch {
        bytes32 merkleRoot;
        string ipfsCid;
        uint64 fromTimestamp;
        uint64 toTimestamp;
        uint32 recordCount;
        uint64 submittedAt;
        address submitter;
    }

    /// @notice Total batches submitted (monotonically increasing)
    uint256 public batchCount;

    /// @notice Batch records indexed by batch ID
    mapping(uint256 => Batch) private _batches;

    /// @notice Tracks submitted roots to prevent duplicates
    mapping(bytes32 => bool) private _knownRoots;

    // Custom errors for gas efficiency
    error ZeroMerkleRoot();
    error ZeroRecordCount();
    error DuplicateMerkleRoot(bytes32 root);
    error InvalidTimestampRange(uint64 fromTs, uint64 toTs);
    error EmptyIpfsCid();
    error BatchDoesNotExist(uint256 batchId);

    event BatchSubmitted(
        uint256 indexed batchId,
        bytes32 indexed merkleRoot,
        string ipfsCid,
        address indexed submitter,
        uint64 submittedAt,
        uint64 fromTimestamp,
        uint64 toTimestamp,
        uint32 recordCount
    );

    constructor(address defaultAdmin, address initialPublisher) {
        if (defaultAdmin == address(0)) revert ZeroMerkleRoot();
        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        if (initialPublisher != address(0)) {
            _grantRole(PUBLISHER_ROLE, initialPublisher);
        }
    }

    /**
     * @notice Submit a new authenticated batch of measurement Merkle roots.
     * @param merkleRoot The root hash of the Merkle tree of measurements.
     * @param ipfsCid IPFS CID pointing to the full batch JSON artifact (or local mock identifier).
     * @param fromTs Earliest measurement timestamp in the batch.
     * @param toTs Latest measurement timestamp in the batch.
     * @param count Number of measurement leaves anchored in this batch.
     * @return batchId The unique identifier of the submitted batch.
     */
    function submitBatch(
        bytes32 merkleRoot,
        string calldata ipfsCid,
        uint64 fromTs,
        uint64 toTs,
        uint32 count
    ) external onlyRole(PUBLISHER_ROLE) whenNotPaused returns (uint256 batchId) {
        if (merkleRoot == bytes32(0)) revert ZeroMerkleRoot();
        if (count == 0) revert ZeroRecordCount();
        if (_knownRoots[merkleRoot]) revert DuplicateMerkleRoot(merkleRoot);
        if (bytes(ipfsCid).length == 0) revert EmptyIpfsCid();
        if (fromTs > toTs) revert InvalidTimestampRange(fromTs, toTs);

        batchId = batchCount;
        uint64 nowTs = uint64(block.timestamp);

        _batches[batchId] = Batch({
            merkleRoot: merkleRoot,
            ipfsCid: ipfsCid,
            fromTimestamp: fromTs,
            toTimestamp: toTs,
            recordCount: count,
            submittedAt: nowTs,
            submitter: msg.sender
        });

        _knownRoots[merkleRoot] = true;
        batchCount = batchId + 1;

        emit BatchSubmitted(
            batchId,
            merkleRoot,
            ipfsCid,
            msg.sender,
            nowTs,
            fromTs,
            toTs,
            count
        );
    }

    /**
     * @notice Retrieve batch details by ID.
     */
    function getBatch(uint256 batchId) external view returns (Batch memory) {
        if (batchId >= batchCount) revert BatchDoesNotExist(batchId);
        return _batches[batchId];
    }

    /**
     * @notice Helper to check if a Merkle root has already been anchored.
     */
    function isKnownRoot(bytes32 root) external view returns (bool) {
        return _knownRoots[root];
    }

    /**
     * @notice Verify a measurement proof against a specific anchored batch root.
     * @dev Double-leaf hashing (leaf = keccak256(bytes.concat(keccak256(abi.encode(leafData)))))
     *      or sorted-pair OpenZeppelin MerkleProof.verify.
     *      Leaves are hashed with keccak256(abi.encode(leafData)).
     * @param batchId The anchored batch ID.
     * @param proof The array of 32-byte sibling hashes.
     * @param leaf The leaf hash to verify.
     * @return isValid True if the proof matches the stored Merkle root.
     */
    function verifyProof(
        uint256 batchId,
        bytes32[] calldata proof,
        bytes32 leaf
    ) external view returns (bool isValid) {
        if (batchId >= batchCount) revert BatchDoesNotExist(batchId);
        bytes32 root = _batches[batchId].merkleRoot;
        return MerkleProof.verify(proof, root, leaf);
    }

    /**
     * @notice Pause batch submission in emergency.
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Resume batch submission.
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
