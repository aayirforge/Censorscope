// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/EvidenceRegistry.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract EvidenceRegistryTest is Test {
    EvidenceRegistry public registry;
    address public admin = address(0xAD);
    address public publisher = address(0xCAFE);
    address public user = address(0xBEEF);

    bytes32 constant ROOT_1 = keccak256("root_1");
    bytes32 constant ROOT_2 = keccak256("root_2");
    string constant CID_1 = "bafybeicensortestcid1";

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

    function setUp() public {
        vm.prank(admin);
        registry = new EvidenceRegistry(admin, publisher);
    }

    // =============================================================
    // UNIT TESTS & REVERT PATHS
    // =============================================================

    function test_InitialState() public view {
        assertEq(registry.batchCount(), 0);
        assertTrue(registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(registry.hasRole(registry.PUBLISHER_ROLE(), publisher));
        assertFalse(registry.hasRole(registry.PUBLISHER_ROLE(), user));
        assertFalse(registry.paused());
    }

    function test_SubmitBatch_Success() public {
        vm.prank(publisher);
        vm.expectEmit(true, true, true, false);
        emit BatchSubmitted(0, ROOT_1, CID_1, publisher, uint64(block.timestamp), 100, 200, 50);

        uint256 id = registry.submitBatch(ROOT_1, CID_1, 100, 200, 50);
        assertEq(id, 0);
        assertEq(registry.batchCount(), 1);
        assertTrue(registry.isKnownRoot(ROOT_1));

        EvidenceRegistry.Batch memory b = registry.getBatch(0);
        assertEq(b.merkleRoot, ROOT_1);
        assertEq(b.ipfsCid, CID_1);
        assertEq(b.fromTimestamp, 100);
        assertEq(b.toTimestamp, 200);
        assertEq(b.recordCount, 50);
        assertEq(b.submitter, publisher);
    }

    function test_Revert_NonPublisherCannotSubmit() public {
        vm.prank(user);
        vm.expectRevert();
        registry.submitBatch(ROOT_1, CID_1, 100, 200, 10);
    }

    function test_Revert_ZeroMerkleRoot() public {
        vm.prank(publisher);
        vm.expectRevert(EvidenceRegistry.ZeroMerkleRoot.selector);
        registry.submitBatch(bytes32(0), CID_1, 100, 200, 10);
    }

    function test_Revert_ZeroRecordCount() public {
        vm.prank(publisher);
        vm.expectRevert(EvidenceRegistry.ZeroRecordCount.selector);
        registry.submitBatch(ROOT_1, CID_1, 100, 200, 0);
    }

    function test_Revert_DuplicateMerkleRoot() public {
        vm.startPrank(publisher);
        registry.submitBatch(ROOT_1, CID_1, 100, 200, 10);

        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.DuplicateMerkleRoot.selector, ROOT_1));
        registry.submitBatch(ROOT_1, "bafybeidupcid", 201, 300, 15);
        vm.stopPrank();
    }

    function test_Revert_EmptyIpfsCid() public {
        vm.prank(publisher);
        vm.expectRevert(EvidenceRegistry.EmptyIpfsCid.selector);
        registry.submitBatch(ROOT_1, "", 100, 200, 10);
    }

    function test_Revert_InvalidTimestampRange() public {
        vm.prank(publisher);
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.InvalidTimestampRange.selector, 300, 200));
        registry.submitBatch(ROOT_1, CID_1, 300, 200, 10);
    }

    function test_Revert_GetBatchDoesNotExist() public {
        vm.expectRevert(abi.encodeWithSelector(EvidenceRegistry.BatchDoesNotExist.selector, 0));
        registry.getBatch(0);
    }

    function test_Revert_PausedCannotSubmit() public {
        vm.prank(admin);
        registry.pause();
        assertTrue(registry.paused());

        vm.prank(publisher);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        registry.submitBatch(ROOT_1, CID_1, 100, 200, 10);

        vm.prank(admin);
        registry.unpause();
        assertFalse(registry.paused());

        vm.prank(publisher);
        uint256 id = registry.submitBatch(ROOT_1, CID_1, 100, 200, 10);
        assertEq(id, 0);
    }

    // =============================================================
    // MERKLE PROOF VERIFICATION & FUZZ TESTS
    // =============================================================

    function hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function test_MerkleProofVerification_TwoLeaves() public {
        // Double-hash leaves as per second-preimage defense
        bytes32 leaf0 = keccak256(bytes.concat(keccak256("leaf0_content")));
        bytes32 leaf1 = keccak256(bytes.concat(keccak256("leaf1_content")));

        bytes32 root = hashPair(leaf0, leaf1);

        vm.prank(publisher);
        uint256 batchId = registry.submitBatch(root, CID_1, 100, 200, 2);

        bytes32[] memory proof0 = new bytes32[](1);
        proof0[0] = leaf1;

        // Verify leaf0 with proof
        assertTrue(registry.verifyProof(batchId, proof0, leaf0));

        // Tampered leaf must fail
        bytes32 tamperedLeaf = keccak256(bytes.concat(keccak256("tampered_content")));
        assertFalse(registry.verifyProof(batchId, proof0, tamperedLeaf));

        // Tampered proof must fail
        bytes32[] memory badProof = new bytes32[](1);
        badProof[0] = keccak256("wrong_sibling");
        assertFalse(registry.verifyProof(batchId, badProof, leaf0));
    }

    function test_MerkleProof_CrossBatchFails() public {
        bytes32 leafA = keccak256(bytes.concat(keccak256("batchA_leaf")));
        bytes32 leafB = keccak256(bytes.concat(keccak256("batchB_leaf")));

        vm.startPrank(publisher);
        uint256 batch0 = registry.submitBatch(leafA, "cidA", 100, 200, 1);
        uint256 batch1 = registry.submitBatch(leafB, "cidB", 201, 300, 1);
        vm.stopPrank();

        bytes32[] memory emptyProof = new bytes32[](0);

        // leafA verifies on batch0
        assertTrue(registry.verifyProof(batch0, emptyProof, leafA));
        // leafA MUST NOT verify on batch1
        assertFalse(registry.verifyProof(batch1, emptyProof, leafA));
    }

    function test_MerkleProof_SingleLeaf() public {
        bytes32 singleLeaf = keccak256(bytes.concat(keccak256("single_item")));

        vm.prank(publisher);
        uint256 bId = registry.submitBatch(singleLeaf, "cid_single", 10, 20, 1);

        bytes32[] memory emptyProof = new bytes32[](0);
        assertTrue(registry.verifyProof(bId, emptyProof, singleLeaf));
    }

    function testFuzz_MerkleProofRandom(bytes32 seedA, bytes32 seedB, uint32 count) public {
        vm.assume(seedA != bytes32(0) && seedB != bytes32(0));
        vm.assume(seedA != seedB);
        vm.assume(count > 0 && count < 100000);

        bytes32 leafA = keccak256(abi.encode(seedA));
        bytes32 leafB = keccak256(abi.encode(seedB));
        bytes32 root = hashPair(leafA, leafB);

        vm.prank(publisher);
        uint256 batchId = registry.submitBatch(root, CID_1, 10, 20, count);

        bytes32[] memory proofA = new bytes32[](1);
        proofA[0] = leafB;

        assertTrue(registry.verifyProof(batchId, proofA, leafA));
    }

    // =============================================================
    // INVARIANT TESTS
    // =============================================================

    function test_Invariant_BatchIdMonotonicallyIncreases() public {
        vm.startPrank(publisher);
        for (uint256 i = 0; i < 5; i++) {
            bytes32 r = keccak256(abi.encode("invariant_root", i));
            uint256 id = registry.submitBatch(r, "cid", uint64(i * 10), uint64(i * 10 + 5), uint32(i + 1));
            assertEq(id, i);
            assertEq(registry.batchCount(), i + 1);
        }
        vm.stopPrank();
    }

    function test_Invariant_StoredRootImmutable() public {
        vm.prank(publisher);
        uint256 batchId = registry.submitBatch(ROOT_1, CID_1, 100, 200, 10);

        EvidenceRegistry.Batch memory bBefore = registry.getBatch(batchId);
        assertEq(bBefore.merkleRoot, ROOT_1);

        // Submitting subsequent batches cannot alter batch 0
        vm.prank(publisher);
        registry.submitBatch(ROOT_2, "cid2", 201, 300, 20);

        EvidenceRegistry.Batch memory bAfter = registry.getBatch(batchId);
        assertEq(bAfter.merkleRoot, ROOT_1);
    }
}
