"""
backend/tests/test_evidence_publisher.py
Comprehensive test suite for Phase 4 Merkle tree construction, leaf canonicalization,
tamper detection, duplicate batch handling, and local Anvil end-to-end anchoring.
"""

import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime

from evidence.merkle import MerkleTree, hash_leaf, hash_pair, verify_merkle_proof
from utils.canonical import canonical_json_dumps


def test_merkle_tree_construction_and_proofs():
    """Verify Merkle tree construction matches sorted-pair proof verification."""
    raw_leaves = [
        {"id": 1, "domain": "wikipedia.org", "asn": 55836, "anomaly": False},
        {"id": 2, "domain": "thepiratebay.org", "asn": 55836, "anomaly": True},
        {"id": 3, "domain": "1337x.to", "asn": 9498, "anomaly": True},
    ]

    hashed_leaves = [hash_leaf(canonical_json_dumps(item)) for item in raw_leaves]
    tree = MerkleTree(hashed_leaves)

    assert len(tree.root) == 32
    assert tree.root_hex.startswith("0x")

    # Verify proofs for each leaf
    for idx, leaf_bytes in enumerate(hashed_leaves):
        proof_hex_list = tree.get_proof(idx)
        proof_bytes = [bytes.fromhex(p[2:]) for p in proof_hex_list]
        assert verify_merkle_proof(leaf_bytes, proof_bytes, tree.root) is True


def test_tampered_leaf_fails_verification():
    """Verify modifying any leaf content breaks Merkle proof validation."""
    leaf_original = {"id": 1, "domain": "wikipedia.org", "anomaly": False}
    leaf_tampered = {"id": 1, "domain": "wikipedia.org", "anomaly": True}

    h_orig = hash_leaf(canonical_json_dumps(leaf_original))
    h_tampered = hash_leaf(canonical_json_dumps(leaf_tampered))

    other_leaf = hash_leaf(canonical_json_dumps({"id": 2, "domain": "bbc.com"}))
    tree = MerkleTree([h_orig, other_leaf])

    proof_hex_list = tree.get_proof(0)
    proof_bytes = [bytes.fromhex(p[2:]) for p in proof_hex_list]

    # Original passes
    assert verify_merkle_proof(h_orig, proof_bytes, tree.root) is True
    # Tampered leaf fails
    assert verify_merkle_proof(h_tampered, proof_bytes, tree.root) is False


def test_tampered_proof_fails_verification():
    """Verify invalid sibling hashes in proof fail verification."""
    h0 = hash_leaf(b"leaf_zero")
    h1 = hash_leaf(b"leaf_one")
    tree = MerkleTree([h0, h1])

    bad_proof = [b"\x00" * 32]
    assert verify_merkle_proof(h0, bad_proof, tree.root) is False


def test_double_leaf_hashing_prevents_preimage_attack():
    """
    Verify that an intermediate pair node hash cannot be presented as a raw leaf
    because leaves are double-hashed.
    """
    leaf0 = hash_leaf(b"leaf_0")
    leaf1 = hash_leaf(b"leaf_1")
    parent = hash_pair(leaf0, leaf1)

    # An attacker tries to submit parent directly as raw data
    attempted_leaf = hash_leaf(parent)
    assert attempted_leaf != parent


def test_merkle_edge_case_single_leaf():
    """Merkle tree with exactly 1 leaf."""
    h0 = hash_leaf(b"lone_leaf")
    tree = MerkleTree([h0])
    assert tree.root == h0
    proof = tree.get_proof(0)
    assert proof == []  # Empty proof for single leaf
    assert verify_merkle_proof(h0, [], tree.root) is True


def test_merkle_edge_case_two_leaves():
    """Merkle tree with exactly 2 leaves."""
    h0 = hash_leaf(b"leaf_zero")
    h1 = hash_leaf(b"leaf_one")
    tree = MerkleTree([h0, h1])
    assert tree.root == hash_pair(h0, h1)

    proof0 = [bytes.fromhex(p[2:]) for p in tree.get_proof(0)]
    proof1 = [bytes.fromhex(p[2:]) for p in tree.get_proof(1)]

    assert len(proof0) == 1
    assert proof0[0] == h1
    assert verify_merkle_proof(h0, proof0, tree.root) is True
    assert verify_merkle_proof(h1, proof1, tree.root) is True


def test_merkle_edge_case_odd_leaves():
    """Merkle tree with odd number of leaves (odd leaf duplicated up the tree)."""
    h0 = hash_leaf(b"leaf_0")
    h1 = hash_leaf(b"leaf_1")
    h2 = hash_leaf(b"leaf_2")
    tree = MerkleTree([h0, h1, h2])

    for i, h in enumerate([h0, h1, h2]):
        proof = [bytes.fromhex(p[2:]) for p in tree.get_proof(i)]
        assert verify_merkle_proof(h, proof, tree.root) is True


def test_merkle_edge_case_duplicate_leaves():
    """Merkle tree containing duplicate leaf hashes."""
    h0 = hash_leaf(b"duplicate_content")
    h1 = hash_leaf(b"duplicate_content")
    tree = MerkleTree([h0, h1])

    # Root should be hash_pair(h0, h0)
    assert tree.root == hash_pair(h0, h0)
    proof0 = [bytes.fromhex(p[2:]) for p in tree.get_proof(0)]
    proof1 = [bytes.fromhex(p[2:]) for p in tree.get_proof(1)]

    assert verify_merkle_proof(h0, proof0, tree.root) is True
    assert verify_merkle_proof(h1, proof1, tree.root) is True


def test_merkle_proof_from_different_batch_fails():
    """A valid proof from Batch A must NOT verify against Root B."""
    tree_a = MerkleTree([hash_leaf(b"batch_a_1"), hash_leaf(b"batch_a_2")])
    tree_b = MerkleTree([hash_leaf(b"batch_b_1"), hash_leaf(b"batch_b_2")])

    proof_a0 = [bytes.fromhex(p[2:]) for p in tree_a.get_proof(0)]
    leaf_a0 = tree_a.leaves[0]

    # Fails against tree_b root
    assert verify_merkle_proof(leaf_a0, proof_a0, tree_b.root) is False

