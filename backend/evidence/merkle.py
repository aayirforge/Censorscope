"""
backend/evidence/merkle.py
Cryptographic Merkle Tree implementation using OpenZeppelin sorted-pair hashing
and double-leaf hashing against second-preimage attacks.
"""

from __future__ import annotations

from typing import List, Tuple
from eth_hash.auto import keccak
from utils.canonical import canonical_json_dumps


def hash_leaf(canonical_bytes: bytes) -> bytes:
    """
    Double-hash the leaf content to prevent second-preimage attacks:
    leaf_hash = keccak256(keccak256(canonical_json_bytes))
    """
    inner = keccak(canonical_bytes)
    return keccak(inner)


def hash_pair(a: bytes, b: bytes) -> bytes:
    """
    OpenZeppelin sorted-pair hashing:
    parent = keccak256(a < b ? concat(a, b) : concat(b, a))
    """
    if a < b:
        return keccak(a + b)
    else:
        return keccak(b + a)


class MerkleTree:
    """
    Deterministic binary Merkle tree with sorted-pair node hashing.
    Generates proofs strictly compatible with OpenZeppelin's MerkleProof.verify.
    """

    def __init__(self, leaves: List[bytes]):
        if not leaves:
            raise ValueError("Cannot construct Merkle tree with empty leaves.")
        self.leaves = leaves
        self.layers: List[List[bytes]] = [leaves]
        self._build_tree()

    def _build_tree(self) -> None:
        current_layer = self.leaves
        while len(current_layer) > 1:
            next_layer: List[bytes] = []
            for i in range(0, len(current_layer), 2):
                if i + 1 < len(current_layer):
                    parent = hash_pair(current_layer[i], current_layer[i + 1])
                else:
                    # Duplicate last node if odd number of elements
                    parent = hash_pair(current_layer[i], current_layer[i])
                next_layer.append(parent)
            self.layers.append(next_layer)
            current_layer = next_layer

    @property
    def root(self) -> bytes:
        return self.layers[-1][0]

    @property
    def root_hex(self) -> str:
        return "0x" + self.root.hex()

    def get_proof(self, index: int) -> List[str]:
        """
        Generate Merkle audit proof for a given leaf index.
        Returns list of 0x-prefixed 32-byte hex strings.
        """
        if index < 0 or index >= len(self.leaves):
            raise IndexError("Leaf index out of bounds.")

        proof: List[str] = []
        idx = index

        for layer in self.layers[:-1]:
            is_right_child = (idx % 2 == 1)
            pair_idx = idx - 1 if is_right_child else idx + 1

            if pair_idx < len(layer):
                sibling = layer[pair_idx]
            else:
                sibling = layer[idx]  # duplicate odd leaf

            proof.append("0x" + sibling.hex())
            idx //= 2

        return proof


def verify_merkle_proof(leaf: bytes, proof: List[bytes], root: bytes) -> bool:
    """Python reference verifier matching OpenZeppelin MerkleProof.verify."""
    computed = leaf
    for sibling in proof:
        computed = hash_pair(computed, sibling)
    return computed == root
