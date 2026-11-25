import test from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import { canonicalJsonStringify } from "../utils/canonical.js";
import { hashLeaf, hashPair } from "../utils/keccak.js";

test("Cross-Language Merkle Test Vectors (20 items)", () => {
  // Resolve data path whether run from root or frontend directory
  let vectorsPath = path.resolve(process.cwd(), "data/cross_language_vectors.json");
  if (!fs.existsSync(vectorsPath)) {
    vectorsPath = path.resolve(process.cwd(), "../data/cross_language_vectors.json");
  }
  const data = JSON.parse(fs.readFileSync(vectorsPath, "utf-8"));

  assert.strictEqual(data.vectors.length, 20);

  for (let i = 0; i < data.vectors.length; i++) {
    const item = data.vectors[i];
    
    // 1. Verify exact canonical string representation matches
    const tsCanonical = canonicalJsonStringify(item.record);
    assert.strictEqual(
      tsCanonical,
      item.canonical_json,
      `Canonical JSON mismatch at vector ${i} (${item.record.domain})`
    );

    // 2. Verify double-leaf hash matches Python output byte-for-byte
    const tsLeafHash = hashLeaf(tsCanonical);
    assert.strictEqual(
      tsLeafHash.toLowerCase(),
      item.leaf_hash.toLowerCase(),
      `Leaf hash mismatch at vector ${i} (${item.record.domain})`
    );

    // 3. Verify Merkle proof calculation yields the exact expected root
    let currentHash = tsLeafHash;
    for (const siblingHex of item.proof) {
      currentHash = hashPair(currentHash, siblingHex);
    }

    assert.strictEqual(
      currentHash.toLowerCase(),
      data.merkle_root.toLowerCase(),
      `Merkle proof root mismatch at vector ${i} (${item.record.domain})`
    );
  }
});
