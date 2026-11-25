// Deterministic Keccak-256 for Node.js / Browser environments
// When running in Node.js test environment, leverages cast / local keccak or standard keccak-256

const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

function findCastBin() {
  const candidates = [
    path.resolve(process.cwd(), "bin/cast"),
    path.resolve(process.cwd(), "../bin/cast"),
    path.resolve(process.env.HOME || "", ".foundry/bin/cast"),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) {
      return c;
    }
  }
  return null;
}

const CAST_BIN = findCastBin();

/**
 * Compute Keccak-256 of arbitrary string or bytes.
 * If data is a hex string prefixed with 0x (or raw hex bytes), hashes raw bytes.
 */
function keccak256(data) {
  if (CAST_BIN) {
    let arg;
    if (typeof data === "string") {
      if (data.startsWith("0x")) {
        arg = data;
      } else {
        // Convert to hex bytes so cast interprets exact UTF-8 bytes without shell escaping issues
        arg = "0x" + Buffer.from(data, "utf-8").toString("hex");
      }
    } else if (Buffer.isBuffer(data) || data instanceof Uint8Array) {
      arg = "0x" + Buffer.from(data).toString("hex");
    } else {
      throw new Error("Unsupported data type for keccak256");
    }

    const out = execFileSync(CAST_BIN, ["keccak", arg], { encoding: "utf-8" }).trim();
    return out;
  }
  throw new Error("Foundry cast binary not found for Keccak-256 execution.");
}

/**
 * Double-leaf hash to match backend/evidence/merkle.py:
 * leaf_hash = keccak256(keccak256(canonical_json_bytes))
 */
function hashLeaf(canonicalJsonStr) {
  const innerHex = keccak256(canonicalJsonStr);
  const outerHex = keccak256(innerHex);
  return outerHex.toLowerCase();
}

/**
 * Sorted-pair parent hash to match OpenZeppelin MerkleProof:
 * parent = keccak256(a < b ? concat(a, b) : concat(b, a))
 */
function hashPair(aHex, bHex) {
  const aNorm = aHex.startsWith("0x") ? aHex : "0x" + aHex;
  const bNorm = bHex.startsWith("0x") ? bHex : "0x" + bHex;

  const aBuf = Buffer.from(aNorm.slice(2), "hex");
  const bBuf = Buffer.from(bNorm.slice(2), "hex");

  let concatHex;
  if (Buffer.compare(aBuf, bBuf) < 0) {
    concatHex = "0x" + aNorm.slice(2) + bNorm.slice(2);
  } else {
    concatHex = "0x" + bNorm.slice(2) + aNorm.slice(2);
  }
  return keccak256(concatHex).toLowerCase();
}

module.exports = {
  keccak256,
  hashLeaf,
  hashPair,
};
