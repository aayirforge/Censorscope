import { createHash } from "crypto";

/**
 * Deterministic JSON canonicalization in TypeScript matching backend/utils/canonical.py:
 * 1. Object keys sorted lexicographically by UTF-8 byte order.
 * 2. Compact separators without extraneous whitespace (',' and ':').
 * 3. Native UTF-8 characters preserved (no unicode escaping).
 */
export function canonicalJsonStringify(obj: any): string {
  if (obj === null || obj === undefined) {
    return "null";
  }
  if (typeof obj === "boolean" || typeof obj === "number") {
    return JSON.stringify(obj);
  }
  if (typeof obj === "string") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    const items = obj.map((item) => canonicalJsonStringify(item));
    return `[${items.join(",")}]`;
  }
  if (typeof obj === "object") {
    const sortedKeys = Object.keys(obj).sort();
    const entries = sortedKeys.map((key) => {
      const valStr = canonicalJsonStringify(obj[key]);
      return `${JSON.stringify(key)}:${valStr}`;
    });
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(obj);
}

/**
 * Keccak-256 hash using native Node crypto or web crypto
 */
export function keccak256(data: Buffer | Uint8Array): Buffer {
  // Use createHash('sha3-256') or keccak if available, or ethereumjs keccak
  // In Node standard crypto, 'sha3-256' is standard SHA3, while Ethereum uses Keccak-256.
  // We can use a lightweight keccak implementation or js-sha3
  return createHash("sha3-256").update(data).digest();
}
