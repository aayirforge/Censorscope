// Lightweight pure JS Keccak-256 implementation (standard Keccak[c=512, r=1088, d=0x01] used by Ethereum)

const RC = [
  0x00000001n, 0x00008082n, 0x8000808an, 0x80008000n,
  0x0000808bn, 0x00000001n, 0x80008001n, 0x80008008n,
  0x00000086n, 0x00000000n, 0x00008000n, 0x00000000n,
  0x00008088n, 0x80000000n, 0x80008087n, 0x80008000n,
  0x00008081n, 0x80000000n, 0x80008008n, 0x00000038n,
  0x80000009n, 0x8000000an, 0x0000008bn, 0x8000008bn
];

function rotl(x: bigint, n: number): bigint {
  const s = BigInt(n);
  return ((x << s) | (x >> (64n - s))) & 0xffffffffffffffffn;
}

const RHO = [
  0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
];

const PI = [
  0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4
];

export function keccak256(data: Uint8Array | Buffer): Uint8Array {
  const rate = 136; // 1088 bits / 8
  const state = new BigUint64Array(25);

  // Pad data with 0x01 ... 0x80
  const len = data.length;
  const padLen = rate - (len % rate);
  const padded = new Uint8Array(len + padLen);
  padded.set(data);
  padded[len] = 0x01;
  padded[padded.length - 1] |= 0x80;

  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let w = 0n;
      for (let b = 0; b < 8; b++) {
        w |= BigInt(padded[offset + i * 8 + b]) << BigInt(b * 8);
      }
      state[i] ^= w;
    }

    // 24 Keccak rounds
    for (let round = 0; round < 24; round++) {
      // Theta
      const C = new BigUint64Array(5);
      for (let x = 0; x < 5; x++) {
        C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
      }
      const D = new BigUint64Array(5);
      for (let x = 0; x < 5; x++) {
        D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
      }
      for (let i = 0; i < 25; i++) {
        state[i] ^= D[i % 5];
      }

      // Rho and Pi
      const B = new BigUint64Array(25);
      for (let i = 0; i < 25; i++) {
        B[PI[i]] = rotl(state[i], RHO[i]);
      }

      // Chi
      for (let y = 0; y < 5; y++) {
        for (let x = 0; x < 5; x++) {
          state[y * 5 + x] = B[y * 5 + x] ^ ((~B[y * 5 + ((x + 1) % 5)]) & B[y * 5 + ((x + 2) % 5)]);
        }
      }

      // Iota
      state[0] ^= RC[round];
    }
  }

  // Extract 32 bytes (256 bits)
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    const val = state[i];
    for (let b = 0; b < 8; b++) {
      out[i * 8 + b] = Number((val >> BigInt(b * 8)) & 0xffn);
    }
  }
  return out;
}

export function hashLeaf(canonicalJsonStr: string): string {
  const bytes = Buffer.from(canonicalJsonStr, "utf-8");
  const inner = keccak256(bytes);
  const outer = keccak256(inner);
  return "0x" + Buffer.from(outer).toString("hex");
}

export function hashPair(aHex: string, bHex: string): string {
  const aBuf = Buffer.from(aHex.replace(/^0x/, ""), "hex");
  const bBuf = Buffer.from(bHex.replace(/^0x/, ""), "hex");

  let concatBuf: Buffer;
  if (Buffer.compare(aBuf, bBuf) < 0) {
    concatBuf = Buffer.concat([aBuf, bBuf]);
  } else {
    concatBuf = Buffer.concat([bBuf, aBuf]);
  }
  return "0x" + Buffer.from(keccak256(concatBuf)).toString("hex");
}
