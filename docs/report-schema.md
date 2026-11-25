# CensorScope Signed Measurement Report Schema

**Version**: 1.0.0  
**Specification**: Cryptographic Ed25519-Signed Network Measurement Telemetry

---

## 1. Overview
CensorScope accepts signed telemetry batches submitted by authorized probe nodes. Each measurement report contains empirical layer-3/4/7 network observation results, cryptographic nonce protection, and an Ed25519 signature generated over a canonical JSON serialization of the measurement payload.

---

## 2. Report Fields

A complete signed report JSON submitted to `POST /api/v1/reports` must contain the following top-level keys:

| Field | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `domain` | `string` | Normalized target apex domain or hostname | `"thepiratebay.org"` |
| `asn` | `integer` | Autonomous System Number of the probe | `55836` |
| `country` | `string` | ISO 3166-1 alpha-2 country code | `"IN"` |
| `test` | `object` | Detailed technical test measurements | *(See Test Object below)* |
| `result` | `object` | Anomaly determination and observed signals | *(See Result Object below)* |
| `control` | `object` | Control resolver/server agreement signals | `{"dns": "clean", "reachable": true}` |
| `probe_pubkey`| `string` | Ed25519 public key in lowercase hex (64 chars)| `"a3b9..."` |
| `nonce` | `string` | Cryptographically random unique string | `"8f4d92a1-..."` |
| `timestamp` | `integer`| UTC unix epoch timestamp in seconds | `1732428000` |
| `software_version`| `string`| Probe client release identifier | `"0.1.0"` |
| `signature` | `string` | Ed25519 signature over canonical payload (128 hex chars) | `"e5f1..."` |

### 2.1 The Test Object
```json
{
  "dns": {
    "resolver": "1.1.1.1",
    "answers": ["127.0.0.1"],
    "response_time_ms": 32.4
  },
  "tcp": {
    "endpoint": "104.21.23.4:443",
    "connected": false,
    "error": "connection_refused"
  },
  "tls": {
    "sni_enabled": true,
    "handshake_success": false,
    "error": "connection_reset_by_peer"
  },
  "http": {
    "status_code": null,
    "block_page_detected": false
  }
}
```

### 2.2 The Result Object
```json
{
  "anomaly": true,
  "technique_labels": ["dns_tampering", "tcp_reset"],
  "signals": {
    "dns": true,
    "tcp": true,
    "tls": false,
    "http": false
  }
}
```

---

## 3. Canonical JSON Serialization & Signing

Signatures must be deterministic and byte-exact across heterogeneous languages (Python, Go, Rust, TypeScript).

### 3.1 Serialization Rules (RFC 8785 Compatible)
1. The `signature` field is excluded from the payload prior to serialization.
2. All keys at all nesting depths are sorted alphabetically in ascending ASCII order.
3. No whitespace (no spaces between keys, colons, or commas: `separators=(',', ':')`).
4. Strings are encoded strictly as UTF-8.
5. Floating point numbers are formatted without exponential representation when standard representation is exact.

### 3.2 Canonical JSON String Example
```json
{"asn":55836,"control":{"dns":"clean","reachable":true},"country":"IN","domain":"thepiratebay.org","nonce":"9e1b54a2-11ef","probe_pubkey":"7c4f8...","result":{"anomaly":true,"signals":{"dns":true,"http":false,"tcp":true,"tls":false},"technique_labels":["dns_tampering"]},"software_version":"0.1.0","test":{"dns":{"answers":["127.0.0.1"],"resolver":"1.1.1.1","response_time_ms":24},"http":{"block_page_detected":false,"status_code":null},"tcp":{"connected":false,"endpoint":"104.21.23.4:443","error":"connection_refused"},"tls":{"error":"connection_reset_by_peer","handshake_success":false,"sni_enabled":true}},"timestamp":1732428000}
```

### 3.3 Signing Scheme
- Algorithm: **Ed25519** (Edwards-curve Digital Signature Algorithm over Curve25519).
- Input: `canonical_json_bytes = canonical_json_string.encode('utf-8')`
- Output: `signature = hex(ed25519_sign(private_key, canonical_json_bytes))` (128 hex chars / 64 bytes).
