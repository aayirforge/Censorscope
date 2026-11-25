# CensorScope Read-Only Public API Documentation

**Base URL**: `http://localhost:8000/api/v1` (or production host)  
**Authentication**: None required for read-only query endpoints. Rate limited to 60 requests/minute per client IP.

---

## 1. Domain Censorship Status
Returns per-ISP accessibility verdicts, confidence metrics, and detected blocking techniques for a specific domain.

- **Endpoint**: `GET /api/v1/verdicts/{domain}`
- **Parameters**:
  - `domain` (path, required): The target domain name (e.g. `example.com`).
- **Response**: `200 OK`
```json
{
  "domain": "example.com",
  "category": "accessible",
  "confidence": 0.95,
  "last_updated": "2026-11-24T12:00:00Z",
  "disclaimer": "Verdicts are dynamic statistical classifications derived from historical probe telemetry...",
  "verdicts_by_isp": [
    {
      "asn": 55836,
      "isp": "Reliance Jio",
      "verdict": "Accessible",
      "confidence": 0.95,
      "evidence_count": 42,
      "techniques": []
    }
  ],
  "articles": []
}
```

---

## 2. Cryptographic Evidence Retrieval
Returns on-chain Merkle root metadata, leaf hash, and proof array for an anchored measurement.

- **Endpoint**: `GET /api/v1/evidence/{measurement_id}`
- **Parameters**:
  - `measurement_id` (path, required): Database integer ID of the measurement.
- **Response**: `200 OK`
```json
{
  "status": "Anchored",
  "measurement_id": 105,
  "batch_id": 1,
  "merkle_root": "0xa0600dc73ad41efaf4541427d0433b78b93bb3687fd2cefb074c42b58d0a49e0",
  "ipfs_cid": "bafybeicensorexamplecid",
  "leaf_hash": "0xe2970f107597a416507b4737363a1500736e34e1fed13732b55f899244633c1b",
  "proof": [
    "0x56570de287d73cd1cb6092bb8fdee6173974955fdef345ae579ee9f475ea7432"
  ],
  "tx_hash": "0x1234...5678",
  "block_number": 51203,
  "chain_id": 11155111,
  "contract_address": "0x1234567890123456789012345678901234567890",
  "is_mock_storage": false,
  "anchoring_explainer": "Anchoring proves only that our stored copy of a record has not changed since the batch was published. Verdicts and confidence scores are calculated dynamically off-chain."
}
```

---

## 3. System Health Check
- **Endpoint**: `GET /api/v1/health`
- **Response**: `200 OK`
```json
{
  "status": "healthy",
  "timestamp": "2026-11-24T12:00:00Z"
}
```
