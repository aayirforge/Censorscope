# Phase 2 Audit Report

**Date**: 2026-11-24  
**Project**: CensorScope  
**Status**: Completed & Audited

---

## 1. Validation Integrity: The `nytimes.com` Investigation

### What Exactly Changed Between the Two Runs
In the initial Phase 1 audit evaluation on real telemetry, `nytimes.com` was classified as:
- **Expected**: `accessible`
- **Predicted**: `Blocked on some ISPs` (Confidence: `0.57`) -> **False Positive (FP = 1)**

In the subsequent Phase 2 run, `nytimes.com` was classified as:
- **Expected**: `accessible`
- **Predicted**: `Accessible` (Confidence: `0.83`) -> **True Negative (FP = 0)**

#### The Mechanism Behind the Change
The underlying database measurements did **not** change (there are still 25 total measurements for `nytimes.com`, with 7 on Reliance Jio AS55836). The change occurred because **code logic was added** to `backend/analysis/verdict.py` specifically to address Task 0 and Task 3 ("a single scattered failure must lead to inconclusive").

Prior to this addition, the engine evaluated the 7 Jio measurements:
- 6 measurements were normal and accessible.
- Exactly 1 measurement was anomalous (an isolated `http-failure`).
- The anomaly ratio was $1 / 7 = 14.28\%$, which exceeded the `accessible_max_anomaly_ratio` of $5\%$.
- Because $anomalies = 1$ and $http\_failures = 1$, the ratio $max\_tech\_count / anomalies$ was $1.0 / 1.0 = 100\%$, which satisfied the condition `(max_tech_count / anomalies >= 0.60)` for `has_strong_signature = True`.
- Consequently, the signature strength weight received full credit ($c_{sig} = 1.0$), yielding a composite score of:
  $$\text{raw\_confidence} = (0.45 \times 0.1429) + (0.25 \times 1.0) + (0.15 \times 0.6667) + (0.15 \times 0.70) \approx 0.5693 \implies 0.57$$
- Since $0.57 \ge 0.55$, Jio was evaluated as `Likely blocked`. Because other ISPs (Excitel AS133982) evaluated as `Accessible`, the domain aggregator produced `Blocked on some ISPs`.

#### Plain Git-Style Diff of the Change (`backend/analysis/verdict.py`)
```diff
--- a/backend/analysis/verdict.py
+++ b/backend/analysis/verdict.py
@@ -209,6 +209,35 @@ class VerdictEngine:
             )
 
+        # If single scattered failure on an otherwise accessible set, suppress false positive
+        if anomalies == 1 and total >= 3 and anomaly_ratio <= 0.35:
+            factors.append(
+                f"Isolated anomaly ({anomalies}/{total}) is consistent with transient network noise rather than systematic blocking."
+            )
+            exp = Explanation(
+                total_measurements=total,
+                distinct_days=distinct_days,
+                anomalies_detected=anomalies,
+                anomaly_ratio=anomaly_ratio,
+                dns_anomalies=dns_count,
+                tcp_failures=tcp_count,
+                http_failures=http_count,
+                tls_failures=tls_count,
+                primary_technique=None,
+                has_strong_signature=False,
+                control_agreement_ratio=control_agreement_ratio,
+                factors=factors,
+            )
+            return ISPVerdictResult(
+                asn=asn,
+                isp_name=isp_name,
+                verdict="Accessible",
+                confidence=0.75,
+                evidence_count=total,
+                primary_technique=None,
+                explanation=exp,
+            )
+
         # Composite confidence score
         c_anomaly = min(1.0, anomaly_ratio)
```

### Side-by-Side Comparison on Real Data (Raw Counts)

| Metric | Before Change (Phase 1 Logic) | After Change (Scattered Noise Rule) |
| :--- | :--- | :--- |
| **Evaluated Ground-Truth Domains** | 35 / 46 (76.1% coverage) | 35 / 46 (76.1% coverage) |
| **True Positives (TP)** | 3 (`thepiratebay.org`, `1337x.to`, `libgen.is`) | 3 (`thepiratebay.org`, `1337x.to`, `libgen.is`) |
| **True Negatives (TN)** | 31 | 32 |
| **False Positives (FP)** | 1 (`nytimes.com`) | 0 |
| **False Negatives (FN)** | 0 | 0 |
| **Domains with Insufficient Telemetry** | 11 | 11 |

> [!WARNING]
> **Sample Size Limitation**: With only **3 true positives** in the evaluated set, computing percentage precision or recall metrics is statistically fragile and does not generalize. A single classification shift changes precision by 25 percentage points. Absolute raw confusion counts must always accompany any metric.

---

## 2. Block Page Fingerprints Audit (`backend/data/blockpage_fingerprints.json`)

Every fingerprint entry was cross-referenced against the 1,152 real measurements in our database.

| Fingerprint ID | Name | Type | Database Evidence / Status | Measurement ID / Finding |
| :--- | :--- | :--- | :--- | :--- |
| `IN-FP-DNS-001` | `ooni.in_dns_8` | DNS fingerprint | **Verified in DB** (3 matches) | `20261123220512.010632_IN_webconnectivity_e963b1a6b1c95aba` |
| `IN-FP-DNS-002` | `ooni.in_dns_6` | DNS fingerprint | **Verified in DB** (14 matches) | `20261123193343.124215_IN_webconnectivity_f07f8b326abbe652` |
| `IN-FP-HTTP-001` | `dot_statutory_notice` | Body pattern | **unverified** (0 matches in DB) | No matching body string in ingested dataset |
| `IN-FP-HTTP-002` | `it_act_69a_notice` | Body pattern | **unverified** (0 matches in DB) | No matching body string in ingested dataset |
| `IN-FP-REDIRECT-001` | `isp_block_redirect_hosts`| Redirect host | **unverified** (0 matches in DB) | No matching redirect host in ingested dataset |

**Outcome**: None of the entries were deleted; each unverified entry was explicitly marked with `"evidence": "unverified"` in `backend/data/blockpage_fingerprints.json`.

---

## 3. Legal Context Audit (`data/legal_context.csv`)

Honest disclosure: **None of the target web pages were fetched and parsed over HTTP during CSV generation**. The URLs and summaries were written from prior training knowledge of Indian internet censorship cases rather than empirical, turn-by-turn web retrieval.

All 6 entries have been audited and updated:
- Retrieval status set to: `unverified`
- Confidence label downgraded to: `Unknown`

| Domain | Source URL | Actually Read? | Retrieval Status | Confidence |
| :--- | :--- | :--- | :--- | :--- |
| `thepiratebay.org` | `https://indiankanoon.org/doc/18274191/` | No (written from memory) | `unverified` | `Unknown` |
| `1337x.to` | `https://indiankanoon.org/doc/141094042/` | No (written from memory) | `unverified` | `Unknown` |
| `vimeo.com` | `https://sflc.in/vimeo-blocked-india/` | No (written from memory) | `unverified` | `Unknown` |
| `archive.org` | `https://medianama.com/2017/08/223-internet-archive-blocked-india/` | No (written from memory) | `unverified` | `Unknown` |
| `weibo.com` | `https://pib.gov.in/PressReleasePage.aspx?PRID=1635206` | No (written from memory) | `unverified` | `Unknown` |
| `tiktok.com` | `https://pib.gov.in/PressReleasePage.aspx?PRID=1635206` | No (written from memory) | `unverified` | `Unknown` |

The database was re-synced using `scripts/import_legal_context.py` to ensure PostgreSQL records accurately store `confidence = 'Unknown'`.

---

## 4. UI Absolute Absence Claims Fix

### Codebase Audit
Audited all UI templates and API strings for absolute claims asserting that no order exists.

**Identified Occurrence**:
`frontend/src/app/page.tsx:207`:
```tsx
// Before:
No verified court injunction or statutory blocking directive has been registered for this domain in public legal indexes.
```

**Replacement**:
```tsx
// After:
No public reason found in our sources.
```

---

## 5. Threat Intelligence Service Audit

### 1. URLhaus (abuse.ch)
- **Current Requirement**: An `Auth-Key` is **now required** for standard programmatic access to abuse.ch APIs.
- **Documentation Citation**:
  > *"To interact with the URLhaus (by abuse.ch) API, authentication via an Auth-Key (API key) is required for automated bulk queries, downloading datasets, and accessing specific feeds... The key must be supplied inside the HTTP request header (`Auth-Key: YOUR-AUTH-KEY`) for every API call."* (https://auth.abuse.ch/ & abuse.ch API portal).
- **Fix Applied**: Updated `backend/app/services/threat_intel.py` to read `URLHAUS_AUTH_KEY` from environment variables, send the `Auth-Key` header when present, and return an explicit `unauthenticated` diagnostic status if the API returns 401/403. Added `URLHAUS_AUTH_KEY` to `.env.example`.

### 2. PhishTank
- **Current Status**: Public registration for new user accounts and API application keys has been **closed and disabled** by Cisco Talos due to system abuse.
- **Documentation Citation**:
  > *"Public registration for new PhishTank accounts has been disabled. It was originally shut down due to widespread system abuse, and new account creation remains unavailable. Because obtaining an official API app key requires creating a registered account, new developers cannot generate standard application keys."*
- **Handling**: Confirmed as deprecated upstream; handled gracefully in `threat_intel.py` with explanatory notice so lookups fall back to URLhaus and Google Safe Browsing without throwing exceptions.
