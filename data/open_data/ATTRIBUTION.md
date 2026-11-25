# CensorScope Open Data Attribution & Licensing Notice

**Dataset**: CensorScope India Censorship Measurements & Anchored Batches  
**Distribution Terms**: Non-Commercial Research & Empirical Verification License

---

## 1. Upstream Data Sources & Actual License Verification

### A. Citizen Lab Global & Country-Specific Test Lists
- **Source Repository**: `https://github.com/citizenlab/test-lists`
- **Verified License**: **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)**
- **Verified Text from Upstream README**:
  > *"All data is provided under Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International and available in full [here](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode) and summarized [here](https://creativecommons.org/licenses/by-nc-sa/4.0/)"*
  > *Citation: Citizen Lab and Others. 2014. URL Testing Lists Intended for Discovering Website Censorship. https://github.com/citizenlab/test-lists.*
- **Legal Terms & Restrictions**:
  - **NonCommercial (NC)**: Test lists may NOT be sold or incorporated into commercial products or services.
  - **ShareAlike (SA)**: Any derivative adaptations of the domain test lists must be released under the identical CC BY-NC-SA 4.0 terms.
  - **Attribution (BY)**: Mandatory citation of Citizen Lab.

### B. Open Observatory of Network Interference (OONI)
- **Source Policy**: `https://ooni.org/about/data-policy/` (referencing `https://github.com/ooni/license`)
- **Verified License**: **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)** (Website content under CC BY-SA 3.0 / CC BY-SA 4.0).
- **Verified Terms & Restrictions**:
  - Network measurement datasets collected by OONI are published under CC BY-NC-SA terms.
  - Sourced measurement telemetry redistributed through CensorScope must strictly remain **Non-Commercial** and carry downstream **ShareAlike** protections.
  - Attribution notice: "Network interference measurements sourced from the Open Observatory of Network Interference (OONI, https://ooni.org)."

### C. Volunteer Probe Telemetry
- **Contribution Agreement**: Submitted by authorized volunteer probe operators under the CensorScope Probe Operator Agreement strictly for non-commercial, public-interest academic and human rights censorship research.

---

## 2. Redistribution & Non-Commercial Compliance

Because upstream Citizen Lab URL test lists and OONI measurement data are licensed under **CC BY-NC-SA 4.0**:
- **CensorScope's open dataset is strictly NON-COMMERCIAL**. No commercial use, sale, or paid syndication of this data is permitted.
- Any derivative datasets, aggregations, or downstream distributions must be licensed under **CC BY-NC-SA 4.0** (ShareAlike condition).
- If CensorScope is ever offered commercially in the future, all Citizen Lab test lists and OONI telemetry must be isolated or replaced with independently curated, commercially permissive test lists.

---

## 3. Data Sanitization & Exclusions Guarantee

The open data dump (`data/open_data/`) strictly contains only public network observation telemetry:
- **No Private Keys**: Zero cryptographic private keys, nonces, or probe secrets.
- **No API Keys or Secrets**: Database passwords, RPC endpoints, and service tokens are completely omitted.
- **No Third-Party Article Text**: Full article bodies, copyrighted news excerpts, or non-redistributable content are excluded.
- **No User Query Logs**: Zero end-user search queries or client IP addresses are included in the export.

---

## 3. Unverified Licenses Notice
- Threat intelligence feeds and news API headlines fetched during ad-hoc queries are **NOT** redistributed in this open data export due to proprietary API terms of service. Only open telemetry (OONI and volunteer probes) is included.
