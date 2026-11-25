"""
backend/analysis/technique.py
Granular network interference technique classification for OONI measurements.
Labels anomalous measurements with:
- dns_tampering
- tcp_reset
- tls_sni_filtering
- http_block_page
- http_injection
- ip_blocking
- unknown
Returns the exact empirical evidence fields justifying each label.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

FINGERPRINTS_FILE = Path(__file__).resolve().parent.parent / "data" / "blockpage_fingerprints.json"


@dataclass
class TechniqueClassification:
    labels: List[str]  # e.g., ["dns_tampering"]
    evidence: Dict[str, Any]  # evidence fields that triggered each label


class TechniqueClassifier:
    """Classifies anomalous measurements into technical interference mechanisms."""

    def __init__(self, fingerprints_path: Optional[Path] = None):
        self.fingerprints_path = fingerprints_path or FINGERPRINTS_FILE
        self.body_patterns: List[re.Pattern] = []
        self.redirect_hosts: Set[str] = set()
        self.dns_fingerprint_names: Set[str] = {"ooni.in_dns_8", "ooni.in_dns_6"}
        self._load_fingerprints()

    def _load_fingerprints(self) -> None:
        if not self.fingerprints_path.exists():
            return
        try:
            with open(self.fingerprints_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for fp in data.get("fingerprints", []):
                    # Phase 3 requirement: Do not use fingerprints marked 'unverified'
                    evidence = fp.get("evidence")
                    if not evidence or evidence == "unverified":
                        continue

                    fp_type = fp.get("type")
                    if fp_type == "body_pattern" and fp.get("pattern"):
                        self.body_patterns.append(re.compile(fp["pattern"], re.IGNORECASE))
                    elif fp_type == "redirect_host" and fp.get("hosts"):
                        self.redirect_hosts.update(h.lower() for h in fp["hosts"])
                    elif fp_type == "dns_fingerprint" and fp.get("name"):
                        self.dns_fingerprint_names.add(fp["name"])
        except Exception:
            pass

    def classify(self, measurement_data: Dict[str, Any]) -> TechniqueClassification:
        """
        Classifies an anomalous measurement dict or raw_json.
        """
        labels: List[str] = []
        evidence: Dict[str, Any] = {}

        raw_json = measurement_data.get("raw_json") or measurement_data
        scores = raw_json.get("scores") or {}
        analysis = scores.get("analysis") or {}
        test_keys = raw_json.get("test_keys") or {}

        # 1. Check for DNS Tampering
        dns_reasons = []
        dns_consistency = raw_json.get("dns_consistency") or test_keys.get("dns_consistency")
        if dns_consistency in ("inconsistent", "failure"):
            dns_reasons.append(f"dns_consistency={dns_consistency}")

        dns_failure = raw_json.get("dns_experiment_failure") or test_keys.get(
            "dns_experiment_failure"
        )
        if dns_failure:
            dns_reasons.append(f"dns_experiment_failure={dns_failure}")

        # Check OONI DNS fingerprints
        for fp in scores.get("fingerprints", []):
            if fp.get("location_found") == "dns" or fp.get("name") in self.dns_fingerprint_names:
                dns_reasons.append(f"fingerprint={fp.get('name')}")

        if analysis.get("blocking_type") == "dns" or raw_json.get("blocking") == "dns":
            dns_reasons.append("ooni_analysis_blocking=dns")

        if dns_reasons:
            labels.append("dns_tampering")
            evidence["dns_tampering"] = dns_reasons

        # 2. Check for HTTP Block Page
        http_block_reasons = []
        # Check redirect hosts
        redirect_url = test_keys.get("redirect_url") or ""
        if redirect_url:
            for host in self.redirect_hosts:
                if host in redirect_url.lower():
                    http_block_reasons.append(f"redirect_to_block_host={host}")

        # Check body pattern match
        response_body = test_keys.get("response_body") or test_keys.get("body") or ""
        if response_body:
            for pattern in self.body_patterns:
                if pattern.search(response_body):
                    http_block_reasons.append(f"body_pattern_match={pattern.pattern}")
                    break

        if http_block_reasons:
            labels.append("http_block_page")
            evidence["http_block_page"] = http_block_reasons

        # 3. Check for TCP Reset
        tcp_reasons = []
        tcp_connect = raw_json.get("tcp_connect") or test_keys.get("tcp_connect")
        tcp_failure = raw_json.get("tcp_experiment_failure") or test_keys.get(
            "tcp_experiment_failure"
        )

        if tcp_connect in ("connection_refused_error", "tcp_timed_out_error", "failure", False):
            tcp_reasons.append(f"tcp_connect={tcp_connect}")
        if tcp_failure:
            tcp_reasons.append(f"tcp_experiment_failure={tcp_failure}")
        if analysis.get("blocking_type") == "tcp_ip" and not dns_reasons:
            tcp_reasons.append("ooni_analysis_blocking=tcp_ip")

        if tcp_reasons:
            labels.append("tcp_reset")
            evidence["tcp_reset"] = tcp_reasons

        # 4. Check for TLS / SNI Filtering
        tls_reasons = []
        tls_read = test_keys.get("tls_handshake_read_status")
        tls_write = test_keys.get("tls_handshake_write_status")
        if tls_read and tls_read != "success":
            tls_reasons.append(f"tls_handshake_read_status={tls_read}")
        if tls_write and tls_write != "success":
            tls_reasons.append(f"tls_handshake_write_status={tls_write}")

        if tls_reasons:
            labels.append("tls_sni_filtering")
            evidence["tls_sni_filtering"] = tls_reasons

        # 5. Check for HTTP Injection / Diff
        http_fail = raw_json.get("http_experiment_failure") or test_keys.get(
            "http_experiment_failure"
        )
        if http_fail and "http_block_page" not in labels:
            labels.append("http_injection")
            evidence["http_injection"] = [f"http_experiment_failure={http_fail}"]

        # 6. Check for IP Blocking (all TCP attempts fail, DNS is verified clean)
        if "tcp_reset" in labels and not dns_reasons:
            if tcp_connect == "tcp_timed_out_error" or analysis.get("blocking_type") == "tcp_ip":
                labels.append("ip_blocking")
                evidence["ip_blocking"] = ["clean_dns_with_timeout_across_endpoints"]

        # 7. Unknown / Fallback
        if not labels:
            labels.append("unknown")
            evidence["unknown"] = [
                f"anomaly={raw_json.get('anomaly', True)}",
                f"scores={scores.get('analysis', {})}",
            ]

        return TechniqueClassification(labels=labels, evidence=evidence)
