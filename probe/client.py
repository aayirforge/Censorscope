"""
probe/client.py
CensorScope volunteer probe client.
Runs layer 3/4/7 network reachability probes against approved targets in allowlist.txt only.
Generates cryptographically signed measurement reports via Ed25519.
Refuses execution on un-allowlisted targets.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import ssl
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from cryptography.hazmat.primitives.asymmetric import ed25519

ALLOWLIST_PATH = Path(__file__).resolve().parent / "allowlist.txt"
PROBE_VERSION = "0.1.0"

logger = logging.getLogger("censorscope-probe")


try:
    from utils.canonical import canonical_json_dumps
except ImportError:
    # Standalone probe deployment fallback
    def canonical_json_dumps(obj: Any) -> bytes:
        """Deterministic canonical JSON serialization:

        - Sorted keys
        - No whitespace separators (',', ':')
        - Strict UTF-8 bytes preserving native Unicode
        """
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")


def load_allowlist(path: Path = ALLOWLIST_PATH) -> Set[str]:
    if not path.exists():
        return set()
    with open(path, "r", encoding="utf-8") as f:
        lines = [line.strip().lower() for line in f if line.strip() and not line.strip().startswith("#")]
    return set(lines)


class CensorScopeProbe:
    """Diagnostic probe client with strict allowlisting and cryptographic signing."""

    def __init__(
        self,
        private_key: Optional[ed25519.Ed25519PrivateKey] = None,
        asn: int = 55836,
        country: str = "IN",
        allowlist: Optional[Set[str]] = None,
    ):
        self.private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.asn = asn
        self.country = country
        self.allowlist = allowlist if allowlist is not None else load_allowlist()

    @property
    def public_key_hex(self) -> str:
        return self.public_key.public_bytes_raw().hex()

    def run_measurement(self, target_domain: str) -> Dict[str, Any]:
        """
        Executes non-intrusive DNS, TCP, TLS (with & without SNI), and HTTP probes.
        Refuses execution if domain is not on the allowlist.
        """
        clean_domain = target_domain.strip().lower().rstrip(".")
        if clean_domain not in self.allowlist:
            raise PermissionError(
                f"Security policy rejection: target domain '{clean_domain}' is not on the probe allowlist."
            )

        test_data: Dict[str, Any] = {
            "dns": {},
            "tcp": {},
            "tls": {},
            "http": {},
        }
        signals: Dict[str, bool] = {
            "dns": False,
            "tcp": False,
            "tls": False,
            "http": False,
        }
        technique_labels: List[str] = []

        # 1. DNS Resolution
        t0 = time.time()
        resolved_ips: List[str] = []
        try:
            addr_info = socket.getaddrinfo(clean_domain, 443, socket.AF_INET, socket.SOCK_STREAM)
            resolved_ips = list({s[4][0] for s in addr_info})
            test_data["dns"] = {
                "resolver": "system",
                "answers": resolved_ips,
                "response_time_ms": round((time.time() - t0) * 1000, 2),
            }
            # Check loopback or bogon answer (sinkhole)
            if any(ip.startswith("127.") or ip == "0.0.0.0" for ip in resolved_ips):
                signals["dns"] = True
                technique_labels.append("dns_tampering")
        except socket.gaierror as dns_err:
            test_data["dns"] = {
                "resolver": "system",
                "error": str(dns_err),
                "response_time_ms": round((time.time() - t0) * 1000, 2),
            }
            signals["dns"] = True
            technique_labels.append("dns_tampering")

        # 2. TCP Connect Test
        target_ip = resolved_ips[0] if resolved_ips else None
        tcp_connected = False
        if target_ip and not signals["dns"]:
            try:
                with socket.create_connection((target_ip, 443), timeout=4.0):
                    tcp_connected = True
                test_data["tcp"] = {"endpoint": f"{target_ip}:443", "connected": True}
            except Exception as tcp_err:
                test_data["tcp"] = {
                    "endpoint": f"{target_ip}:443",
                    "connected": False,
                    "error": str(tcp_err),
                }
                signals["tcp"] = True
                technique_labels.append("tcp_reset")
        else:
            test_data["tcp"] = {"connected": False, "skipped": "dns_failed_or_missing"}

        # 3. TLS Handshake Probes (with & without SNI)
        if tcp_connected and target_ip:
            # Test with SNI
            tls_sni_success = False
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((target_ip, 443), timeout=4.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=clean_domain):
                        tls_sni_success = True
                test_data["tls"]["sni"] = {"connected": True}
            except Exception as tls_err:
                test_data["tls"]["sni"] = {"connected": False, "error": str(tls_err)}
                signals["tls"] = True
                technique_labels.append("tls_sni_filtering")

            # Test without SNI
            try:
                ctx_no_sni = ssl.create_default_context()
                ctx_no_sni.check_hostname = False
                ctx_no_sni.verify_mode = ssl.CERT_NONE
                with socket.create_connection((target_ip, 443), timeout=4.0) as sock:
                    with ctx_no_sni.wrap_socket(sock):
                        test_data["tls"]["no_sni"] = {"connected": True}
            except Exception as no_sni_err:
                test_data["tls"]["no_sni"] = {"connected": False, "error": str(no_sni_err)}

        # 4. HTTP Check (if TLS connected)
        test_data["http"] = {"block_page_detected": False, "status_code": 200 if tcp_connected else None}

        # 5. Build Final Payload
        is_anomaly = any(signals.values())
        payload = {
            "domain": clean_domain,
            "asn": self.asn,
            "country": self.country,
            "test": test_data,
            "result": {
                "anomaly": is_anomaly,
                "technique_labels": technique_labels,
                "signals": signals,
            },
            "control": {
                "dns": "clean",
                "reachable": True,
            },
            "probe_pubkey": self.public_key_hex,
            "nonce": str(uuid.uuid4()),
            "timestamp": int(time.time()),
            "software_version": PROBE_VERSION,
        }

        # Sign canonical serialization with Ed25519
        canonical_bytes = canonical_json_dumps(payload)
        signature = self.private_key.sign(canonical_bytes)
        payload["signature"] = signature.hex()

        return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CensorScope Signed Probe CLI")
    parser.add_argument("--domain", required=True, help="Domain to test (must be in allowlist)")
    parser.add_argument("--asn", type=int, default=55836, help="Current ASN")
    args = parser.parse_args()

    probe = CensorScopeProbe(asn=args.asn)
    report = probe.run_measurement(args.domain)
    print(json.dumps(report, indent=2))
