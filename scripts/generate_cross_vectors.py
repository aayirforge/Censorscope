"""
Generate 20 comprehensive test vectors for cross-language Merkle verification
between Python and TypeScript.
"""
import json
from pathlib import Path
from utils.canonical import canonical_json_dumps
from evidence.merkle import MerkleTree, hash_leaf

VECTORS = [
    {"id": 1, "domain": "wikipedia.org", "asn": 55836, "anomaly": False, "score": 0.0, "null_val": None},
    {"id": 2, "domain": "thepiratebay.org", "asn": 55836, "anomaly": True, "score": 0.95, "tags": ["copyright", "dot"]},
    {"id": 3, "domain": "विकिपीडिया.org", "asn": 9498, "anomaly": False, "unicode_str": "सत्यापन", "large_int": 9007199254740991},
    {"id": 4, "domain": "1337x.to", "asn": 45609, "anomaly": True, "score": 0.875, "details": {"sub_key": "val", "flag": True}},
    {"id": 5, "domain": "libgen.is", "asn": 24560, "anomaly": True, "rates": [1.5, 2.25, 3.125], "verified": True},
    {"id": 6, "domain": "bbc.com", "asn": 55836, "anomaly": False, "meta": {"empty_arr": [], "empty_obj": {}}},
    {"id": 7, "domain": "nyt.com", "asn": 55836, "anomaly": False, "score": 0.125, "active": False},
    {"id": 8, "domain": "telegram.org", "asn": 9498, "anomaly": False, "nested": {"a": {"b": {"c": "deep"}}}},
    {"id": 9, "domain": "signal.org", "asn": 55836, "anomaly": False, "large_int_2": 123456789012345},
    {"id": 10, "domain": "cloudflare.com", "asn": 13335, "anomaly": False, "ipv6_ref": "2606:4700::6810:85e5"},
    {"id": 11, "domain": "google.com", "asn": 15169, "anomaly": False, "nulls": [None, None], "bools": [True, False]},
    {"id": 12, "domain": "duckduckgo.com", "asn": 55836, "anomaly": False, "escape_test": 'quotes " and \\ slashes'},
    {"id": 13, "domain": "archive.org", "asn": 9498, "anomaly": True, "tech": "http_block_page", "code": 403},
    {"id": 14, "domain": "torproject.org", "asn": 55836, "anomaly": True, "tech": "tls_sni_filtering"},
    {"id": 15, "domain": "proton.me", "asn": 45609, "anomaly": False, "unicode_multilingual": "Русский, 中文, 日本語, العربية"},
    {"id": 16, "domain": "github.com", "asn": 55836, "anomaly": False, "stats": {"zero": 0, "neg": -1, "float_zero": 0.0}},
    {"id": 17, "domain": "reddit.com", "asn": 9498, "anomaly": False, "z_first": 1, "a_last": 2},
    {"id": 18, "domain": "vimeo.com", "asn": 55836, "anomaly": True, "tech": "dns_tampering", "ips": ["127.0.0.1"]},
    {"id": 19, "domain": "dailymotion.com", "asn": 45609, "anomaly": True, "count": 42},
    {"id": 20, "domain": "pastebin.com", "asn": 55836, "anomaly": True, "ratio": 0.6666666666666666},
]

leaves_bytes = []
vectors_output = []

for idx, record in enumerate(VECTORS):
    canon_bytes = canonical_json_dumps(record)
    l_hash = hash_leaf(canon_bytes)
    leaves_bytes.append(l_hash)

tree = MerkleTree(leaves_bytes)
root_hex = tree.root_hex

for idx, record in enumerate(VECTORS):
    canon_str = canonical_json_dumps(record).decode("utf-8")
    l_hex = "0x" + leaves_bytes[idx].hex()
    proof = tree.get_proof(idx)
    vectors_output.append({
        "record": record,
        "canonical_json": canon_str,
        "leaf_hash": l_hex,
        "proof": proof,
    })

data = {
    "merkle_root": root_hex,
    "total_records": len(VECTORS),
    "vectors": vectors_output,
}

out_path = Path("data/cross_language_vectors.json")
out_path.parent.mkdir(exist_ok=True)
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print(f"Generated {len(VECTORS)} vectors with Merkle root {root_hex} in {out_path}")
