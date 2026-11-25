"""
backend/evidence/publisher.py
Automated, idempotent evidence batch publisher.
Anchors measurement Merkle roots to EvidenceRegistry on Ethereum (Anvil / Sepolia).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from eth_account import Account
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider

from app.db.models import Batch, Domain, Measurement, MeasurementProof
from evidence.merkle import MerkleTree, hash_leaf
from evidence.storage import EvidenceStorage
from utils.canonical import canonical_json_dumps

logger = logging.getLogger(__name__)

# EvidenceRegistry ABI for submitBatch
EVIDENCE_REGISTRY_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"},
            {"internalType": "string", "name": "ipfsCid", "type": "string"},
            {"internalType": "uint64", "name": "fromTs", "type": "uint64"},
            {"internalType": "uint64", "name": "toTs", "type": "uint64"},
            {"internalType": "uint32", "name": "count", "type": "uint32"},
        ],
        "name": "submitBatch",
        "outputs": [{"internalType": "uint256", "name": "batchId", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "root", "type": "bytes32"}],
        "name": "isKnownRoot",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "batchCount",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
]


class EvidencePublisher:
    """Orchestrates leaf construction, Merkle batch generation, IPFS publication, and on-chain anchoring."""

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        private_key: Optional[str] = None,
        contract_address: Optional[str] = None,
    ):
        self.rpc_url = rpc_url or os.getenv("ETHEREUM_RPC_URL", "http://127.0.0.1:8545")
        self.private_key = private_key or os.getenv("PUBLISHER_PRIVATE_KEY") or os.getenv("DEPLOYER_PRIVATE_KEY")
        self.contract_address = contract_address or os.getenv("EVIDENCE_REGISTRY_ADDRESS")
        self.storage = EvidenceStorage()

    def build_leaf_payload(self, m: Measurement, domain_str: str) -> Tuple[Dict[str, Any], bytes]:
        """
        Build deterministic canonical leaf dictionary and double-hashed leaf bytes.
        """
        measured_iso = m.measured_at.strftime("%Y-%m-%dT%H:%M:%SZ") if m.measured_at else ""
        ingested_iso = m.created_at.strftime("%Y-%m-%dT%H:%M:%SZ") if m.created_at else ""

        # Normalize signals
        sig = m.signals if isinstance(m.signals, dict) else {}
        trimmed_signals = {
            "dns_tampering": bool(sig.get("dns")),
            "tcp_reset": bool(sig.get("tcp")),
            "tls_sni_failure": bool(sig.get("tls")),
            "http_failure": bool(sig.get("http")),
        }

        # Technique string
        technique = "none"
        if m.technique_labels and isinstance(m.technique_labels, list) and len(m.technique_labels) > 0:
            technique = m.technique_labels[0]

        source = m.source_rel.name if m.source_rel else "ooni"

        leaf_dict = {
            "id": int(m.id),
            "source": str(source),
            "domain": str(domain_str),
            "asn": int(m.asn_id) if m.asn_id else 0,
            "measured_at": measured_iso,
            "technique": technique,
            "anomaly": bool(m.anomaly),
            "signals": trimmed_signals,
            "ingested_at": ingested_iso,
        }

        canonical_bytes = canonical_json_dumps(leaf_dict)
        leaf_bytes = hash_leaf(canonical_bytes)
        return leaf_dict, leaf_bytes

    async def publish_pending_batch(self, db: AsyncSession, limit: int = 100) -> Optional[Batch]:
        """
        Selects unanchored measurements, constructs Merkle tree, uploads to IPFS/mock,
        and submits transaction on-chain.
        """
        # 1. Fetch measurements without proofs (eager-load source_rel to avoid lazy load in async)
        from sqlalchemy.orm import selectinload
        subquery = select(MeasurementProof.measurement_id)
        stmt = (
            select(Measurement, Domain.domain)
            .join(Domain, Measurement.domain_id == Domain.id)
            .options(selectinload(Measurement.source_rel))
            .where(~Measurement.id.in_(subquery))
            .order_by(Measurement.measured_at.asc())
            .limit(limit)
        )
        res = await db.execute(stmt)
        rows = res.all()

        if not rows:
            logger.info("No unanchored measurements available.")
            return None

        # 2. Build Leaves
        leaves_data: List[Dict[str, Any]] = []
        leaves_bytes: List[bytes] = []
        measurements: List[Measurement] = []

        for m, dom_name in rows:
            leaf_dict, leaf_hash = self.build_leaf_payload(m, dom_name)
            leaves_data.append(leaf_dict)
            leaves_bytes.append(leaf_hash)
            measurements.append(m)

        # 3. Construct Merkle Tree
        tree = MerkleTree(leaves_bytes)
        root_hex = tree.root_hex

        from_ts = int(min(m.measured_at for m in measurements).timestamp())
        to_ts = int(max(m.measured_at for m in measurements).timestamp())
        count = len(measurements)

        # 4. Store Artifact in IPFS / Mock Storage
        batch_artifact = {
            "merkle_root": root_hex,
            "from_timestamp": from_ts,
            "to_timestamp": to_ts,
            "record_count": count,
            "records": leaves_data,
        }
        cid, is_mock = await self.storage.store_batch(batch_artifact)

        # 5. On-Chain Anchoring (if contract credentials configured)
        tx_hash = None
        block_number = None
        onchain_id = None
        chain_id = 31337

        if self.private_key and self.contract_address:
            w3 = AsyncWeb3(AsyncHTTPProvider(self.rpc_url))
            chain_id = await w3.eth.chain_id
            account = Account.from_key(self.private_key)

            checksum_address = AsyncWeb3.to_checksum_address(self.contract_address)
            contract = w3.eth.contract(address=checksum_address, abi=EVIDENCE_REGISTRY_ABI)

            # Check if root is already known (idempotency guard)
            is_known = await contract.functions.isKnownRoot(bytes.fromhex(root_hex[2:])).call()
            if not is_known:
                nonce = await w3.eth.get_transaction_count(account.address, "pending")
                tx = await contract.functions.submitBatch(
                    bytes.fromhex(root_hex[2:]),
                    cid,
                    from_ts,
                    to_ts,
                    count,
                ).build_transaction({
                    "from": account.address,
                    "nonce": nonce,
                    "chainId": chain_id,
                })

                signed_tx = account.sign_transaction(tx)
                tx_hash_bytes = await w3.eth.send_raw_transaction(signed_tx.raw_transaction)
                tx_hash = "0x" + tx_hash_bytes.hex()
                logger.info(f"Broadcasted submitBatch transaction: {tx_hash}")

                # Await confirmation
                receipt = await w3.eth.wait_for_transaction_receipt(tx_hash_bytes, timeout=60)
                block_number = receipt["blockNumber"]

                # Extract onchain batch id from event or query total batch count - 1
                total_batches = await contract.functions.batchCount().call()
                onchain_id = total_batches - 1

        # 6. Persist Batch & Proofs in DB
        batch_record = Batch(
            onchain_batch_id=onchain_id,
            merkle_root=root_hex,
            ipfs_cid=cid,
            from_timestamp=min(m.measured_at for m in measurements),
            to_timestamp=max(m.measured_at for m in measurements),
            record_count=count,
            tx_hash=tx_hash,
            block_number=block_number,
            chain_id=chain_id,
            contract_address=self.contract_address,
            is_mock_storage=is_mock,
        )
        db.add(batch_record)
        await db.flush()

        # Add proofs for all measurements
        for idx, m in enumerate(measurements):
            proof_hexes = tree.get_proof(idx)
            proof_rec = MeasurementProof(
                measurement_id=m.id,
                batch_id=batch_record.id,
                leaf_hash="0x" + leaves_bytes[idx].hex(),
                leaf_data_json=leaves_data[idx],
                proof=proof_hexes,
            )
            db.add(proof_rec)

        await db.commit()
        await db.refresh(batch_record)
        logger.info(f"Successfully anchored batch {batch_record.id} with {count} proofs.")
        return batch_record
