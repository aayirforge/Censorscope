"""
backend/evidence/storage.py
Handles artifact storage for evidence batches with IPFS (Pinata/Infura) and local mock storage.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Tuple

import httpx

logger = logging.getLogger(__name__)

IPFS_MOCK_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "ipfs_mock"


class EvidenceStorage:
    """Manages batch artifact persistence to IPFS or local fallback mock."""

    def __init__(self):
        self.pinata_jwt = os.getenv("PINATA_JWT")
        self.pinata_api_key = os.getenv("PINATA_API_KEY")
        self.pinata_secret_key = os.getenv("PINATA_SECRET_KEY")

        # Determine mode
        self.has_ipfs_creds = bool(self.pinata_jwt or (self.pinata_api_key and self.pinata_secret_key))
        if not self.has_ipfs_creds:
            IPFS_MOCK_DIR.mkdir(parents=True, exist_ok=True)

    async def store_batch(self, batch_data: Dict[str, Any]) -> Tuple[str, bool]:
        """
        Stores batch JSON.
        Returns: (cid_or_identifier, is_mock_storage)
        """
        json_bytes = json.dumps(batch_data, indent=2).encode("utf-8")

        if self.has_ipfs_creds:
            try:
                cid = await self._upload_to_pinata(json_bytes)
                logger.info(f"Published evidence batch to IPFS: {cid}")
                return cid, False
            except Exception as e:
                logger.warning(f"IPFS upload failed ({e}); falling back to local mock storage.")

        # Local mock storage mode
        content_hash = hashlib.sha256(json_bytes).hexdigest()
        mock_cid = f"mock-bafy-{content_hash[:32]}"
        file_path = IPFS_MOCK_DIR / f"{mock_cid}.json"
        with open(file_path, "wb") as f:
            f.write(json_bytes)

        logger.info(f"Published evidence batch to local mock storage: {mock_cid}")
        return mock_cid, True

    async def _upload_to_pinata(self, content_bytes: bytes) -> str:
        headers = {}
        if self.pinata_jwt:
            headers["Authorization"] = f"Bearer {self.pinata_jwt}"
        else:
            headers["pinata_api_key"] = self.pinata_api_key
            headers["pinata_secret_api_key"] = self.pinata_secret_key

        files = {"file": ("batch.json", content_bytes, "application/json")}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                "https://api.pinata.cloud/pinning/pinFileToIPFS",
                headers=headers,
                files=files,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["IpfsHash"]
