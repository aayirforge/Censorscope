"""
backend/app/db/models.py
SQLAlchemy models for CensorScope relational storage.
"""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.types import JSON

from app.db.base import Base

# Use JSONB if available or JSON as generic fallback
JsonType = JSON().with_variant(JSONB, "postgresql")


class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    category = Column(String(64), nullable=True, index=True)
    expected_status = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    measurements = relationship(
        "Measurement", back_populates="domain", cascade="all, delete-orphan"
    )
    verdicts = relationship("Verdict", back_populates="domain", cascade="all, delete-orphan")
    legal_contexts = relationship(
        "LegalContext", back_populates="domain", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Domain(id={self.id}, domain='{self.domain}', category='{self.category}')>"


class ASN(Base):
    __tablename__ = "asns"

    id = Column(Integer, primary_key=True, index=True)
    asn = Column(Integer, unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=True)
    isp = Column(String(128), nullable=False, index=True)
    organization = Column(String(255), nullable=True)
    verification_status = Column(String(32), default="verified", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    measurements = relationship("Measurement", back_populates="asn_rel")
    verdicts = relationship("Verdict", back_populates="asn_rel")

    def __repr__(self) -> str:
        return f"<ASN(asn={self.asn}, isp='{self.isp}', status='{self.verification_status}')>"


class Source(Base):
    __tablename__ = "sources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(64), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    url = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    measurements = relationship("Measurement", back_populates="source_rel")

    def __repr__(self) -> str:
        return f"<Source(name='{self.name}')>"


class Measurement(Base):
    __tablename__ = "measurements"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(
        Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asn_id = Column(Integer, ForeignKey("asns.id", ondelete="CASCADE"), nullable=False, index=True)
    source_id = Column(
        Integer, ForeignKey("sources.id", ondelete="SET NULL"), nullable=True, index=True
    )
    source_measurement_id = Column(String(255), nullable=False, index=True)
    test_type = Column(String(64), default="web_connectivity", nullable=False)
    measured_at = Column(DateTime, nullable=False, index=True)
    raw_json = Column(JsonType, nullable=False)
    anomaly = Column(Boolean, default=False, nullable=False, index=True)
    signals = Column(
        JsonType, nullable=False
    )  # e.g., {"dns": true, "tcp": false, "http": false, "tls": false}
    technique_labels = Column(JsonType, nullable=True)  # e.g., ["dns_tampering", "tcp_reset"]
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    domain = relationship("Domain", back_populates="measurements")
    asn_rel = relationship("ASN", back_populates="measurements")
    source_rel = relationship("Source", back_populates="measurements")

    __table_args__ = (
        UniqueConstraint("source_id", "source_measurement_id", name="uq_source_measurement_id"),
        Index("ix_measurements_domain_asn_time", "domain_id", "asn_id", "measured_at"),
        Index("ix_measurements_domain_time", "domain_id", "measured_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<Measurement(id={self.id}, domain_id={self.domain_id}, asn_id={self.asn_id}, "
            f"anomaly={self.anomaly}, measured_at='{self.measured_at}')>"
        )


class Verdict(Base):
    __tablename__ = "verdicts"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(
        Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asn_id = Column(Integer, ForeignKey("asns.id", ondelete="CASCADE"), nullable=True, index=True)
    verdict = Column(
        String(32), nullable=False
    )  # Blocked, Blocked on some ISPs, Likely blocked, Accessible, Insufficient data
    category = Column(
        String(32), nullable=True, index=True
    )  # censorship_suspected, security_related, infrastructure_failure, inconclusive
    confidence = Column(Float, nullable=False)  # 0.0 to 1.0
    explanation_json = Column(JsonType, nullable=False)
    computed_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    evidence_count = Column(Integer, default=0, nullable=False)

    domain = relationship("Domain", back_populates="verdicts")
    asn_rel = relationship("ASN", back_populates="verdicts")

    __table_args__ = (
        Index("ix_verdicts_domain_asn", "domain_id", "asn_id"),
        Index("ix_verdicts_computed_at", "computed_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<Verdict(domain_id={self.domain_id}, asn_id={self.asn_id}, "
            f"verdict='{self.verdict}', confidence={self.confidence:.2f})>"
        )


class LegalContext(Base):
    __tablename__ = "legal_context"

    id = Column(Integer, primary_key=True, index=True)
    domain_id = Column(
        Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True
    )
    summary = Column(Text, nullable=False)
    source_url = Column(String(512), nullable=True)
    source_type = Column(String(64), nullable=True)
    confidence = Column(
        String(32), default="Unknown", nullable=False
    )  # Confirmed order, Reported, Unknown
    published_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    domain = relationship("Domain", back_populates="legal_contexts")

    def __repr__(self) -> str:
        return f"<LegalContext(domain_id={self.domain_id}, confidence='{self.confidence}')>"


class Batch(Base):
    __tablename__ = "batches"

    id = Column(Integer, primary_key=True, index=True)
    onchain_batch_id = Column(BigInteger, unique=True, nullable=True, index=True)
    merkle_root = Column(String(66), unique=True, nullable=False, index=True)
    ipfs_cid = Column(String(255), nullable=False)
    from_timestamp = Column(DateTime, nullable=False)
    to_timestamp = Column(DateTime, nullable=False)
    record_count = Column(Integer, nullable=False)
    tx_hash = Column(String(66), nullable=True, index=True)
    block_number = Column(BigInteger, nullable=True)
    chain_id = Column(BigInteger, nullable=False, default=31337)
    contract_address = Column(String(42), nullable=True)
    is_mock_storage = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    proofs = relationship("MeasurementProof", back_populates="batch_rel", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Batch(id={self.id}, onchain_batch_id={self.onchain_batch_id}, root='{self.merkle_root[:10]}...')>"


class MeasurementProof(Base):
    __tablename__ = "measurement_proofs"

    id = Column(Integer, primary_key=True, index=True)
    measurement_id = Column(
        Integer, ForeignKey("measurements.id", ondelete="CASCADE"), unique=True, nullable=False, index=True
    )
    batch_id = Column(
        Integer, ForeignKey("batches.id", ondelete="CASCADE"), nullable=False, index=True
    )
    leaf_hash = Column(String(66), nullable=False, index=True)
    leaf_data_json = Column(JsonType, nullable=False)
    proof = Column(JsonType, nullable=False)  # List of 32-byte hex strings
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    batch_rel = relationship("Batch", back_populates="proofs")
    measurement_rel = relationship("Measurement")

    def __repr__(self) -> str:
        return f"<MeasurementProof(measurement_id={self.measurement_id}, batch_id={self.batch_id})>"
