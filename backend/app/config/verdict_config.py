"""
backend/app/config/verdict_config.py
Configurable thresholds, weights, and criteria for the CensorScope verdict engine.
"""

from pydantic import BaseModel, Field


class VerdictThresholds(BaseModel):
    # Minimum sample counts required to avoid 'Insufficient data'
    min_measurements_for_evaluation: int = Field(
        default=3, description="Minimum measurements for per-ISP verdict"
    )
    min_measurements_for_accessible: int = Field(
        default=4, description="Minimum measurements to declare Accessible"
    )
    min_distinct_days_for_high_confidence: int = Field(
        default=2, description="Distinct days required for high confidence"
    )

    # Anomaly ratio thresholds
    accessible_max_anomaly_ratio: float = Field(
        default=0.05, description="Max anomaly ratio for Accessible"
    )
    likely_blocked_min_anomaly_ratio: float = Field(
        default=0.50, description="Min anomaly ratio to consider blocking"
    )

    # Confidence thresholds
    confidence_blocked_threshold: float = Field(
        default=0.80, description="Minimum confidence for Blocked"
    )
    confidence_likely_blocked_threshold: float = Field(
        default=0.55, description="Minimum confidence for Likely blocked"
    )

    # Scoring weights (sum to 1.0)
    weight_anomaly_ratio: float = Field(
        default=0.45, description="Weight of empirical anomaly ratio"
    )
    weight_signature_strength: float = Field(
        default=0.25, description="Weight of technical signature consistency (DNS, TCP, HTTP)"
    )
    weight_temporal_coverage: float = Field(
        default=0.15, description="Weight of multi-day temporal coverage"
    )
    weight_sample_depth: float = Field(
        default=0.15, description="Weight of measurement volume/depth"
    )


# Singleton instance used by the analysis engine
DEFAULT_CONFIG = VerdictThresholds()
