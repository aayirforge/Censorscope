"""
backend/app/api/check_routes.py
API endpoints for On-Demand Live Domain Health & Censorship Checks.

Endpoints:
- POST /api/v1/check: Submits a domain for live inspection (returns job id).
- GET  /api/v1/check/{id}: Queries progress and full result payload.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app.api.limiter import check_rate_limit
from services.check_manager import LiveCheckManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/check", tags=["Live Domain Check"])


class CheckRequest(BaseModel):
    domain: str = Field(..., description="Fully qualified domain name to inspect", example="example.com")
    pow_token: Optional[str] = Field(None, description="Optional proof-of-work or CAPTCHA token")


class CheckInitiateResponse(BaseModel):
    job_id: str
    domain: str
    status: str
    cached: bool
    poll_url: str


@router.post("", response_model=CheckInitiateResponse, status_code=status.HTTP_202_ACCEPTED)
async def submit_live_check(req: CheckRequest, request: Request, response: Response):
    """
    Submits a domain for asynchronous live reachability, RDAP registration,
    and multi-country interference analysis.
    """
    # Rate limit: client rate limiting
    check_rate_limit(request)

    try:
        job_id, is_cached = await LiveCheckManager.create_check_job(
            raw_domain=req.domain,
            pow_token=req.pow_token,
        )
        status_str = "completed" if is_cached else "queued"
        status_code = status.HTTP_200_OK if is_cached else status.HTTP_202_ACCEPTED
        response.status_code = status_code

        return CheckInitiateResponse(
            job_id=job_id,
            domain=req.domain,
            status=status_str,
            cached=is_cached,
            poll_url=f"/api/v1/check/{job_id}",
        )
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except RuntimeError as re:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(re))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        logger.exception("Unexpected error in submit_live_check: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@router.get("/{job_id}")
async def get_check_status(job_id: str, request: Request):
    """
    Retrieves progress and results for a live check job.
    """
    # Rate limit polling
    check_rate_limit(request)

    job = LiveCheckManager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Check job not found or expired.")

    return job
