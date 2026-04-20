"""SEAS Verification API – on-demand signature and submission verification."""

import json
import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException

logger = logging.getLogger("seas.verification")

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.database import get_db
from app.db.models import PollingStationSubmission, PollingStation
from app.schemas.models import VerifySignatureRequest, VerificationResult
from app.crypto.signatures import verify_signature, compute_payload_hash

router = APIRouter()


@router.post("/signature", response_model=VerificationResult)
async def verify_submission_signature(
    payload: VerifySignatureRequest, db: AsyncSession = Depends(get_db)
) -> VerificationResult:
    """
    Verify the Ed25519 signature on a submitted result payload.

    Can be called independently to confirm that a stored submission was
    genuinely signed by the registered polling station officer.

    Args:
        payload: The original submission payload to re-verify.
        db:      Injected database session.

    Returns:
        Verification result including validity flag and payload hash.

    Raises:
        HTTPException 404: If no matching submission exists.
    """
    logger.info(
        "Signature verification requested | station_id=%d election_id=%d",
        payload.polling_station_id, payload.election_id,
    )
    station_result = await db.execute(
        select(PollingStation).where(PollingStation.id == payload.polling_station_id)
    )
    station = station_result.scalar_one_or_none()
    if not station:
        logger.warning(
            "Verification failed – polling station not found | station_id=%d",
            payload.polling_station_id,
        )
        raise HTTPException(status_code=404, detail="Polling station not found.")

    sub_result = await db.execute(
        select(PollingStationSubmission).where(
            PollingStationSubmission.polling_station_id == payload.polling_station_id,
            PollingStationSubmission.election_id == payload.election_id,
        )
    )
    submission = sub_result.scalar_one_or_none()
    if not submission:
        logger.warning(
            "Verification failed – submission not found | station_id=%d election_id=%d",
            payload.polling_station_id, payload.election_id,
        )
        raise HTTPException(status_code=404, detail="Submission not found.")

    enc_votes_dict = {
        cid: enc.model_dump() for cid, enc in payload.encrypted_votes.items()
    }
    signed_payload = {
        "polling_station_id": payload.polling_station_id,
        "election_id": payload.election_id,
        "encrypted_votes": enc_votes_dict,
    }

    valid = verify_signature(station.officer_public_key, signed_payload, payload.signature)
    ph = compute_payload_hash(signed_payload)

    if valid:
        logger.info(
            "Signature verified as VALID | submission_id=%d station_id=%d election_id=%d payload_hash=%s",
            submission.id, payload.polling_station_id, payload.election_id, ph,
        )
    else:
        logger.warning(
            "Signature verified as INVALID | submission_id=%d station_id=%d "
            "station_code='%s' election_id=%d payload_hash=%s",
            submission.id, payload.polling_station_id, station.station_code,
            payload.election_id, ph,
        )

    return VerificationResult(
        submission_id=submission.id,
        polling_station_id=payload.polling_station_id,
        signature_valid=valid,
        payload_hash=ph,
        verified_at=datetime.now(timezone.utc),
    )


@router.get("/submission/{submission_id}", response_model=VerificationResult)
async def verify_stored_submission(
    submission_id: int, db: AsyncSession = Depends(get_db)
) -> VerificationResult:
    """
    Re-verify the stored signature of an existing submission by ID.

    Args:
        submission_id: Primary key of the submission to re-verify.
        db:            Injected database session.

    Returns:
        Verification result confirming current signature validity.

    Raises:
        HTTPException 404: If the submission does not exist.
    """
    logger.info("Re-verifying stored submission | submission_id=%d", submission_id)
    sub_result = await db.execute(
        select(PollingStationSubmission).where(
            PollingStationSubmission.id == submission_id
        )
    )
    submission = sub_result.scalar_one_or_none()
    if not submission:
        logger.warning(
            "Re-verification failed – submission not found | submission_id=%d", submission_id
        )
        raise HTTPException(status_code=404, detail="Submission not found.")

    station_result = await db.execute(
        select(PollingStation).where(
            PollingStation.id == submission.polling_station_id
        )
    )
    station = station_result.scalar_one_or_none()

    enc_votes_dict = json.loads(submission.encrypted_votes)
    signed_payload = {
        "polling_station_id": submission.polling_station_id,
        "election_id": submission.election_id,
        "encrypted_votes": enc_votes_dict,
    }

    valid = verify_signature(
        station.officer_public_key, signed_payload, submission.signature
    )

    if valid:
        logger.info(
            "Stored submission re-verified as VALID | submission_id=%d station_id=%d election_id=%d",
            submission.id, submission.polling_station_id, submission.election_id,
        )
    else:
        logger.warning(
            "Stored submission re-verified as INVALID – possible data tampering | "
            "submission_id=%d station_id=%d election_id=%d original_hash=%s",
            submission.id, submission.polling_station_id,
            submission.election_id, submission.payload_hash,
        )

    return VerificationResult(
        submission_id=submission.id,
        polling_station_id=submission.polling_station_id,
        signature_valid=valid,
        payload_hash=submission.payload_hash,
        verified_at=datetime.now(timezone.utc),
    )