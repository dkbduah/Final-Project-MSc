"""
SEAS Polling API – Station management and encrypted result submission.

Handles polling station registration (with Ed25519 key generation),
result submission, signature verification, and audit recording.
"""

import json
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

logger = logging.getLogger("seas.polling")

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.db.database import get_db
from app.db.models import (
    PollingStation,
    PollingStationSubmission,
    Election,
    Constituency,
    Region,
)
from app.schemas.models import (
    PollingStationCreate,
    PollingStationOut,
    PollingStationWithKey,
    SubmitResultRequest,
    SubmissionOut,
    AggregationProgress,
)
from app.crypto.signatures import (
    generate_ed25519_keypair,
    verify_signature,
    compute_payload_hash,
)
from app.services.audit import log_event
from app.services.websocket_manager import manager as ws_manager

router = APIRouter()


# ---------------------------------------------------------------------------
# Station Registration
# ---------------------------------------------------------------------------


@router.post(
    "/stations",
    response_model=PollingStationWithKey,
    status_code=status.HTTP_201_CREATED,
)
async def register_polling_station(
    payload: PollingStationCreate, db: AsyncSession = Depends(get_db)
) -> PollingStationWithKey:
    """
    Register a new polling station and generate an Ed25519 officer keypair.

    The private key is returned ONCE in this response and never stored in
    plaintext again (only the public key is persisted).  In production,
    key delivery would use a secure out-of-band channel.

    Args:
        payload: Station registration data including officer name.
        db:      Injected database session.

    Returns:
        Station record including the one-time private key for the officer.

    Raises:
        HTTPException 400: If the station_code already exists.
        HTTPException 404: If the constituency_id does not exist.
    """
    logger.info(
        "Registering polling station | station_code='%s' constituency_id=%d officer='%s'",
        payload.station_code, payload.constituency_id, payload.officer_name,
    )
    const_result = await db.execute(
        select(Constituency).where(Constituency.id == payload.constituency_id)
    )
    if not const_result.scalar_one_or_none():
        logger.warning(
            "Station registration failed – constituency not found | station_code='%s' constituency_id=%d",
            payload.station_code, payload.constituency_id,
        )
        raise HTTPException(status_code=404, detail="Constituency not found.")

    existing = await db.execute(
        select(PollingStation).where(PollingStation.station_code == payload.station_code)
    )
    if existing.scalar_one_or_none():
        logger.warning(
            "Station registration failed – duplicate station code | station_code='%s'",
            payload.station_code,
        )
        raise HTTPException(
            status_code=400, detail=f"Station code '{payload.station_code}' already exists."
        )

    priv_key_b64, pub_key_b64 = generate_ed25519_keypair()

    station = PollingStation(
        name=payload.name,
        station_code=payload.station_code,
        constituency_id=payload.constituency_id,
        registered_voters=payload.registered_voters,
        officer_name=payload.officer_name,
        officer_public_key=pub_key_b64,
        officer_private_key=priv_key_b64,  # stored for simulation; remove in prod
    )
    db.add(station)
    await db.commit()
    await db.refresh(station)

    logger.info(
        "Polling station registered successfully | station_id=%d station_code='%s' officer='%s' constituency_id=%d",
        station.id, station.station_code, station.officer_name, station.constituency_id,
    )

    await log_event(
        db,
        event_type="STATION_REGISTERED",
        entity_type="polling_station",
        entity_id=str(station.id),
        data={"station_code": station.station_code, "officer": station.officer_name},
    )

    return PollingStationWithKey(
        id=station.id,
        name=station.name,
        station_code=station.station_code,
        constituency_id=station.constituency_id,
        registered_voters=station.registered_voters,
        officer_name=station.officer_name,
        officer_public_key=pub_key_b64,
        officer_private_key=priv_key_b64,
    )


@router.get("/stations", response_model=List[PollingStationOut])
async def list_stations(db: AsyncSession = Depends(get_db)) -> List[PollingStationOut]:
    """
    Return all registered polling stations.

    Args:
        db: Injected database session.

    Returns:
        List of polling station records (private keys excluded).
    """
    result = await db.execute(select(PollingStation))
    return result.scalars().all()


@router.get("/stations/{station_id}", response_model=PollingStationOut)
async def get_station(
    station_id: int, db: AsyncSession = Depends(get_db)
) -> PollingStationOut:
    """
    Retrieve a single polling station by ID.

    Args:
        station_id: Primary key of the polling station.
        db:         Injected database session.

    Returns:
        Polling station record.

    Raises:
        HTTPException 404: If no station with the given ID exists.
    """
    result = await db.execute(
        select(PollingStation).where(PollingStation.id == station_id)
    )
    station = result.scalar_one_or_none()
    if not station:
        raise HTTPException(status_code=404, detail="Polling station not found.")
    return station


# ---------------------------------------------------------------------------
# Result Submission
# ---------------------------------------------------------------------------


@router.post(
    "/submit",
    response_model=SubmissionOut,
    status_code=status.HTTP_201_CREATED,
)
async def submit_results(
    payload: SubmitResultRequest, db: AsyncSession = Depends(get_db)
) -> SubmissionOut:
    """
    Accept a signed, Paillier-encrypted result submission from an officer.

    Processing steps:
      1. Validate the station and election exist.
      2. Check for duplicate submissions (one per station per election).
      3. Reconstruct the signed payload canonical form.
      4. Verify the Ed25519 signature against the officer's registered key.
      5. Persist the submission with signature validity status.
      6. Append audit log entry and broadcast WebSocket event.

    Args:
        payload: Submission containing encrypted votes and Ed25519 signature.
        db:      Injected database session.

    Returns:
        Persisted submission record with verification outcome.

    Raises:
        HTTPException 404: If station or election not found.
        HTTPException 409: If a submission already exists for this station/election.
    """
    logger.info(
        "Result submission received | station_id=%d election_id=%d candidate_count=%d",
        payload.polling_station_id, payload.election_id, len(payload.encrypted_votes),
    )
    # Validate station
    station_result = await db.execute(
        select(PollingStation).where(PollingStation.id == payload.polling_station_id)
    )
    station = station_result.scalar_one_or_none()
    if not station:
        logger.warning(
            "Submission rejected – polling station not found | station_id=%d election_id=%d",
            payload.polling_station_id, payload.election_id,
        )
        raise HTTPException(status_code=404, detail="Polling station not found.")

    # Validate election
    election_result = await db.execute(
        select(Election).where(Election.id == payload.election_id)
    )
    election = election_result.scalar_one_or_none()
    if not election:
        logger.warning(
            "Submission rejected – election not found | station_id=%d election_id=%d",
            payload.polling_station_id, payload.election_id,
        )
        raise HTTPException(status_code=404, detail="Election not found.")

    # Check for duplicate submission
    dup_result = await db.execute(
        select(PollingStationSubmission).where(
            PollingStationSubmission.polling_station_id == payload.polling_station_id,
            PollingStationSubmission.election_id == payload.election_id,
            PollingStationSubmission.rejected == False,
        )
    )
    if dup_result.scalar_one_or_none():
        logger.warning(
            "Submission rejected – duplicate submission | station_id=%d station_code='%s' election_id=%d",
            payload.polling_station_id, station.station_code, payload.election_id,
        )
        raise HTTPException(
            status_code=409,
            detail="A valid submission already exists for this station and election.",
        )

    # Build canonical payload dict for signature verification
    enc_votes_dict = {
        cid: enc.model_dump() for cid, enc in payload.encrypted_votes.items()
    }
    signed_payload = {
        "polling_station_id": payload.polling_station_id,
        "election_id": payload.election_id,
        "encrypted_votes": enc_votes_dict,
    }

    # Verify Ed25519 signature
    signature_valid = verify_signature(
        station.officer_public_key, signed_payload, payload.signature
    )

    rejection_reason = None
    rejected = False
    if not signature_valid:
        rejected = True
        rejection_reason = "Ed25519 signature verification failed."
        logger.warning(
            "Submission signature invalid | station_id=%d station_code='%s' election_id=%d payload_hash=%s",
            payload.polling_station_id, station.station_code, payload.election_id,
            compute_payload_hash(signed_payload),
        )
    else:
        logger.debug(
            "Submission signature verified | station_id=%d station_code='%s' election_id=%d",
            payload.polling_station_id, station.station_code, payload.election_id,
        )

    payload_hash = compute_payload_hash(signed_payload)

    submission = PollingStationSubmission(
        polling_station_id=payload.polling_station_id,
        election_id=payload.election_id,
        encrypted_votes=json.dumps(enc_votes_dict),
        signature=payload.signature,
        payload_hash=payload_hash,
        signature_valid=signature_valid,
        rejected=rejected,
        rejection_reason=rejection_reason,
    )
    db.add(submission)
    await db.commit()
    await db.refresh(submission)

    if rejected:
        logger.error(
            "Submission persisted as REJECTED | submission_id=%d station_id=%d station_code='%s' "
            "election_id=%d reason='%s' payload_hash=%s",
            submission.id, payload.polling_station_id, station.station_code,
            payload.election_id, rejection_reason, payload_hash,
        )
    else:
        logger.info(
            "Submission accepted and persisted | submission_id=%d station_id=%d station_code='%s' "
            "election_id=%d payload_hash=%s",
            submission.id, payload.polling_station_id, station.station_code,
            payload.election_id, payload_hash,
        )

    event_type = "SUBMISSION_REJECTED" if rejected else "SUBMISSION_RECEIVED"
    await log_event(
        db,
        event_type=event_type,
        entity_type="polling_station_submission",
        entity_id=str(submission.id),
        actor_id=str(station.id),
        data={
            "station_code": station.station_code,
            "election_id": payload.election_id,
            "signature_valid": signature_valid,
            "rejection_reason": rejection_reason,
            "payload_hash": payload_hash,
        },
    )

    await ws_manager.broadcast(
        event_type,
        {
            "submission_id": submission.id,
            "station_id": payload.polling_station_id,
            "station_code": station.station_code,
            "election_id": payload.election_id,
            "signature_valid": signature_valid,
        },
    )

    return submission


@router.get("/submissions/{election_id}", response_model=List[SubmissionOut])
async def list_submissions(
    election_id: int, db: AsyncSession = Depends(get_db)
) -> List[SubmissionOut]:
    """
    Return all submissions for a given election.

    Args:
        election_id: Target election identifier.
        db:          Injected database session.

    Returns:
        All submission records including rejected ones.
    """
    result = await db.execute(
        select(PollingStationSubmission).where(
            PollingStationSubmission.election_id == election_id
        )
    )
    return result.scalars().all()


@router.get("/progress/{election_id}", response_model=AggregationProgress)
async def get_progress(
    election_id: int, db: AsyncSession = Depends(get_db)
) -> AggregationProgress:
    """
    Return real-time aggregation progress metrics for an election.

    Args:
        election_id: Target election identifier.
        db:          Injected database session.

    Returns:
        Submission counts, verification rates, and tier completion status.
    """
    from app.db.models import ConstituencyAggregate, RegionalAggregate, NationalAggregate

    total_stations_r = await db.execute(select(func.count(PollingStation.id)))
    total_stations = total_stations_r.scalar_one()

    submitted_r = await db.execute(
        select(func.count(PollingStationSubmission.id)).where(
            PollingStationSubmission.election_id == election_id
        )
    )
    total_submitted = submitted_r.scalar_one()

    verified_r = await db.execute(
        select(func.count(PollingStationSubmission.id)).where(
            PollingStationSubmission.election_id == election_id,
            PollingStationSubmission.signature_valid == True,
            PollingStationSubmission.rejected == False,
        )
    )
    total_verified = verified_r.scalar_one()

    rejected_r = await db.execute(
        select(func.count(PollingStationSubmission.id)).where(
            PollingStationSubmission.election_id == election_id,
            PollingStationSubmission.rejected == True,
        )
    )
    total_rejected = rejected_r.scalar_one()

    const_agg_r = await db.execute(
        select(func.count(ConstituencyAggregate.id)).where(
            ConstituencyAggregate.election_id == election_id
        )
    )
    const_agg_count = const_agg_r.scalar_one()

    reg_agg_r = await db.execute(
        select(func.count(RegionalAggregate.id)).where(
            RegionalAggregate.election_id == election_id
        )
    )
    reg_agg_count = reg_agg_r.scalar_one()

    nat_r = await db.execute(
        select(NationalAggregate).where(NationalAggregate.election_id == election_id)
    )
    nat = nat_r.scalar_one_or_none()

    rate = (total_submitted / total_stations * 100) if total_stations else 0.0

    return AggregationProgress(
        election_id=election_id,
        total_stations=total_stations,
        stations_submitted=total_submitted,
        stations_verified=total_verified,
        stations_rejected=total_rejected,
        constituencies_aggregated=const_agg_count,
        regions_aggregated=reg_agg_count,
        national_finalized=nat is not None and nat.decrypted_totals is not None,
        submission_rate_pct=round(rate, 2),
    )