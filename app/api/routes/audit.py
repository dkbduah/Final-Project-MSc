"""SEAS Audit API – tamper-evident audit log and chain verification."""

import json
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Query

logger = logging.getLogger("seas.audit")

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.database import get_db
from app.db.models import AuditLog
from app.schemas.models import AuditLogOut, ChainVerificationResult
from app.services.audit import verify_chain

router = APIRouter()


@router.get("/", response_model=List[AuditLogOut])
async def list_audit_log(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
) -> List[AuditLogOut]:
    """
    Return paginated audit log entries, optionally filtered by event type.

    Args:
        limit:      Maximum entries to return (default 100, max 500).
        offset:     Pagination offset.
        event_type: Optional filter for specific event types.
        db:         Injected database session.

    Returns:
        List of audit log entries in insertion order.
    """
    logger.debug(
        "Fetching audit log | limit=%d offset=%d event_type=%s",
        limit, offset, event_type or "ALL",
    )
    query = select(AuditLog).order_by(AuditLog.id.asc()).limit(limit).offset(offset)
    if event_type:
        query = query.where(AuditLog.event_type == event_type)

    result = await db.execute(query)
    entries = result.scalars().all()
    logger.info("Audit log query returned %d entries | limit=%d offset=%d", len(entries), limit, offset)

    return [
        AuditLogOut(
            id=e.id,
            event_type=e.event_type,
            entity_type=e.entity_type,
            entity_id=e.entity_id,
            actor_id=e.actor_id,
            data=json.loads(e.data),
            payload_hash=e.payload_hash,
            chain_hash=e.chain_hash,
            prev_hash=e.prev_hash,
            timestamp=e.timestamp,
        )
        for e in entries
    ]


@router.get("/verify-chain", response_model=ChainVerificationResult)
async def verify_audit_chain(db: AsyncSession = Depends(get_db)) -> ChainVerificationResult:
    """
    Verify the integrity of the entire audit hash chain.

    Recomputes chain hashes for every entry and detects any insertion,
    deletion, or modification that would break the chain continuity.

    Args:
        db: Injected database session.

    Returns:
        Verification result with validity flag and first broken entry, if any.
    """
    logger.info("Starting audit chain verification")
    result = await verify_chain(db)
    verified = ChainVerificationResult(**result)
    if verified.valid:
        logger.info("Audit chain verification PASSED – chain integrity confirmed")
    else:
        logger.error(
            "Audit chain verification FAILED – chain integrity broken | first_broken_entry=%s",
            verified.first_broken_entry,
        )
    return verified