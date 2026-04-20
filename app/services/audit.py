"""
SEAS Audit Log Service.

Implements an append-only, SHA-256 hash-chained audit ledger.  Each entry
records a system event and links to the previous entry via its chain hash,
forming a tamper-evident structure analogous to a simplified blockchain.

Retroactive modification of any entry invalidates all subsequent chain
hashes, making tampering immediately detectable via verify_chain().
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog
from app.crypto.signatures import compute_payload_hash, compute_chain_hash

# Sentinel for the first entry in the chain
GENESIS_HASH = "0" * 64


async def log_event(
    db: AsyncSession,
    event_type: str,
    entity_type: str,
    data: Dict[str, Any],
    entity_id: Optional[str] = None,
    actor_id: Optional[str] = None,
) -> AuditLog:
    """
    Append a new event to the audit log with hash-chain integrity.

    The chain is maintained by fetching the most recent entry's chain_hash
    before writing.  If no entries exist, the genesis hash (64 zeros) is used
    as the predecessor, establishing the chain root.

    Args:
        db:          Active SQLAlchemy async session.
        event_type:  Category string, e.g. "SUBMISSION_RECEIVED".
        entity_type: Type of the affected entity, e.g. "polling_station".
        data:        Arbitrary JSON-serialisable event payload.
        entity_id:   Optional string identifier of the affected entity.
        actor_id:    Optional identifier of the acting officer or system.

    Returns:
        The persisted AuditLog ORM instance.
    """
    # Serialise and hash the event payload
    payload_hash = compute_payload_hash(data)

    # Fetch the previous chain hash
    result = await db.execute(
        select(AuditLog.chain_hash)
        .order_by(AuditLog.id.desc())
        .limit(1)
    )
    prev_hash = result.scalar_one_or_none() or GENESIS_HASH

    # Compute new chain hash
    chain_hash = compute_chain_hash(payload_hash, prev_hash)

    entry = AuditLog(
        event_type=event_type,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        actor_id=str(actor_id) if actor_id is not None else None,
        data=json.dumps(data, default=str),
        payload_hash=payload_hash,
        chain_hash=chain_hash,
        prev_hash=prev_hash,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry


async def verify_chain(db: AsyncSession) -> Dict[str, Any]:
    """
    Verify the integrity of the entire audit hash chain.

    Iterates through all entries in insertion order and recomputes
    the expected chain hash at each step.  Returns the verification
    outcome and the ID of the first broken link, if any.

    Args:
        db: Active SQLAlchemy async session.

    Returns:
        Dict with keys: valid (bool), total_entries (int),
        first_broken_at (int | None), message (str).
    """
    result = await db.execute(select(AuditLog).order_by(AuditLog.id.asc()))
    entries = result.scalars().all()

    if not entries:
        return {
            "valid": True,
            "total_entries": 0,
            "first_broken_at": None,
            "message": "Audit log is empty.",
        }

    expected_prev = GENESIS_HASH

    for entry in entries:
        expected_chain = compute_chain_hash(entry.payload_hash, expected_prev)
        if entry.chain_hash != expected_chain or entry.prev_hash != expected_prev:
            return {
                "valid": False,
                "total_entries": len(entries),
                "first_broken_at": entry.id,
                "message": f"Chain broken at entry id={entry.id}. "
                           "Possible tampering detected.",
            }
        expected_prev = entry.chain_hash

    return {
        "valid": True,
        "total_entries": len(entries),
        "first_broken_at": None,
        "message": f"All {len(entries)} entries verified. Chain intact.",
    }
