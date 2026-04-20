"""
SEAS Aggregation Service – Multi-Tier Homomorphic Pipeline.

Orchestrates the four-tier encrypted aggregation pipeline:

  Polling Stations  →  Constituency  →  Region  →  National

At each tier, homomorphic addition combines encrypted partial sums
without decryption.  Only the national finalise step decrypts.
All tier transitions are logged to the audit chain.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    PollingStationSubmission,
    ConstituencyAggregate,
    RegionalAggregate,
    NationalAggregate,
    Election,
    Constituency,
    Region,
    PollingStation,
)
from app.crypto.paillier import homomorphic_add, decrypt_totals
from app.services.audit import log_event
from app.services.websocket_manager import manager as ws_manager


async def aggregate_constituency(
    db: AsyncSession, election_id: int, constituency_id: int
) -> Optional[ConstituencyAggregate]:
    """
    Homomorphically aggregate all verified polling station submissions
    within a constituency for the given election.

    Fetches all non-rejected, signature-valid submissions, extracts
    their encrypted vote dicts, and performs Paillier homomorphic
    addition across all of them.  The resulting constituency aggregate
    is stored (or updated) and broadcast via WebSocket.

    Args:
        db:               Active async database session.
        election_id:      Target election identifier.
        constituency_id:  Target constituency identifier.

    Returns:
        The ConstituencyAggregate ORM instance, or None if no valid
        submissions exist for this constituency.
    """
    # Load the election's public key
    election_result = await db.execute(
        select(Election).where(Election.id == election_id)
    )
    election = election_result.scalar_one_or_none()
    if not election:
        return None

    pub_key = json.loads(election.paillier_public_key)

    # Fetch polling stations in this constituency
    stations_result = await db.execute(
        select(PollingStation.id).where(
            PollingStation.constituency_id == constituency_id
        )
    )
    station_ids = [row[0] for row in stations_result.fetchall()]

    if not station_ids:
        return None

    # Fetch valid submissions for those stations
    subs_result = await db.execute(
        select(PollingStationSubmission).where(
            PollingStationSubmission.election_id == election_id,
            PollingStationSubmission.polling_station_id.in_(station_ids),
            PollingStationSubmission.signature_valid == True,
            PollingStationSubmission.rejected == False,
        )
    )
    submissions = subs_result.scalars().all()

    if not submissions:
        return None

    # Collect encrypted vote dicts
    encrypted_list: List[Dict[str, Any]] = []
    for sub in submissions:
        enc_dict = json.loads(sub.encrypted_votes)
        # Normalise: each value should be {ciphertext, exponent}
        encrypted_list.append(enc_dict)

    # Homomorphic addition – no decryption occurs here
    aggregated = homomorphic_add(pub_key, encrypted_list)

    # Upsert constituency aggregate
    existing_result = await db.execute(
        select(ConstituencyAggregate).where(
            ConstituencyAggregate.election_id == election_id,
            ConstituencyAggregate.constituency_id == constituency_id,
        )
    )
    agg = existing_result.scalar_one_or_none()

    if agg:
        agg.encrypted_totals = json.dumps(aggregated)
        agg.stations_included = len(submissions)
        agg.computed_at = datetime.now(timezone.utc)
    else:
        agg = ConstituencyAggregate(
            election_id=election_id,
            constituency_id=constituency_id,
            encrypted_totals=json.dumps(aggregated),
            stations_included=len(submissions),
        )
        db.add(agg)

    await db.commit()
    await db.refresh(agg)

    # Audit
    await log_event(
        db,
        event_type="CONSTITUENCY_AGGREGATED",
        entity_type="constituency_aggregate",
        entity_id=str(constituency_id),
        data={
            "election_id": election_id,
            "constituency_id": constituency_id,
            "stations_included": len(submissions),
        },
    )

    # Broadcast
    await ws_manager.broadcast(
        "CONSTITUENCY_AGGREGATED",
        {
            "election_id": election_id,
            "constituency_id": constituency_id,
            "stations_included": len(submissions),
        },
    )

    return agg


async def aggregate_region(
    db: AsyncSession, election_id: int, region_id: int
) -> Optional[RegionalAggregate]:
    """
    Homomorphically aggregate all constituency aggregates within a region.

    Args:
        db:           Active async database session.
        election_id:  Target election identifier.
        region_id:    Target region identifier.

    Returns:
        The RegionalAggregate ORM instance, or None if no constituency
        aggregates exist for this region.
    """
    election_result = await db.execute(
        select(Election).where(Election.id == election_id)
    )
    election = election_result.scalar_one_or_none()
    if not election:
        return None

    pub_key = json.loads(election.paillier_public_key)

    # Fetch constituencies in this region
    const_result = await db.execute(
        select(Constituency.id).where(Constituency.region_id == region_id)
    )
    constituency_ids = [row[0] for row in const_result.fetchall()]

    if not constituency_ids:
        return None

    # Fetch constituency aggregates
    aggs_result = await db.execute(
        select(ConstituencyAggregate).where(
            ConstituencyAggregate.election_id == election_id,
            ConstituencyAggregate.constituency_id.in_(constituency_ids),
        )
    )
    const_aggs = aggs_result.scalars().all()

    if not const_aggs:
        return None

    encrypted_list = [json.loads(ca.encrypted_totals) for ca in const_aggs]
    aggregated = homomorphic_add(pub_key, encrypted_list)

    existing_result = await db.execute(
        select(RegionalAggregate).where(
            RegionalAggregate.election_id == election_id,
            RegionalAggregate.region_id == region_id,
        )
    )
    agg = existing_result.scalar_one_or_none()

    if agg:
        agg.encrypted_totals = json.dumps(aggregated)
        agg.constituencies_included = len(const_aggs)
        agg.computed_at = datetime.now(timezone.utc)
    else:
        agg = RegionalAggregate(
            election_id=election_id,
            region_id=region_id,
            encrypted_totals=json.dumps(aggregated),
            constituencies_included=len(const_aggs),
        )
        db.add(agg)

    await db.commit()
    await db.refresh(agg)

    await log_event(
        db,
        event_type="REGION_AGGREGATED",
        entity_type="regional_aggregate",
        entity_id=str(region_id),
        data={
            "election_id": election_id,
            "region_id": region_id,
            "constituencies_included": len(const_aggs),
        },
    )

    await ws_manager.broadcast(
        "REGION_AGGREGATED",
        {
            "election_id": election_id,
            "region_id": region_id,
            "constituencies_included": len(const_aggs),
        },
    )

    return agg


async def aggregate_national(
    db: AsyncSession, election_id: int
) -> Optional[NationalAggregate]:
    """
    Homomorphically aggregate all regional aggregates into a national total.

    The resulting national ciphertext is stored unmodified.  Decryption
    is a separate privileged operation (finalise_national).

    Args:
        db:           Active async database session.
        election_id:  Target election identifier.

    Returns:
        The NationalAggregate ORM instance, or None if no regional
        aggregates exist.
    """
    election_result = await db.execute(
        select(Election).where(Election.id == election_id)
    )
    election = election_result.scalar_one_or_none()
    if not election:
        return None

    pub_key = json.loads(election.paillier_public_key)

    regional_result = await db.execute(
        select(RegionalAggregate).where(
            RegionalAggregate.election_id == election_id
        )
    )
    region_aggs = regional_result.scalars().all()

    if not region_aggs:
        return None

    encrypted_list = [json.loads(ra.encrypted_totals) for ra in region_aggs]
    aggregated = homomorphic_add(pub_key, encrypted_list)

    existing_result = await db.execute(
        select(NationalAggregate).where(
            NationalAggregate.election_id == election_id
        )
    )
    agg = existing_result.scalar_one_or_none()

    if agg:
        agg.encrypted_totals = json.dumps(aggregated)
        agg.regions_included = len(region_aggs)
        agg.decrypted_totals = None
        agg.finalized_at = None
    else:
        agg = NationalAggregate(
            election_id=election_id,
            encrypted_totals=json.dumps(aggregated),
            regions_included=len(region_aggs),
        )
        db.add(agg)

    await db.commit()
    await db.refresh(agg)

    await log_event(
        db,
        event_type="NATIONAL_AGGREGATED",
        entity_type="national_aggregate",
        entity_id=str(election_id),
        data={"election_id": election_id, "regions_included": len(region_aggs)},
    )

    await ws_manager.broadcast(
        "NATIONAL_AGGREGATED",
        {"election_id": election_id, "regions_included": len(region_aggs)},
    )

    return agg


async def finalise_national(
    db: AsyncSession, election_id: int
) -> Optional[NationalAggregate]:
    """
    Decrypt the national aggregate to reveal plaintext vote totals.

    This is the only point in the system where the Paillier private key
    is used.  The decrypted totals are stored alongside the ciphertext
    so that the result can be independently verified by recomputing the
    decryption from the stored ciphertext.

    Args:
        db:           Active async database session.
        election_id:  Target election identifier.

    Returns:
        Updated NationalAggregate with decrypted_totals populated.
    """
    election_result = await db.execute(
        select(Election).where(Election.id == election_id)
    )
    election = election_result.scalar_one_or_none()
    if not election:
        return None

    nat_result = await db.execute(
        select(NationalAggregate).where(
            NationalAggregate.election_id == election_id
        )
    )
    agg = nat_result.scalar_one_or_none()
    if not agg:
        return None

    pub_key = json.loads(election.paillier_public_key)
    priv_key = json.loads(election.paillier_private_key)
    encrypted_totals = json.loads(agg.encrypted_totals)

    decrypted = decrypt_totals(pub_key, priv_key, encrypted_totals)

    agg.decrypted_totals = json.dumps(decrypted)
    agg.finalized_at = datetime.now(timezone.utc)
    election.status = "finalized"

    await db.commit()
    await db.refresh(agg)

    await log_event(
        db,
        event_type="NATIONAL_FINALIZED",
        entity_type="national_aggregate",
        entity_id=str(election_id),
        data={"election_id": election_id, "decrypted_totals": decrypted},
    )

    await ws_manager.broadcast(
        "NATIONAL_FINALIZED",
        {"election_id": election_id, "decrypted_totals": decrypted},
    )

    return agg
