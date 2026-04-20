"""
SEAS Aggregation API – Multi-tier homomorphic aggregation endpoints.

Exposes endpoints to trigger constituency, regional, and national
aggregation.  Each operation is idempotent: re-running it updates the
stored aggregate with the latest verified submissions.
"""

import json
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException

logger = logging.getLogger("seas.aggregation")

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.database import get_db
from app.db.models import (
    ConstituencyAggregate,
    RegionalAggregate,
    NationalAggregate,
    Constituency,
    Region,
)
from app.schemas.models import (
    ConstituencyAggregateOut,
    RegionalAggregateOut,
    NationalAggregateOut,
)
from app.services.aggregation import (
    aggregate_constituency,
    aggregate_region,
    aggregate_national,
    finalise_national,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Constituency Tier
# ---------------------------------------------------------------------------


@router.post("/constituency/{election_id}/{constituency_id}")
async def run_constituency_aggregation(
    election_id: int,
    constituency_id: int,
    db: AsyncSession = Depends(get_db),
) -> ConstituencyAggregateOut:
    """
    Trigger homomorphic aggregation for a single constituency.

    Combines all verified polling station submissions within the
    constituency using additive homomorphic addition.  No decryption
    occurs.  Re-running updates the existing aggregate.

    Args:
        election_id:      Target election identifier.
        constituency_id:  Target constituency identifier.
        db:               Injected database session.

    Returns:
        Constituency aggregate with encrypted totals and station count.

    Raises:
        HTTPException 404: If no valid submissions exist for this constituency.
    """
    logger.info(
        "Triggering constituency aggregation | election_id=%d constituency_id=%d",
        election_id, constituency_id,
    )
    agg = await aggregate_constituency(db, election_id, constituency_id)
    if not agg:
        logger.warning(
            "Constituency aggregation failed – no valid submissions found | "
            "election_id=%d constituency_id=%d",
            election_id, constituency_id,
        )
        raise HTTPException(
            status_code=404,
            detail="No valid submissions found for this constituency.",
        )
    logger.info(
        "Constituency aggregation complete | election_id=%d constituency_id=%d "
        "stations_included=%d agg_id=%d",
        election_id, constituency_id, agg.stations_included, agg.id,
    )
    return _constituency_agg_out(agg)


@router.post("/all-constituencies/{election_id}")
async def run_all_constituency_aggregations(
    election_id: int, db: AsyncSession = Depends(get_db)
) -> List[ConstituencyAggregateOut]:
    """
    Trigger homomorphic aggregation for all constituencies in one call.

    Iterates over every constituency that has at least one verified
    submission and computes its encrypted aggregate.

    Args:
        election_id: Target election identifier.
        db:          Injected database session.

    Returns:
        List of updated constituency aggregates.
    """
    result = await db.execute(select(Constituency))
    constituencies = result.scalars().all()
    logger.info(
        "Triggering aggregation for all constituencies | election_id=%d total_constituencies=%d",
        election_id, len(constituencies),
    )

    aggregates = []
    skipped = 0
    for const in constituencies:
        agg = await aggregate_constituency(db, election_id, const.id)
        if agg:
            aggregates.append(_constituency_agg_out(agg))
        else:
            skipped += 1
            logger.debug(
                "Skipping constituency – no valid submissions | election_id=%d constituency_id=%d",
                election_id, const.id,
            )

    logger.info(
        "All-constituency aggregation complete | election_id=%d aggregated=%d skipped=%d",
        election_id, len(aggregates), skipped,
    )
    return aggregates


@router.get("/constituency/{election_id}", response_model=List[ConstituencyAggregateOut])
async def get_constituency_aggregates(
    election_id: int, db: AsyncSession = Depends(get_db)
) -> List[ConstituencyAggregateOut]:
    """
    Return all computed constituency aggregates for an election.

    Args:
        election_id: Target election identifier.
        db:          Injected database session.

    Returns:
        List of constituency aggregates.
    """
    result = await db.execute(
        select(ConstituencyAggregate).where(
            ConstituencyAggregate.election_id == election_id
        )
    )
    aggs = result.scalars().all()
    return [_constituency_agg_out(a) for a in aggs]


# ---------------------------------------------------------------------------
# Regional Tier
# ---------------------------------------------------------------------------


@router.post("/region/{election_id}/{region_id}")
async def run_regional_aggregation(
    election_id: int,
    region_id: int,
    db: AsyncSession = Depends(get_db),
) -> RegionalAggregateOut:
    """
    Trigger homomorphic aggregation for a single region.

    Combines all constituency aggregates within the region.

    Args:
        election_id: Target election identifier.
        region_id:   Target region identifier.
        db:          Injected database session.

    Returns:
        Regional aggregate with encrypted totals and constituency count.

    Raises:
        HTTPException 404: If no constituency aggregates exist for this region.
    """
    logger.info(
        "Triggering regional aggregation | election_id=%d region_id=%d",
        election_id, region_id,
    )
    agg = await aggregate_region(db, election_id, region_id)
    if not agg:
        logger.warning(
            "Regional aggregation failed – no constituency aggregates found | "
            "election_id=%d region_id=%d",
            election_id, region_id,
        )
        raise HTTPException(
            status_code=404,
            detail="No constituency aggregates found for this region.",
        )
    logger.info(
        "Regional aggregation complete | election_id=%d region_id=%d "
        "constituencies_included=%d agg_id=%d",
        election_id, region_id, agg.constituencies_included, agg.id,
    )
    return _regional_agg_out(agg)


@router.post("/all-regions/{election_id}")
async def run_all_regional_aggregations(
    election_id: int, db: AsyncSession = Depends(get_db)
) -> List[RegionalAggregateOut]:
    """
    Trigger homomorphic aggregation for all regions in one call.

    Args:
        election_id: Target election identifier.
        db:          Injected database session.

    Returns:
        List of updated regional aggregates.
    """
    result = await db.execute(select(Region))
    regions = result.scalars().all()
    logger.info(
        "Triggering aggregation for all regions | election_id=%d total_regions=%d",
        election_id, len(regions),
    )

    aggregates = []
    skipped = 0
    for region in regions:
        agg = await aggregate_region(db, election_id, region.id)
        if agg:
            aggregates.append(_regional_agg_out(agg))
        else:
            skipped += 1
            logger.debug(
                "Skipping region – no constituency aggregates | election_id=%d region_id=%d",
                election_id, region.id,
            )

    logger.info(
        "All-region aggregation complete | election_id=%d aggregated=%d skipped=%d",
        election_id, len(aggregates), skipped,
    )
    return aggregates


@router.get("/region/{election_id}", response_model=List[RegionalAggregateOut])
async def get_regional_aggregates(
    election_id: int, db: AsyncSession = Depends(get_db)
) -> List[RegionalAggregateOut]:
    """Return all regional aggregates for an election."""
    result = await db.execute(
        select(RegionalAggregate).where(RegionalAggregate.election_id == election_id)
    )
    aggs = result.scalars().all()
    return [_regional_agg_out(a) for a in aggs]


# ---------------------------------------------------------------------------
# National Tier
# ---------------------------------------------------------------------------


@router.post("/national/{election_id}")
async def run_national_aggregation(
    election_id: int, db: AsyncSession = Depends(get_db)
) -> NationalAggregateOut:
    """
    Aggregate all regional results into the national encrypted total.

    Does NOT decrypt.  The result remains ciphertext until /finalise is called.

    Args:
        election_id: Target election identifier.
        db:          Injected database session.

    Returns:
        National aggregate with encrypted totals (decrypted_totals is null).

    Raises:
        HTTPException 404: If no regional aggregates exist.
    """
    logger.info("Triggering national aggregation | election_id=%d", election_id)
    agg = await aggregate_national(db, election_id)
    if not agg:
        logger.warning(
            "National aggregation failed – no regional aggregates found | election_id=%d",
            election_id,
        )
        raise HTTPException(
            status_code=404,
            detail="No regional aggregates found for national aggregation.",
        )
    logger.info(
        "National aggregation complete (encrypted) | election_id=%d regions_included=%d agg_id=%d",
        election_id, agg.regions_included, agg.id,
    )
    return _national_agg_out(agg)


@router.post("/finalise/{election_id}")
async def finalise_election(
    election_id: int, db: AsyncSession = Depends(get_db)
) -> NationalAggregateOut:
    """
    Decrypt the national homomorphic aggregate to reveal final vote totals.

    This endpoint exercises the Paillier private key.  In production this
    would require multi-party authorisation.  Decrypted totals are persisted
    and broadcast to all connected WebSocket clients.

    Args:
        election_id: Target election identifier.
        db:          Injected database session.

    Returns:
        National aggregate with decrypted_totals populated.

    Raises:
        HTTPException 404: If no national aggregate exists to finalise.
    """
    logger.info(
        "Finalising election – decrypting national aggregate | election_id=%d", election_id
    )
    agg = await finalise_national(db, election_id)
    if not agg:
        logger.error(
            "Finalisation failed – no national aggregate found to decrypt | election_id=%d",
            election_id,
        )
        raise HTTPException(
            status_code=404,
            detail="No national aggregate found to finalise.",
        )
    logger.info(
        "Election finalised successfully – decrypted totals available | "
        "election_id=%d agg_id=%d finalized_at=%s",
        election_id, agg.id, agg.finalized_at,
    )
    return _national_agg_out(agg)


@router.get("/national/{election_id}", response_model=NationalAggregateOut)
async def get_national_aggregate(
    election_id: int, db: AsyncSession = Depends(get_db)
) -> NationalAggregateOut:
    """Return the national aggregate for an election, if it exists."""
    result = await db.execute(
        select(NationalAggregate).where(NationalAggregate.election_id == election_id)
    )
    agg = result.scalar_one_or_none()
    if not agg:
        raise HTTPException(status_code=404, detail="National aggregate not found.")
    return _national_agg_out(agg)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _constituency_agg_out(agg: ConstituencyAggregate) -> ConstituencyAggregateOut:
    return ConstituencyAggregateOut(
        id=agg.id,
        constituency_id=agg.constituency_id,
        election_id=agg.election_id,
        stations_included=agg.stations_included,
        computed_at=agg.computed_at,
        encrypted_totals=json.loads(agg.encrypted_totals),
    )


def _regional_agg_out(agg: RegionalAggregate) -> RegionalAggregateOut:
    return RegionalAggregateOut(
        id=agg.id,
        region_id=agg.region_id,
        election_id=agg.election_id,
        constituencies_included=agg.constituencies_included,
        computed_at=agg.computed_at,
        encrypted_totals=json.loads(agg.encrypted_totals),
    )


def _national_agg_out(agg: NationalAggregate) -> NationalAggregateOut:
    return NationalAggregateOut(
        id=agg.id,
        election_id=agg.election_id,
        regions_included=agg.regions_included,
        encrypted_totals=json.loads(agg.encrypted_totals),
        decrypted_totals=json.loads(agg.decrypted_totals) if agg.decrypted_totals else None,
        finalized_at=agg.finalized_at,
    )