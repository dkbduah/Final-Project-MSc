"""
SEAS Elections API – Election lifecycle management.

Handles election creation (including Paillier keypair generation),
candidate registration, and status transitions.
"""

import json
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

logger = logging.getLogger("seas.elections")

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.database import get_db
from app.db.models import Election, Candidate, PollingStation
from app.schemas.models import ElectionCreate, ElectionOut
from app.crypto.paillier import generate_keypair
from app.services.audit import log_event

router = APIRouter()


@router.post("/", response_model=ElectionOut, status_code=status.HTTP_201_CREATED)
async def create_election(
    payload: ElectionCreate, db: AsyncSession = Depends(get_db)
) -> ElectionOut:
    """
    Create a new election and generate its Paillier keypair.

    The Paillier keypair is generated server-side with the configured
    key_size.  The public key is stored openly; the private key is stored
    in the database and must be secured via access controls in production.

    Args:
        payload: Election creation request including title, date, candidates,
                 and optional key_size override.
        db:      Injected database session.

    Returns:
        The created Election with its public key and candidates.

    Raises:
        HTTPException 400: If duplicate candidate codes are supplied.
    """
    logger.info(
        "Creating election | title='%s' date='%s' candidates=%d key_size=%s",
        payload.title, payload.election_date, len(payload.candidates), payload.key_size,
    )
    codes = [c.candidate_code for c in payload.candidates]
    if len(codes) != len(set(codes)):
        dupes = [c for c in codes if codes.count(c) > 1]
        logger.warning(
            "Election creation rejected – duplicate candidate codes | dupes=%s title='%s'",
            dupes, payload.title,
        )
        raise HTTPException(
            status_code=400, detail="Duplicate candidate_code values provided."
        )

    logger.debug("Generating Paillier keypair | key_size=%s", payload.key_size)
    pub_dict, priv_dict = generate_keypair(payload.key_size)

    election = Election(
        title=payload.title,
        election_date=payload.election_date,
        status="active",
        paillier_public_key=json.dumps(pub_dict),
        paillier_private_key=json.dumps(priv_dict),
    )
    db.add(election)
    await db.flush()

    for c in payload.candidates:
        db.add(
            Candidate(
                election_id=election.id,
                name=c.name,
                party=c.party,
                candidate_code=c.candidate_code,
            )
        )

    await db.commit()
    await db.refresh(election)

    logger.info(
        "Election created successfully | election_id=%d title='%s' candidates=%d",
        election.id, election.title, len(payload.candidates),
    )

    await log_event(
        db,
        event_type="ELECTION_CREATED",
        entity_type="election",
        entity_id=str(election.id),
        data={"title": election.title, "election_date": election.election_date},
    )

    # Build response – parse JSON fields for the schema
    election.paillier_public_key = json.loads(election.paillier_public_key)  # type: ignore
    result = await db.execute(
        select(Election).where(Election.id == election.id)
    )
    db_election = result.scalar_one()

    return ElectionOut(
        id=db_election.id,
        title=db_election.title,
        election_date=db_election.election_date,
        status=db_election.status,
        paillier_public_key=json.loads(db_election.paillier_public_key),
        candidates=[
            {
                "id": c.id,
                "election_id": c.election_id,
                "name": c.name,
                "party": c.party,
                "candidate_code": c.candidate_code,
            }
            for c in db_election.candidates
        ],
        created_at=db_election.created_at,
    )


@router.get("/", response_model=List[ElectionOut])
async def list_elections(db: AsyncSession = Depends(get_db)) -> List[ElectionOut]:
    """
    Return all elections with their public keys and candidates.

    Args:
        db: Injected database session.

    Returns:
        List of all elections.
    """
    result = await db.execute(select(Election))
    elections = result.scalars().all()

    out = []
    for e in elections:
        candidates_result = await db.execute(
            select(Candidate).where(Candidate.election_id == e.id)
        )
        candidates = candidates_result.scalars().all()
        out.append(
            ElectionOut(
                id=e.id,
                title=e.title,
                election_date=e.election_date,
                status=e.status,
                paillier_public_key=json.loads(e.paillier_public_key),
                candidates=[
                    {
                        "id": c.id,
                        "election_id": c.election_id,
                        "name": c.name,
                        "party": c.party,
                        "candidate_code": c.candidate_code,
                    }
                    for c in candidates
                ],
                created_at=e.created_at,
            )
        )
    return out


@router.get("/{election_id}", response_model=ElectionOut)
async def get_election(
    election_id: int, db: AsyncSession = Depends(get_db)
) -> ElectionOut:
    """
    Retrieve a single election by ID.

    Args:
        election_id: Primary key of the election.
        db:          Injected database session.

    Returns:
        The Election with its public key and candidates.

    Raises:
        HTTPException 404: If no election with the given ID exists.
    """
    logger.debug("Fetching election | election_id=%d", election_id)
    result = await db.execute(select(Election).where(Election.id == election_id))
    election = result.scalar_one_or_none()
    if not election:
        logger.warning("Election not found | election_id=%d", election_id)
        raise HTTPException(status_code=404, detail="Election not found.")

    candidates_result = await db.execute(
        select(Candidate).where(Candidate.election_id == election_id)
    )
    candidates = candidates_result.scalars().all()

    return ElectionOut(
        id=election.id,
        title=election.title,
        election_date=election.election_date,
        status=election.status,
        paillier_public_key=json.loads(election.paillier_public_key),
        candidates=[
            {
                "id": c.id,
                "election_id": c.election_id,
                "name": c.name,
                "party": c.party,
                "candidate_code": c.candidate_code,
            }
            for c in candidates
        ],
        created_at=election.created_at,
    )