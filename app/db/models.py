"""
SEAS ORM Models – Ghana Four-Tier Administrative Hierarchy.

The data model mirrors Ghana's official electoral structure:
  Tier 4  →  Polling Station   (~33,000 nationally)
  Tier 3  →  Constituency      (275)
  Tier 2  →  Region            (16)
  Tier 1  →  National          (1)

All cryptographic payloads (encrypted votes, signatures, public keys)
are stored as JSON strings to preserve exact big-integer fidelity.
The AuditLog table implements an append-only hash-chained ledger.
"""

import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


def _now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Administrative Hierarchy
# ---------------------------------------------------------------------------


class Region(Base):
    """
    One of Ghana's 16 administrative regions.

    Regions aggregate constituency results and transmit to the national tier.
    """

    __tablename__ = "regions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    region_code: Mapped[str] = mapped_column(String(10), nullable=False, unique=True)

    constituencies: Mapped[list["Constituency"]] = relationship(
        "Constituency", back_populates="region"
    )
    regional_aggregates: Mapped[list["RegionalAggregate"]] = relationship(
        "RegionalAggregate", back_populates="region"
    )


class Constituency(Base):
    """
    One of Ghana's 275 parliamentary constituencies.

    Constituencies aggregate polling station results and forward to regions.
    """

    __tablename__ = "constituencies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    constituency_code: Mapped[str] = mapped_column(String(15), nullable=False, unique=True)
    region_id: Mapped[int] = mapped_column(ForeignKey("regions.id"), nullable=False)

    region: Mapped["Region"] = relationship("Region", back_populates="constituencies")
    polling_stations: Mapped[list["PollingStation"]] = relationship(
        "PollingStation", back_populates="constituency"
    )
    constituency_aggregates: Mapped[list["ConstituencyAggregate"]] = relationship(
        "ConstituencyAggregate", back_populates="constituency"
    )


class PollingStation(Base):
    """
    An individual polling station where ballots are cast and counted.

    Each station is operated by an officer whose Ed25519 public key is
    registered here and used to verify all result submissions.
    """

    __tablename__ = "polling_stations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    station_code: Mapped[str] = mapped_column(String(20), nullable=False, unique=True)
    constituency_id: Mapped[int] = mapped_column(
        ForeignKey("constituencies.id"), nullable=False
    )
    registered_voters: Mapped[int] = mapped_column(Integer, default=0)

    # Officer credentials
    officer_name: Mapped[str] = mapped_column(String(150), nullable=False)
    officer_public_key: Mapped[str] = mapped_column(Text, nullable=False)
    officer_private_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    constituency: Mapped["Constituency"] = relationship(
        "Constituency", back_populates="polling_stations"
    )
    submissions: Mapped[list["PollingStationSubmission"]] = relationship(
        "PollingStationSubmission", back_populates="polling_station"
    )


# ---------------------------------------------------------------------------
# Election & Candidates
# ---------------------------------------------------------------------------


class Election(Base):
    """
    A national election event.

    Holds the Paillier keypair: the public key is distributed to all
    polling stations for encryption; the private key is held by the
    national aggregator and used only during final decryption.
    """

    __tablename__ = "elections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    election_date: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active"
    )  # setup | active | closed | finalized

    # Paillier keypair (JSON strings of big-int decimal values)
    paillier_public_key: Mapped[str] = mapped_column(Text, nullable=False)
    paillier_private_key: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    candidates: Mapped[list["Candidate"]] = relationship(
        "Candidate", back_populates="election", cascade="all, delete-orphan"
    )
    submissions: Mapped[list["PollingStationSubmission"]] = relationship(
        "PollingStationSubmission", back_populates="election"
    )
    constituency_aggregates: Mapped[list["ConstituencyAggregate"]] = relationship(
        "ConstituencyAggregate", back_populates="election"
    )
    regional_aggregates: Mapped[list["RegionalAggregate"]] = relationship(
        "RegionalAggregate", back_populates="election"
    )
    national_aggregate: Mapped[Optional["NationalAggregate"]] = relationship(
        "NationalAggregate", back_populates="election", uselist=False
    )


class Candidate(Base):
    """
    A candidate standing in a given election.

    Candidate codes serve as the keys in encrypted vote dictionaries,
    allowing candidates to be referenced without exposing names during
    homomorphic aggregation.
    """

    __tablename__ = "candidates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    election_id: Mapped[int] = mapped_column(ForeignKey("elections.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    party: Mapped[str] = mapped_column(String(100), nullable=False)
    candidate_code: Mapped[str] = mapped_column(String(20), nullable=False)

    __table_args__ = (
        UniqueConstraint("election_id", "candidate_code", name="uq_election_candidate"),
    )

    election: Mapped["Election"] = relationship("Election", back_populates="candidates")


# ---------------------------------------------------------------------------
# Submissions & Aggregates
# ---------------------------------------------------------------------------


class PollingStationSubmission(Base):
    """
    A signed, encrypted result submission from a single polling station.

    The encrypted_votes field stores the Paillier ciphertexts; the signature
    is the Ed25519 signature over the canonicalised payload.  Tampered or
    duplicate submissions are flagged and logged without deletion.
    """

    __tablename__ = "polling_station_submissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    polling_station_id: Mapped[int] = mapped_column(
        ForeignKey("polling_stations.id"), nullable=False
    )
    election_id: Mapped[int] = mapped_column(ForeignKey("elections.id"), nullable=False)

    # Cryptographic payload
    encrypted_votes: Mapped[str] = mapped_column(Text, nullable=False)  # JSON
    signature: Mapped[str] = mapped_column(Text, nullable=False)         # base64
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Verification outcome
    signature_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    rejected: Mapped[bool] = mapped_column(Boolean, default=False)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now
    )

    polling_station: Mapped["PollingStation"] = relationship(
        "PollingStation", back_populates="submissions"
    )
    election: Mapped["Election"] = relationship("Election", back_populates="submissions")


class ConstituencyAggregate(Base):
    """
    Homomorphic aggregate of all verified polling station submissions
    within a constituency, computed without decryption.
    """

    __tablename__ = "constituency_aggregates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    constituency_id: Mapped[int] = mapped_column(
        ForeignKey("constituencies.id"), nullable=False
    )
    election_id: Mapped[int] = mapped_column(ForeignKey("elections.id"), nullable=False)
    encrypted_totals: Mapped[str] = mapped_column(Text, nullable=False)  # JSON
    stations_included: Mapped[int] = mapped_column(Integer, default=0)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    constituency: Mapped["Constituency"] = relationship(
        "Constituency", back_populates="constituency_aggregates"
    )
    election: Mapped["Election"] = relationship(
        "Election", back_populates="constituency_aggregates"
    )


class RegionalAggregate(Base):
    """
    Homomorphic aggregate of all constituency aggregates within a region.
    """

    __tablename__ = "regional_aggregates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    region_id: Mapped[int] = mapped_column(ForeignKey("regions.id"), nullable=False)
    election_id: Mapped[int] = mapped_column(ForeignKey("elections.id"), nullable=False)
    encrypted_totals: Mapped[str] = mapped_column(Text, nullable=False)
    constituencies_included: Mapped[int] = mapped_column(Integer, default=0)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    region: Mapped["Region"] = relationship(
        "Region", back_populates="regional_aggregates"
    )
    election: Mapped["Election"] = relationship(
        "Election", back_populates="regional_aggregates"
    )


class NationalAggregate(Base):
    """
    Final national homomorphic aggregate and its plaintext decryption.

    The decrypted_totals column is NULL until the national authority
    explicitly invokes the finalise endpoint with the private key.
    """

    __tablename__ = "national_aggregates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    election_id: Mapped[int] = mapped_column(
        ForeignKey("elections.id"), nullable=False, unique=True
    )
    encrypted_totals: Mapped[str] = mapped_column(Text, nullable=False)
    decrypted_totals: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    regions_included: Mapped[int] = mapped_column(Integer, default=0)
    finalized_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    election: Mapped["Election"] = relationship(
        "Election", back_populates="national_aggregate"
    )


# ---------------------------------------------------------------------------
# Append-Only Audit Log
# ---------------------------------------------------------------------------


class AuditLog(Base):
    """
    Append-only, hash-chained tamper-evident audit ledger.

    Every significant system event (submission, verification, aggregation,
    rejection, decryption) is recorded here.  Each entry stores:
      - payload_hash:  SHA-256 of the event data.
      - chain_hash:    SHA-256(prev_chain_hash || payload_hash).

    Verifying chain_hash continuity across all entries detects any
    retroactive insertion, deletion, or modification.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    actor_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    data: Mapped[str] = mapped_column(Text, nullable=False)  # JSON
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )
