"""
SEAS Pydantic Schemas – Request / Response Models.

All API surface types are defined here.  Pydantic v2 is used for
validation, serialisation, and OpenAPI schema generation.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Candidate
# ---------------------------------------------------------------------------


class CandidateCreate(BaseModel):
    name: str = Field(..., description="Candidate's full name.")
    party: str = Field(..., description="Political party affiliation.")
    candidate_code: str = Field(..., description="Unique short code, e.g. 'NDC1'.")


class CandidateOut(BaseModel):
    id: int
    election_id: int
    name: str
    party: str
    candidate_code: str

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Election
# ---------------------------------------------------------------------------


class ElectionCreate(BaseModel):
    title: str = Field(..., description="Official election title.")
    election_date: str = Field(..., description="Date in YYYY-MM-DD format.")
    candidates: List[CandidateCreate]
    key_size: int = Field(
        2048,
        description="Paillier key size in bits. Use 512 only for testing.",
    )


class ElectionOut(BaseModel):
    id: int
    title: str
    election_date: str
    status: str
    paillier_public_key: Dict[str, Any]
    candidates: List[CandidateOut]
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Administrative Hierarchy
# ---------------------------------------------------------------------------


class RegionOut(BaseModel):
    id: int
    name: str
    region_code: str

    model_config = {"from_attributes": True}


class ConstituencyOut(BaseModel):
    id: int
    name: str
    constituency_code: str
    region_id: int

    model_config = {"from_attributes": True}


class PollingStationOut(BaseModel):
    id: int
    name: str
    station_code: str
    constituency_id: int
    registered_voters: int
    officer_name: str
    officer_public_key: str

    model_config = {"from_attributes": True}


class PollingStationCreate(BaseModel):
    name: str
    station_code: str
    constituency_id: int
    registered_voters: int = 0
    officer_name: str


class PollingStationWithKey(PollingStationOut):
    """Extended response that includes the private key on initial creation."""
    officer_private_key: str


# ---------------------------------------------------------------------------
# Submissions
# ---------------------------------------------------------------------------


class EncryptedVoteEntry(BaseModel):
    """Paillier ciphertext for a single candidate."""
    ciphertext: str = Field(..., description="Decimal string of the Paillier ciphertext integer.")
    exponent: int = Field(..., description="Fixed-point exponent used by phe internally.")


class SubmitResultRequest(BaseModel):
    """
    Signed, encrypted result submission from a polling station officer.

    The encrypted_votes dict maps candidate_code → EncryptedVoteEntry.
    The signature is an Ed25519 signature over the canonicalised payload
    dict (excluding the signature field itself).
    """

    polling_station_id: int
    election_id: int
    encrypted_votes: Dict[str, EncryptedVoteEntry] = Field(
        ...,
        description="Paillier-encrypted vote counts keyed by candidate_code.",
    )
    signature: str = Field(
        ...,
        description="Base64-encoded Ed25519 signature over the canonical payload.",
    )


class SubmissionOut(BaseModel):
    id: int
    polling_station_id: int
    election_id: int
    signature_valid: bool
    rejected: bool
    rejection_reason: Optional[str]
    submitted_at: datetime
    payload_hash: str

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


class ConstituencyAggregateOut(BaseModel):
    id: int
    constituency_id: int
    election_id: int
    stations_included: int
    computed_at: datetime
    encrypted_totals: Dict[str, Any]

    model_config = {"from_attributes": True}


class RegionalAggregateOut(BaseModel):
    id: int
    region_id: int
    election_id: int
    constituencies_included: int
    computed_at: datetime
    encrypted_totals: Dict[str, Any]

    model_config = {"from_attributes": True}


class NationalAggregateOut(BaseModel):
    id: int
    election_id: int
    regions_included: int
    encrypted_totals: Dict[str, Any]
    decrypted_totals: Optional[Dict[str, int]] = None
    finalized_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class FinaliseRequest(BaseModel):
    """
    Request to decrypt the national aggregate.

    In production this would use threshold decryption or HSM.
    For simulation, the private key is passed directly.
    """
    election_id: int


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


class VerifySignatureRequest(BaseModel):
    polling_station_id: int
    election_id: int
    encrypted_votes: Dict[str, EncryptedVoteEntry]
    signature: str


class VerificationResult(BaseModel):
    submission_id: int
    polling_station_id: int
    signature_valid: bool
    payload_hash: str
    verified_at: datetime


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------


class AuditLogOut(BaseModel):
    id: int
    event_type: str
    entity_type: str
    entity_id: Optional[str]
    actor_id: Optional[str]
    data: Dict[str, Any]
    payload_hash: str
    chain_hash: str
    prev_hash: str
    timestamp: datetime

    model_config = {"from_attributes": True}


class ChainVerificationResult(BaseModel):
    valid: bool
    total_entries: int
    first_broken_at: Optional[int] = None
    message: str


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------


class WSMessage(BaseModel):
    """Generic WebSocket broadcast envelope."""
    event: str
    data: Dict[str, Any]
    timestamp: datetime


# ---------------------------------------------------------------------------
# Stats / Dashboard
# ---------------------------------------------------------------------------


class AggregationProgress(BaseModel):
    election_id: int
    total_stations: int
    stations_submitted: int
    stations_verified: int
    stations_rejected: int
    constituencies_aggregated: int
    regions_aggregated: int
    national_finalized: bool
    submission_rate_pct: float
