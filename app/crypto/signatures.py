"""
Ed25519 Digital Signature Scheme – SEAS Authentication Layer.

Ed25519 (Bernstein et al., 2011) is an elliptic-curve signature scheme built
on Curve25519, offering 128-bit security, 64-byte signatures, and fast
constant-time verification.  Each polling station officer is issued a unique
Ed25519 keypair during system registration.  The private key signs every
encrypted result payload before transmission, while the backend verifies
signatures against the registered public key, providing:

  • Authentication  – confirms the submitter's identity.
  • Integrity       – detects any post-signing modification.
  • Non-repudiation – the officer cannot later deny the submission.

Payload canonicalisation (JSON with sorted keys, UTF-8 encoded) ensures
deterministic byte strings across all language implementations so that
Python-generated and JavaScript-generated signatures are interoperable.
"""

import base64
import hashlib
import json
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Key Generation
# ---------------------------------------------------------------------------


def generate_ed25519_keypair() -> Tuple[str, str]:
    """
    Generate an Ed25519 keypair for a new polling station officer account.

    Keys are returned as raw 32-byte values encoded in URL-safe base64
    for safe storage and transmission in JSON API responses.

    Returns:
        Tuple of (private_key_b64, public_key_b64).
        Private key: 32 bytes → 44-char base64 string.
        Public  key: 32 bytes → 44-char base64 string.
    """
    private_key = Ed25519PrivateKey.generate()
    priv_bytes = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return (
        base64.b64encode(priv_bytes).decode(),
        base64.b64encode(pub_bytes).decode(),
    )


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def sign_payload(private_key_b64: str, payload: dict) -> str:
    """
    Sign a JSON-serialisable payload with an Ed25519 private key.

    The payload is canonicalised to a deterministic byte string before
    signing: keys are sorted alphabetically and the result is UTF-8
    encoded.  This guarantees that the same logical payload always
    produces the same signed bytes regardless of key insertion order.

    Args:
        private_key_b64: Base64-encoded 32-byte Ed25519 private key.
        payload:         JSON-serialisable dict representing the submission.

    Returns:
        Base64-encoded 64-byte Ed25519 signature string.

    Raises:
        ValueError: If the private key bytes are not exactly 32 bytes.
    """
    priv_bytes = base64.b64decode(private_key_b64)
    if len(priv_bytes) != 32:
        raise ValueError("Ed25519 private key must be exactly 32 bytes.")
    private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    canonical = _canonicalise(payload)
    signature = private_key.sign(canonical)
    return base64.b64encode(signature).decode()


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_signature(
    public_key_b64: str, payload: dict, signature_b64: str
) -> bool:
    """
    Verify an Ed25519 signature against a registered officer public key.

    The payload is canonicalised using the same deterministic scheme as
    sign_payload before verification, ensuring cross-language compatibility.

    Args:
        public_key_b64: Base64-encoded 32-byte Ed25519 public key.
        payload:        The original dict that was signed.
        signature_b64:  Base64-encoded 64-byte signature to verify.

    Returns:
        True if the signature is cryptographically valid; False otherwise.
        Returns False (rather than raising) so callers can log rejections
        without exception handling overhead in hot aggregation paths.
    """
    try:
        pub_bytes = base64.b64decode(public_key_b64)
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        canonical = _canonicalise(payload)
        sig_bytes = base64.b64decode(signature_b64)
        public_key.verify(sig_bytes, canonical)
        return True
    except (InvalidSignature, Exception):
        return False


# ---------------------------------------------------------------------------
# Audit Hashing
# ---------------------------------------------------------------------------


def compute_payload_hash(payload: dict) -> str:
    """
    Compute a SHA-256 digest of a canonicalised payload for audit chaining.

    Each audit log entry stores the hash of its payload and the hash of the
    previous entry, forming a tamper-evident append-only chain analogous to
    a blockchain ledger.

    Args:
        payload: JSON-serialisable dictionary to hash.

    Returns:
        Hex-encoded 64-character SHA-256 digest.
    """
    canonical = _canonicalise(payload)
    return hashlib.sha256(canonical).hexdigest()


def compute_chain_hash(payload_hash: str, prev_hash: str) -> str:
    """
    Compute a chained hash linking consecutive audit log entries.

    The chain hash H_n = SHA-256(H_{n-1} || H_payload_n) means that
    retroactively altering any entry invalidates all subsequent hashes,
    making tampering immediately detectable on verification.

    Args:
        payload_hash: SHA-256 hash of the current entry's payload.
        prev_hash:    Chain hash of the immediately preceding audit entry.

    Returns:
        Hex-encoded SHA-256 chain digest.
    """
    combined = (prev_hash + payload_hash).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------


def _canonicalise(payload: dict) -> bytes:
    """
    Serialise a dictionary to a deterministic UTF-8 byte string.

    Keys are recursively sorted to guarantee identical output regardless
    of dictionary construction order or Python version.

    Args:
        payload: JSON-serialisable dictionary.

    Returns:
        UTF-8 encoded canonical JSON bytes.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
