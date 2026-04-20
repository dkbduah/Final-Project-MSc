"""
SEAS Cryptographic Unit Tests.

Verifies correctness of:
  - Paillier key generation, encryption, homomorphic addition, and decryption.
  - Ed25519 keypair generation, signing, and verification.
  - Signature rejection on tampered payload.
  - Audit hash chain integrity.
"""

import json
import pytest
from app.crypto.paillier import (
    generate_keypair,
    encrypt_votes,
    homomorphic_add,
    decrypt_totals,
)
from app.crypto.signatures import (
    generate_ed25519_keypair,
    sign_payload,
    verify_signature,
    compute_payload_hash,
    compute_chain_hash,
)


# ---------------------------------------------------------------------------
# Paillier Tests
# ---------------------------------------------------------------------------


class TestPaillierEncryption:
    """Correctness tests for the Paillier homomorphic encryption module."""

    def setup_method(self) -> None:
        """Generate a small test keypair (512-bit for speed)."""
        self.pub_dict, self.priv_dict = generate_keypair(key_size=512)

    def test_encrypt_and_decrypt_single_candidate(self) -> None:
        """Encrypting and immediately decrypting should return the original count."""
        votes = {"NDC": 120}
        enc = encrypt_votes(self.pub_dict, votes)
        dec = decrypt_totals(self.pub_dict, self.priv_dict, enc)
        assert dec["NDC"] == 120

    def test_encrypt_multiple_candidates(self) -> None:
        """All candidate totals should survive an encrypt–decrypt round trip."""
        votes = {"NDC": 500, "NPP": 300, "IND": 50}
        enc = encrypt_votes(self.pub_dict, votes)
        dec = decrypt_totals(self.pub_dict, self.priv_dict, enc)
        assert dec == votes

    def test_homomorphic_addition_two_stations(self) -> None:
        """Homomorphic sum of two encrypted results must equal the plaintext sum."""
        votes_a = {"NDC": 200, "NPP": 150}
        votes_b = {"NDC": 100, "NPP": 250}
        enc_a = encrypt_votes(self.pub_dict, votes_a)
        enc_b = encrypt_votes(self.pub_dict, votes_b)
        agg = homomorphic_add(self.pub_dict, [enc_a, enc_b])
        dec = decrypt_totals(self.pub_dict, self.priv_dict, agg)
        assert dec["NDC"] == 300
        assert dec["NPP"] == 400

    def test_homomorphic_addition_five_stations(self) -> None:
        """Homomorphic sum across five stations must match plaintext accumulation."""
        candidate_ids = ["NDC", "NPP", "IND"]
        import random
        random.seed(42)
        plaintext_totals = {c: 0 for c in candidate_ids}
        encrypted_list = []
        for _ in range(5):
            votes = {c: random.randint(50, 500) for c in candidate_ids}
            for c in candidate_ids:
                plaintext_totals[c] += votes[c]
            encrypted_list.append(encrypt_votes(self.pub_dict, votes))

        agg = homomorphic_add(self.pub_dict, encrypted_list)
        dec = decrypt_totals(self.pub_dict, self.priv_dict, agg)
        assert dec == plaintext_totals, (
            f"Decrypted {dec} does not match plaintext {plaintext_totals}"
        )

    def test_homomorphic_add_empty_list_returns_empty(self) -> None:
        """Empty input to homomorphic_add should return an empty dict."""
        result = homomorphic_add(self.pub_dict, [])
        assert result == {}

    def test_negative_vote_count_raises(self) -> None:
        """Negative vote counts should raise ValueError."""
        with pytest.raises(ValueError, match="non-negative"):
            encrypt_votes(self.pub_dict, {"NDC": -5})

    def test_inconsistent_candidates_raises(self) -> None:
        """Mismatched candidate sets should raise ValueError during aggregation."""
        enc_a = encrypt_votes(self.pub_dict, {"NDC": 10, "NPP": 20})
        enc_b = encrypt_votes(self.pub_dict, {"NDC": 10, "IND": 5})
        with pytest.raises(ValueError, match="mismatch"):
            homomorphic_add(self.pub_dict, [enc_a, enc_b])


# ---------------------------------------------------------------------------
# Ed25519 Tests
# ---------------------------------------------------------------------------


class TestEd25519Signatures:
    """Correctness and security tests for the Ed25519 signature module."""

    def setup_method(self) -> None:
        """Generate a fresh keypair for each test."""
        self.priv_b64, self.pub_b64 = generate_ed25519_keypair()

    def test_sign_and_verify_valid_payload(self) -> None:
        """A freshly signed payload should verify successfully."""
        payload = {"station_id": 1, "election_id": 1, "votes": {"NDC": 100}}
        sig = sign_payload(self.priv_b64, payload)
        assert verify_signature(self.pub_b64, payload, sig) is True

    def test_tampered_payload_fails_verification(self) -> None:
        """Modifying the payload after signing must invalidate the signature."""
        payload = {"station_id": 1, "election_id": 1, "votes": {"NDC": 100}}
        sig = sign_payload(self.priv_b64, payload)
        tampered = dict(payload)
        tampered["votes"] = {"NDC": 9999}  # Tamper
        assert verify_signature(self.pub_b64, tampered, sig) is False

    def test_wrong_public_key_fails_verification(self) -> None:
        """Signature verified against a different public key should fail."""
        _, other_pub = generate_ed25519_keypair()
        payload = {"data": "test"}
        sig = sign_payload(self.priv_b64, payload)
        assert verify_signature(other_pub, payload, sig) is False

    def test_forged_signature_rejected(self) -> None:
        """A randomly constructed base64 string should not pass verification."""
        import base64, os
        payload = {"data": "sensitive"}
        forged_sig = base64.b64encode(os.urandom(64)).decode()
        assert verify_signature(self.pub_b64, payload, forged_sig) is False

    def test_signature_is_deterministic_for_same_payload(self) -> None:
        """
        Ed25519 is actually deterministic (RFC 8032), so the same key+payload
        should produce the same signature.
        """
        payload = {"station_id": 5, "value": 42}
        sig1 = sign_payload(self.priv_b64, payload)
        sig2 = sign_payload(self.priv_b64, payload)
        assert sig1 == sig2

    def test_key_insertion_order_does_not_affect_signature(self) -> None:
        """Canonical serialisation means key order must not affect signature."""
        payload_a = {"b": 2, "a": 1}
        payload_b = {"a": 1, "b": 2}
        sig_a = sign_payload(self.priv_b64, payload_a)
        sig_b = sign_payload(self.priv_b64, payload_b)
        assert sig_a == sig_b


# ---------------------------------------------------------------------------
# Audit Hash Chain Tests
# ---------------------------------------------------------------------------


class TestAuditHashChain:
    """Verifies the tamper-evidence of the SHA-256 hash chain."""

    def test_chain_hash_is_deterministic(self) -> None:
        """Same inputs must always produce the same chain hash."""
        ph = compute_payload_hash({"event": "SUBMISSION_RECEIVED", "id": 1})
        prev = "0" * 64
        h1 = compute_chain_hash(ph, prev)
        h2 = compute_chain_hash(ph, prev)
        assert h1 == h2

    def test_chain_hash_changes_on_tamper(self) -> None:
        """Changing any input must produce a different chain hash."""
        ph = compute_payload_hash({"event": "SUBMISSION_RECEIVED", "id": 1})
        ph_tampered = compute_payload_hash({"event": "SUBMISSION_RECEIVED", "id": 2})
        prev = "0" * 64
        assert compute_chain_hash(ph, prev) != compute_chain_hash(ph_tampered, prev)

    def test_consecutive_chain_links(self) -> None:
        """A three-entry chain must be internally consistent."""
        genesis = "0" * 64
        ph1 = compute_payload_hash({"entry": 1})
        ch1 = compute_chain_hash(ph1, genesis)
        ph2 = compute_payload_hash({"entry": 2})
        ch2 = compute_chain_hash(ph2, ch1)
        ph3 = compute_payload_hash({"entry": 3})
        ch3 = compute_chain_hash(ph3, ch2)

        # Verify chain by recomputing
        assert compute_chain_hash(ph1, genesis) == ch1
        assert compute_chain_hash(ph2, ch1) == ch2
        assert compute_chain_hash(ph3, ch2) == ch3
