"""
Paillier Additive Homomorphic Encryption – SEAS Cryptographic Core.

The Paillier cryptosystem (Paillier, 1999) is a probabilistic asymmetric
public-key encryption scheme with the additive homomorphic property:

    Enc(a) · Enc(b) ≡ Enc(a + b)  (mod n²)
    Enc(a) ^ k      ≡ Enc(a · k)  (mod n²)

This allows encrypted vote totals from individual polling stations to be
summed at constituency, regional, and national tiers WITHOUT decryption
at any intermediary stage. Only the national authority holding the private
key can reveal plaintext totals from the final homomorphic aggregate.

Security note: Key size of 2048 bits provides ~112-bit security level,
equivalent to RSA-2048, and is recommended by NIST for use beyond 2030.
"""

import phe as paillier
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Key Management
# ---------------------------------------------------------------------------


def generate_keypair(key_size: int = 2048) -> Tuple[dict, dict]:
    """
    Generate a Paillier public/private keypair for an election instance.

    The public key is distributed to all polling station clients for
    encryption. The private key is held exclusively by the national
    aggregator and is never transmitted to lower tiers.

    Args:
        key_size: RSA-modulus length in bits. Default 2048 for production.
                  Use 512 or 1024 only for test/benchmark environments.

    Returns:
        Tuple of (public_key_dict, private_key_dict) as JSON-serialisable
        dictionaries containing big-integer values as decimal strings.
    """
    public_key, private_key = paillier.generate_paillier_keypair(n_length=key_size)
    pub_dict = {"n": str(public_key.n)}
    priv_dict = {"p": str(private_key.p), "q": str(private_key.q)}
    return pub_dict, priv_dict


def load_public_key(pub_dict: dict) -> paillier.PaillierPublicKey:
    """
    Reconstruct a PaillierPublicKey object from its serialised dictionary.

    Args:
        pub_dict: Dictionary with key "n" containing the modulus as a string.

    Returns:
        A PaillierPublicKey instance ready for encryption operations.
    """
    n = int(pub_dict["n"])
    return paillier.PaillierPublicKey(n)


def load_private_key(
    pub_dict: dict, priv_dict: dict
) -> paillier.PaillierPrivateKey:
    """
    Reconstruct a PaillierPrivateKey from serialised public and private dicts.

    Args:
        pub_dict:  Dictionary with the modulus n.
        priv_dict: Dictionary with prime factors p and q as decimal strings.

    Returns:
        A PaillierPrivateKey instance ready for decryption.
    """
    public_key = load_public_key(pub_dict)
    p = int(priv_dict["p"])
    q = int(priv_dict["q"])
    return paillier.PaillierPrivateKey(public_key, p, q)


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------


def encrypt_votes(
    public_key_dict: dict, vote_totals: Dict[str, int]
) -> Dict[str, dict]:
    """
    Encrypt a candidate → vote-count mapping using the election public key.

    Each integer vote count is independently encrypted, yielding a
    probabilistic ciphertext that reveals no information about the
    underlying plaintext to any party without the private key.

    Args:
        public_key_dict: Serialised Paillier public key {"n": "<int>"}.
        vote_totals:     Mapping of candidate_id (str) → plaintext count (int).

    Returns:
        Mapping of candidate_id → {"ciphertext": "<int>", "exponent": <int>}.
        The exponent encodes the fixed-point scale used by phe internally.

    Raises:
        ValueError: If any vote count is negative.
    """
    for cid, count in vote_totals.items():
        if count < 0:
            raise ValueError(f"Vote count for {cid} must be non-negative.")

    public_key = load_public_key(public_key_dict)
    encrypted: Dict[str, dict] = {}
    for candidate_id, count in vote_totals.items():
        enc = public_key.encrypt(count)
        encrypted[candidate_id] = {
            "ciphertext": str(enc.ciphertext()),
            "exponent": enc.exponent,
        }
    return encrypted


# ---------------------------------------------------------------------------
# Homomorphic Aggregation
# ---------------------------------------------------------------------------


def homomorphic_add(
    public_key_dict: dict,
    encrypted_results: List[Dict[str, dict]],
) -> Dict[str, dict]:
    """
    Perform additive homomorphic aggregation over a list of encrypted results.

    The Paillier additive property means:

        Enc(v₁) · Enc(v₂) · … · Enc(vₙ) ≡ Enc(v₁ + v₂ + … + vₙ)

    No decryption occurs during this operation.  The resulting ciphertext
    can only be opened by the private-key holder at the national tier.

    Args:
        public_key_dict:   Serialised election public key.
        encrypted_results: List of encrypted vote dicts from lower-tier
                           submissions or sub-aggregations.

    Returns:
        Aggregated encrypted totals dict with the same candidate keys.

    Raises:
        ValueError: If the list is empty or candidate sets are inconsistent.
    """
    if not encrypted_results:
        return {}

    public_key = load_public_key(public_key_dict)
    candidates = set(encrypted_results[0].keys())

    for i, result in enumerate(encrypted_results):
        if set(result.keys()) != candidates:
            raise ValueError(
                f"Candidate set mismatch in submission {i}: "
                f"expected {candidates}, got {set(result.keys())}."
            )

    # Initialise aggregate at encrypted-zero for each candidate
    aggregate = {cid: public_key.encrypt(0) for cid in candidates}

    for result in encrypted_results:
        for candidate_id, enc_dict in result.items():
            enc_number = paillier.EncryptedNumber(
                public_key,
                int(enc_dict["ciphertext"]),
                enc_dict["exponent"],
            )
            aggregate[candidate_id] = aggregate[candidate_id] + enc_number

    return {
        cid: {
            "ciphertext": str(agg.ciphertext()),
            "exponent": agg.exponent,
        }
        for cid, agg in aggregate.items()
    }


# ---------------------------------------------------------------------------
# Decryption (National Tier Only)
# ---------------------------------------------------------------------------


def decrypt_totals(
    public_key_dict: dict,
    private_key_dict: dict,
    encrypted_totals: Dict[str, dict],
) -> Dict[str, int]:
    """
    Decrypt final homomorphic aggregate to recover plaintext national totals.

    This function is invoked exclusively at the national aggregation tier
    after all encrypted partial sums have been combined.  The result is
    the true national vote count for each candidate.

    Args:
        public_key_dict:   Serialised election public key.
        private_key_dict:  Serialised election private key (p, q).
        encrypted_totals:  Homomorphically aggregated ciphertext dict.

    Returns:
        Mapping of candidate_id → integer vote total.
    """
    private_key = load_private_key(public_key_dict, private_key_dict)
    decrypted: Dict[str, int] = {}
    for candidate_id, enc_dict in encrypted_totals.items():
        enc_number = paillier.EncryptedNumber(
            private_key.public_key,
            int(enc_dict["ciphertext"]),
            enc_dict["exponent"],
        )
        decrypted[candidate_id] = int(private_key.decrypt(enc_number))
    return decrypted
