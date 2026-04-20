"""
SEAS Locust Load Test – Simulated 200 Polling Station Submissions.

Simulates concurrent polling station officers encrypting vote totals
with the Paillier public key, signing with Ed25519, and submitting to
the backend.  Measures:
  - Submission throughput (requests/second)
  - P50/P95/P99 latency
  - Signature verification pass rate
  - Rejection rate

Usage:
    locust -f locustfile.py --host=http://localhost:8000 --users=200 --spawn-rate=10

The locust web UI is available at http://localhost:8089.
"""

import base64
import json
import os
import random
import time

import phe as paillier
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from locust import HttpUser, task, between, events


# ---------------------------------------------------------------------------
# Shared state loaded once at startup
# ---------------------------------------------------------------------------

_election: dict = {}
_stations: list = []
_pub_key: paillier.PaillierPublicKey = None
_station_keys: dict = {}  # station_code -> (pub_key_b64, priv_key_b64)


@events.init.add_listener
def load_election_data(environment, **kwargs):
    """Fetch election and station data from the live backend before tests run."""
    global _election, _stations, _pub_key, _station_keys

    import requests
    host = environment.host or "http://localhost:8000"

    # Load elections
    r = requests.get(f"{host}/api/elections/")
    elections = r.json()
    if not elections:
        raise RuntimeError("No elections found. Run seed.py first.")
    _election = elections[0]
    n = int(_election["paillier_public_key"]["n"])
    _pub_key = paillier.PaillierPublicKey(n)

    # Load stations
    r = requests.get(f"{host}/api/polling/stations")
    _stations = r.json()

    # Load station private keys if available
    if os.path.exists("station_keys.json"):
        with open("station_keys.json") as f:
            _station_keys = json.load(f)

    print(f"[Locust] Loaded election: {_election['title']}")
    print(f"[Locust] Polling stations: {len(_stations)}")
    print(f"[Locust] Candidates: {[c['candidate_code'] for c in _election['candidates']]}")


# ---------------------------------------------------------------------------
# Helper: sign payload with Ed25519
# ---------------------------------------------------------------------------


def _sign_payload(priv_key_b64: str, payload: dict) -> str:
    """Sign a canonical payload dict and return a base64 signature."""
    priv_bytes = base64.b64decode(priv_key_b64)
    private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = private_key.sign(canonical)
    return base64.b64encode(sig).decode()


# ---------------------------------------------------------------------------
# Locust User
# ---------------------------------------------------------------------------


class PollingStationOfficer(HttpUser):
    """
    Simulates a polling station officer submitting encrypted results.

    Each virtual user picks a random polling station, encrypts synthetic
    vote totals with the election's Paillier public key, signs the payload
    with the officer's Ed25519 private key, and POSTs to /api/polling/submit.
    """

    wait_time = between(0.5, 2.0)

    def on_start(self) -> None:
        """Assign a random polling station to this virtual user on startup."""
        self.station = random.choice(_stations)

    @task(10)
    def submit_encrypted_results(self) -> None:
        """
        Submit a signed, Paillier-encrypted result for this officer's station.

        Generates random synthetic vote counts, encrypts each with the
        public key, and signs the full payload before submission.
        """
        if not _pub_key or not _election.get("candidates"):
            return

        candidates = _election["candidates"]
        total_votes = random.randint(300, 1200)
        # Distribute votes randomly across candidates
        splits = sorted(random.sample(range(1, total_votes), len(candidates) - 1))
        splits = [0] + splits + [total_votes]
        vote_counts = {
            c["candidate_code"]: splits[i + 1] - splits[i]
            for i, c in enumerate(candidates)
        }

        # Encrypt with Paillier public key
        encrypted_votes = {}
        for cid, count in vote_counts.items():
            enc = _pub_key.encrypt(count)
            encrypted_votes[cid] = {
                "ciphertext": str(enc.ciphertext()),
                "exponent": enc.exponent,
            }

        # Build canonical payload for signing
        station_id = self.station["id"]
        election_id = _election["id"]
        signed_payload = {
            "polling_station_id": station_id,
            "election_id": election_id,
            "encrypted_votes": encrypted_votes,
        }

        # Sign
        station_code = self.station.get("station_code", "")
        priv_key_b64 = None
        if station_code in _station_keys:
            priv_key_b64 = _station_keys[station_code][1]

        if not priv_key_b64:
            # Generate ephemeral key (will fail signature verification – tests rejection)
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K
            tmp = K.generate()
            priv_key_b64 = base64.b64encode(
                tmp.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            ).decode()

        signature = _sign_payload(priv_key_b64, signed_payload)

        body = {
            "polling_station_id": station_id,
            "election_id": election_id,
            "encrypted_votes": encrypted_votes,
            "signature": signature,
        }

        with self.client.post(
            "/api/polling/submit",
            json=body,
            catch_response=True,
            name="POST /api/polling/submit",
        ) as response:
            if response.status_code in (201, 409):
                response.success()
            else:
                response.failure(f"Unexpected status: {response.status_code}")

    @task(2)
    def check_progress(self) -> None:
        """Poll the aggregation progress endpoint."""
        self.client.get(
            f"/api/polling/progress/{_election.get('id', 1)}",
            name="GET /api/polling/progress",
        )

    @task(1)
    def list_submissions(self) -> None:
        """Fetch submission list for the active election."""
        self.client.get(
            f"/api/polling/submissions/{_election.get('id', 1)}",
            name="GET /api/polling/submissions",
        )
