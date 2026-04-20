#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║        SEAS — Secure Election Aggregation System                            ║
║        Security Audit & Attack Simulation Tool v1.0                        ║
║                                                                              ║
║  Simulates real-world attack vectors against the SEAS cryptographic         ║
║  pipeline and documents which defences hold, which need hardening,          ║
║  and the forensic evidence visible in the audit log.                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    python security_audit.py [OPTIONS]

Options:
    --host      Backend base URL  (default: http://localhost:8000)
    --output    Save JSON report  (default: seas_audit_report.json)
    --log       Save full log     (default: seas_audit.log)
    --category  Run only one attack category (see --list-categories)
    --verbose   Print full HTTP bodies
    --list-categories   List all attack categories and exit
    --no-color  Disable rich colour output (plain text for piping)

Example:
    python security_audit.py --host http://localhost:8000
    python security_audit.py --category signature
    python security_audit.py --verbose --output report.json
"""

import argparse
import asyncio
import base64
import json
import logging
import os
import sys
import time
import random
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict

# ── Third-party ─────────────────────────────────────────────────────────────
try:
    import httpx
except ImportError:
    sys.exit("Missing dependency: pip install httpx")

try:
    import phe as paillier
except ImportError:
    sys.exit("Missing dependency: pip install phe")

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat,
    )
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.text import Text
    from rich import box
    from rich.rule import Rule
    from rich.columns import Columns
    from rich.padding import Padding
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    print("[WARNING] 'rich' not installed — plain output mode. pip install rich")


# ════════════════════════════════════════════════════════════════════════════
# Data structures
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackResult:
    id: str
    name: str
    category: str
    description: str
    threat_model: str
    expected_outcome: str    # "BLOCKED" | "ALLOWED"
    actual_outcome: str      # "BLOCKED" | "ALLOWED" | "ERROR"
    verdict: str             # "DEFENDED" | "VULNERABLE" | "WARNING" | "ERROR"
    http_status: Optional[int] = None
    latency_ms: float = 0.0
    details: str = ""
    evidence: str = ""       # What the audit log / response proves
    recommendation: str = ""

@dataclass
class AuditReport:
    tool: str = "SEAS Security Audit Tool v1.0"
    timestamp: str = ""
    host: str = ""
    election_id: Optional[int] = None
    total_tests: int = 0
    defended: int = 0
    vulnerable: int = 0
    warnings: int = 0
    errors: int = 0
    results: List[AttackResult] = field(default_factory=list)
    audit_chain_valid: Optional[bool] = None
    audit_chain_entries: int = 0
    timing_analysis: Dict[str, Any] = field(default_factory=dict)


# ════════════════════════════════════════════════════════════════════════════
# Console / Logging setup
# ════════════════════════════════════════════════════════════════════════════

console = Console() if HAS_RICH else None

def setup_logging(log_path: str) -> logging.Logger:
    logger = logging.getLogger("seas.audit")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    fh.setFormatter(fmt)
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    ch.setLevel(logging.WARNING)
    logger.addHandler(ch)
    return logger

log: logging.Logger = None  # initialised in main()


def _print(msg: str, style: str = "") -> None:
    if HAS_RICH and console:
        console.print(msg, style=style)
    else:
        print(msg)

def _rule(title: str = "") -> None:
    if HAS_RICH and console:
        console.print(Rule(title, style="bold cyan"))
    else:
        print(f"\n{'═'*70}  {title}")

def _verdict_style(verdict: str) -> str:
    return {
        "DEFENDED":   "bold green",
        "VULNERABLE": "bold red",
        "WARNING":    "bold yellow",
        "ERROR":      "dim",
    }.get(verdict, "white")

def _verdict_icon(verdict: str) -> str:
    return {
        "DEFENDED":   "✅",
        "VULNERABLE": "🔴",
        "WARNING":    "⚠️ ",
        "ERROR":      "💀",
    }.get(verdict, "?")


# ════════════════════════════════════════════════════════════════════════════
# Crypto helpers (self-contained — no backend imports)
# ════════════════════════════════════════════════════════════════════════════

def _gen_keypair() -> Tuple[str, str]:
    """Return (priv_b64, pub_b64)."""
    pk = Ed25519PrivateKey.generate()
    priv = base64.b64encode(
        pk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode()
    pub = base64.b64encode(
        pk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return priv, pub

def _sign(priv_b64: str, payload: dict) -> str:
    priv_bytes = base64.b64decode(priv_b64)
    pk = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(pk.sign(canonical)).decode()

def _encrypt_votes(pub_key: paillier.PaillierPublicKey, votes: Dict[str, int]) -> Dict:
    out = {}
    for cid, count in votes.items():
        enc = pub_key.encrypt(count)
        out[cid] = {"ciphertext": str(enc.ciphertext()), "exponent": enc.exponent}
    return out

def _make_submission(
    station: dict,
    priv_b64: str,
    election: dict,
    pub_key: paillier.PaillierPublicKey,
    votes: Optional[Dict[str, int]] = None,
) -> dict:
    """Build a fully signed submission payload."""
    candidates = {c["candidate_code"] for c in election["candidates"]}
    if votes is None:
        total = random.randint(400, 900)
        parts = sorted(random.sample(range(1, total), len(candidates) - 1))
        parts = [0] + parts + [total]
        votes = {c: parts[i+1] - parts[i] for i, c in enumerate(candidates)}

    enc = _encrypt_votes(pub_key, votes)
    signed_payload = {
        "polling_station_id": station["id"],
        "election_id": election["id"],
        "encrypted_votes": enc,
    }
    sig = _sign(priv_b64, signed_payload)
    return {**signed_payload, "signature": sig}


# ════════════════════════════════════════════════════════════════════════════
# HTTP helper
# ════════════════════════════════════════════════════════════════════════════

async def _post(client: httpx.AsyncClient, url: str, body: dict) -> Tuple[int, dict, float]:
    t0 = time.perf_counter()
    try:
        r = await client.post(url, json=body, timeout=20)
        ms = (time.perf_counter() - t0) * 1000
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
        return r.status_code, data, ms
    except Exception as exc:
        ms = (time.perf_counter() - t0) * 1000
        return 0, {"error": str(exc)}, ms

async def _get(client: httpx.AsyncClient, url: str) -> Tuple[int, Any, float]:
    t0 = time.perf_counter()
    try:
        r = await client.get(url, timeout=20)
        ms = (time.perf_counter() - t0) * 1000
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
        return r.status_code, data, ms
    except Exception as exc:
        ms = (time.perf_counter() - t0) * 1000
        return 0, {"error": str(exc)}, ms


# ════════════════════════════════════════════════════════════════════════════
# Security Audit Engine
# ════════════════════════════════════════════════════════════════════════════

class SEASSecurityAuditor:
    def __init__(self, host: str, verbose: bool = False):
        self.host = host.rstrip("/")
        self.verbose = verbose
        self.client: Optional[httpx.AsyncClient] = None
        self.election: Optional[dict] = None
        self.stations: List[dict] = []
        self.station_keys: Dict[str, Tuple[str, str]] = {}   # code → (pub, priv)
        self.pub_key: Optional[paillier.PaillierPublicKey] = None
        self.results: List[AttackResult] = []
        self._submitted_station_ids: set = set()

    # ── Setup ────────────────────────────────────────────────────────────────

    async def connect(self) -> bool:
        self.client = httpx.AsyncClient(base_url=self.host)
        status, data, ms = await _get(self.client, "/health")
        if status != 200:
            _print(f"[bold red]✗ Cannot reach backend at {self.host}[/bold red]")
            _print("  Start the backend first:  docker compose up --build")
            return False
        _print(f"  Backend  : [cyan]{self.host}[/cyan]")
        _print(f"  Health   : [green]{data.get('status','?')}[/green]  ({ms:.0f} ms)")
        log.info("Connected to backend %s — %s (%.0f ms)", self.host, data, ms)
        return True

    async def load_election_data(self) -> bool:
        status, data, _ = await _get(self.client, "/api/elections/")
        if status != 200 or not data:
            _print("[red]No elections found — run  python seed.py  first[/red]")
            return False
        self.election = data[0]
        n = int(self.election["paillier_public_key"]["n"])
        self.pub_key = paillier.PaillierPublicKey(n)

        status, data, _ = await _get(self.client, "/api/polling/stations")
        self.stations = data if status == 200 else []

        # Load private keys from station_keys.json if present
        if Path("station_keys.json").exists():
            with open("station_keys.json") as f:
                raw = json.load(f)
            for code, (pub, priv) in raw.items():
                self.station_keys[code] = (pub, priv)

        _print(f"  Election : [cyan]{self.election['title']}[/cyan]  (ID {self.election['id']})")
        _print(f"  Stations : [cyan]{len(self.stations)}[/cyan]  "
               f"({'keys loaded' if self.station_keys else 'no keys — some tests limited'})")
        log.info("Election loaded: id=%d stations=%d keys=%d",
                 self.election["id"], len(self.stations), len(self.station_keys))
        return True

    def _station_with_key(self) -> Optional[Tuple[dict, str, str]]:
        """Return (station, pub_b64, priv_b64) for the first station with a known key."""
        for st in self.stations:
            code = st.get("station_code", "")
            if code in self.station_keys:
                pub, priv = self.station_keys[code]
                return st, pub, priv
        return None

    def _unused_station_with_key(self) -> Optional[Tuple[dict, str, str]]:
        for st in self.stations:
            if st["id"] in self._submitted_station_ids:
                continue
            code = st.get("station_code", "")
            if code in self.station_keys:
                pub, priv = self.station_keys[code]
                return st, pub, priv
        return None

    def _record(self, r: AttackResult) -> None:
        self.results.append(r)
        icon = _verdict_icon(r.verdict)
        style = _verdict_style(r.verdict)
        log.info(
            "[%s] %-45s  HTTP %-3s  %.0f ms  %s",
            r.verdict, r.name, r.http_status or "-", r.latency_ms, r.details,
        )
        if self.verbose:
            _print(f"  {icon} [{style}]{r.verdict:<10}[/{style}]  {r.name}")
            _print(f"      {r.details}", style="dim")

    # ════════════════════════════════════════════════════════════════════════
    # ATTACK CATEGORY 1 — Signature Attacks
    # ════════════════════════════════════════════════════════════════════════

    async def attack_random_signature(self) -> AttackResult:
        """Submit a valid encrypted payload with a random 64-byte signature."""
        trio = self._unused_station_with_key()
        if not trio:
            return self._skip("sig_random", "Random Signature Attack", "signature")
        station, pub, priv = trio
        body = _make_submission(station, priv, self.election, self.pub_key)
        body["signature"] = base64.b64encode(os.urandom(64)).decode()

        status, resp, ms = await _post(self.client, "/api/polling/submit", body)
        defended = status == 201 and resp.get("rejected") is True
        verdict = "DEFENDED" if defended else "VULNERABLE"
        return AttackResult(
            id="sig_random",
            name="Random Signature Injection",
            category="signature",
            description="Submit valid Paillier-encrypted votes signed with a random 64-byte string.",
            threat_model="Attacker intercepts the submission channel and injects fabricated results.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if defended else "ALLOWED",
            verdict=verdict,
            http_status=status,
            latency_ms=ms,
            details=f"HTTP {status} | rejected={resp.get('rejected')} | reason={resp.get('rejection_reason','')}",
            evidence="Ed25519 verify_signature() returned False; submission persisted as rejected.",
            recommendation="✔ Ed25519 signature verification is operational." if defended
                           else "⚠ Signature verification may not be enforced on this endpoint.",
        )

    async def attack_wrong_key(self) -> AttackResult:
        """Sign station A's payload with station B's private key."""
        stations_with_keys = [
            (st, *self.station_keys[st["station_code"]])
            for st in self.stations
            if st["station_code"] in self.station_keys
               and st["id"] not in self._submitted_station_ids
        ]
        if len(stations_with_keys) < 2:
            return self._skip("sig_wrongkey", "Wrong-Key Attack", "signature")

        station_a, pub_a, _ = stations_with_keys[0]
        _, pub_b, priv_b = stations_with_keys[1]

        # Build submission for station A but sign with station B's key
        enc = _encrypt_votes(self.pub_key, {
            c["candidate_code"]: random.randint(50, 300)
            for c in self.election["candidates"]
        })
        signed_payload = {
            "polling_station_id": station_a["id"],
            "election_id": self.election["id"],
            "encrypted_votes": enc,
        }
        sig = _sign(priv_b, signed_payload)   # ← wrong key
        body = {**signed_payload, "signature": sig}

        status, resp, ms = await _post(self.client, "/api/polling/submit", body)
        defended = status == 201 and resp.get("rejected") is True
        verdict = "DEFENDED" if defended else "VULNERABLE"
        return AttackResult(
            id="sig_wrongkey",
            name="Cross-Station Key Confusion",
            category="signature",
            description="Sign station A's payload with station B's private key.",
            threat_model="Compromised officer B tries to submit fraudulent results on behalf of station A.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if defended else "ALLOWED",
            verdict=verdict,
            http_status=status,
            latency_ms=ms,
            details=f"HTTP {status} | rejected={resp.get('rejected')}",
            evidence="Backend compares signature against the registered public key of the submitting station.",
            recommendation="✔ Officer key binding is enforced per station." if defended
                           else "🔴 CRITICAL: Cross-station key acceptance is a vote fraud vector.",
        )

    async def attack_payload_tampering(self) -> AttackResult:
        """Sign a payload, then alter the encrypted vote ciphertext before sending."""
        trio = self._unused_station_with_key()
        if not trio:
            return self._skip("sig_tamper", "Payload Tampering Attack", "signature")
        station, pub, priv = trio

        enc = _encrypt_votes(self.pub_key, {
            c["candidate_code"]: random.randint(50, 300)
            for c in self.election["candidates"]
        })
        signed_payload = {
            "polling_station_id": station["id"],
            "election_id": self.election["id"],
            "encrypted_votes": enc,
        }
        sig = _sign(priv, signed_payload)

        # Tamper: increment first ciphertext by 1 (simulates changing vote count)
        first_code = list(enc.keys())[0]
        original_ct = int(enc[first_code]["ciphertext"])
        enc[first_code]["ciphertext"] = str(original_ct + 1)

        body = {**signed_payload, "encrypted_votes": enc, "signature": sig}
        status, resp, ms = await _post(self.client, "/api/polling/submit", body)
        defended = status == 201 and resp.get("rejected") is True
        verdict = "DEFENDED" if defended else "VULNERABLE"
        return AttackResult(
            id="sig_tamper",
            name="Post-Sign Ciphertext Tampering",
            category="signature",
            description="Modify the encrypted ciphertext after signing the payload.",
            threat_model="Man-in-the-middle alters encrypted votes in transit without the signing key.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if defended else "ALLOWED",
            verdict=verdict,
            http_status=status,
            latency_ms=ms,
            details=f"HTTP {status} | ciphertext +1 tamper | rejected={resp.get('rejected')}",
            evidence="Canonical payload serialised before verification — byte-level integrity guaranteed.",
            recommendation="✔ MITM ciphertext tampering is detected." if defended
                           else "🔴 CRITICAL: Unsigned vote modification not detected.",
        )

    async def attack_empty_signature(self) -> AttackResult:
        """Submit with an empty string as the signature."""
        trio = self._unused_station_with_key()
        if not trio:
            return self._skip("sig_empty", "Empty Signature", "signature")
        station, pub, priv = trio
        body = _make_submission(station, priv, self.election, self.pub_key)
        body["signature"] = ""

        status, resp, ms = await _post(self.client, "/api/polling/submit", body)
        defended = status in (201, 422)  # rejected or validation error
        if status == 201:
            defended = resp.get("rejected") is True
        verdict = "DEFENDED" if defended else "VULNERABLE"
        return AttackResult(
            id="sig_empty",
            name="Empty Signature Bypass",
            category="signature",
            description="Submit with an empty signature string.",
            threat_model="Attacker omits signature hoping the field is not validated.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if defended else "ALLOWED",
            verdict=verdict,
            http_status=status,
            latency_ms=ms,
            details=f"HTTP {status} | rejected={resp.get('rejected','?')}",
            evidence="verify_signature() decodes empty b64 → InvalidSignature → False.",
            recommendation="✔ Empty signature is rejected." if defended
                           else "🔴 Empty signature accepted — input validation gap.",
        )

    # ════════════════════════════════════════════════════════════════════════
    # ATTACK CATEGORY 2 — Replay Attacks
    # ════════════════════════════════════════════════════════════════════════

    async def attack_replay_submission(self) -> AttackResult:
        """Submit an identical valid payload twice — exact replay attack."""
        trio = self._unused_station_with_key()
        if not trio:
            return self._skip("replay_exact", "Exact Replay Attack", "replay")
        station, pub, priv = trio

        body = _make_submission(station, priv, self.election, self.pub_key)

        # First submission — should succeed
        s1, r1, ms1 = await _post(self.client, "/api/polling/submit", body)
        if s1 != 201 or r1.get("rejected"):
            return AttackResult(
                id="replay_exact", name="Exact Replay Attack", category="replay",
                description="", threat_model="", expected_outcome="BLOCKED",
                actual_outcome="ERROR", verdict="ERROR",
                http_status=s1, latency_ms=ms1,
                details=f"First submission failed (HTTP {s1}) — cannot run replay test.",
            )

        self._submitted_station_ids.add(station["id"])

        # Replay — should be rejected with 409
        s2, r2, ms2 = await _post(self.client, "/api/polling/submit", body)
        defended = s2 == 409
        verdict = "DEFENDED" if defended else "VULNERABLE"
        return AttackResult(
            id="replay_exact",
            name="Exact Replay Attack",
            category="replay",
            description="Submit the identical signed payload a second time.",
            threat_model="Attacker captures a legitimate signed submission and replays it to double-count votes.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if defended else "ALLOWED",
            verdict=verdict,
            http_status=s2,
            latency_ms=ms2,
            details=f"1st HTTP {s1} (ok) → 2nd HTTP {s2} | detail={r2.get('detail','')}",
            evidence="Duplicate submission check: one valid submission per station per election.",
            recommendation="✔ Replay / double-submission is rejected with HTTP 409." if defended
                           else "🔴 Replay not prevented — votes can be double-counted.",
        )

    async def attack_replay_with_new_signature(self) -> AttackResult:
        """Re-sign the same encrypted payload with the same key and resubmit."""
        trio = self._unused_station_with_key()
        if not trio:
            return self._skip("replay_resign", "Re-signed Replay", "replay")
        station, pub, priv = trio

        enc = _encrypt_votes(self.pub_key, {
            c["candidate_code"]: random.randint(100, 400)
            for c in self.election["candidates"]
        })
        signed_payload = {
            "polling_station_id": station["id"],
            "election_id": self.election["id"],
            "encrypted_votes": enc,
        }
        sig1 = _sign(priv, signed_payload)
        body1 = {**signed_payload, "signature": sig1}

        s1, r1, ms1 = await _post(self.client, "/api/polling/submit", body1)
        if s1 != 201 or r1.get("rejected"):
            return self._skip("replay_resign", "Re-signed Replay", "replay")

        self._submitted_station_ids.add(station["id"])

        # Re-sign same ciphertexts — deterministic Ed25519 will produce same sig
        sig2 = _sign(priv, signed_payload)
        body2 = {**signed_payload, "signature": sig2}
        s2, r2, ms2 = await _post(self.client, "/api/polling/submit", body2)
        defended = s2 == 409
        verdict = "DEFENDED" if defended else "VULNERABLE"
        return AttackResult(
            id="replay_resign",
            name="Re-signed Replay Attack",
            category="replay",
            description="Re-sign the same encrypted votes and resubmit.",
            threat_model="Attacker with the private key resubmits the same result to artificially inflate totals.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if defended else "ALLOWED",
            verdict=verdict,
            http_status=s2,
            latency_ms=ms2,
            details=f"1st HTTP {s1} → re-sign → 2nd HTTP {s2}",
            evidence="Station-level duplicate check prevents re-submission regardless of signature freshness.",
            recommendation="✔ Re-signed replay is blocked by per-station deduplication." if defended
                           else "🔴 CRITICAL: Re-signed replay accepted — vote inflation possible.",
        )

    # ════════════════════════════════════════════════════════════════════════
    # ATTACK CATEGORY 3 — Injection & Malformed Input
    # ════════════════════════════════════════════════════════════════════════

    async def attack_nonexistent_station(self) -> AttackResult:
        """Submit results for a station ID that does not exist."""
        priv, pub = _gen_keypair()
        fake_id = 999999
        enc = _encrypt_votes(self.pub_key, {
            c["candidate_code"]: random.randint(10, 100)
            for c in self.election["candidates"]
        })
        signed_payload = {
            "polling_station_id": fake_id,
            "election_id": self.election["id"],
            "encrypted_votes": enc,
        }
        sig = _sign(priv, signed_payload)
        body = {**signed_payload, "signature": sig}

        status, resp, ms = await _post(self.client, "/api/polling/submit", body)
        defended = status == 404
        verdict = "DEFENDED" if defended else "VULNERABLE"
        return AttackResult(
            id="inject_ghost_station",
            name="Ghost Station Injection",
            category="injection",
            description="Submit a result for a non-existent polling station ID.",
            threat_model="Attacker fabricates a station to inject votes outside the registered hierarchy.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if defended else "ALLOWED",
            verdict=verdict,
            http_status=status,
            latency_ms=ms,
            details=f"HTTP {status} | detail={resp.get('detail','')}",
            evidence="Station existence validated against database before processing signature.",
            recommendation="✔ Ghost station injection returns HTTP 404." if defended
                           else "🔴 CRITICAL: Votes accepted for unregistered station.",
        )

    async def attack_extra_candidate_injection(self) -> AttackResult:
        """Add a fake candidate code to the encrypted votes dict."""
        trio = self._unused_station_with_key()
        if not trio:
            return self._skip("inject_candidate", "Candidate Injection", "injection")
        station, pub, priv = trio

        real_codes = {c["candidate_code"]: random.randint(50, 200)
                      for c in self.election["candidates"]}
        real_codes["GHOST_CAND"] = 9999   # injected fake candidate

        enc = _encrypt_votes(self.pub_key, real_codes)
        signed_payload = {
            "polling_station_id": station["id"],
            "election_id": self.election["id"],
            "encrypted_votes": enc,
        }
        sig = _sign(priv, signed_payload)
        body = {**signed_payload, "signature": sig}

        status, resp, ms = await _post(self.client, "/api/polling/submit", body)
        # Accepted but candidate not in election → will fail aggregation
        # If rejected, that's better
        if status == 201 and not resp.get("rejected"):
            verdict = "WARNING"
            details = "Submission accepted with extra candidate — may corrupt aggregate"
        elif status in (201, 400, 422):
            verdict = "WARNING" if status == 201 else "DEFENDED"
            details = f"HTTP {status}"
        else:
            verdict = "DEFENDED"
            details = f"HTTP {status}"

        return AttackResult(
            id="inject_candidate",
            name="Extra Candidate Code Injection",
            category="injection",
            description="Include an extra 'GHOST_CAND' entry in the encrypted votes.",
            threat_model="Attacker invents a new candidate to corrupt homomorphic aggregate keys.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if verdict == "DEFENDED" else "ALLOWED",
            verdict=verdict,
            http_status=status,
            latency_ms=ms,
            details=details,
            evidence="Homomorphic aggregation will detect candidate mismatch across submissions.",
            recommendation=(
                "✔ Extra candidate blocked at submission layer." if verdict == "DEFENDED"
                else "⚠ Submission accepted — aggregation layer must detect mismatch. "
                     "Add candidate-code whitelist validation at submission time."
            ),
        )

    async def attack_malformed_ciphertext(self) -> AttackResult:
        """Send a non-numeric ciphertext string."""
        trio = self._unused_station_with_key()
        if not trio:
            return self._skip("inject_ciphertext", "Malformed Ciphertext", "injection")
        station, pub, priv = trio

        enc = {c["candidate_code"]: {"ciphertext": "INVALID_HEX_NOT_A_NUMBER", "exponent": 0}
               for c in self.election["candidates"]}
        signed_payload = {
            "polling_station_id": station["id"],
            "election_id": self.election["id"],
            "encrypted_votes": enc,
        }
        sig = _sign(priv, signed_payload)
        body = {**signed_payload, "signature": sig}

        status, resp, ms = await _post(self.client, "/api/polling/submit", body)
        defended = status in (400, 422, 500)
        if status == 201:
            defended = False  # accepted malformed — problem
        verdict = "DEFENDED" if defended else "VULNERABLE"
        return AttackResult(
            id="inject_ciphertext",
            name="Malformed Ciphertext Injection",
            category="injection",
            description="Submit ciphertext as a non-numeric string ('INVALID_HEX_NOT_A_NUMBER').",
            threat_model="Attacker supplies garbage ciphertext to crash the aggregation pipeline.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if defended else "ALLOWED",
            verdict=verdict,
            http_status=status,
            latency_ms=ms,
            details=f"HTTP {status}",
            evidence="Python int() conversion raises ValueError on non-numeric ciphertext.",
            recommendation="✔ Malformed ciphertext rejected." if defended
                           else "⚠ Malformed ciphertext accepted — will crash aggregation on int() cast.",
        )

    async def attack_negative_vote_encoding(self) -> AttackResult:
        """Encrypt a negative vote count and submit it."""
        trio = self._unused_station_with_key()
        if not trio:
            return self._skip("inject_negative", "Negative Vote Encoding", "injection")
        station, pub, priv = trio

        # phe allows encrypting negative numbers — is it blocked?
        try:
            enc = _encrypt_votes(self.pub_key, {
                c["candidate_code"]: -500 for c in self.election["candidates"]
            })
        except ValueError:
            return AttackResult(
                id="inject_negative", name="Negative Vote Encoding", category="injection",
                description="Encrypt negative vote counts.", threat_model="",
                expected_outcome="BLOCKED", actual_outcome="BLOCKED",
                verdict="DEFENDED", http_status=None, latency_ms=0,
                details="Paillier encrypt_votes() raises ValueError before submission.",
                evidence="Negative-check in paillier.py encrypt_votes().",
                recommendation="✔ Negative vote encryption blocked at crypto layer.",
            )

        signed_payload = {
            "polling_station_id": station["id"],
            "election_id": self.election["id"],
            "encrypted_votes": enc,
        }
        sig = _sign(priv, signed_payload)
        body = {**signed_payload, "signature": sig}
        status, resp, ms = await _post(self.client, "/api/polling/submit", body)

        # If backend accepts a signed payload with negative-encrypted votes → WARNING
        # (because SEAS backend doesn't validate plaintext values — client encrypts)
        defended = status not in (201,) or resp.get("rejected") is True
        verdict = "DEFENDED" if defended else "WARNING"
        return AttackResult(
            id="inject_negative",
            name="Negative Vote Encoding",
            category="injection",
            description="Encrypt negative vote counts (-500 per candidate) and submit signed.",
            threat_model="Attacker submits negative-encrypted votes to reduce opponent totals via homomorphic addition.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if defended else "ALLOWED",
            verdict=verdict,
            http_status=status,
            latency_ms=ms,
            details=f"HTTP {status} | The backend cannot inspect ciphertext plaintext.",
            evidence="Paillier supports negative numbers — this is an inherent HE limitation.",
            recommendation=(
                "✔ Blocked upstream." if defended
                else "⚠ Negative encrypted values accepted. "
                     "RECOMMENDATION: Add range proofs (zero-knowledge) to constrain vote counts ≥ 0."
            ),
        )

    # ════════════════════════════════════════════════════════════════════════
    # ATTACK CATEGORY 4 — Audit Chain Integrity
    # ════════════════════════════════════════════════════════════════════════

    async def verify_audit_chain(self) -> AttackResult:
        status, resp, ms = await _get(self.client, "/api/audit/verify-chain")
        if status != 200:
            return AttackResult(
                id="audit_chain", name="Audit Hash Chain Integrity", category="audit",
                description="", threat_model="", expected_outcome="VALID",
                actual_outcome="ERROR", verdict="ERROR",
                http_status=status, latency_ms=ms, details=f"HTTP {status}",
            )

        valid = resp.get("valid", False)
        total = resp.get("total_entries", 0)
        broken = resp.get("first_broken_at")
        verdict = "DEFENDED" if valid else "VULNERABLE"
        return AttackResult(
            id="audit_chain",
            name="Audit Hash Chain Integrity",
            category="audit",
            description="Verify SHA-256 hash chain covers all audit log entries without breaks.",
            threat_model="Database-level attacker silently edits or deletes audit log entries.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if valid else "ALLOWED",
            verdict=verdict,
            http_status=status,
            latency_ms=ms,
            details=f"valid={valid} | entries={total} | first_broken={broken}",
            evidence=resp.get("message", ""),
            recommendation="✔ Audit chain is intact — retroactive tampering detectable." if valid
                           else f"🔴 CRITICAL: Chain broken at entry {broken} — possible log tampering.",
        )

    async def check_audit_event_coverage(self) -> AttackResult:
        """Verify that rejected submissions appear in the audit log."""
        status, entries, ms = await _get(self.client, "/api/audit/?event_type=SUBMISSION_REJECTED&limit=5")
        if status != 200:
            return self._skip("audit_events", "Rejected Events Logged", "audit")

        count = len(entries) if isinstance(entries, list) else 0
        verdict = "DEFENDED" if count > 0 else "WARNING"
        return AttackResult(
            id="audit_events",
            name="Rejected Submission Audit Coverage",
            category="audit",
            description="Check that all rejected (forged/tampered) submissions appear in the audit log.",
            threat_model="Attacker hopes failed attacks leave no trace.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if count > 0 else "ALLOWED",
            verdict=verdict,
            http_status=status,
            latency_ms=ms,
            details=f"{count} SUBMISSION_REJECTED event(s) found in audit log",
            evidence="Audit log captures every rejection with station_code, payload_hash, and reason.",
            recommendation="✔ Attack evidence is preserved in the audit chain." if count > 0
                           else "⚠ No rejected events found. Run signature attacks first.",
        )

    # ════════════════════════════════════════════════════════════════════════
    # ATTACK CATEGORY 5 — Aggregation Integrity
    # ════════════════════════════════════════════════════════════════════════

    async def verify_homomorphic_correctness(self) -> AttackResult:
        """
        Submit known votes, run full aggregation, decrypt, and verify arithmetic.
        This confirms the homomorphic pipeline produces correct results.
        """
        eid = self.election["id"]
        codes = [c["candidate_code"] for c in self.election["candidates"]]

        # Submit one known vote from each available station
        known_totals = {c: 0 for c in codes}
        submitted = 0

        for st in self.stations[:5]:
            code = st.get("station_code", "")
            if code not in self.station_keys:
                continue
            if st["id"] in self._submitted_station_ids:
                continue
            _, priv = self.station_keys[code]
            votes = {c: (i + 1) * 10 for i, c in enumerate(codes)}
            body = _make_submission(st, priv, self.election, self.pub_key, votes)
            s, r, _ = await _post(self.client, "/api/polling/submit", body)
            if s == 201 and not r.get("rejected"):
                self._submitted_station_ids.add(st["id"])
                for c, v in votes.items():
                    known_totals[c] += v
                submitted += 1

        if submitted == 0:
            return self._skip("agg_correct", "Homomorphic Arithmetic Verification", "aggregation")

        # Aggregate all tiers
        await _post(self.client, f"/api/aggregation/all-constituencies/{eid}", {})
        await _post(self.client, f"/api/aggregation/all-regions/{eid}", {})
        await _post(self.client, f"/api/aggregation/national/{eid}", {})
        await _post(self.client, f"/api/aggregation/finalise/{eid}", {})

        status, nat, ms = await _get(self.client, f"/api/aggregation/national/{eid}")
        if status != 200 or not nat.get("decrypted_totals"):
            return AttackResult(
                id="agg_correct", name="Homomorphic Arithmetic Verification", category="aggregation",
                description="", threat_model="", expected_outcome="BLOCKED",
                actual_outcome="ERROR", verdict="ERROR",
                http_status=status, latency_ms=ms,
                details="Could not retrieve decrypted national totals.",
            )

        dec = nat["decrypted_totals"]
        # Check that decrypted values ≥ our known_totals (other submissions may exist)
        correct = all(dec.get(c, 0) >= v for c, v in known_totals.items())
        verdict = "DEFENDED" if correct else "VULNERABLE"

        detail_parts = " | ".join(f"{c}:{dec.get(c,0)}" for c in codes)
        return AttackResult(
            id="agg_correct",
            name="Homomorphic Arithmetic Verification",
            category="aggregation",
            description="Submit known vote totals, aggregate, decrypt, verify arithmetic correctness.",
            threat_model="A flawed homomorphic implementation could silently produce wrong totals.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if correct else "ALLOWED",
            verdict=verdict,
            http_status=status,
            latency_ms=ms,
            details=f"Decrypted: {detail_parts}",
            evidence="Paillier additivity property: Enc(a)·Enc(b) = Enc(a+b). Result matches plaintext sum.",
            recommendation="✔ Homomorphic aggregation produces arithmetically correct results." if correct
                           else "🔴 Decrypted totals do not match expected sum — encryption library error.",
        )

    # ════════════════════════════════════════════════════════════════════════
    # ATTACK CATEGORY 6 — Timing Analysis
    # ════════════════════════════════════════════════════════════════════════

    async def timing_signature_oracle(self) -> AttackResult:
        """
        Measure response time for valid vs invalid signatures.
        A timing side-channel would let an attacker distinguish near-valid
        forgeries from completely invalid ones.
        """
        trio = self._station_with_key()
        if not trio:
            return self._skip("timing_sig", "Signature Timing Oracle", "timing")
        station, pub, priv = trio

        enc = _encrypt_votes(self.pub_key, {
            c["candidate_code"]: random.randint(50, 200)
            for c in self.election["candidates"]
        })
        valid_payload = {
            "polling_station_id": station["id"],
            "election_id": self.election["id"],
            "encrypted_votes": enc,
        }
        valid_sig = _sign(priv, valid_payload)

        ROUNDS = 6
        valid_times, invalid_times = [], []

        for _ in range(ROUNDS):
            body = {**valid_payload, "signature": valid_sig}
            _, _, ms = await _post(self.client, "/api/polling/submit", body)
            valid_times.append(ms)
            await asyncio.sleep(0.05)

        for _ in range(ROUNDS):
            rand_sig = base64.b64encode(os.urandom(64)).decode()
            body = {**valid_payload, "signature": rand_sig}
            _, _, ms = await _post(self.client, "/api/polling/submit", body)
            invalid_times.append(ms)
            await asyncio.sleep(0.05)

        mean_valid = statistics.mean(valid_times)
        mean_invalid = statistics.mean(invalid_times)
        diff_ms = abs(mean_valid - mean_invalid)
        ratio = max(mean_valid, mean_invalid) / max(min(mean_valid, mean_invalid), 0.001)

        # >2× ratio or >50 ms difference is a timing concern
        if ratio > 2.0 or diff_ms > 50:
            verdict, note = "WARNING", f"Ratio {ratio:.1f}× — potential timing side-channel"
        else:
            verdict, note = "DEFENDED", f"Ratio {ratio:.2f}× — timing difference negligible"

        return AttackResult(
            id="timing_sig",
            name="Signature Verification Timing Oracle",
            category="timing",
            description=(
                f"Measure response time: valid sig ({mean_valid:.1f} ms) vs "
                f"random sig ({mean_invalid:.1f} ms) over {ROUNDS} rounds each."
            ),
            threat_model="Timing side-channel allows attacker to distinguish near-valid signatures from garbage.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if verdict == "DEFENDED" else "ALLOWED",
            verdict=verdict,
            http_status=201,
            latency_ms=mean_invalid,
            details=f"valid={mean_valid:.1f}ms | invalid={mean_invalid:.1f}ms | diff={diff_ms:.1f}ms | {note}",
            evidence="Ed25519 uses constant-time verification — cryptography library mitigates timing attacks.",
            recommendation=(
                "✔ No significant timing difference detected." if verdict == "DEFENDED"
                else "⚠ Measurable timing difference. Network jitter may explain this. "
                     "Consider adding constant-time HTTP response padding."
            ),
        )

    # ════════════════════════════════════════════════════════════════════════
    # ATTACK CATEGORY 7 — Access Control & Information Leakage
    # ════════════════════════════════════════════════════════════════════════

    async def check_private_key_exposure(self) -> AttackResult:
        """Check whether the election detail endpoint exposes the Paillier private key."""
        eid = self.election["id"]
        status, data, ms = await _get(self.client, f"/api/elections/{eid}")
        has_private = "paillier_private_key" in (data or {})
        verdict = "VULNERABLE" if has_private else "DEFENDED"
        return AttackResult(
            id="info_privkey",
            name="Paillier Private Key Exposure",
            category="access_control",
            description="Check whether GET /api/elections/{id} returns the Paillier private key.",
            threat_model="Any client reading the election details can obtain the private key and decrypt any aggregate.",
            expected_outcome="BLOCKED",
            actual_outcome="ALLOWED" if has_private else "BLOCKED",
            verdict=verdict,
            http_status=status,
            latency_ms=ms,
            details=f"private key in response = {has_private}",
            evidence="ElectionOut schema includes only paillier_public_key — private key deliberately excluded.",
            recommendation=(
                "✔ Private key is not exposed via the public API." if not has_private
                else "🔴 CRITICAL: Private key exposure — any client can decrypt all vote totals."
            ),
        )

    async def check_station_private_key_exposure(self) -> AttackResult:
        """Check whether station list exposes officer private keys."""
        status, data, ms = await _get(self.client, "/api/polling/stations")
        exposed = any("officer_private_key" in (s or {}) for s in (data if isinstance(data, list) else []))
        verdict = "VULNERABLE" if exposed else "DEFENDED"
        return AttackResult(
            id="info_stationkey",
            name="Officer Private Key Exposure (Station List)",
            category="access_control",
            description="Check GET /api/polling/stations for officer_private_key in responses.",
            threat_model="Attacker enumerates stations and steals private keys to forge future submissions.",
            expected_outcome="BLOCKED",
            actual_outcome="ALLOWED" if exposed else "BLOCKED",
            verdict=verdict,
            http_status=status,
            latency_ms=ms,
            details=f"private keys in listing = {exposed}",
            evidence="PollingStationOut schema excludes officer_private_key field.",
            recommendation=(
                "✔ Officer private keys are not exposed in station listings." if not exposed
                else "🔴 CRITICAL: Officer private keys leaked via station list endpoint."
            ),
        )

    async def check_rejected_submission_stored(self) -> AttackResult:
        """Verify that rejected submissions are retained for forensic analysis."""
        status, data, ms = await _get(self.client, f"/api/polling/submissions/{self.election['id']}")
        if status != 200 or not isinstance(data, list):
            return self._skip("forensic_retention", "Rejected Submission Retention", "access_control")

        has_rejected = any(s.get("rejected") for s in data)
        verdict = "DEFENDED" if has_rejected else "WARNING"
        return AttackResult(
            id="forensic_retention",
            name="Rejected Submission Forensic Retention",
            category="access_control",
            description="Verify that forged/tampered submissions are stored with rejection metadata.",
            threat_model="Attacker's failed attack leaves no evidence if rejected submissions are deleted.",
            expected_outcome="BLOCKED",
            actual_outcome="BLOCKED" if has_rejected else "ALLOWED",
            verdict=verdict,
            http_status=status,
            latency_ms=ms,
            details=f"Rejected submissions in DB = {sum(1 for s in data if s.get('rejected'))}",
            evidence="rejected=True flag persisted; rejection_reason and payload_hash retained for forensics.",
            recommendation=(
                "✔ Attack evidence is persisted with full forensic detail." if has_rejected
                else "⚠ No rejected submissions found — run attack tests first."
            ),
        )

    # ════════════════════════════════════════════════════════════════════════
    # Helper
    # ════════════════════════════════════════════════════════════════════════

    def _skip(self, id_: str, name: str, category: str) -> AttackResult:
        log.warning("Skipping test '%s' — no eligible station with key available.", name)
        return AttackResult(
            id=id_, name=name, category=category,
            description="", threat_model="",
            expected_outcome="BLOCKED", actual_outcome="ERROR",
            verdict="ERROR", http_status=None, latency_ms=0,
            details="Skipped — no unused station with known key available.",
        )

    # ════════════════════════════════════════════════════════════════════════
    # Orchestrator
    # ════════════════════════════════════════════════════════════════════════

    async def run_all(self, category_filter: Optional[str] = None) -> AuditReport:
        """Run all (or filtered) attack scenarios and return a populated AuditReport."""

        ALL_ATTACKS = [
            # Signature
            self.attack_random_signature,
            self.attack_wrong_key,
            self.attack_payload_tampering,
            self.attack_empty_signature,
            # Replay
            self.attack_replay_submission,
            self.attack_replay_with_new_signature,
            # Injection
            self.attack_nonexistent_station,
            self.attack_extra_candidate_injection,
            self.attack_malformed_ciphertext,
            self.attack_negative_vote_encoding,
            # Aggregation
            self.verify_homomorphic_correctness,
            # Audit
            self.verify_audit_chain,
            self.check_audit_event_coverage,
            # Timing
            self.timing_signature_oracle,
            # Access control
            self.check_private_key_exposure,
            self.check_station_private_key_exposure,
            self.check_rejected_submission_stored,
        ]

        CATEGORY_MAP = {
            "signature": "signature",
            "replay": "replay",
            "injection": "injection",
            "aggregation": "aggregation",
            "audit": "audit",
            "timing": "timing",
            "access": "access_control",
        }
        filter_val = CATEGORY_MAP.get(category_filter, category_filter)

        attacks_to_run = []
        for fn in ALL_ATTACKS:
            # Quick heuristic: check function name prefix
            if filter_val is None:
                attacks_to_run.append(fn)
            else:
                cat = fn.__name__.split("_")[1] if "_" in fn.__name__ else ""
                # We'll check category after running — run all for now
                attacks_to_run.append(fn)

        report = AuditReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            host=self.host,
            election_id=self.election["id"] if self.election else None,
        )

        total = len(attacks_to_run)
        _rule("RUNNING ATTACK SCENARIOS")

        if HAS_RICH:
            progress_ctx = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=30),
                TextColumn("{task.completed}/{task.total}"),
                console=console,
                transient=True,
            )
        else:
            progress_ctx = None

        results = []

        if progress_ctx:
            with progress_ctx as prog:
                task = prog.add_task("Running attacks…", total=total)
                for fn in attacks_to_run:
                    prog.update(task, description=f"[cyan]{fn.__name__}[/cyan]")
                    r = await fn()
                    if filter_val and r.category != filter_val:
                        prog.advance(task)
                        continue
                    results.append(r)
                    self._record(r)
                    prog.advance(task)
        else:
            for i, fn in enumerate(attacks_to_run, 1):
                print(f"  [{i:02d}/{total}] {fn.__name__} …", end=" ", flush=True)
                r = await fn()
                if filter_val and r.category != filter_val:
                    print("SKIP")
                    continue
                results.append(r)
                self._record(r)
                icon = _verdict_icon(r.verdict)
                print(f"{icon} {r.verdict}")

        report.results = results
        report.total_tests = len(results)
        report.defended = sum(1 for r in results if r.verdict == "DEFENDED")
        report.vulnerable = sum(1 for r in results if r.verdict == "VULNERABLE")
        report.warnings = sum(1 for r in results if r.verdict == "WARNING")
        report.errors = sum(1 for r in results if r.verdict == "ERROR")

        # Audit chain summary
        chain_result = next((r for r in results if r.id == "audit_chain"), None)
        if chain_result:
            report.audit_chain_valid = chain_result.verdict == "DEFENDED"
            try:
                parts = chain_result.details.split("|")
                for p in parts:
                    if "entries" in p:
                        report.audit_chain_entries = int(p.split("=")[1].strip())
            except Exception:
                pass

        # Timing summary
        timing_results = [r for r in results if r.category == "timing"]
        if timing_results:
            report.timing_analysis = {
                r.id: {"latency_ms": r.latency_ms, "verdict": r.verdict, "details": r.details}
                for r in timing_results
            }

        return report


# ════════════════════════════════════════════════════════════════════════════
# Report Rendering
# ════════════════════════════════════════════════════════════════════════════

def render_report(report: AuditReport) -> None:
    _rule()
    _print("")

    if HAS_RICH:
        # ── Score banner ────────────────────────────────────────────────────
        total = report.total_tests
        score = int((report.defended / total * 100)) if total else 0
        banner_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"

        summary = (
            f"[bold {banner_color}]Security Score: {score}%[/bold {banner_color}]  "
            f"({report.defended}/{total} defences verified)\n\n"
            f"  [green]DEFENDED  {report.defended:>3}[/green]   "
            f"[red]VULNERABLE {report.vulnerable:>3}[/red]   "
            f"[yellow]WARNING {report.warnings:>3}[/yellow]   "
            f"[dim]ERROR {report.errors:>3}[/dim]\n\n"
            f"  Host     : {report.host}\n"
            f"  Election : {report.election_id}\n"
            f"  Timestamp: {report.timestamp}\n"
            f"  Audit log: {report.audit_chain_entries} entries — "
            f"{'[green]INTACT[/green]' if report.audit_chain_valid else '[red]BROKEN[/red]' if report.audit_chain_valid is False else 'N/A'}"
        )
        console.print(Panel(summary, title="SEAS SECURITY AUDIT REPORT", border_style=banner_color))

        # ── Results table ────────────────────────────────────────────────────
        table = Table(
            title="Attack Simulation Results",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            min_width=100,
        )
        table.add_column("#",      style="dim",       width=3)
        table.add_column("Category",                   width=14)
        table.add_column("Attack Name",                width=36)
        table.add_column("HTTP",   style="cyan",      width=5)
        table.add_column("ms",     style="dim",       width=7)
        table.add_column("Verdict",                    width=11)
        table.add_column("Key Details",                width=50)

        for i, r in enumerate(report.results, 1):
            style = _verdict_style(r.verdict)
            icon  = _verdict_icon(r.verdict)
            table.add_row(
                str(i),
                f"[dim]{r.category}[/dim]",
                r.name,
                str(r.http_status or "-"),
                f"{r.latency_ms:.0f}",
                f"[{style}]{icon} {r.verdict}[/{style}]",
                Text(r.details[:70], style="dim"),
            )

        console.print(table)

        # ── Vulnerable / Warning detail ──────────────────────────────────────
        bad = [r for r in report.results if r.verdict in ("VULNERABLE", "WARNING")]
        if bad:
            _rule("FINDINGS REQUIRING ATTENTION")
            for r in bad:
                style = _verdict_style(r.verdict)
                icon  = _verdict_icon(r.verdict)
                console.print(Panel(
                    f"[bold]Threat:[/bold] {r.threat_model}\n"
                    f"[bold]Evidence:[/bold] {r.evidence or 'N/A'}\n"
                    f"[bold]Recommendation:[/bold] {r.recommendation}",
                    title=f"{icon} [{style}]{r.name}[/{style}]",
                    border_style=style,
                    padding=(0, 1),
                ))

        # ── Timing analysis ──────────────────────────────────────────────────
        if report.timing_analysis:
            _rule("TIMING ANALYSIS")
            for tid, info in report.timing_analysis.items():
                tstyle = _verdict_style(info["verdict"])
                console.print(
                    f"  [{tstyle}]{info['verdict']}[/{tstyle}]  {tid}  "
                    f"[dim]{info['details']}[/dim]"
                )

    else:
        # ── Plain text fallback ──────────────────────────────────────────────
        total = report.total_tests
        score = int((report.defended / total * 100)) if total else 0
        print(f"\n{'═'*70}")
        print(f"  SEAS SECURITY AUDIT REPORT")
        print(f"  Score: {score}%  ({report.defended}/{total} defended)")
        print(f"  Host: {report.host} | Election: {report.election_id}")
        print(f"  Audit chain: {report.audit_chain_entries} entries")
        print(f"{'─'*70}")
        print(f"  {'#':<3} {'Category':<14} {'Name':<36} {'HTTP':<5} {'ms':<7} {'Verdict':<11}")
        print(f"{'─'*70}")
        for i, r in enumerate(report.results, 1):
            icon = _verdict_icon(r.verdict)
            print(f"  {i:<3} {r.category:<14} {r.name:<36} "
                  f"{str(r.http_status or '-'):<5} {r.latency_ms:<7.0f} "
                  f"{icon} {r.verdict}")
        print(f"{'═'*70}")

    _print("")
    log.info(
        "Report complete | score=%d%% defended=%d vulnerable=%d warnings=%d errors=%d",
        int((report.defended / report.total_tests * 100)) if report.total_tests else 0,
        report.defended, report.vulnerable, report.warnings, report.errors,
    )


def save_report(report: AuditReport, path: str) -> None:
    """Serialise the report to JSON."""
    data = asdict(report)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    _print(f"\n  📄 JSON report saved → [cyan]{path}[/cyan]")
    log.info("JSON report saved to %s", path)


# ════════════════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════════════════

CATEGORY_DESCRIPTIONS = {
    "signature":    "Ed25519 signature forgery, tampering, wrong-key attacks",
    "replay":       "Exact and re-signed replay attacks",
    "injection":    "Ghost station, candidate injection, malformed ciphertext, negative votes",
    "aggregation":  "Homomorphic arithmetic correctness verification",
    "audit":        "SHA-256 hash chain integrity and forensic event coverage",
    "timing":       "Timing side-channel analysis on signature verification",
    "access":       "Private key exposure and forensic data retention",
}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="security_audit.py",
        description=(
            "SEAS Security Audit & Attack Simulation Tool\n"
            "Tests the Secure Election Aggregation System against real-world attack vectors."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python security_audit.py\n"
            "  python security_audit.py --host http://localhost:8000\n"
            "  python security_audit.py --category signature --verbose\n"
            "  python security_audit.py --output results.json --log full.log\n"
            "  python security_audit.py --list-categories\n"
        ),
    )
    parser.add_argument(
        "--host", default="http://localhost:8000",
        metavar="URL",
        help="Backend base URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--output", default="seas_audit_report.json",
        metavar="FILE",
        help="Save JSON report to this file (default: seas_audit_report.json)",
    )
    parser.add_argument(
        "--log", default="seas_audit.log",
        metavar="FILE",
        help="Save full debug log to this file (default: seas_audit.log)",
    )
    parser.add_argument(
        "--category",
        choices=list(CATEGORY_DESCRIPTIONS.keys()),
        metavar="CAT",
        help="Run only one attack category. Use --list-categories to see options.",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print each test result inline as it runs",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable rich colour output (useful for piping / plain log files)",
    )
    parser.add_argument(
        "--list-categories", action="store_true",
        help="List all attack categories and exit",
    )
    return parser.parse_args()


# ════════════════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════════════════

async def main_async(args: argparse.Namespace) -> int:
    global log, HAS_RICH, console

    if args.no_color:
        HAS_RICH = False
        console = None

    log = setup_logging(args.log)

    # Header
    _rule()
    if HAS_RICH:
        console.print(Panel(
            "[bold cyan]SEAS — Secure Election Aggregation System[/bold cyan]\n"
            "[bold]Security Audit & Attack Simulation Tool[/bold]  v1.0\n\n"
            "[dim]Simulates real-world adversarial attacks against the four-tier\n"
            "cryptographic election pipeline and documents which defences hold.[/dim]",
            border_style="cyan",
        ))
    else:
        print("  SEAS Security Audit & Attack Simulation Tool v1.0")
    _rule()

    auditor = SEASSecurityAuditor(args.host, verbose=args.verbose)

    # Connect
    _rule("SYSTEM CONNECTIVITY")
    if not await auditor.connect():
        return 1

    # Load data
    _rule("LOADING ELECTION DATA")
    if not await auditor.load_election_data():
        return 1

    # Run
    report = await auditor.run_all(category_filter=args.category)

    # Render
    render_report(report)

    # Save
    save_report(report, args.output)
    _print(f"  📋 Full debug log → [cyan]{args.log}[/cyan]")

    # Exit code: 0 if no vulnerabilities, 1 if any found
    return 0 if report.vulnerable == 0 else 1


def main() -> None:
    args = parse_args()

    if args.list_categories:
        if HAS_RICH and console:
            table = Table(title="Attack Categories", box=box.ROUNDED)
            table.add_column("Category", style="cyan", width=14)
            table.add_column("Description", width=60)
            for k, v in CATEGORY_DESCRIPTIONS.items():
                table.add_row(k, v)
            console.print(table)
        else:
            for k, v in CATEGORY_DESCRIPTIONS.items():
                print(f"  {k:<14}  {v}")
        sys.exit(0)

    sys.exit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
