# SEAS Backend

> **FastAPI backend for the Secure Election Aggregation System — Ghana's cryptographic four-tier election results pipeline.**

---

## Table of Contents

- [Overview](#overview)
- [Cryptographic Design](#cryptographic-design)
  - [Why Paillier Homomorphic Encryption?](#why-paillier-homomorphic-encryption)
  - [Why Ed25519 Digital Signatures?](#why-ed25519-digital-signatures)
  - [Why SHA-256 Hash Chaining?](#why-sha-256-hash-chaining)
  - [How They Work Together](#how-they-work-together)
- [Project Structure](#project-structure)
- [Running with Docker](#running-with-docker)
- [Running Locally (Without Docker)](#running-locally-without-docker)
- [Seeding the Database](#seeding-the-database)
- [API Reference](#api-reference)
- [Running Tests](#running-tests)
- [Load Testing with Locust](#load-testing-with-locust)
- [Environment Variables](#environment-variables)
- [Security Notes](#security-notes)

---

## Overview

The SEAS backend is a **FastAPI + SQLite** service that implements a four-tier encrypted vote aggregation pipeline modelled on Ghana's national electoral structure:

```
Polling Stations (~33,000)  →  Constituencies (275)  →  Regions (16)  →  National
```

At every tier except the final one, vote totals remain **encrypted**. No intermediate node ever sees a plaintext vote count. Only the national authority — in possession of the Paillier private key — can reveal the final result.

---

## Cryptographic Design

Three cryptographic primitives work together to guarantee confidentiality, authenticity, and audit integrity.

### Why Paillier Homomorphic Encryption?

**The problem:** In a traditional system, each tier must decrypt incoming totals, add them up, then re-encrypt. This means every aggregator (constituency, region) can see vote counts — creating hundreds of attack surfaces.

**The solution:** The [Paillier cryptosystem (1999)](https://link.springer.com/chapter/10.1007/3-540-48910-X_16) is an *additively homomorphic* encryption scheme. This means:

```
Encrypt(a) × Encrypt(b)  ≡  Encrypt(a + b)   (mod n²)
```

Encrypted ciphertexts can be **multiplied together** to produce the encryption of their sum — without ever decrypting. Applied to vote aggregation:

```
Enc(station₁_votes) · Enc(station₂_votes) · … · Enc(stationₙ_votes)
                     ≡  Enc(constituency_total)
```

Constituency and regional aggregators perform only this multiplication. They never hold the private key and cannot learn any vote count.

**Key size — 2048 bits:**  A 2048-bit Paillier modulus provides approximately 112 bits of security, equivalent to RSA-2048. NIST recommends this level for data requiring protection beyond 2030. For local testing, 512-bit keys can be used (see the `key_size` parameter), though these are cryptographically unsafe and exist only to speed up test runs.

**Where it lives in the codebase:** `app/crypto/paillier.py`

| Function | Purpose |
|---|---|
| `generate_keypair(key_size)` | Generates public/private Paillier keypair for an election |
| `encrypt_votes(pub_key, vote_totals)` | Encrypts a `candidate → count` dict |
| `homomorphic_add(pub_key, encrypted_list)` | Aggregates ciphertexts without decryption |
| `decrypt_totals(pub_key, priv_key, enc_totals)` | National-only decryption to plaintext |

---

### Why Ed25519 Digital Signatures?

**The problem:** An aggregator receiving an encrypted submission has no way to know whether it came from a legitimate polling station officer or from an attacker injecting fake results.

**The solution:** Every polling station officer is issued a unique **Ed25519 keypair** during registration. Before submitting results, the officer's device:
1. Constructs a canonical JSON payload (sorted keys, no whitespace).
2. Signs it with their private key — producing a 64-byte signature.
3. Includes the signature in the submission.

The backend verifies the signature against the officer's registered public key before accepting the submission. Any tampered or forged payload is immediately rejected and flagged in the audit log.

**Why Ed25519 specifically?**

| Property | Detail |
|---|---|
| Security level | 128-bit (equivalent to RSA-3072) |
| Signature size | 64 bytes — compact for high-volume submissions |
| Verification speed | ~70,000 verifications/sec on commodity hardware |
| Side-channel safety | Constant-time implementation — immune to timing attacks |
| Deterministic | Same key + message always produces the same signature; no random nonce required |

**Payload canonicalisation** (`app/crypto/signatures.py → _canonicalise`) uses `json.dumps(payload, sort_keys=True, separators=(",", ":"))` so that Python (backend) and JavaScript (frontend) produce identical byte strings from the same logical payload, ensuring cross-language signature interoperability.

**Where it lives:** `app/crypto/signatures.py`

| Function | Purpose |
|---|---|
| `generate_ed25519_keypair()` | Creates a new officer keypair at station registration |
| `sign_payload(priv_key_b64, payload)` | Signs canonical payload bytes |
| `verify_signature(pub_key_b64, payload, sig_b64)` | Returns `True`/`False` — never raises |
| `compute_payload_hash(payload)` | SHA-256 digest of canonical payload for the audit chain |

---

### Why SHA-256 Hash Chaining?

**The problem:** Even if every submission is verified and every aggregate is correct, an attacker with database access could silently delete, insert, or alter audit log entries after the fact.

**The solution:** Every audit log entry stores two hashes:

```
payload_hash  =  SHA-256( event_data )
chain_hash    =  SHA-256( prev_chain_hash || payload_hash )
```

This creates a **hash chain** — the same structure used in blockchain systems. Altering any entry changes its `payload_hash`, which invalidates its `chain_hash`, which invalidates every subsequent entry's `chain_hash`. The `GET /api/audit/verify-chain` endpoint detects this instantly by replaying the chain.

The genesis hash (the "previous hash" for the very first entry) is 64 zero characters: `"0000...0000"`.

**Where it lives:** `app/services/audit.py` and `app/crypto/signatures.py`

---

### How They Work Together

A complete submission flow looks like this:

```
[Polling Station Frontend]
  1. Fetch election public key (Paillier n)
  2. Encrypt vote counts:  Enc(NDC_votes), Enc(NPP_votes), Enc(IND_votes)
  3. Sign canonical payload with officer's Ed25519 private key
  4. POST /api/polling/submit  { encrypted_votes, signature }

[Backend – polling.py]
  5. Verify station and election exist
  6. Reject duplicate submissions (one per station per election)
  7. Reconstruct canonical payload
  8. Verify Ed25519 signature → reject and flag if invalid
  9. Persist submission + append to audit chain

[Backend – aggregation.py]
  10. Constituency tier: homomorphic_add(all station ciphertexts) → Enc(constituency_total)
  11. Regional tier:     homomorphic_add(all constituency ciphertexts) → Enc(regional_total)
  12. National tier:     homomorphic_add(all regional ciphertexts) → Enc(national_total)
  13. Finalise:          decrypt_totals(private_key, Enc(national_total)) → plaintext result
```

Steps 10–12 require **no decryption** and **no private key**. The private key is loaded only in step 13.

---

## Project Structure

```
backend/
├── app/
│   ├── main.py                  FastAPI app, middleware, router wiring, lifespan
│   ├── config.py                Pydantic Settings — all env-configurable parameters
│   ├── crypto/
│   │   ├── paillier.py          Paillier HE: keygen, encrypt, homomorphic_add, decrypt
│   │   └── signatures.py        Ed25519 keygen/sign/verify + SHA-256 hash chaining
│   ├── db/
│   │   ├── database.py          Async SQLAlchemy engine, session factory, init_db
│   │   ├── models.py            ORM models: Region, Constituency, PollingStation,
│   │   │                        Election, Candidate, Submission, Aggregates, AuditLog
│   │   └── crud.py              (reserved — business logic lives in services/)
│   ├── schemas/
│   │   └── models.py            Pydantic v2 request/response schemas for all endpoints
│   ├── api/routes/
│   │   ├── elections.py         Election lifecycle (create, list, get)
│   │   ├── polling.py           Station registration + result submission
│   │   ├── aggregation.py       Tier-by-tier homomorphic aggregation + finalise
│   │   ├── verification.py      On-demand signature re-verification
│   │   ├── audit.py             Audit log retrieval + chain integrity check
│   │   └── websocket.py         Real-time WebSocket event feed
│   └── services/
│       ├── aggregation.py       Multi-tier pipeline orchestration service
│       ├── audit.py             Hash-chained audit logger
│       └── websocket_manager.py WebSocket connection pool + broadcast
├── tests/
│   └── test_crypto.py           pytest unit tests for all crypto primitives
├── seed.py                      Database seeder: Ghana regions, constituencies, stations
├── locustfile.py                Locust load test: 200 concurrent station submissions
├── requirements.txt
└── Dockerfile
```

---

## Running with Docker

A `docker-compose.yml` is included in the `backend/` folder. It wires up the backend service and a named SQLite volume — no frontend required.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) ≥ 24
- [Docker Compose](https://docs.docker.com/compose/) ≥ 2 (included with Docker Desktop)

### 1. Start the backend

From inside the `backend/` directory:

```bash
cd backend
docker compose up --build
```

The first build downloads Python dependencies and compiles the `phe` C extension (GMP-backed). This takes 2–4 minutes. Subsequent starts use the cache and are much faster.

To run in the background:

```bash
docker compose up --build -d
```

### 2. Verify the backend is healthy

```bash
curl http://localhost:8000/health
# → {"status":"healthy","service":"SEAS Backend","version":"1.0.0"}
```

Or open the auto-generated API docs: [http://localhost:8000/docs](http://localhost:8000/docs)

### 3. Seed the database

```bash
docker compose exec backend python seed.py
```

This creates 5 regions, 10 constituencies, 50 polling stations, 1 election, and 3 candidates. It also writes `station_keys.json` inside the container for use by the Locust load tester.

Expected output:

```
Generating 2048-bit Paillier keypair (may take a few seconds)...
✅ Seeded: 5 regions, 10 constituencies, 50 polling stations, 1 election, 3 candidates.
   Election ID: 1
   Paillier public key n[:40]: 24759012378...
   Station keys written to station_keys.json for Locust.
```

### 4. Access the backend

| Endpoint | URL |
|---|---|
| API Docs (Swagger) | http://localhost:8000/docs |
| API Docs (ReDoc) | http://localhost:8000/redoc |
| Health check | http://localhost:8000/health |
| WebSocket feed | ws://localhost:8000/ws/feed |

### Useful commands

```bash
# View live logs
docker compose logs -f

# Open a shell inside the container
docker compose exec backend bash

# Stop the backend
docker compose down

# Stop and remove the database volume (resets all data)
docker compose down -v
```

---

## Running Locally (Without Docker)

### Prerequisites

- Python 3.11+
- `gcc` and `libgmp-dev` (required by the `phe` C extension)

On Ubuntu/Debian:
```bash
sudo apt-get install gcc libgmp-dev
```

On macOS (with Homebrew):
```bash
brew install gmp
```

### Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Configure the database

```bash
# Create the data directory
mkdir -p /data

# Or use a local path by overriding the DATABASE_URL
export DATABASE_URL="sqlite+aiosqlite:///./seas.db"
```

### Start the server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Seed the database

```bash
python seed.py
```

---

## Seeding the Database

The `seed.py` script populates the database with a realistic Ghana election simulation:

| Entity | Count | Details |
|---|---|---|
| Regions | 5 | Greater Accra, Ashanti, Northern, Western, Eastern |
| Constituencies | 10 | 2 per region |
| Polling Stations | 50 | 5 per constituency, each with a unique Ed25519 keypair |
| Elections | 1 | "2024 Ghana Presidential Election" (date: 2024-12-07) |
| Candidates | 3 | NDC, NPP, Independent |

Each polling station's Ed25519 private key is stored in `station_keys.json` for use by the Locust load tester. In a production system, private keys would never be stored server-side.

---

## API Reference

Full interactive documentation is available at `/docs` (Swagger UI) and `/redoc` (ReDoc) when the server is running.

### Elections

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/elections/` | Create election + generate Paillier keypair |
| `GET` | `/api/elections/` | List all elections |
| `GET` | `/api/elections/{id}` | Get election details with public key and candidates |

### Polling Stations

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/polling/stations` | Register station + generate Ed25519 keypair |
| `GET` | `/api/polling/stations` | List all stations |
| `GET` | `/api/polling/stations/{id}` | Get a single station |
| `POST` | `/api/polling/submit` | Submit signed, encrypted results |
| `GET` | `/api/polling/submissions/{election_id}` | List all submissions for an election |
| `GET` | `/api/polling/progress/{election_id}` | Submission and aggregation progress metrics |

### Aggregation

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/aggregation/constituency/{election_id}/{constituency_id}` | Aggregate one constituency |
| `POST` | `/api/aggregation/all-constituencies/{election_id}` | Aggregate all constituencies |
| `GET` | `/api/aggregation/constituency/{election_id}` | Retrieve all constituency aggregates |
| `POST` | `/api/aggregation/region/{election_id}/{region_id}` | Aggregate one region |
| `POST` | `/api/aggregation/all-regions/{election_id}` | Aggregate all regions |
| `GET` | `/api/aggregation/region/{election_id}` | Retrieve all regional aggregates |
| `POST` | `/api/aggregation/national/{election_id}` | Aggregate to encrypted national total |
| `POST` | `/api/aggregation/finalise/{election_id}` | **Decrypt** national total (private key used here) |
| `GET` | `/api/aggregation/national/{election_id}` | Retrieve national aggregate |

### Verification

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/verification/signature` | Verify an Ed25519 signature on a payload |
| `GET` | `/api/verification/submission/{submission_id}` | Re-verify a stored submission by ID |

### Audit

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/audit/` | Paginated audit log (filter by `event_type`) |
| `GET` | `/api/audit/verify-chain` | Verify SHA-256 hash chain integrity |

### Health

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe — returns `{"status": "healthy"}` |

### WebSocket

```
ws://localhost:8000/ws/feed
```

Send `"ping"` to receive `"pong"`. All election events are broadcast automatically.

**Event types emitted:**

| Event | Trigger |
|---|---|
| `CONNECTED` | Client connects — includes active connection count |
| `SUBMISSION_RECEIVED` | Valid signed submission accepted |
| `SUBMISSION_REJECTED` | Submission failed signature verification |
| `CONSTITUENCY_AGGREGATED` | Constituency homomorphic aggregate computed |
| `REGION_AGGREGATED` | Regional homomorphic aggregate computed |
| `NATIONAL_AGGREGATED` | National encrypted aggregate updated |
| `NATIONAL_FINALIZED` | Decrypted results available |

---

## Running Tests

Unit tests cover all cryptographic primitives and the audit chain.

```bash
cd backend
pip install -r requirements.txt
pytest tests/test_crypto.py -v
```

**Test coverage:**

| Test | What it checks |
|---|---|
| Paillier encrypt/decrypt | Round-trip correctness for various vote counts |
| Homomorphic addition | 5-station aggregate equals sum of individual counts |
| Ed25519 sign/verify | Valid signature accepted |
| Tampered payload rejection | Modified payload fails verification |
| Forged signature rejection | Wrong private key produces rejected signature |
| SHA-256 chain integrity | Constructed chain verifies correctly |
| Chain tampering detection | Altered entry breaks chain verification |

---

## Load Testing with Locust

Simulates 200 concurrent polling station officers submitting encrypted results.

### Setup

```bash
cd backend
pip install -r requirements.txt

# The seeder must have been run first (generates station_keys.json)
python seed.py
```

### Run the load test

```bash
locust -f locustfile.py \
  --host=http://localhost:8000 \
  --users=200 \
  --spawn-rate=10 \
  --headless \
  --run-time=120s
```

Or open the Locust web UI at [http://localhost:8089](http://localhost:8089):

```bash
locust -f locustfile.py --host=http://localhost:8000
```

**What it measures:**

- Submission throughput (requests/second)
- P50 / P95 / P99 latency
- Signature verification pass rate (stations with valid keys vs. ephemeral keys)
- Duplicate submission rejection rate (HTTP 409)

**Note:** Station submissions with valid keys (from `station_keys.json`) will pass signature verification. If `station_keys.json` is missing, Locust generates ephemeral keys that produce deliberate signature failures — useful for testing the rejection path.

---

## Environment Variables

All settings are in `app/config.py` and can be overridden via environment variables or a `.env` file.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./seas.db` | SQLAlchemy async database URL |
| `DEBUG` | `False` | Enables SQL query logging and DEBUG log level |
| `PAILLIER_KEY_SIZE` | `2048` | Key size in bits for new elections |
| `SECRET_KEY` | `seas-dev-secret-...` | JWT signing secret — **change in production** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | 8-hour officer session duration |
| `CORS_ORIGINS` | localhost:3000, 5173, 5174 | Allowed CORS origins |

The Docker container sets `DATABASE_URL=sqlite+aiosqlite:////data/seas.db` so data persists in the `/data` volume across restarts.

---

## Security Notes

This system is a **research simulation**. The following properties hold within the simulation, with notes on what a production deployment would require:

| Property | Current Implementation | Production Requirement |
|---|---|---|
| Vote confidentiality | Paillier encryption; decryption only at national tier | Same — HSM-backed private key storage |
| Submission authenticity | Ed25519 signature per officer | Same — keys delivered via secure channel, not stored server-side |
| Non-repudiation | Signature stored with every submission | Same |
| Replay attack prevention | Duplicate submission check per station per election | Same + nonce/timestamp binding |
| Audit integrity | SHA-256 hash chain | Same + external notarisation of chain root |
| Private key access control | No access controls (simulation) | Multi-party threshold decryption or HSM |
| Officer private key storage | Stored in database for simulation convenience | Never stored server-side |

---

*University Research Project · Ghana Homomorphic Election Aggregation · 2024*
