# SEAS Security Audit Tool — Quick Start

## Prerequisites

```bash
pip install httpx phe cryptography rich
```

---

## Workflow

### 1. Start the backend

```bash
cd backend
docker compose up --build -d
```

Wait ~30 seconds for the first build. Check it's healthy:

```bash
curl http://localhost:8000/health
# → {"status":"healthy","service":"SEAS Backend","version":"1.0.0"}
```

### 2. Seed the database

```bash
docker compose exec backend python seed.py
```

Creates 5 regions · 10 constituencies · 50 polling stations · 1 election · 3 candidates.

### 3. Copy station keys out of the container

```bash
docker compose cp backend:/app/station_keys.json ./station_keys.json
```

Run this from the same directory as `security_audit.py`.

### 4. Run the full security audit

```bash
python security_audit.py
```

### 5. Run a specific attack category

```bash
python security_audit.py --category signature
python security_audit.py --category replay
python security_audit.py --category injection
python security_audit.py --category audit
python security_audit.py --category timing
python security_audit.py --category access
python security_audit.py --category aggregation
```

### 6. Other useful options

```bash
# See each test printed inline as it runs
python security_audit.py --verbose

# Custom output paths
python security_audit.py --output my_report.json --log my_audit.log

# Plain text — good for piping / logging
python security_audit.py --no-color | tee results.txt

# List all attack categories
python security_audit.py --list-categories
```

---

## Useful docker compose commands

```bash
docker compose logs -f                    # live backend logs
docker compose down                       # stop
docker compose down -v                    # stop + wipe database
docker compose up --build -d              # rebuild and restart
docker compose exec backend python seed.py
docker compose cp backend:/app/station_keys.json ./station_keys.json
```

---

## Attack Categories

| Category     | Attacks Included                                                  |
|--------------|-------------------------------------------------------------------|
| `signature`  | Random signature, wrong-key, post-sign ciphertext tamper, empty sig |
| `replay`     | Exact replay, re-signed replay                                    |
| `injection`  | Ghost station, extra candidate, malformed ciphertext, negative votes |
| `aggregation`| Homomorphic arithmetic correctness                                |
| `audit`      | SHA-256 hash chain integrity, rejected-event forensic coverage    |
| `timing`     | Signature verification timing oracle (side-channel)               |
| `access`     | Paillier private key exposure, officer key exposure, retention    |

---

## Output Files

| File                     | Description                                  |
|--------------------------|----------------------------------------------|
| `seas_audit_report.json` | Structured JSON report — all test results     |
| `seas_audit.log`         | Full debug log with timestamps and HTTP codes |

---

## Verdict Codes

| Icon | Verdict      | Meaning                                                     |
|------|--------------|-------------------------------------------------------------|
| ✅   | `DEFENDED`   | Attack was blocked — defence working as expected            |
| 🔴   | `VULNERABLE` | Attack succeeded — action required                          |
| ⚠️   | `WARNING`    | Partial or ambiguous — review recommended                   |
| 💀   | `ERROR`      | Test could not run (e.g. no eligible station key available) |

---

## Exit Codes

- `0` — All defences verified, no vulnerabilities found  
- `1` — One or more `VULNERABLE` results detected

This makes the tool scriptable in CI:
```bash
python security_audit.py && echo "PASS" || echo "SECURITY FAILURES DETECTED"
```
