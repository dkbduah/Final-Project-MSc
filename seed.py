"""
SEAS Seed Script – Populate the database with Ghana election simulation data.

Creates:
  - 5 of Ghana's 16 administrative regions
  - 10 constituencies spread across those regions
  - 50 polling stations (10 per region, 5 per constituency)
  - 1 active election: "2024 Ghana Presidential Election"
  - 3 candidates: NDC, NPP, Independent

Run: python seed.py
"""

import asyncio
import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from sqlalchemy.ext.asyncio import AsyncSession
from app.db.database import init_db, AsyncSessionLocal
from app.db.models import Region, Constituency, PollingStation, Election, Candidate
from app.crypto.paillier import generate_keypair
from app.crypto.signatures import generate_ed25519_keypair

REGIONS = [
    {"name": "Greater Accra", "region_code": "GA"},
    {"name": "Ashanti", "region_code": "ASH"},
    {"name": "Northern", "region_code": "NOR"},
    {"name": "Western", "region_code": "WES"},
    {"name": "Eastern", "region_code": "EAS"},
]

CONSTITUENCIES = [
    {"name": "Ablekuma Central", "code": "GA-001", "region_code": "GA"},
    {"name": "Ayawaso East", "code": "GA-002", "region_code": "GA"},
    {"name": "Kumasi Central", "code": "ASH-001", "region_code": "ASH"},
    {"name": "Oforikrom", "code": "ASH-002", "region_code": "ASH"},
    {"name": "Tamale Central", "code": "NOR-001", "region_code": "NOR"},
    {"name": "Savelugu", "code": "NOR-002", "region_code": "NOR"},
    {"name": "Sekondi", "code": "WES-001", "region_code": "WES"},
    {"name": "Takoradi", "code": "WES-002", "region_code": "WES"},
    {"name": "Koforidua", "code": "EAS-001", "region_code": "EAS"},
    {"name": "New Juaben", "code": "EAS-002", "region_code": "EAS"},
]

CANDIDATES = [
    {"name": "John Kwame Mensah", "party": "National Democratic Congress (NDC)", "code": "NDC"},
    {"name": "Akosua Prempeh", "party": "New Patriotic Party (NPP)", "code": "NPP"},
    {"name": "Kofi Asante Boateng", "party": "Independent", "code": "IND"},
]


async def seed() -> None:
    """Execute all seed operations within a single database session."""
    await init_db()

    async with AsyncSessionLocal() as db:
        # Regions
        region_map = {}
        for r in REGIONS:
            region = Region(name=r["name"], region_code=r["region_code"])
            db.add(region)
        await db.flush()

        # Rebuild region map after flush
        from sqlalchemy import select
        region_result = await db.execute(select(Region))
        for region in region_result.scalars().all():
            region_map[region.region_code] = region.id

        # Constituencies
        const_map = {}
        for c in CONSTITUENCIES:
            const = Constituency(
                name=c["name"],
                constituency_code=c["code"],
                region_id=region_map[c["region_code"]],
            )
            db.add(const)
        await db.flush()

        const_result = await db.execute(select(Constituency))
        for const in const_result.scalars().all():
            const_map[const.constituency_code] = const.id

        # Polling stations – 5 per constituency
        station_keys = {}  # station_code -> (pub_key, priv_key)
        station_num = 1
        for c_code, c_id in const_map.items():
            for i in range(1, 6):
                priv_b64, pub_b64 = generate_ed25519_keypair()
                s_code = f"{c_code}-PS{i:03d}"
                station = PollingStation(
                    name=f"Polling Station {station_num}",
                    station_code=s_code,
                    constituency_id=c_id,
                    registered_voters=500 + (station_num * 17 % 1000),
                    officer_name=f"Officer {station_num:03d}",
                    officer_public_key=pub_b64,
                    officer_private_key=priv_b64,
                )
                db.add(station)
                station_keys[s_code] = (pub_b64, priv_b64)
                station_num += 1

        # Election
        print("Generating 2048-bit Paillier keypair (may take a few seconds)...")
        pub_dict, priv_dict = generate_keypair(key_size=2048)
        election = Election(
            title="2024 Ghana Presidential Election",
            election_date="2024-12-07",
            status="active",
            paillier_public_key=json.dumps(pub_dict),
            paillier_private_key=json.dumps(priv_dict),
        )
        db.add(election)
        await db.flush()

        for cand in CANDIDATES:
            db.add(
                Candidate(
                    election_id=election.id,
                    name=cand["name"],
                    party=cand["party"],
                    candidate_code=cand["code"],
                )
            )

        await db.commit()
        print(f"✅ Seeded: {len(REGIONS)} regions, {len(CONSTITUENCIES)} constituencies, "
              f"{station_num - 1} polling stations, 1 election, {len(CANDIDATES)} candidates.")
        print(f"   Election ID: {election.id}")
        print(f"   Paillier public key n[:40]: {pub_dict['n'][:40]}...")

        # Write station keys to file for Locust load testing
        with open("station_keys.json", "w") as f:
            json.dump(station_keys, f)
        print("   Station keys written to station_keys.json for Locust.")


if __name__ == "__main__":
    asyncio.run(seed())
