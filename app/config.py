"""
SEAS Application Configuration.

All configurable parameters are defined here using Pydantic Settings,
allowing environment variable overrides for different deployment stages.
"""

from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    """Central configuration for the SEAS backend."""

    # App
    APP_NAME: str = "SEAS – Secure Election Aggregation System"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",   # Polling station frontend (dev)
        "http://localhost:5174",   # Verification frontend (dev)
        "http://localhost:3000",
        "http://frontend-polling:5173",
        "http://frontend-verification:5174",
    ]

    # Database (SQLite for portability in Docker)
    DATABASE_URL: str = "sqlite+aiosqlite:///./seas.db"

    # Paillier key size (bits) – 2048 for production-grade security
    PAILLIER_KEY_SIZE: int = 2048

    # JWT / Auth (for officer login)
    SECRET_KEY: str = "seas-dev-secret-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8-hour polling day session

    # Ghana administrative tiers
    TIERS: List[str] = ["polling_station", "constituency", "region", "national"]

    class Config:
        env_file = ".env"


settings = Settings()
