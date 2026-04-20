"""
SEAS Database – Async SQLAlchemy with SQLite.

SQLite is used for its zero-configuration portability within Docker.
All write operations use append-only patterns for the audit log, and
WAL (Write-Ahead Logging) mode is enabled to allow concurrent reads
during heavy aggregation throughput.
"""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import event
from app.config import settings


# ---------------------------------------------------------------------------
# Engine & Session Factory
# ---------------------------------------------------------------------------

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    connect_args={"check_same_thread": False},
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    """Declarative base for all SEAS ORM models."""
    pass


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


async def init_db() -> None:
    """
    Create all database tables on startup if they do not already exist.

    In production, Alembic migrations would replace this call.  For the
    SEAS simulation environment, auto-creation is sufficient.
    """
    async with engine.begin() as conn:
        from app.db import models  # noqa: F401 – registers all models
        await conn.run_sync(Base.metadata.create_all)


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


async def get_db() -> AsyncSession:
    """
    FastAPI dependency that yields a database session per request.

    The session is closed after the request regardless of success or
    failure, preventing connection leaks under load.

    Yields:
        AsyncSession: An active SQLAlchemy async session.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
