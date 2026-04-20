"""
SEAS – Secure Election Aggregation System
FastAPI application entry point.

Wires together all routers, middleware, and lifecycle handlers.
"""

import logging
import logging.config
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db.database import init_db
from app.api.routes import elections, polling, aggregation, verification, audit, websocket

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(name)s – %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "stream": "ext://sys.stdout",
        },
    },
    "loggers": {
        "seas": {
            "handlers": ["console"],
            "level": "DEBUG" if settings.DEBUG else "INFO",
            "propagate": False,
        },
        "uvicorn.access": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "WARNING",
    },
}

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("seas.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise the database schema on startup."""
    logger.info(
        "SEAS starting up | version=%s debug=%s db=%s",
        settings.APP_VERSION, settings.DEBUG, settings.DATABASE_URL,
    )
    await init_db()
    logger.info("Database initialised successfully")
    yield
    logger.info("SEAS shutting down")


app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Cryptography-based framework using Paillier homomorphic encryption "
        "and Ed25519 digital signatures for secure, verifiable election results "
        "aggregation across Ghana's four-tier administrative hierarchy."
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# REST routers
app.include_router(elections.router,    prefix="/api/elections",    tags=["Elections"])
app.include_router(polling.router,      prefix="/api/polling",      tags=["Polling"])
app.include_router(aggregation.router,  prefix="/api/aggregation",  tags=["Aggregation"])
app.include_router(verification.router, prefix="/api/verification", tags=["Verification"])
app.include_router(audit.router,        prefix="/api/audit",        tags=["Audit"])

# WebSocket router
app.include_router(websocket.router, prefix="/ws", tags=["WebSocket"])


@app.get("/health", tags=["Health"])
async def health_check() -> dict:
    """Liveness probe endpoint for Docker health checks."""
    return {"status": "healthy", "service": "SEAS Backend", "version": settings.APP_VERSION}