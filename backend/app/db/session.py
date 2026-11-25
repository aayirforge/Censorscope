"""
backend/app/db/session.py
Database connection configuration and session dependencies.
Supports PostgreSQL async engine and sync fallback for migrations/tests.
"""

import os

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import sessionmaker

# Database URL from environment
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://censorscope_user:censorscope_local_secret_change_me@localhost:5435/censorscope_db",
)

# Convert sync URL for Alembic or psycopg2 if needed
SYNC_DATABASE_URL = os.getenv(
    "SYNC_DATABASE_URL",
    DATABASE_URL.replace("postgresql+asyncpg://", "postgresql+psycopg2://").replace(
        "sqlite+aiosqlite://", "sqlite://"
    ),
)

# Create engines with graceful pool settings
connect_args = {}
if "sqlite" in DATABASE_URL:
    connect_args["check_same_thread"] = False

async_engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    connect_args=connect_args,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

sync_engine = create_engine(
    SYNC_DATABASE_URL,
    echo=False,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SyncSessionLocal = sessionmaker(
    bind=sync_engine,
    autocommit=False,
    autoflush=False,
)


async def get_db():
    """FastAPI async dependency yielding database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
