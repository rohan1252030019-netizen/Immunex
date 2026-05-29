import os
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base

from utils.logger import log

# Retrieve database URL from environment, fallback dynamically to local docker container preset
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql+asyncpg://immunex_admin:secure_banking_password@localhost:5432/immunex_db"
)

# Initialize SQLAlchemy async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=20,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=1800
)

# Async sessionmaker pool
async_session_pool = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()

async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency provider for scoping async db sessions in FastAPI routes."""
    async with async_session_pool() as session:
        try:
            yield session
            await session.commit()
        except Exception as exc:
            await session.rollback()
            log.error("Postgres Transaction Rollback", exc_info=exc)
            raise
        finally:
            await session.close()
