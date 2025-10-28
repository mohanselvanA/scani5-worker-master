from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
    AsyncAttrs,
)
from sqlalchemy.orm import declarative_base
from app.config.config import settings
from typing import Annotated, AsyncIterator
from fastapi import Depends
from sqlalchemy.exc import SQLAlchemyError
import logging

logger = logging.getLogger(__name__)

# ----------------------------
# Worker DB Setup
# ----------------------------

WORKER_DB_URL = (
    f"postgresql+asyncpg://{settings.WORKER_DB_USER}:{settings.WORKER_DB_PASSWORD}"
    f"@{settings.WORKER_DB_HOST}:{settings.WORKER_DB_PORT}/{settings.WORKER_DB}"
)

async_worker_engine = create_async_engine(
    WORKER_DB_URL,
    echo=False,
    pool_pre_ping=True,
)

AsyncWorkerSessionLocal = async_sessionmaker(
    bind=async_worker_engine,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)

BaseWorker = declarative_base(cls=AsyncAttrs)

async def get_worker_session() -> AsyncIterator[AsyncSession]:
    async with AsyncWorkerSessionLocal() as session:
        try:
            yield session
        except SQLAlchemyError as e:
            logger.exception("Worker DB session error: %s", e)
            raise

AsyncWorkerDBSession = Annotated[AsyncSession, Depends(get_worker_session)]


# ----------------------------
# NVD DB Setup 
# ----------------------------

NVD_DB_URL = (
    f"postgresql+asyncpg://{settings.NVD_DB_USER}:{settings.NVD_DB_PASSWORD}"
    f"@{settings.NVD_DB_HOST}:{settings.NVD_DB_PORT}/{settings.NVD_DB}"
)

async_nvd_engine = create_async_engine(
    NVD_DB_URL,
    echo=False,
    pool_pre_ping=True,
)

AsyncNVDSessionLocal = async_sessionmaker(
    bind=async_nvd_engine,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)

BaseNVD = declarative_base(cls=AsyncAttrs)

async def get_nvd_session() -> AsyncIterator[AsyncSession]:
    async with AsyncNVDSessionLocal() as session:
        try:
            yield session
        except SQLAlchemyError as e:
            logger.exception("NVD DB session error: %s", e)
            raise

AsyncNVDSession = Annotated[AsyncSession, Depends(get_nvd_session)]
