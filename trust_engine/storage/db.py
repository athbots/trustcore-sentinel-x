import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from datetime import datetime

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/trustcore")

engine = create_async_engine(DATABASE_URL, echo=False, pool_size=20, max_overflow=10)
AsyncSessionFactory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()

class UserBehaviorLog(Base):
    """Stores historical behavioral actions for time-based/anomaly stateful analysis"""
    __tablename__ = "user_behavior_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(50), index=True)
    device_id = Column(String(100))
    ip_address = Column(String(50))
    action = Column(String(50), index=True)
    metadata_json = Column(JSON, default={})
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

class DeviceTrustState(Base):
    """Tracks long-term device state and decay"""
    __tablename__ = "device_trust_states"
    
    device_id = Column(String(100), primary_key=True)
    user_id = Column(String(50), index=True)
    last_seen = Column(DateTime, default=datetime.utcnow)
    trust_score_penalty = Column(Float, default=0.0)
    is_compromised = Column(Integer, default=0)

async def init_db():
    """Create all tables in the database"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
async def get_db_session() -> AsyncSession:
    """Dependency for providing a session"""
    async with AsyncSessionFactory() as session:
        yield session
