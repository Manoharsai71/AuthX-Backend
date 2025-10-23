"""
Database initialization script.
Run this to create all tables and initial data.
"""
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from app.core.config import settings
from app.models.base import Base
from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.models.session_history import SessionHistory
from app.models.otp_code import OTPCode
from app.models.magic_link import MagicLink


async def init_db():
    """Initialize database with all tables."""
    engine = create_async_engine(settings.DATABASE_URL, echo=True)
    
    async with engine.begin() as conn:
        # Drop all tables (be careful in production!)
        await conn.run_sync(Base.metadata.drop_all)
        
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)
    
    await engine.dispose()
    print("Database initialized successfully!")


if __name__ == "__main__":
    asyncio.run(init_db())