#!/usr/bin/env python3
"""
Database update script to add new tables for email verification and password reset.
"""

import asyncio
import sys
import os

# Add the app directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from sqlalchemy.ext.asyncio import create_async_engine
from models.base import Base
from models.user import User
from models.refresh_token import RefreshToken
from models.session_history import SessionHistory
from models.otp_code import OTPCode
from models.magic_link import MagicLink
from models.email_verification import EmailVerificationToken
from models.password_reset import PasswordResetToken
from core.config import settings

async def update_database():
    """Create new tables if they don't exist."""
    engine = create_async_engine(settings.DATABASE_URL, echo=True)

    async with engine.begin() as conn:
        # Create all tables (will only create new ones)
        await conn.run_sync(Base.metadata.create_all)

    await engine.dispose()
    print("✅ Database updated successfully!")

if __name__ == "__main__":
    asyncio.run(update_database())