#!/usr/bin/env python3
"""
Debug script to test session functionality
"""
import asyncio
import sys
import os

# Add the app directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from db.database import async_session_maker
from models.user import User
from models.session_history import SessionHistory

async def debug_sessions():
    """Debug session information"""
    async with async_session_maker() as db:
        try:
            # Get all users
            users_result = await db.execute(select(User))
            users = users_result.scalars().all()
            print(f"📊 Total users in database: {len(users)}")
            
            for user in users:
                print(f"\n👤 User: {user.email} (ID: {user.id})")
                print(f"   Active: {user.is_active}, Verified: {user.is_verified}")
                
                # Get sessions for this user
                sessions_result = await db.execute(
                    select(SessionHistory).where(SessionHistory.user_id == user.id)
                    .order_by(SessionHistory.login_at.desc())
                )
                sessions = sessions_result.scalars().all()
                print(f"   Total sessions: {len(sessions)}")
                
                for session in sessions:
                    print(f"   📱 Session {session.session_id[:8]}...")
                    print(f"      Active: {session.is_active}")
                    print(f"      Login: {session.login_at}")
                    print(f"      Method: {session.login_method}")
                    print(f"      Device: {session.device_type} ({session.device_brand} {session.device_model})")
                    print(f"      IP: {session.ip_address}")
                    print(f"      Location: {session.location}")
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    print("🔍 Debugging session information...")
    asyncio.run(debug_sessions())