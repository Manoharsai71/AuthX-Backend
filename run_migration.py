"""
Script to run the session history enhancement migration.
"""
import asyncio
import sys
import os

# Add the current directory to the path so we can import from app
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from app.migrations.session_history_enhancement import run_migration

if __name__ == "__main__":
    asyncio.run(run_migration())