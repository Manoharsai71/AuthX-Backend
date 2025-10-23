import sys
import os
sys.path.append('app')

from app.core.config import settings

print("Testing configuration...")
print(f"DATABASE_URL: {settings.DATABASE_URL}")
print(f"SECRET_KEY: {settings.SECRET_KEY[:20]}...")
print(f"REDIS_URL: {settings.REDIS_URL}")
print(f"FRONTEND_URL: {settings.FRONTEND_URL}")