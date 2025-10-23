import asyncio
from fastapi_mail import FastMail, MessageSchema
from pydantic import EmailStr
from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/authx"
    
    # JWT
    SECRET_KEY: str = "your-super-secret-key-change-this-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Email Configuration
    MAIL_USERNAME: str = "manoharsaiambati@gmail.com"
    MAIL_PASSWORD: str = "pyuwvgepzkinuurw"  # App Password
    MAIL_FROM: str = "manoharsaiambati@gmail.com"
    MAIL_PORT: int = 587
    MAIL_SERVER: str = "smtp.gmail.com"
    MAIL_FROM_NAME: str = "AuthX"
    MAIL_STARTTLS: bool = True
    MAIL_SSL_TLS: bool = False
    USE_CREDENTIALS: bool = True
    VALIDATE_CERTS: bool = True

    
    # OAuth
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    
    # Frontend
    FRONTEND_URL: str = "http://localhost:3000"
    FRONTEND_URL_IP: str = "http://192.168.0.11:3000"
    
    # OTP Settings
    OTP_EXPIRE_MINUTES: int = 10
    MAGIC_LINK_EXPIRE_MINUTES: int = 15
    
    # Session Settings
    MAX_SESSIONS_PER_USER: int = 5
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()