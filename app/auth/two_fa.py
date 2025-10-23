from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta, timezone
import json
import secrets
import uuid

from models.refresh_token import RefreshToken
from models.session_history import SessionHistory
from utils.helpers import get_client_info, get_location_from_ip
from db.database import get_async_session
from models.user import User
from schemas.auth import (
    SessionInfo, TwoFASetupResponse, TwoFAVerify, TwoFADisable, MessageResponse
)
from core.security import (
    generate_otp_secret, generate_qr_code, verify_otp_code,
    get_current_user_from_token, verify_password, create_access_token, create_refresh_token
)

router = APIRouter()


def generate_backup_codes(count: int = 8) -> list:
    """Generate backup codes for 2FA."""
    codes = []
    for _ in range(count):
        code = f"{secrets.randbelow(100000):05d}-{secrets.randbelow(100000):05d}"
        codes.append(code)
    return codes


@router.post("/setup", response_model=TwoFASetupResponse)
async def setup_2fa(
    current_user: dict = Depends(get_current_user_from_token),
    db: AsyncSession = Depends(get_async_session)
):
    """Setup Two-Factor Authentication for user."""
    # Get user
    result = await db.execute(select(User).where(User.id == current_user["user_id"]))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if user.is_2fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is already enabled for this account"
        )

    # Generate TOTP secret
    secret = generate_otp_secret()

    # Generate QR code
    qr_code = generate_qr_code(secret, user.email)

    # Generate backup codes
    backup_codes = generate_backup_codes()

    # Store secret temporarily (not enabled yet)
    user.totp_secret = secret
    user.backup_codes = json.dumps(backup_codes)

    await db.commit()

    return {
        "secret": secret,
        "qr_code": qr_code,
        "backup_codes": backup_codes
    }


@router.post("/enable", response_model=MessageResponse)
async def enable_2fa(
    verify_data: TwoFAVerify,
    current_user: dict = Depends(get_current_user_from_token),
    db: AsyncSession = Depends(get_async_session)
):
    """Enable 2FA after verifying TOTP code."""
    # Get user
    result = await db.execute(select(User).where(User.id == current_user["user_id"]))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if user.is_2fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is already enabled"
        )

    if not user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA setup not initiated. Call /setup first"
        )

    # Verify TOTP code
    if not verify_otp_code(user.totp_secret, verify_data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP code"
        )

    # Enable 2FA
    user.is_2fa_enabled = True
    user.updated_at = datetime.now(timezone.utc)

    await db.commit()

    return {"message": "Two-Factor Authentication enabled successfully"}


# @router.post("/verify")
# async def verify_2fa(
#     verify_data: TwoFAVerify,
#     request: Request,
#     current_user: dict = Depends(get_current_user_from_token),
#     db: AsyncSession = Depends(get_async_session)
# ):
#     """Verify 2FA code during login or sensitive operations."""
#     from app.models.refresh_token import RefreshToken
#     from app.models.session_history import SessionHistory
#     from app.utils.helpers import get_client_info, get_location_from_ip

#     # Get user
#     result = await db.execute(select(User).where(User.id == current_user["user_id"]))
#     user = result.scalar_one_or_none()

#     if not user:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail="User not found"
#         )

#     if not user.is_2fa_enabled:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="2FA is not enabled for this account"
#         )

#     # Check if this is a 2FA verification request during login
#     is_login_verification = current_user.get("requires_2fa", False)

#     # Check if it's a backup code
#     if "-" in verify_data.code and user.backup_codes:
#         backup_codes = json.loads(user.backup_codes)
#         if verify_data.code in backup_codes:
#             # Remove used backup code
#             backup_codes.remove(verify_data.code)
#             user.backup_codes = json.dumps(backup_codes)
#         else:
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Invalid backup code"
#             )
#     else:
#         # Verify TOTP code
#         if not verify_otp_code(user.totp_secret, verify_data.code):
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Invalid TOTP code"
#             )

#     # Only create full tokens and session if this is a login verification
#     if is_login_verification:
#         # Create full access tokens after successful 2FA
#         access_token = create_access_token(data={"sub": str(user.id), "email": user.email})
#         refresh_token_str = create_refresh_token(data={"sub": str(user.id), "email": user.email})

#         # Get client info
#         client_info = get_client_info(request)

#         # Store refresh token
#         refresh_token = RefreshToken(
#             token=refresh_token_str,
#             user_id=user.id,
#             device_info=client_info.get("device_info"),
#             ip_address=client_info.get("ip_address"),
#             user_agent=client_info.get("user_agent"),
#             expires_at=datetime.now(timezone.utc) + timedelta(days=7)
#         )
#         db.add(refresh_token)

#         # Get location info
#         location_str, location_data = await get_location_from_ip(client_info.get("ip_address"))
#         device_details = client_info.get("device_details", {})
        
#         # Create session history with enhanced details
#         session_history = SessionHistory(
#             user_id=user.id,
#             session_id=str(uuid.uuid4()),
#             ip_address=client_info.get("ip_address"),
#             user_agent=client_info.get("user_agent"),
#             device_info=client_info.get("device_info"),
            
#             # Enhanced device details
#             browser_name=device_details.get("browser_name"),
#             browser_version=device_details.get("browser_version"),
#             os_name=device_details.get("os_name"),
#             os_version=device_details.get("os_version"),
#             device_type=device_details.get("device_type"),
#             device_brand=device_details.get("device_brand"),
#             device_model=device_details.get("device_model"),
            
#             # Enhanced location details
#             location=location_str,
#             country=location_data.get("country"),
#             city=location_data.get("city"),
#             region=location_data.get("region"),
#             timezone=location_data.get("timezone"),
#             location_data=location_data,
            
#             login_method="password_2fa"
#         )
#         db.add(session_history)

#         # Update last login
#         user.last_login = datetime.now(timezone.utc)

#         await db.commit()

#         return {
#             "access_token": access_token,
#             "refresh_token": refresh_token_str,
#             "token_type": "bearer",
#             "message": "2FA verification successful"
#         }
#     else:
#         # This is a general 2FA verification (not login)
#         await db.commit()
#         return {"message": "2FA code verified successfully"}


@router.post("/verify")
async def verify_2fa(
    verify_data: TwoFAVerify,
    request: Request,
    current_user: dict = Depends(get_current_user_from_token),
    db: AsyncSession = Depends(get_async_session),
):
    """Verify 2FA code during login or sensitive operations."""
    try:
        # --- Step 1: Fetch User ---
        result = await db.execute(select(User).where(User.id == current_user["user_id"]))
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        if not user.is_2fa_enabled:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is not enabled for this account")

        # --- Step 2: Determine if login verification ---
        is_login_verification = current_user.get("requires_2fa", False)

        # --- Step 3: Verify Code or Backup Code ---
        if "-" in verify_data.code and user.backup_codes:
            backup_codes = json.loads(user.backup_codes)
            if verify_data.code in backup_codes:
                backup_codes.remove(verify_data.code)
                user.backup_codes = json.dumps(backup_codes)
            else:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid backup code")
        else:
            if not verify_otp_code(user.totp_secret, verify_data.code):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code")

        # --- Step 4: Login verification flow ---
        if is_login_verification:
            try:
                # Create tokens
                access_token = create_access_token(data={"sub": str(user.id), "email": user.email})
                refresh_token_str = create_refresh_token(data={"sub": str(user.id), "email": user.email})

                # Get client info
                client_info = get_client_info(request)
                device_details = client_info.get("device_details", {})

                # Store refresh token
                refresh_token = RefreshToken(
                    token=refresh_token_str,
                    user_id=user.id,
                    device_info=client_info.get("device_info"),
                    ip_address=client_info.get("ip_address"),
                    user_agent=client_info.get("user_agent"),
                    expires_at=datetime.now(timezone.utc) + timedelta(days=7),
                )
                db.add(refresh_token)

                # Get location info safely
                try:
                    location_str, location_data = await get_location_from_ip(client_info.get("ip_address"))
                except Exception:
                    location_str, location_data = "Unknown", {}

                # --- Map directly to ORM fields ---
                session_history = SessionHistory(
                    user_id=user.id,
                    session_id=str(uuid.uuid4()),
                    ip_address=client_info.get("ip_address"),
                    user_agent=client_info.get("user_agent"),
                    device_type=device_details.get("device_type"),
                    device_brand=device_details.get("device_brand"),
                    device_model=device_details.get("device_model"),
                    browser_name=device_details.get("browser_name"),
                    browser_version=device_details.get("browser_version"),
                    os_name=device_details.get("os_name"),
                    os_version=device_details.get("os_version"),
                    location=location_str,
                    country=location_data.get("country"),
                    city=location_data.get("city"),
                    region=location_data.get("region"),
                    timezone=location_data.get("timezone"),
                    location_data=location_data,
                    login_method="password_2fa",
                    login_at=datetime.now(timezone.utc),
                    last_activity=datetime.now(timezone.utc),
                    is_active=True
                )
                db.add(session_history)

                # Update user's last login
                user.last_login = datetime.now(timezone.utc)

                await db.commit()

                return {
                    "access_token": access_token,
                    "refresh_token": refresh_token_str,
                    "token_type": "bearer",
                    "message": "2FA verification successful",
                }

            except Exception as e:
                await db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Login verification failed: {str(e)}"
                )

        else:
            # General 2FA verification (not login)
            await db.commit()
            return {"message": "2FA code verified successfully"}

    except HTTPException:
        # Known exceptions handled by FastAPI
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred: {str(e)}"
        )


@router.post("/disable", response_model=MessageResponse)
async def disable_2fa(
    disable_data: TwoFADisable,
    current_user: dict = Depends(get_current_user_from_token),
    db: AsyncSession = Depends(get_async_session)
):
    """Disable Two-Factor Authentication."""
    # Get user
    result = await db.execute(select(User).where(User.id == current_user["user_id"]))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if not user.is_2fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled for this account"
        )

    # Verify password
    if not user.hashed_password or not verify_password(disable_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password"
        )

    # Disable 2FA
    user.is_2fa_enabled = False
    user.totp_secret = None
    user.backup_codes = None
    user.updated_at = datetime.now(timezone.utc)

    await db.commit()

    return {"message": "Two-Factor Authentication disabled successfully"}


@router.get("/status")
async def get_2fa_status(
    current_user: dict = Depends(get_current_user_from_token),
    db: AsyncSession = Depends(get_async_session)
):
    """Get 2FA status for current user."""
    # Get user
    result = await db.execute(select(User).where(User.id == current_user["user_id"]))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    backup_codes_count = 0
    if user.backup_codes:
        backup_codes = json.loads(user.backup_codes)
        backup_codes_count = len(backup_codes)

    return {
        "is_2fa_enabled": user.is_2fa_enabled,
        "backup_codes_remaining": backup_codes_count
    }


@router.post("/regenerate-backup-codes")
async def regenerate_backup_codes(
    current_user: dict = Depends(get_current_user_from_token),
    db: AsyncSession = Depends(get_async_session)
):
    """Regenerate backup codes for 2FA."""
    # Get user
    result = await db.execute(select(User).where(User.id == current_user["user_id"]))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if not user.is_2fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled for this account"
        )

    # Generate new backup codes
    backup_codes = generate_backup_codes()
    user.backup_codes = json.dumps(backup_codes)
    user.updated_at = datetime.now(timezone.utc)

    await db.commit()

    return {
        "message": "Backup codes regenerated successfully",
        "backup_codes": backup_codes
    }