from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta, timezone
import uuid

from db.database import get_async_session
from models.user import User
from models.magic_link import MagicLink
from models.refresh_token import RefreshToken
from models.session_history import SessionHistory
from models.otp_code import OTPCode
from schemas.auth import (
    MagicLinkRequest, MagicLinkResponse, MagicLinkVerify, Token,
    OTPRequest, OTPVerify, OTPResponse, MessageResponse
)
from core.security import (
    generate_magic_token, generate_email_otp, create_access_token,
    create_refresh_token
)
from core.config import settings
from core.email_utils import email_manager
from utils.helpers import get_client_info, get_location_from_ip

router = APIRouter()


@router.post("/send-link", response_model=MagicLinkResponse)
async def send_magic_link(
    request_data: MagicLinkRequest,
    request: Request,
    db: AsyncSession = Depends(get_async_session)
):
    """Send magic link to user's email."""
    try:
        # Check if user exists
        result = await db.execute(select(User).where(User.email == request_data.email))
        user = result.scalar_one_or_none()
        
        if not user:
            # For security, don't reveal if email exists
            return {
                "message": "If the email exists, a magic link has been sent",
                "expires_in": settings.MAGIC_LINK_EXPIRE_MINUTES * 60
            }
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is deactivated"
            )
        
        # Generate magic token
        token = generate_magic_token()
        
        # Get client info
        client_info = get_client_info(request)
        
        # Check for existing magic links and invalidate them
        result = await db.execute(
            select(MagicLink).where(
                MagicLink.user_id == user.id,
                MagicLink.is_used == False,
                MagicLink.purpose == "login"
            )
        )
        existing_links = result.scalars().all()
        
        for link in existing_links:
            link.is_used = True
        
        # Store magic link
        magic_link = MagicLink(
            user_id=user.id,
            token=token,
            purpose="login",
            ip_address=client_info.get("ip_address"),
            user_agent=client_info.get("user_agent"),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.MAGIC_LINK_EXPIRE_MINUTES)
        )
        
        db.add(magic_link)
        await db.commit()
        
        # Create magic link URL
        magic_link_url = f"{settings.FRONTEND_URL}/auth/magic-link/verify?token={token}"
        
        # Send email
        email_sent = await email_manager.send_magic_link_email(
            email=user.email,
            magic_link=magic_link_url,
            user_name=user.full_name or user.username or "User"
        )
        
        if not email_sent:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send magic link email"
            )
        
        return {
            "message": "Magic link sent to your email",
            "expires_in": settings.MAGIC_LINK_EXPIRE_MINUTES * 60
        }
        
    except HTTPException:
        # Re-raise HTTP exceptions as they are already properly formatted
        raise
        
    except Exception as e:
        print(f"Error in send_magic_link: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # Provide a more user-friendly error message
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while sending the magic link. Please try again later."
        )


@router.post("/verify-link", response_model=Token)
async def verify_magic_link(
    verify_data: MagicLinkVerify,
    request: Request,
    db: AsyncSession = Depends(get_async_session)
):
    """Verify magic link and authenticate user."""
    try:
        print(f"Verifying magic link token: {verify_data.token}")
        
        # Find magic link
        result = await db.execute(
            select(MagicLink).where(
                MagicLink.token == verify_data.token,
                MagicLink.is_used == False
            )
        )
        magic_link = result.scalar_one_or_none()
        print(f"Magic link found: {magic_link is not None}")
        
        if not magic_link:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired magic link"
            )
        
        # Check if expired
        if magic_link.expires_at < datetime.now(timezone.utc):
            # Mark as used to prevent reuse of expired links
            magic_link.is_used = True
            await db.commit()
            
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Magic link has expired"
            )
        
        # Get user
        result = await db.execute(select(User).where(User.id == magic_link.user_id))
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
            
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is deactivated"
            )
        
        # Mark magic link as used
        magic_link.is_used = True
        magic_link.used_at = datetime.now(timezone.utc)
        
        # Create tokens
        access_token = create_access_token(data={"sub": str(user.id), "email": user.email})
        refresh_token_str = create_refresh_token(data={"sub": str(user.id), "email": user.email})
        
        # Get client info
        client_info = get_client_info(request)
        
        # Store refresh token
        refresh_token = RefreshToken(
            token=refresh_token_str,
            user_id=user.id,
            ip_address=client_info.get("ip_address"),
            user_agent=client_info.get("user_agent"),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7)
        )
        db.add(refresh_token)
        
        # Get location info
        location_str, location_data = await get_location_from_ip(client_info.get("ip_address"))
        device_details = client_info.get("device_details", {})
        
        # Create session history with enhanced details
        session_history = SessionHistory(
            user_id=user.id,
            session_id=str(uuid.uuid4()),
            ip_address=client_info.get("ip_address"),
            user_agent=client_info.get("user_agent"),
            
            # Enhanced device details
            browser_name=device_details.get("browser_name"),
            browser_version=device_details.get("browser_version"),
            os_name=device_details.get("os_name"),
            os_version=device_details.get("os_version"),
            device_type=device_details.get("device_type"),
            device_brand=device_details.get("device_brand"),
            device_model=device_details.get("device_model"),
            
            # Enhanced location details
            location=location_str,
            country=location_data.get("country"),
            city=location_data.get("city"),
            region=location_data.get("region"),
            timezone=location_data.get("timezone"),
            location_data=location_data,
            
            login_method="magic_link"
        )
        db.add(session_history)
        
        # Update last login
        user.last_login = datetime.now(timezone.utc)
        user.is_verified = True  # Magic link confirms email ownership
        
        await db.commit()
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token_str,
            "token_type": "bearer"
        }
    
    except HTTPException:
        # Re-raise HTTP exceptions as they are already properly formatted
        raise
        
    except Exception as e:
        print(f"Error in verify_magic_link: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # Provide a more user-friendly error message
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while verifying the magic link. Please try again or request a new link."
        )


@router.post("/send-otp", response_model=OTPResponse)
async def send_email_otp(
    request_data: OTPRequest,
    request: Request,
    db: AsyncSession = Depends(get_async_session)
):
    """Send OTP code to user's email."""
    # Check if user exists
    result = await db.execute(select(User).where(User.email == request_data.email))
    user = result.scalar_one_or_none()
    
    if not user:
        # For security, don't reveal if email exists
        return {
            "message": "If the email exists, an OTP has been sent",
            "expires_in": settings.OTP_EXPIRE_MINUTES * 60
        }
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is deactivated"
        )
    
    # Generate OTP
    otp_code = str(generate_email_otp())
    
    # Store OTP
    otp = OTPCode(
        user_id=user.id,
        code=otp_code,
        purpose="login",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)
    )
    
    db.add(otp)
    await db.commit()
    
    # Send email
    email_sent = await email_manager.send_otp_email(
        email=user.email,
        otp_code=otp_code,
        user_name=user.full_name or user.username or "User"
    )
    
    if not email_sent:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send OTP email"
        )
    
    return {
        "message": "OTP sent to your email",
        "expires_in": settings.OTP_EXPIRE_MINUTES * 60
    }


# @router.post("/verify-otp", response_model=Token)
# async def verify_email_otp(
#     verify_data: OTPVerify,
#     request: Request,
#     db: AsyncSession = Depends(get_async_session)
# ):
#     """Verify OTP code and authenticate user."""
#     try:
#         # Get user
#         result = await db.execute(select(User).where(User.email == verify_data.email))
#         user = result.scalar_one_or_none()
        
#         if not user:
#             raise HTTPException(
#                 status_code=status.HTTP_404_NOT_FOUND,
#                 detail="User not found"
#             )
            
#         if not user.is_active:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="User account is deactivated"
#             )
        
#         # Find valid OTP
#         result = await db.execute(
#             select(OTPCode).where(
#                 OTPCode.user_id == user.id,
#                 OTPCode.code == verify_data.code,
#                 OTPCode.purpose == "login",
#                 OTPCode.is_used == False,
#                 OTPCode.expires_at > datetime.now(timezone.utc)
#             ).order_by(OTPCode.created_at.desc())
#         )
#         otp = result.scalar_one_or_none()
        
#         if not otp:
#             # Increment attempts for rate limiting
#             result = await db.execute(
#                 select(OTPCode).where(
#                     OTPCode.user_id == user.id,
#                     OTPCode.purpose == "login",
#                     OTPCode.is_used == False
#                 ).order_by(OTPCode.created_at.desc())
#             )
#             latest_otp = result.scalar_one_or_none()
            
#             if latest_otp:
#                 latest_otp.attempts += 1
#                 if latest_otp.attempts >= latest_otp.max_attempts:
#                     latest_otp.is_used = True
#                 await db.commit()
            
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Invalid or expired OTP code"
#             )
        
#         # Mark OTP as used
#         otp.is_used = True
#         otp.used_at = datetime.now(timezone.utc)
        
#         # Create tokens
#         access_token = create_access_token(data={"sub": str(user.id), "email": user.email})
#         refresh_token_str = create_refresh_token(data={"sub": str(user.id), "email": user.email})
        
#         # Get client info
#         client_info = get_client_info(request)
        
#         # Store refresh token
#         refresh_token = RefreshToken(
#             token=refresh_token_str,
#             user_id=user.id,
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
            
#             login_method="email_otp"
#         )
#         db.add(session_history)
        
#         # Update last login
#         user.last_login = datetime.now(timezone.utc)
#         user.is_verified = True  # OTP confirms email ownership
        
#         await db.commit()
        
#         return {
#             "access_token": access_token,
#             "refresh_token": refresh_token_str,
#             "token_type": "bearer"
#         }
        
#     except HTTPException:
#         # Re-raise HTTP exceptions as they are already properly formatted
#         raise
        
#     except Exception as e:
#         print(f"Error in verify_email_otp: {str(e)}")
#         import traceback
#         traceback.print_exc()
        
#         # Provide a more user-friendly error message
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="An error occurred while verifying the OTP code. Please try again or request a new code."
#         )



@router.post("/verify-otp", response_model=Token)
async def verify_email_otp(
    verify_data: OTPVerify,
    request: Request,
    db: AsyncSession = Depends(get_async_session)
):
    """Verify OTP code and log in the user if OTP is correct."""
    try:
        # 1️⃣ Get user by email
        result = await db.execute(select(User).where(User.email == verify_data.email))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account is deactivated")

        # 2️⃣ Find valid OTP
        result = await db.execute(
            select(OTPCode)
            .where(
                OTPCode.user_id == user.id,
                OTPCode.code == verify_data.code,
                OTPCode.purpose == "login",
                OTPCode.is_used == False,
                OTPCode.expires_at > datetime.now(timezone.utc)
            )
            .order_by(OTPCode.created_at.desc())
        )
        otp = result.scalar_one_or_none()
        if not otp:
            # Increment attempts for rate-limiting
            result = await db.execute(
                select(OTPCode)
                .where(
                    OTPCode.user_id == user.id,
                    OTPCode.purpose == "login",
                    OTPCode.is_used == False
                )
                .order_by(OTPCode.created_at.desc())
            )
            latest_otp = result.scalar_one_or_none()
            if latest_otp:
                latest_otp.attempts += 1
                if latest_otp.attempts >= latest_otp.max_attempts:
                    latest_otp.is_used = True
                await db.commit()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP code")

        # 3️⃣ Mark OTP as used
        otp.is_used = True
        otp.used_at = datetime.now(timezone.utc)

        # 4️⃣ Generate tokens
        access_token = create_access_token(data={"sub": str(user.id), "email": user.email})
        refresh_token_str = create_refresh_token(data={"sub": str(user.id), "email": user.email})

        # 5️⃣ Get client info
        client_info = get_client_info(request)
        device_details = client_info.get("device_details", {})

        # 6️⃣ Store refresh token
        refresh_token = RefreshToken(
            token=refresh_token_str,
            user_id=user.id,
            ip_address=client_info.get("ip_address"),
            user_agent=client_info.get("user_agent"),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7)
        )
        db.add(refresh_token)

        # 7️⃣ Store session history
        try:
            location_str, location_data = await get_location_from_ip(client_info.get("ip_address"))
        except:
            location_str = "Unknown"
            location_data = {}

        session_history = SessionHistory(
            user_id=user.id,
            session_id=str(uuid.uuid4()),
            ip_address=client_info.get("ip_address"),
            user_agent=client_info.get("user_agent"),
            browser_name=device_details.get("browser_name"),
            browser_version=device_details.get("browser_version"),
            os_name=device_details.get("os_name"),
            os_version=device_details.get("os_version"),
            device_type=device_details.get("device_type"),
            device_brand=device_details.get("device_brand"),
            device_model=device_details.get("device_model"),
            location=location_str,
            country=location_data.get("country"),
            city=location_data.get("city"),
            region=location_data.get("region"),
            timezone=location_data.get("timezone"),
            location_data=location_data,
            login_method="email_otp"
        )
        db.add(session_history)

        # 8️⃣ Update user info
        user.last_login = datetime.now(timezone.utc)
        user.is_verified = True

        await db.commit()

        # 9️⃣ Return tokens
        return {
            "access_token": access_token,
            "refresh_token": refresh_token_str,
            "token_type": "bearer"
        }

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while verifying the OTP code. Please try again."
        )
