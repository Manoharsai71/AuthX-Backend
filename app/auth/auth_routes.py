from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta, timezone
import uuid

from db.database import get_async_session
from models.user import User
from models.refresh_token import RefreshToken
from models.session_history import SessionHistory
from models.email_verification import EmailVerificationToken
from models.password_reset import PasswordResetToken
from schemas.auth import (
    SessionInfo, UserCreate, UserLogin, UserResponse, TokenRefresh, 
    AccessToken, MessageResponse, PasswordChange, SessionHistory as SessionHistorySchema,
    LoginResponse, EmailVerificationRequest,
    EmailVerificationVerify, UserUpdate, ForgotPasswordRequest, ForgotPasswordVerify,
    CurrentSessionInfo
)
from core.security import (
    verify_password, get_password_hash, create_access_token, 
    create_refresh_token, verify_token, get_current_user_from_token
)
from core.email_utils import email_manager
from core.config import settings
from utils.helpers import get_client_info, get_location_from_ip

router = APIRouter()


# @router.post("/register", response_model=UserResponse)
# async def register(
#     user_data: UserCreate,
#     request: Request,
#     db: AsyncSession = Depends(get_async_session)
# ):
#     """Register a new user."""
#     # Check if user already exists
#     result = await db.execute(select(User).where(User.email == user_data.email))
#     if result.scalar_one_or_none():
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail="Email already registered"
#         )

#     # Check username if provided
#     if user_data.username:
#         result = await db.execute(select(User).where(User.username == user_data.username))
#         if result.scalar_one_or_none():
#             raise HTTPException(
#                 status_code=status.HTTP_400_BAD_REQUEST,
#                 detail="Username already taken"
#             )

#     # Create new user
#     hashed_password = get_password_hash(user_data.password)
#     db_user = User(
#         email=user_data.email,
#         username=user_data.username,
#         full_name=user_data.full_name,
#         hashed_password=hashed_password,
#         is_verified=False  # Require email verification
#     )

#     db.add(db_user)
#     await db.commit()
#     await db.refresh(db_user)

#     # Generate email verification token
#     token = str(uuid.uuid4())
#     expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

#     verification_token = EmailVerificationToken(
#         user_id=db_user.id,
#         token=token,
#         email=db_user.email,
#         expires_at=expires_at
#     )
#     db.add(verification_token)
#     await db.commit()

#     # Send verification email instead of welcome email
#     verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
#     await email_manager.send_email_verification(
#         email=db_user.email,
#         verification_url=verification_url,
#         user_name=db_user.full_name or db_user.username or "User"
#     )

#     return db_user


@router.post("/register", response_model=UserResponse)
async def register(
    user_data: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_async_session)
):
    """Register a new user."""

    # Check if email already exists
    result = await db.execute(select(User).where(User.email == user_data.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Check if username is taken
    if user_data.username:
        result = await db.execute(select(User).where(User.username == user_data.username))
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken"
            )

    # Create new user
    hashed_password = get_password_hash(user_data.password)
    db_user = User(
        email=user_data.email,
        username=user_data.username,
        full_name=user_data.full_name,
        hashed_password=hashed_password,
        is_verified=False
    )

    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)

    # Generate email verification token
    token = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
    verification_token = EmailVerificationToken(
        user_id=db_user.id,
        token=token,
        email=db_user.email,
        expires_at=expires_at
    )
    db.add(verification_token)
    await db.commit()

    # Verification URL
    verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"

    # Debug: print credentials being used
    print("Attempting to send verification email using:")
    print("MAIL_USERNAME:", settings.MAIL_USERNAME)
    print("MAIL_PASSWORD:", settings.MAIL_PASSWORD[:4] + "****")  # hide full password

    # Send email
    try:
        sent = await email_manager.send_email_verification(
            email=db_user.email,
            verification_url=verification_url,
            user_name=db_user.full_name or db_user.username or "User"
        )
        if not sent:
            print("⚠️  Email verification could not be sent. Check SMTP credentials.")
    except Exception as e:
        print(f"⚠️  Exception when sending email: {e}")

    return db_user


@router.post("/login", response_model=LoginResponse)
async def login(
    user_credentials: UserLogin,
    request: Request,
    db: AsyncSession = Depends(get_async_session)
):
    """Authenticate user and return tokens."""
    try:
        print(f"Login attempt for email: {user_credentials.email}")
        
        # Get user
        result = await db.execute(select(User).where(User.email == user_credentials.email))
        user = result.scalar_one_or_none()

        if not user or not verify_password(user_credentials.password, user.hashed_password):
            print(f"Login failed: Incorrect email or password for {user_credentials.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )

        if not user.is_active:
            print(f"Login failed: Account is deactivated for {user_credentials.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is deactivated"
            )

        if not user.is_verified:
            print(f"Login failed: Email not verified for {user_credentials.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Please verify your email address before logging in"
            )

        # Check if 2FA is enabled
        if user.is_2fa_enabled:
            print(f"2FA required for {user_credentials.email}")
            # Create temporary token for 2FA verification
            temp_token = create_access_token(
                data={"sub": str(user.id), "email": user.email, "requires_2fa": True},
                expires_delta=timedelta(minutes=10)  # Short-lived token
            )
            return {
                "access_token": temp_token,
                "token_type": "bearer",
                "requires_2fa": True,
                "message": "2FA verification required"
            }

        # Create tokens for non-2FA users
        print(f"Creating tokens for {user_credentials.email}")
        access_token = create_access_token(data={"sub": str(user.id), "email": user.email})
        refresh_token_str = create_refresh_token(data={"sub": str(user.id), "email": user.email})

        # Get client info
        client_info = get_client_info(request)
        device_details = client_info.get("device_details", {})
        
        try:
            # Get location info
            location_str, location_data = await get_location_from_ip(client_info.get("ip_address"))
        except Exception as e:
            print(f"Error getting location: {str(e)}")
            location_str = "Unknown"
            location_data = {}

        # Store refresh token
        refresh_token = RefreshToken(
            token=refresh_token_str,
            user_id=user.id,
            device_info=client_info.get("device_info"),
            ip_address=client_info.get("ip_address"),
            user_agent=client_info.get("user_agent"),
            expires_at=datetime.now(timezone.utc) + timedelta(days=7)
        )
        db.add(refresh_token)

        try:
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
                login_method="password"
            )
            
            # Only add location_data if it's a valid dictionary
            if isinstance(location_data, dict) and location_data:
                session_history.location_data = location_data
                
            db.add(session_history)
        except Exception as e:
            print(f"Error creating session history: {str(e)}")
            # Continue without session history if there's an error

        # Update last login
        user.last_login = datetime.now(timezone.utc)

        await db.commit()
        print(f"Login successful for {user_credentials.email}")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_str,
            "token_type": "bearer",
            "requires_2fa": False
        }
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        print(f"Unexpected error during login: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during login. Please try again."
        )


@router.post("/refresh", response_model=AccessToken)
async def refresh_token(
    token_data: TokenRefresh,
    request: Request,
    db: AsyncSession = Depends(get_async_session)
):
    """Refresh access token using refresh token."""
    # Verify refresh token
    payload = verify_token(token_data.refresh_token, "refresh")
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    # Check if refresh token exists and is active
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token == token_data.refresh_token,
            RefreshToken.is_active == True,
            RefreshToken.is_revoked == False
        )
    )
    refresh_token = result.scalar_one_or_none()

    if not refresh_token or refresh_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired or invalid"
        )

    # Get user
    result = await db.execute(select(User).where(User.id == refresh_token.user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )

    # Create new access token
    access_token = create_access_token(data={"sub": str(user.id), "email": user.email})

    # Update refresh token last used
    refresh_token.last_used = datetime.now(timezone.utc)
    await db.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


@router.post("/logout", response_model=MessageResponse)
async def logout(
    token_data: TokenRefresh,
    current_user: dict = Depends(get_current_user_from_token),
    db: AsyncSession = Depends(get_async_session)
):
    """Logout user and revoke refresh token."""
    # Revoke refresh token
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token == token_data.refresh_token,
            RefreshToken.user_id == current_user["user_id"]
        )
    )
    refresh_token = result.scalar_one_or_none()

    if refresh_token:
        refresh_token.is_revoked = True
        refresh_token.is_active = False

        # Update session history
        result = await db.execute(
            select(SessionHistory).where(
                SessionHistory.user_id == current_user["user_id"],
                SessionHistory.is_active == True
            ).order_by(SessionHistory.login_at.desc()).limit(1)
        )
        session = result.scalar_one_or_none()
        if session:
            session.is_active = False
            session.logout_at = datetime.now(timezone.utc)
            session.logout_reason = "manual"

        await db.commit()

    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    current_user: dict = Depends(get_current_user_from_token),
    db: AsyncSession = Depends(get_async_session)
):
    """Get current user information."""
    try:
        print(f"Getting user info for user_id: {current_user['user_id']}")
        
        result = await db.execute(select(User).where(User.id == current_user["user_id"]))
        user = result.scalar_one_or_none()

        if not user:
            print(f"User not found for user_id: {current_user['user_id']}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        print(f"User found: {user.email}")
        return user
    except HTTPException:
        raise
    except Exception as e:
        print(f"Unexpected error in get_current_user: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while retrieving user information"
        )


@router.put("/change-password", response_model=MessageResponse)
async def change_password(
    password_data: PasswordChange,
    current_user: dict = Depends(get_current_user_from_token),
    db: AsyncSession = Depends(get_async_session)
):
    """Change user password."""
    # Get user
    result = await db.execute(select(User).where(User.id == current_user["user_id"]))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Verify current password
    if not verify_password(password_data.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect current password"
        )

    # Update password
    user.hashed_password = get_password_hash(password_data.new_password)
    user.updated_at = datetime.now(timezone.utc)

    # Revoke all refresh tokens for security
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user.id,
            RefreshToken.is_active == True
        )
    )
    refresh_tokens = result.scalars().all()

    for token in refresh_tokens:
        token.is_revoked = True
        token.is_active = False

    await db.commit()

    return {"message": "Password changed successfully. Please login again."}


# @router.get("/sessions", response_model=SessionHistorySchema)
# async def get_user_sessions(
#     current_user: dict = Depends(get_current_user_from_token),
#     db: AsyncSession = Depends(get_async_session)
# ):
#     """Get user's session history."""
#     result = await db.execute(
#         select(SessionHistory).where(
#             SessionHistory.user_id == current_user["user_id"]
#         ).order_by(SessionHistory.login_at.desc()).limit(20)
#     )
#     sessions = result.scalars().all()

#     # Mark current session
#     session_list = []
#     for session in sessions:
#         session_info = {
#             "session_id": session.session_id,
#             "device_info": session.device_info,
#             "ip_address": session.ip_address,
#             "location": session.location,
#             "login_method": session.login_method,
#             "login_at": session.login_at,
#             "last_activity": session.last_activity,
#             "is_current": session.is_active,
            
#             # Enhanced device details
#             "browser_name": session.browser_name,
#             "browser_version": session.browser_version,
#             "os_name": session.os_name,
#             "os_version": session.os_version,
#             "device_type": session.device_type,
#             "device_brand": session.device_brand,
#             "device_model": session.device_model,
            
#             # Enhanced location details
#             "country": session.country,
#             "city": session.city,
#             "region": session.region,
#             "timezone": session.timezone,
#             "location_data": session.location_data
#         }
#         session_list.append(session_info)

#     return {
#         "sessions": session_list,
#         "total": len(session_list)
#     }


@router.get("/sessions", response_model=SessionHistorySchema)
async def get_user_sessions(
    current_user: dict = Depends(get_current_user_from_token),
    db: AsyncSession = Depends(get_async_session),
):
    """Get user's session history."""
    try:
        result = await db.execute(
            select(SessionHistory)
            .where(SessionHistory.user_id == current_user["user_id"])
            .order_by(SessionHistory.login_at.desc())
            .limit(20)
        )
        sessions = result.scalars().all()

        session_list = []
        for session in sessions:
            session_info = SessionInfo(
                session_id=session.session_id,
                ip_address=session.ip_address,
                location=session.location,
                login_method=session.login_method,
                login_at=session.login_at,
                last_activity=session.last_activity,
                is_current=session.is_active,
                browser_name=session.browser_name,
                browser_version=session.browser_version,
                os_name=session.os_name,
                os_version=session.os_version,
                device_type=session.device_type,
                device_brand=session.device_brand,
                device_model=session.device_model,
                country=session.country,
                city=session.city,
                region=session.region,
                timezone=session.timezone,
                location_data=session.location_data,
            )
            session_list.append(session_info)

        return SessionHistorySchema(sessions=session_list, total=len(session_list))

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch session history: {str(e)}"
        )


# @router.get("/current-session", response_model=CurrentSessionInfo)
# async def get_current_session(
#     request: Request,
#     current_user: dict = Depends(get_current_user_from_token),
#     db: AsyncSession = Depends(get_async_session)
# ):
#     """Get detailed information about the current session."""
#     try:
#         print(f"Getting current session for user_id: {current_user.get('user_id')}")
        
#         # Find the most recent active session for this user
#         result = await db.execute(
#             select(SessionHistory).where(
#                 SessionHistory.user_id == current_user["user_id"],
#                 SessionHistory.is_active == True
#             ).order_by(SessionHistory.login_at.desc()).limit(1)
#         )
#         session = result.scalar_one_or_none()
        
#         if not session:
#             print(f"No active session found for user_id: {current_user.get('user_id')}")
#             # Check if there are any sessions at all for this user
#             all_sessions_result = await db.execute(
#                 select(SessionHistory).where(
#                     SessionHistory.user_id == current_user["user_id"]
#                 ).order_by(SessionHistory.login_at.desc()).limit(5)
#             )
#             all_sessions = all_sessions_result.scalars().all()
#             print(f"Total sessions for user: {len(all_sessions)}")
#             for s in all_sessions:
#                 print(f"  Session {s.session_id}: active={s.is_active}, login_at={s.login_at}")
            
#             raise HTTPException(
#                 status_code=status.HTTP_404_NOT_FOUND,
#                 detail="No active session found. Please log in again."
#             )
        
#         print(f"Found active session: {session.session_id}")
#     except HTTPException:
#         raise
#     except Exception as e:
#         print(f"Error getting current session: {str(e)}")
#         import traceback
#         traceback.print_exc()
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Failed to retrieve session information"
#         )
    
#     # Update last activity
#     session.last_activity = datetime.now(timezone.utc)
#     await db.commit()
    
#     # Extract ISP and organization from location data
#     isp = None
#     organization = None
#     if session.location_data:
#         isp = session.location_data.get("isp")
#         organization = session.location_data.get("org")
    
#     return {
#         "session_id": session.session_id,
#         "login_at": session.login_at,
#         "last_activity": session.last_activity,
#         "login_method": session.login_method,
        
#         # Device information
#         "device_info": session.device_info,
#         "browser_name": session.browser_name,
#         "browser_version": session.browser_version,
#         "os_name": session.os_name,
#         "os_version": session.os_version,
#         "device_type": session.device_type,
#         "device_brand": session.device_brand,
#         "device_model": session.device_model,
        
#         # Location information
#         "ip_address": session.ip_address,
#         "location": session.location,
#         "country": session.country,
#         "city": session.city,
#         "region": session.region,
#         "timezone": session.timezone,
        
#         # ISP information
#         "isp": isp,
#         "organization": organization
#     }



# /current-session endpoint
@router.get("/current-session", response_model=CurrentSessionInfo)
async def get_current_session(
    request: Request,
    current_user: dict = Depends(get_current_user_from_token),
    db: AsyncSession = Depends(get_async_session)
):
    """Get detailed information about the current session."""
    try:
        # Get the latest active session
        result = await db.execute(
            select(SessionHistory)
            .where(SessionHistory.user_id == current_user["user_id"])
            .where(SessionHistory.is_active == True)
            .order_by(SessionHistory.login_at.desc())
            .limit(1)
        )
        session = result.scalar_one_or_none()

        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No active session found. Please log in again."
            )

        # Update last activity
        session.last_activity = datetime.now(timezone.utc)
        await db.commit()

        # Extract ISP/org if available
        isp = session.location_data.get("isp") if session.location_data else None
        organization = session.location_data.get("org") if session.location_data else None

        return {
            "session_id": session.session_id,
            "login_at": session.login_at,
            "last_activity": session.last_activity,
            "login_method": session.login_method,
            "browser_name": session.browser_name,
            "browser_version": session.browser_version,
            "os_name": session.os_name,
            "os_version": session.os_version,
            "device_type": session.device_type,
            "device_brand": session.device_brand,
            "device_model": session.device_model,
            "ip_address": session.ip_address,
            "location": session.location,
            "country": session.country,
            "city": session.city,
            "region": session.region,
            "timezone": session.timezone,
            "isp": isp,
            "organization": organization
        }

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve session information: {str(e)}"
        )


@router.post("/send-verification-email", response_model=MessageResponse)
async def send_verification_email(
    data: EmailVerificationRequest,
    db: AsyncSession = Depends(get_async_session)
):
    """Send email verification link."""
    # Get user
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already verified"
        )

    # Generate verification token
    token = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

    # Delete any existing verification tokens for this user
    await db.execute(
        select(EmailVerificationToken).where(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.email == data.email
        )
    )
    existing_tokens = await db.execute(
        select(EmailVerificationToken).where(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.email == data.email
        )
    )
    for token_obj in existing_tokens.scalars().all():
        await db.delete(token_obj)

    # Create new verification token
    verification_token = EmailVerificationToken(
        user_id=user.id,
        token=token,
        email=data.email,
        expires_at=expires_at
    )
    db.add(verification_token)
    await db.commit()

    # Send verification email
    verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
    await email_manager.send_email_verification(
        email=data.email,
        verification_url=verification_url,
        user_name=user.full_name or user.username or "User"
    )

    return {"message": "Verification email sent successfully"}


@router.post("/verify-email", response_model=MessageResponse)
async def verify_email(
    data: EmailVerificationVerify,
    db: AsyncSession = Depends(get_async_session)
):
    """Verify email address using token."""
    # Find verification token
    result = await db.execute(
        select(EmailVerificationToken).where(
            EmailVerificationToken.token == data.token,
            EmailVerificationToken.is_used == False,
            EmailVerificationToken.expires_at > datetime.now(timezone.utc)
        )
    )
    verification_token = result.scalar_one_or_none()

    if not verification_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token"
        )

    # Get user
    result = await db.execute(select(User).where(User.id == verification_token.user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Update user verification status
    user.is_verified = True
    
    # Check if this is an email change verification
    if hasattr(user, 'is_email_change_pending') and user.is_email_change_pending and hasattr(user, 'new_email') and verification_token.email == user.new_email:
        # Update the email
        old_email = user.email
        user.email = verification_token.email
        user.new_email = None
        user.is_email_change_pending = False
        message = f"Email changed from {old_email} to {verification_token.email} and verified successfully"
    else:
        # Regular verification
        user.email = verification_token.email  # In case this was an email change
        message = "Email verified successfully"
    
    user.updated_at = datetime.now(timezone.utc)

    # Mark token as used
    verification_token.is_used = True

    await db.commit()

    return {"message": message}


@router.put("/update-profile", response_model=UserResponse)
async def update_profile(
    data: UserUpdate,
    current_user: dict = Depends(get_current_user_from_token),
    db: AsyncSession = Depends(get_async_session)
):
    """Update user profile."""
    # Get user
    result = await db.execute(select(User).where(User.id == current_user["user_id"]))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check if username is being changed and is unique
    if data.username and data.username != user.username:
        result = await db.execute(select(User).where(User.username == data.username))
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken"
            )
        user.username = data.username

    # Update full name
    if data.full_name is not None:
        user.full_name = data.full_name

    # Handle email change
    if data.email and data.email != user.email:
        if not data.current_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password required for email change"
            )
        
        # Verify current password
        if not verify_password(data.current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect current password"
            )

        # Check if new email is already taken
        result = await db.execute(select(User).where(User.email == data.email))
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        # Generate verification token for new email
        token = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

        # Delete any existing verification tokens for this user and new email
        existing_tokens = await db.execute(
            select(EmailVerificationToken).where(
                EmailVerificationToken.user_id == user.id,
                EmailVerificationToken.email == data.email
            )
        )
        for token_obj in existing_tokens.scalars().all():
            await db.delete(token_obj)

        # Create new verification token
        verification_token = EmailVerificationToken(
            user_id=user.id,
            token=token,
            email=data.email,
            expires_at=expires_at
        )
        db.add(verification_token)

        # Store the new email in a temporary field
        # The email will be updated after verification
        user.new_email = data.email
        user.is_email_change_pending = True

        # Send verification email to new email
        verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
        await email_manager.send_email_verification(
            email=data.email,
            verification_url=verification_url,
            user_name=user.full_name or user.username or "User"
        )

    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)

    if data.email and data.email != user.email:
        return {
            "message": "Profile updated. Please check your new email for verification.",
            "new_email": user.new_email,
            "is_email_change_pending": user.is_email_change_pending
        }

    return user


@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(
    data: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_async_session)
):
    """Send password reset code via email."""
    # Get user
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if not user:
        # Don't reveal if email exists or not for security
        return {"message": "If the email exists, a password reset code has been sent"}

    # Generate 6-digit OTP code
    from app.core.security import generate_email_otp
    reset_code = str(generate_email_otp())
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

    # Delete any existing reset tokens for this user
    existing_tokens = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.email == data.email
        )
    )
    for token_obj in existing_tokens.scalars().all():
        await db.delete(token_obj)

    # Create new reset token
    reset_token = PasswordResetToken(
        user_id=user.id,
        code=reset_code,
        email=data.email,
        expires_at=expires_at
    )
    db.add(reset_token)
    await db.commit()

    # Send reset code email
    await email_manager.send_password_reset_code(
        email=data.email,
        reset_code=reset_code,
        user_name=user.full_name or user.username or "User"
    )

    return {"message": "If the email exists, a password reset code has been sent"}


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
    data: ForgotPasswordVerify,
    db: AsyncSession = Depends(get_async_session)
):
    """Reset password using OTP code."""
    # Find reset token
    result = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.email == data.email,
            PasswordResetToken.code == data.code,
            PasswordResetToken.is_used == False,
            PasswordResetToken.expires_at > datetime.now(timezone.utc)
        )
    )
    reset_token = result.scalar_one_or_none()

    if not reset_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset code"
        )

    # Get user
    result = await db.execute(select(User).where(User.id == reset_token.user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Update password
    user.hashed_password = get_password_hash(data.new_password)
    user.updated_at = datetime.now(timezone.utc)

    # Mark token as used
    reset_token.is_used = True

    # Revoke all refresh tokens for security
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user.id,
            RefreshToken.is_active == True
        )
    )
    refresh_tokens = result.scalars().all()

    for token in refresh_tokens:
        token.is_revoked = True
        token.is_active = False

    await db.commit()

    return {"message": "Password reset successfully"}