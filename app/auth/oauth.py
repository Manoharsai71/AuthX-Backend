from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from authlib.integrations.httpx_client import AsyncOAuth2Client
import httpx
from datetime import datetime, timedelta, timezone
import uuid

from db.database import get_async_session
from models.user import User
from models.refresh_token import RefreshToken
from models.session_history import SessionHistory
from schemas.auth import Token, MessageResponse
from core.security import create_access_token, create_refresh_token, get_current_user_from_token
from core.config import settings
from utils.helpers import get_client_info, get_location_from_ip

router = APIRouter()


class OAuthProvider:
    def __init__(self, name: str, client_id: str, client_secret: str, 
                 authorize_url: str, token_url: str, user_info_url: str):
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.user_info_url = user_info_url


# OAuth providers configuration
OAUTH_PROVIDERS = {
    "google": OAuthProvider(
        name="google",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        authorize_url="https://accounts.google.com/o/oauth2/auth",
        token_url="https://oauth2.googleapis.com/token",
        user_info_url="https://www.googleapis.com/oauth2/v2/userinfo"
    ),
    "github": OAuthProvider(
        name="github",
        client_id=settings.GITHUB_CLIENT_ID,
        client_secret=settings.GITHUB_CLIENT_SECRET,
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        user_info_url="https://api.github.com/user"
    )
}


@router.get("/{provider}/login")
async def oauth_login(provider: str):
    """Initiate OAuth login flow."""
    if provider not in OAUTH_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported OAuth provider"
        )
    
    oauth_provider = OAUTH_PROVIDERS[provider]
    
    # Create OAuth client
    client = AsyncOAuth2Client(
        client_id=oauth_provider.client_id,
        client_secret=oauth_provider.client_secret
    )
    
    # Generate authorization URL
    redirect_uri = f"{settings.FRONTEND_URL}/auth/callback/{provider}"
    
    if provider == "google":
        authorization_url, state = client.create_authorization_url(
            oauth_provider.authorize_url,
            redirect_uri=redirect_uri,
            scope="openid email profile"
        )
    elif provider == "github":
        authorization_url, state = client.create_authorization_url(
            oauth_provider.authorize_url,
            redirect_uri=redirect_uri,
            scope="user:email"
        )
    
    return {
        "authorization_url": authorization_url,
        "state": state
    }


@router.post("/{provider}/callback", response_model=Token)
async def oauth_callback(
    provider: str,
    code: str,
    state: str,
    request: Request,
    db: AsyncSession = Depends(get_async_session)
):
    """Handle OAuth callback and authenticate user."""
    if provider not in OAUTH_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported OAuth provider"
        )
    
    oauth_provider = OAUTH_PROVIDERS[provider]
    
    try:
        # Exchange code for token
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                oauth_provider.token_url,
                data={
                    "client_id": oauth_provider.client_id,
                    "client_secret": oauth_provider.client_secret,
                    "code": code,
                    "redirect_uri": f"{settings.FRONTEND_URL}/auth/callback/{provider}"
                },
                headers={"Accept": "application/json"}
            )

            if token_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to exchange code for token"
                )
            
            token_data = token_response.json()
            access_token = token_data.get("access_token")
            
            if not access_token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="No access token received"
                )
            
            # Get user info
            user_response = await client.get(
                oauth_provider.user_info_url,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if user_response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to get user information"
                )
            
            user_data = user_response.json()
            
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth authentication failed: {str(e)}"
        )
    
    # Extract user information based on provider
    if provider == "google":
        email = user_data.get("email")
        full_name = user_data.get("name")
        avatar_url = user_data.get("picture")
        provider_id = user_data.get("id")
        username = email.split("@")[0] if email else None
    elif provider == "github":
        email = user_data.get("email")
        full_name = user_data.get("name")
        avatar_url = user_data.get("avatar_url")
        provider_id = str(user_data.get("id"))
        username = user_data.get("login")
        
        # GitHub might not return email in user endpoint
        if not email:
            email_response = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            if email_response.status_code == 200:
                emails = email_response.json()
                primary_email = next((e for e in emails if e.get("primary")), None)
                if primary_email:
                    email = primary_email.get("email")

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email not provided by OAuth provider"
        )

    # Check if user exists
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user:
        # Update OAuth info if not set
        if provider == "google" and not user.google_id:
            user.google_id = provider_id
        elif provider == "github" and not user.github_id:
            user.github_id = provider_id

        # Update avatar if not set
        if not user.avatar_url and avatar_url:
            user.avatar_url = avatar_url

        user.last_login = datetime.now(timezone.utc)
        user.is_verified = True  # OAuth users are considered verified
    else:
        # Create new user
        user = User(
            email=email,
            username=username,
            full_name=full_name,
            avatar_url=avatar_url,
            is_verified=True,
            is_active=True
        )

        if provider == "google":
            user.google_id = provider_id
        elif provider == "github":
            user.github_id = provider_id

        db.add(user)
        await db.flush()  # Get user ID

    # Create tokens
    jwt_access_token = create_access_token(data={"sub": str(user.id), "email": user.email})
    jwt_refresh_token = create_refresh_token(data={"sub": str(user.id), "email": user.email})

    # Get client info
    client_info = get_client_info(request)

    # Store refresh token
    refresh_token = RefreshToken(
        token=jwt_refresh_token,
        user_id=user.id,
        device_info=client_info.get("device_info"),
        ip_address=client_info.get("ip_address"),
        user_agent=client_info.get("user_agent"),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7)
    )
    db.add(refresh_token)

    try:
        # Get location info
        location_str, location_data = await get_location_from_ip(client_info.get("ip_address"))
    except Exception as e:
        print(f"Error getting location: {str(e)}")
        location_str = "Unknown"
        location_data = {}

    device_details = client_info.get("device_details", {})

    try:
        # Create session history with enhanced details
        session_history = SessionHistory(
            user_id=user.id,
            session_id=str(uuid.uuid4()),
            ip_address=client_info.get("ip_address"),
            user_agent=client_info.get("user_agent"),
            device_info=client_info.get("device_info"),

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
            login_method=provider
        )

        # Only add location_data if it's a valid dictionary
        if isinstance(location_data, dict) and location_data:
            session_history.location_data = location_data

        db.add(session_history)
    except Exception as e:
        print(f"Error creating session history: {str(e)}")
        # Continue without session history if there's an error

    await db.commit()

    return {
        "access_token": jwt_access_token,
        "refresh_token": jwt_refresh_token,
        "token_type": "bearer"
    }


@router.post("/{provider}/unlink", response_model=MessageResponse)
async def unlink_oauth_account(
    provider: str,
    current_user: dict = Depends(get_current_user_from_token),
    db: AsyncSession = Depends(get_async_session)
):
    """Unlink OAuth account from user."""
    if provider not in OAUTH_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported OAuth provider"
        )

    # Get user
    result = await db.execute(select(User).where(User.id == current_user["user_id"]))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check if user has password or other OAuth methods
    has_password = bool(user.hashed_password)
    has_google = bool(user.google_id)
    has_github = bool(user.github_id)

    oauth_methods = sum([has_google, has_github])

    if not has_password and oauth_methods <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot unlink the only authentication method. Set a password first."
        )

    # Unlink the provider
    if provider == "google":
        if not user.google_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google account is not linked"
            )
        user.google_id = None
    elif provider == "github":
        if not user.github_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="GitHub account is not linked"
            )
        user.github_id = None

    user.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {"message": f"{provider.title()} account unlinked successfully"}
