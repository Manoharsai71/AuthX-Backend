from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import secrets
import pyotp
import qrcode
from io import BytesIO
import base64

from core.config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security scheme
security = HTTPBearer()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT refresh token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def verify_token(token: str, token_type: str = "access") -> Optional[dict]:
    """Verify and decode JWT token."""
    if not token:
        print(f"Empty token provided for verification")
        return None
        
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != token_type:
            print(f"Token type mismatch: expected {token_type}, got {payload.get('type')}")
            return None
        return payload
    except JWTError as e:
        print(f"JWT verification error: {str(e)}")
        return None
    except Exception as e:
        print(f"Unexpected error in verify_token: {str(e)}")
        return None


def generate_otp_secret() -> str:
    """Generate a random OTP secret."""
    return pyotp.random_base32()


def generate_otp_code(secret: str) -> str:
    """Generate TOTP code."""
    totp = pyotp.TOTP(secret)
    return totp.now()


def verify_otp_code(secret: str, code: str) -> bool:
    """Verify TOTP code."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_qr_code(secret: str, user_email: str, issuer_name: str = "AuthX") -> str:
    """Generate QR code for TOTP setup."""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user_email,
        issuer_name=issuer_name
    )

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    # Convert to base64
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_base64}"


def generate_magic_token() -> str:
    """Generate secure random token for magic links."""
    return secrets.token_urlsafe(32)


def generate_email_otp() -> str:
    """Generate 6-digit OTP for email verification."""
    return secrets.randbelow(900000) + 100000


async def get_current_user_from_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Extract current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not credentials:
        print("No credentials provided")
        raise credentials_exception
    
    try:
        print(f"Verifying token: {credentials.credentials[:20]}...")
        payload = verify_token(credentials.credentials, "access")
        if payload is None:
            print("Token verification failed: Invalid token")
            raise credentials_exception
        
        user_id: str = payload.get("sub")
        if user_id is None:
            print("Token verification failed: No user_id in payload")
            raise credentials_exception
        
        print(f"Token verified for user_id: {user_id}")
        return {
            "user_id": int(user_id), 
            "email": payload.get("email"),
            "requires_2fa": payload.get("requires_2fa", False)
        }
    except Exception as e:
        print(f"Token verification error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise credentials_exception