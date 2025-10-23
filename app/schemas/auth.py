from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


# Base schemas
class UserBase(BaseModel):
    email: EmailStr
    username: Optional[str] = None
    full_name: Optional[str] = None


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters")


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserLogin2FA(BaseModel):
    email: EmailStr
    password: str
    totp_code: Optional[str] = None


class UserResponse(UserBase):
    id: int
    is_active: bool
    is_verified: bool
    is_2fa_enabled: bool
    avatar_url: Optional[str] = None
    created_at: datetime
    last_login: Optional[datetime] = None
    new_email: Optional[str] = None
    is_email_change_pending: bool = False

    class Config:
        from_attributes = True


# Token schemas
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenWith2FA(BaseModel):
    requires_2fa: bool = True
    message: str = "2FA verification required"


class LoginResponse(BaseModel):
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    requires_2fa: bool = False
    message: Optional[str] = None


class TokenRefresh(BaseModel):
    refresh_token: str


class AccessToken(BaseModel):
    access_token: str
    token_type: str = "bearer"


# OTP schemas
class OTPRequest(BaseModel):
    email: EmailStr


class OTPVerify(BaseModel):
    email: EmailStr
    code: str


class OTPResponse(BaseModel):
    message: str
    expires_in: int


# Magic Link schemas
class MagicLinkRequest(BaseModel):
    email: EmailStr


class MagicLinkVerify(BaseModel):
    token: str


class MagicLinkResponse(BaseModel):
    message: str
    expires_in: int


# 2FA schemas
class TwoFASetupResponse(BaseModel):
    secret: str
    qr_code: str
    backup_codes: List[str]


class TwoFAVerify(BaseModel):
    code: str


class TwoFADisable(BaseModel):
    password: str


# Session schemas
class SessionInfo(BaseModel):
    session_id: str
    device_info: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None
    login_method: str
    login_at: datetime
    last_activity: datetime
    is_current: bool = False
    
    # Enhanced device details
    browser_name: Optional[str] = None
    browser_version: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    device_type: Optional[str] = None
    device_brand: Optional[str] = None
    device_model: Optional[str] = None
    
    # Enhanced location details
    country: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    timezone: Optional[str] = None
    
    # Additional location data
    location_data: Optional[dict] = None

    class Config:
        from_attributes = True


class SessionHistory(BaseModel):
    sessions: List[SessionInfo]
    total: int


class CurrentSessionInfo(BaseModel):
    session_id: str
    login_at: datetime
    last_activity: datetime
    login_method: str
    
    # Device information
    device_info: Optional[str] = None
    browser_name: Optional[str] = None
    browser_version: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    device_type: Optional[str] = None
    device_brand: Optional[str] = None
    device_model: Optional[str] = None
    
    # Location information
    ip_address: Optional[str] = None
    location: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    timezone: Optional[str] = None
    
    # ISP information
    isp: Optional[str] = None
    organization: Optional[str] = None


# Password schemas
class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


class PasswordReset(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ForgotPasswordVerify(BaseModel):
    email: EmailStr
    code: str
    new_password: str = Field(..., min_length=8)


# Email verification schemas
class EmailVerificationRequest(BaseModel):
    email: EmailStr


class EmailVerificationVerify(BaseModel):
    token: str


# User update schemas
class UserUpdate(BaseModel):
    username: Optional[str] = None
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    current_password: Optional[str] = None  # Required for email change


# Response schemas
class MessageResponse(BaseModel):
    message: str
    new_email: Optional[str] = None
    is_email_change_pending: Optional[bool] = None


class ErrorResponse(BaseModel):
    detail: str


class SessionInfo(BaseModel):
    session_id: str
    device_info: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None
    login_method: str
    login_at: datetime
    last_activity: Optional[datetime] = None
    is_current: bool
    
    # Enhanced device details
    browser_name: Optional[str] = None
    browser_version: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    device_type: Optional[str] = None
    device_brand: Optional[str] = None
    device_model: Optional[str] = None
    
    # Enhanced location details
    country: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    timezone: Optional[str] = None
    location_data: Optional[Dict[str, Any]] = None


class SessionHistory(BaseModel):
    sessions: List[SessionInfo]
    total: int


class CurrentSessionInfo(BaseModel):
    session_id: str
    login_at: datetime
    last_activity: Optional[datetime] = None
    login_method: str
    
    # Device information
    device_info: Optional[str] = None
    browser_name: Optional[str] = None
    browser_version: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    device_type: Optional[str] = None
    device_brand: Optional[str] = None
    device_model: Optional[str] = None
    
    # Location information
    ip_address: Optional[str] = None
    location: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    timezone: Optional[str] = None
    
    # ISP information
    isp: Optional[str] = None
    organization: Optional[str] = None