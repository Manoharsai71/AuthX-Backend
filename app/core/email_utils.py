from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from typing import List, Optional
from pathlib import Path
import os

from core.config import settings


class EmailManager:
    def __init__(self):
        # Check if email is configured
        if not settings.MAIL_USERNAME or not settings.MAIL_FROM:
            self.conf = None
            self.fm = None
            print("⚠️  Email not configured. Email features will be disabled.")
            return
            
        try:
            self.conf = ConnectionConfig(
                MAIL_USERNAME=settings.MAIL_USERNAME,
                MAIL_PASSWORD=settings.MAIL_PASSWORD,
                MAIL_FROM=settings.MAIL_FROM,
                MAIL_PORT=settings.MAIL_PORT,
                MAIL_SERVER=settings.MAIL_SERVER,
                MAIL_FROM_NAME=settings.MAIL_FROM_NAME,
                MAIL_STARTTLS=settings.MAIL_STARTTLS,
                MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
                USE_CREDENTIALS=settings.USE_CREDENTIALS,
                VALIDATE_CERTS=settings.VALIDATE_CERTS,
                TEMPLATE_FOLDER=Path(__file__).parent.parent / 'templates'
            )
            self.fm = FastMail(self.conf)
        except Exception as e:
            self.conf = None
            self.fm = None
            print(f"⚠️  Email configuration error: {e}. Email features will be disabled.")

    async def send_otp_email(self, email: str, otp_code: str, user_name: str = "User") -> bool:
        """Send OTP code via email."""
        if not self.fm:
            print(f"⚠️  Email not configured. Would send OTP {otp_code} to {email}")
            return True  # Return True for development without email
            
        try:
            html_content = f"""
            <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background-color: #f8f9fa; padding: 20px; border-radius: 10px;">
                        <h2 style="color: #333; text-align: center;">AuthX - Email Verification</h2>
                        <div style="background-color: white; padding: 30px; border-radius: 8px; margin: 20px 0;">
                            <p>Hello {user_name},</p>
                            <p>Your verification code is:</p>
                            <div style="text-align: center; margin: 30px 0;">
                                <span style="font-size: 32px; font-weight: bold; color: #007bff; 
                                           background-color: #f8f9fa; padding: 15px 25px; 
                                           border-radius: 8px; letter-spacing: 5px;">{otp_code}</span>
                            </div>
                            <p>This code will expire in {settings.OTP_EXPIRE_MINUTES} minutes.</p>
                            <p>If you didn't request this code, please ignore this email.</p>
                        </div>
                        <p style="text-align: center; color: #666; font-size: 12px;">
                            © 2024 AuthX. All rights reserved.
                        </p>
                    </div>
                </body>
            </html>
            """

            message = MessageSchema(
                subject="AuthX - Your Verification Code",
                recipients=[email],
                body=html_content,
                subtype=MessageType.html
            )

            await self.fm.send_message(message)
            return True
        except Exception as e:
            print(f"Failed to send OTP email: {e}")
            return False

    async def send_magic_link_email(self, email: str, magic_link: str, user_name: str = "User") -> bool:
        """Send magic link via email."""
        if not self.fm:
            print(f"⚠️  Email not configured. Would send magic link to {email}: {magic_link}")
            return True  # Return True for development without email
            
        try:
            html_content = f"""
            <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background-color: #f8f9fa; padding: 20px; border-radius: 10px;">
                        <h2 style="color: #333; text-align: center;">AuthX - Magic Link Login</h2>
                        <div style="background-color: white; padding: 30px; border-radius: 8px; margin: 20px 0;">
                            <p>Hello {user_name},</p>
                            <p>Click the button below to sign in to your account:</p>
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{magic_link}" 
                                   style="background-color: #007bff; color: white; padding: 15px 30px; 
                                          text-decoration: none; border-radius: 8px; font-weight: bold;
                                          display: inline-block;">
                                    Sign In to AuthX
                                </a>
                            </div>
                            <p>This link will expire in {settings.MAGIC_LINK_EXPIRE_MINUTES} minutes.</p>
                            <p>If you didn't request this link, please ignore this email.</p>
                            <p style="font-size: 12px; color: #666;">
                                If the button doesn't work, copy and paste this link: {magic_link}
                            </p>
                        </div>
                        <p style="text-align: center; color: #666; font-size: 12px;">
                            © 2024 AuthX. All rights reserved.
                        </p>
                    </div>
                </body>
            </html>
            """

            message = MessageSchema(
                subject="AuthX - Your Magic Link",
                recipients=[email],
                body=html_content,
                subtype=MessageType.html
            )

            await self.fm.send_message(message)
            return True
        except Exception as e:
            print(f"Failed to send magic link email: {e}")
            return False

    async def send_welcome_email(self, email: str, user_name: str) -> bool:
        """Send welcome email to new users."""
        if not self.fm:
            print(f"⚠️  Email not configured. Would send welcome email to {email}")
            return True  # Return True for development without email
            
        try:
            html_content = f"""
            <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background-color: #f8f9fa; padding: 20px; border-radius: 10px;">
                        <h2 style="color: #333; text-align: center;">Welcome to AuthX!</h2>
                        <div style="background-color: white; padding: 30px; border-radius: 8px; margin: 20px 0;">
                            <p>Hello {user_name},</p>
                            <p>Welcome to AuthX! Your account has been successfully created.</p>
                            <p>You can now enjoy all the features of our secure authentication system:</p>
                            <ul>
                                <li>✅ Secure JWT-based authentication</li>
                                <li>✅ Two-factor authentication</li>
                                <li>✅ Social login with Google & GitHub</li>
                                <li>✅ Magic link login</li>
                                <li>✅ Session management</li>
                            </ul>
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{settings.FRONTEND_URL}/dashboard" 
                                   style="background-color: #28a745; color: white; padding: 15px 30px; 
                                          text-decoration: none; border-radius: 8px; font-weight: bold;
                                          display: inline-block;">
                                    Go to Dashboard
                                </a>
                            </div>
                        </div>
                        <p style="text-align: center; color: #666; font-size: 12px;">
                            © 2024 AuthX. All rights reserved.
                        </p>
                    </div>
                </body>
            </html>
            """

            message = MessageSchema(
                subject="Welcome to AuthX!",
                recipients=[email],
                body=html_content,
                subtype=MessageType.html
            )

            await self.fm.send_message(message)
            return True
        except Exception as e:
            print(f"Failed to send welcome email: {e}")
            return False

    async def send_email_verification(self, email: str, verification_url: str, user_name: str = "User") -> bool:
        """Send email verification link."""
        if not self.fm:
            print(f"⚠️  Email not configured. Would send verification email to {email}: {verification_url}")
            return True  # Return True for development without email
            
        try:
            html_content = f"""
            <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background-color: #f8f9fa; padding: 20px; border-radius: 10px;">
                        <h2 style="color: #333; text-align: center;">AuthX - Verify Your Email</h2>
                        <div style="background-color: white; padding: 30px; border-radius: 8px; margin: 20px 0;">
                            <p>Hello {user_name},</p>
                            <p>Please verify your email address by clicking the button below:</p>
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{verification_url}" 
                                   style="background-color: #007bff; color: white; padding: 15px 30px; 
                                          text-decoration: none; border-radius: 8px; font-weight: bold;
                                          display: inline-block;">
                                    Verify Email Address
                                </a>
                            </div>
                            <p>This link will expire in 24 hours.</p>
                            <p>If you didn't create an account, please ignore this email.</p>
                            <p style="font-size: 12px; color: #666;">
                                If the button doesn't work, copy and paste this link: {verification_url}
                            </p>
                        </div>
                        <p style="text-align: center; color: #666; font-size: 12px;">
                            © 2024 AuthX. All rights reserved.
                        </p>
                    </div>
                </body>
            </html>
            """

            message = MessageSchema(
                subject="AuthX - Verify Your Email Address",
                recipients=[email],
                body=html_content,
                subtype=MessageType.html
            )

            await self.fm.send_message(message)
            return True
        except Exception as e:
            print(f"Failed to send email verification: {e}")
            return False

    async def send_password_reset_code(self, email: str, reset_code: str, user_name: str = "User") -> bool:
        """Send password reset code via email."""
        if not self.fm:
            print(f"⚠️  Email not configured. Would send password reset code {reset_code} to {email}")
            return True  # Return True for development without email
            
        try:
            html_content = f"""
            <html>
                <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <div style="background-color: #f8f9fa; padding: 20px; border-radius: 10px;">
                        <h2 style="color: #333; text-align: center;">AuthX - Password Reset Code</h2>
                        <div style="background-color: white; padding: 30px; border-radius: 8px; margin: 20px 0;">
                            <p>Hello {user_name},</p>
                            <p>You requested to reset your password. Use the code below:</p>
                            <div style="text-align: center; margin: 30px 0;">
                                <span style="font-size: 32px; font-weight: bold; color: #dc3545; 
                                           background-color: #f8f9fa; padding: 15px 25px; 
                                           border-radius: 8px; letter-spacing: 5px;">{reset_code}</span>
                            </div>
                            <p>This code will expire in 15 minutes.</p>
                            <p>If you didn't request this, please ignore this email.</p>
                        </div>
                        <p style="text-align: center; color: #666; font-size: 12px;">
                            © 2024 AuthX. All rights reserved.
                        </p>
                    </div>
                </body>
            </html>
            """

            message = MessageSchema(
                subject="AuthX - Password Reset Code",
                recipients=[email],
                body=html_content,
                subtype=MessageType.html
            )

            await self.fm.send_message(message)
            return True
        except Exception as e:
            print(f"Failed to send password reset email: {e}")
            return False


# Global email manager instance
email_manager = EmailManager()


