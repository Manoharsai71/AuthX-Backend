from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from models.base import Base


class SessionHistory(Base):
    __tablename__ = "session_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Session details
    session_id = Column(String(255), unique=True, index=True, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(1000), nullable=True)
      
    # Enhanced device details
    browser_name = Column(String(100), nullable=True)
    browser_version = Column(String(100), nullable=True)
    os_name = Column(String(100), nullable=True)
    os_version = Column(String(100), nullable=True)
    device_type = Column(String(50), nullable=True)  # Desktop, Mobile, Tablet, Bot
    device_brand = Column(String(100), nullable=True)
    device_model = Column(String(100), nullable=True)
    
    # Location details
    location = Column(String(255), nullable=True)  # City, Country
    country = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    region = Column(String(100), nullable=True)
    timezone = Column(String(100), nullable=True)
    
    # Additional location data (stored as JSON)
    location_data = Column(JSON, nullable=True)
    
    # Login method
    login_method = Column(String(50), nullable=False)  # password, google, github, magic_link, otp
    
    # Session status
    is_active = Column(Boolean, default=True)
    logout_reason = Column(String(100), nullable=True)  # manual, expired, revoked, security
    
    # Timestamps
    login_at = Column(DateTime(timezone=True), server_default=func.now())
    logout_at = Column(DateTime(timezone=True), nullable=True)
    last_activity = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User", back_populates="session_history")

    def __repr__(self):
        return f"<SessionHistory(id={self.id}, user_id={self.user_id}, session_id='{self.session_id}')>"