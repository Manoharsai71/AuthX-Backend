from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from models.base import Base


class MagicLink(Base):
    __tablename__ = "magic_links"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Magic link details
    token = Column(String(255), unique=True, index=True, nullable=False)
    purpose = Column(String(50), nullable=False)  # login, registration, password_reset
    
    # Request details
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(1000), nullable=True)
    
    # Status
    is_used = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="magic_links")

    def __repr__(self):
        return f"<MagicLink(id={self.id}, user_id={self.user_id}, purpose='{self.purpose}')>"