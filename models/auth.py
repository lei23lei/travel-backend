from sqlalchemy import Column, Integer, String, DateTime, Boolean
from datetime import datetime
from database import Base, engine

# User model
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    provider_id = Column(String, nullable=True, index=True)  # OAuth provider user ID
    username = Column(String, nullable=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)  # Required for login
    password_hash = Column(String, nullable=True)  # For email/password login (hashed)
    avatar_url = Column(String, nullable=True)
    name = Column(String, nullable=True)
    provider = Column(String, nullable=True)  # "github", "google", or "email"
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

# Create tables
Base.metadata.create_all(bind=engine)