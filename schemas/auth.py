from pydantic import BaseModel
from pydantic import EmailStr
import re
from pydantic import validator


class UserResponse(BaseModel):
    id: int
    provider_id: str | None  # Unified ID for all providers
    username: str | None
    email: str  # Email is always required
    avatar_url: str | None  # Allow None values
    name: str | None  # Allow None values
    provider: str | None  # "github" or "google"
    
    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Za-z]', v):
            raise ValueError('Password must contain at least one letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one number')
        return v

class UserLogin(BaseModel):
    email: str
    password: str