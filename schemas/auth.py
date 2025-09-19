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

# Password Reset Schemas
class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
    
    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not re.search(r'[A-Za-z]', v):
            raise ValueError('Password must contain at least one letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one number')
        return v

class UserUpdate(BaseModel):
    name: str
    
    @validator('name')
    def validate_name(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Name is required and cannot be empty')
        
        name = v.strip()
        if len(name) > 30:
            raise ValueError('Name must be 30 characters or less')
        
        return name

class AvatarUpdate(BaseModel):
    avatar_url: str
    
    @validator('avatar_url')
    def validate_avatar_url(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Avatar URL is required and cannot be empty')
        
        url = v.strip()
        
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            raise ValueError('Avatar URL must be a valid HTTP or HTTPS URL')
        
        # Check if it's a Cloudinary URL (optional validation)
        if 'cloudinary.com' not in url and 'res.cloudinary.com' not in url:
            # Allow other valid URLs but warn
            pass
        
        return url