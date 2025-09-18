from fastapi import Depends, HTTPException, status, APIRouter, Response
from fastapi.security import HTTPBearer
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from database import get_db
from models.auth import User
from schemas.auth import UserResponse, UserCreate, UserLogin
from schemas.response import APIResponse
import jwt
import os
from datetime import datetime, timedelta
from urllib.parse import quote
import requests
from typing import Optional
from passlib.context import CryptContext
from pydantic import ValidationError

security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter()

DATABASE_URL = os.getenv("DATABASE_URL")
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
SECRET_KEY = os.getenv("SECRET_KEY")
FRONTEND_URL = os.getenv("FRONTEND_URL")  # Your Next.js frontend URL

# Password hashing functions
def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)

# JWT functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("sub")
        provider = payload.get("provider", "github")  # Default to github for backward compatibility
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        return user_id, provider
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

# Dependency to get current user
async def get_current_user(token: str = Depends(security), db: Session = Depends(get_db)):
    user_id, provider = verify_token(token.credentials)
    
    # Query user based on provider type
    if provider == "email":
        # For email authentication, user_id is the actual database ID
        user = db.query(User).filter(
            User.id == int(user_id),
            User.provider == provider
        ).first()
    else:
        # For OAuth providers, use provider_id
        user = db.query(User).filter(
            User.provider_id == str(user_id),
            User.provider == provider
        ).first()
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    return user

# OAuth2 routes
@router.get("/github")
async def github_login():
    """Redirect to GitHub OAuth"""
    callback_url = "http://localhost:8000/auth/github/callback"  # Match GitHub OAuth setup
    github_auth_url = (
        f"https://github.com/login/oauth/authorize?"
        f"client_id={GITHUB_CLIENT_ID}&"
        f"redirect_uri={callback_url}&"
        f"scope=user:email"
    )
    return RedirectResponse(github_auth_url)

@router.get("/github/callback")
async def github_callback(code: str, db: Session = Depends(get_db)):
    """Handle GitHub OAuth callback"""
    
    # Exchange authorization code for access token
    token_url = "https://github.com/login/oauth/access_token"
    token_data = {
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code,
    }
    
    token_headers = {"Accept": "application/json"}
    token_response = requests.post(token_url, data=token_data, headers=token_headers)
    
    if token_response.status_code != 200:
        error_message = "Failed to exchange authorization code for token"
        frontend_redirect_url = f"{FRONTEND_URL}/success?error=auth_failed&message={quote(error_message)}"
        return RedirectResponse(frontend_redirect_url)
    
    token_json = token_response.json()
    access_token = token_json.get("access_token")
    
    if not access_token:
        error_message = "No access token received from GitHub"
        frontend_redirect_url = f"{FRONTEND_URL}/success?error=auth_failed&message={quote(error_message)}"
        return RedirectResponse(frontend_redirect_url)
    
    # Get user information from GitHub
    user_headers = {"Authorization": f"Bearer {access_token}"}
    user_response = requests.get("https://api.github.com/user", headers=user_headers)
    
    if user_response.status_code != 200:
        error_message = "Failed to get user information from GitHub"
        frontend_redirect_url = f"{FRONTEND_URL}/success?error=auth_failed&message={quote(error_message)}"
        return RedirectResponse(frontend_redirect_url)
    
    user_data = user_response.json()
    
    # Get user email (might be private)
    email_response = requests.get("https://api.github.com/user/emails", headers=user_headers)
    emails = email_response.json() if email_response.status_code == 200 else []
    primary_email = next((email["email"] for email in emails if email["primary"]), None)
    
    # Fallback to public email if primary email not found
    if not primary_email:
        primary_email = user_data.get("email", f"{user_data['login']}@users.noreply.github.com")
    
    # Create or update user in database
    user = db.query(User).filter(
        User.provider_id == str(user_data["id"]),
        User.provider == "github"
    ).first()
    
    if not user:
        # Check if user exists with same email but different provider
        existing_user = db.query(User).filter(User.email == primary_email).first()
        if existing_user:
            # Redirect to frontend with error instead of throwing exception
            error_message = f"Email {primary_email} is already registered with {existing_user.provider.title()}. Please use {existing_user.provider.title()} to sign in or use a different email address."
            frontend_redirect_url = f"{FRONTEND_URL}/success?error=email_conflict&message={quote(error_message)}"
            return RedirectResponse(frontend_redirect_url)
        
        user = User(
            provider_id=str(user_data["id"]),
            username=user_data["login"],
            email=primary_email,  # Now guaranteed to have a value
            avatar_url=user_data.get("avatar_url", ""),
            name=user_data.get("name", ""),
            provider="github"
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Update existing user
        user.username = user_data["login"]
        user.email = primary_email  # Now guaranteed to have a value
        user.avatar_url = user_data.get("avatar_url", "")
        user.name = user_data.get("name", "")
        db.commit()
    
    # Create JWT token
    access_token_expires = timedelta(days=7)
    jwt_token = create_access_token(
        data={"sub": user.provider_id, "provider": "github"}, expires_delta=access_token_expires
    )
    
    # Redirect to frontend with token
    frontend_redirect_url = f"{FRONTEND_URL}/success?token={jwt_token}"
    return RedirectResponse(frontend_redirect_url)

# Google OAuth2 routes
@router.get("/google")
async def google_login():
    """Redirect to Google OAuth"""
    callback_url = "http://localhost:8000/auth/google/callback"  # Match OAuth setup
    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/auth?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={callback_url}&"
        f"scope=openid email profile&"
        f"response_type=code&"
        f"access_type=offline"
    )
    return RedirectResponse(google_auth_url)

@router.get("/google/callback")
async def google_callback(code: str, db: Session = Depends(get_db)):
    """Handle Google OAuth callback"""
    
    # Exchange authorization code for access token
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": "http://localhost:8000/auth/google/callback"
    }
    
    token_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    token_response = requests.post(token_url, data=token_data, headers=token_headers)
    
    if token_response.status_code != 200:
        error_message = "Failed to exchange authorization code for token"
        frontend_redirect_url = f"{FRONTEND_URL}/success?error=auth_failed&message={quote(error_message)}"
        return RedirectResponse(frontend_redirect_url)
    
    token_json = token_response.json()
    access_token = token_json.get("access_token")
    
    if not access_token:
        error_message = "No access token received from Google"
        frontend_redirect_url = f"{FRONTEND_URL}/success?error=auth_failed&message={quote(error_message)}"
        return RedirectResponse(frontend_redirect_url)
    
    # Get user information from Google
    user_headers = {"Authorization": f"Bearer {access_token}"}
    user_response = requests.get("https://www.googleapis.com/oauth2/v2/userinfo", headers=user_headers)
    
    if user_response.status_code != 200:
        error_message = "Failed to get user information from Google"
        frontend_redirect_url = f"{FRONTEND_URL}/success?error=auth_failed&message={quote(error_message)}"
        return RedirectResponse(frontend_redirect_url)
    
    user_data = user_response.json()
    print("user_data from google")
    print(user_data)
    # Create or update user in database
    user = db.query(User).filter(
        User.provider_id == user_data["id"],
        User.provider == "google"
    ).first()
    
    if not user:
        # Check if user exists with same email but different provider
        existing_user = db.query(User).filter(User.email == user_data["email"]).first()
        if existing_user:
            # Redirect to frontend with error instead of throwing exception
            error_message = f"Email {user_data['email']} is already registered with {existing_user.provider.title()}. Please use {existing_user.provider.title()} to sign in or use a different email address."
            frontend_redirect_url = f"{FRONTEND_URL}/success?error=email_conflict&message={quote(error_message)}"
            return RedirectResponse(frontend_redirect_url)
        else:
            # Create new user
            user = User(
                provider_id=user_data["id"],
                username=user_data.get("name", user_data["email"].split("@")[0]),
                email=user_data["email"],
                avatar_url=user_data.get("picture", ""),
                name=user_data.get("name", ""),
                provider="google"
            )
            db.add(user)
            db.commit()
            db.refresh(user)
    else:
        # Update existing user
        user.username = user_data.get("name", user_data["email"].split("@")[0])
        user.email = user_data["email"]
        user.avatar_url = user_data.get("picture", "")
        user.name = user_data.get("name", "")
        db.commit()
    
    # Create JWT token
    access_token_expires = timedelta(days=7)
    jwt_token = create_access_token(
        data={"sub": user.provider_id, "provider": "google"}, expires_delta=access_token_expires
    )
    
    # Redirect to frontend with token
    frontend_redirect_url = f"{FRONTEND_URL}/success?token={jwt_token}"
    return RedirectResponse(frontend_redirect_url)

# Protected routes
@router.get("/me", response_model=APIResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return APIResponse(
        status="success",
        message="User information retrieved successfully",
        data=UserResponse.from_orm(current_user).dict()
    )

@router.post("/logout", response_model=APIResponse)
async def logout():
    """Logout endpoint (client should remove token)"""
    return APIResponse(
        status="success",
        message="Successfully logged out",
        data=None
    )


# Email register and Login
@router.post("/register", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, response: Response, db: Session = Depends(get_db)):
    """Register a new user with email and password"""
    try:
        # Check if user already exists
        existing_user = db.query(User).filter(User.email == user_data.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "status": "fail",
                    "message": "Email already registered. Please use a different email or try logging in.",
                    "data": None
                }
            )
        
        # Create new user
        hashed_password = hash_password(user_data.password)
        new_user = User(
            email=user_data.email,
            password_hash=hashed_password,
            provider="email",
            username=user_data.email.split("@")[0],  # Default username from email
            name=None,
            provider_id=None
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        # Create JWT token
        access_token_expires = timedelta(days=7)
        jwt_token = create_access_token(
            data={"sub": str(new_user.id), "provider": "email"}, 
            expires_delta=access_token_expires
        )
        
        # RESTful: 201 Created for successful resource creation
        response.status_code = status.HTTP_201_CREATED
        return APIResponse(
            status="success",
            message="User registered successfully",
            data={
                "user": UserResponse.from_orm(new_user).dict(),
                "access_token": jwt_token,
                "token_type": "bearer"
            }
        )
        
    except HTTPException:
        raise  # Re-raise HTTP exceptions (like our 409 Conflict)
    except ValidationError as e:
        error_msg = str(e.errors()[0]['msg']) if e.errors() else "Validation failed"
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "status": "fail",
                "message": f"Validation error: {error_msg}",
                "data": {"errors": e.errors()}
            }
        )
    except Exception as e:
        print(f"Registration error: {str(e)}")  # Debug logging
        import traceback
        traceback.print_exc()  # Print full stack trace
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "status": "fail",
                "message": f"Registration failed: {str(e)}",
                "data": None
            }
        )

@router.post("/login", response_model=APIResponse, status_code=status.HTTP_200_OK)
async def login(user_credentials: UserLogin, db: Session = Depends(get_db)):
    """Login user with email and password"""
    try:
        # Find user by email
        user = db.query(User).filter(
            User.email == user_credentials.email,
            User.provider == "email"
        ).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "status": "fail",
                    "message": "Invalid email or password",
                    "data": None
                }
            )
        
        # Verify password
        if not user.password_hash or not verify_password(user_credentials.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "status": "fail",
                    "message": "Invalid email or password",
                    "data": None
                }
            )
        
        # Create JWT token
        access_token_expires = timedelta(days=7)
        jwt_token = create_access_token(
            data={"sub": str(user.id), "provider": "email"}, 
            expires_delta=access_token_expires
        )
        
        # RESTful: 200 OK for successful login
        return APIResponse(
            status="success",
            message="Login successful",
            data={
                "user": UserResponse.from_orm(user).dict(),
                "access_token": jwt_token,
                "token_type": "bearer"
            }
        )
        
    except HTTPException:
        raise  # Re-raise HTTP exceptions
    except Exception as e:
        print(f"Login error: {str(e)}")  # Debug logging
        import traceback
        traceback.print_exc()  # Print full stack trace
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "status": "fail",
                "message": f"Login failed: {str(e)}",
                "data": None
            }
        )