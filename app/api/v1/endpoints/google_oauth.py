"""
Google OAuth authentication endpoints
"""
import logging
from typing import Dict, Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db
from app.db.models import User
from app.api.v1.endpoints.auth import create_access_token, get_user_by_email, create_user, update_user_last_login, create_audit_log

logger = logging.getLogger(__name__)
router = APIRouter()

# Configure OAuth
config = Config(environ={"GOOGLE_CLIENT_ID": settings.GOOGLE_CLIENT_ID, 
                        "GOOGLE_CLIENT_SECRET": settings.GOOGLE_CLIENT_SECRET})
oauth = OAuth(config)

REDIRECT_URI = "https://inbox-guard.online/api/v1/auth/google/callback"
if REDIRECT_URI.startswith("http://"):
    REDIRECT_URI = REDIRECT_URI.replace("http://", "https://")

google = oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    client_kwargs={
        "scope": "openid email profile",
        "redirect_uri": REDIRECT_URI
    }
)

# In your google_oauth.py
REDIRECT_URI = "https://inbox-guard.online/api/v1/auth/google/callback"  # Hardcoded HTTPS

@router.get("/login")
async def login(request: Request):
    """Modified login endpoint"""
    # Verify we're getting the correct host
    if request.headers.get('host') != "inbox-guard.online":
        raise HTTPException(400, "Invalid host header")
    
    # Generate secure callback URL
    callback_url = request.url_for("google_auth")
    if str(callback_url).startswith('http://'):
        callback_url = str(callback_url).replace('http://', 'https://')
    
    logger.info(f"OAuth initiated with callback: {callback_url}")
    return await google.authorize_redirect(request, str(callback_url))

    
@router.get("/callback")
async def google_auth(request: Request, db: Session = Depends(get_db)):
    """Handle Google OAuth callback"""
    try:
        token = await google.authorize_access_token(request)
        
        # Use userinfo endpoint
        resp = await google.get('https://www.googleapis.com/oauth2/v1/userinfo', token=token)
        user_info = resp.json()
        
        # Extract user data
        email = user_info.get("email")
        name = user_info.get("name") or f"{user_info.get('given_name', '')} {user_info.get('family_name', '')}"
        google_id = user_info.get("id")
        
        if not email or not google_id:
            # Redirect to frontend with error
            return RedirectResponse(url=f"{settings.FRONTEND_URL}/login?error=Could not retrieve necessary information from Google")
        
        # Check if user exists by email
        user = get_user_by_email(db, email=email)
        if not user:
            # Create new user
            user = create_user(
                db=db,
                email=email,
                password=None,  # No password for Google auth users
                name=name,
                google_id=google_id
            )
            # Log user registration
            create_audit_log(db, user.id, "user_registered", {"registration_method": "google"})
        elif not user.google_id:
            # User exists but wasn't registered with Google - update to add Google ID
            user.google_id = google_id
            db.commit()
        
        # Update last login time
        update_user_last_login(db, user.id)
        
        # Create audit log
        create_audit_log(db, user.id, "user_login", {"login_method": "google"})
        
        # Create access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token, expires = create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        
        # Construct a URL with token parameters
        frontend_auth_callback_url = f"{settings.FRONTEND_URL}/auth-callback?access_token={access_token}&token_type=bearer&expires_in={settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60}&user_id={user.id}&name={user.name}&email={user.email}"
        
        return RedirectResponse(url=frontend_auth_callback_url)
    
    except Exception as e:
        logger.exception(f"Google authentication error: {str(e)}")
        return RedirectResponse(url=f"{settings.FRONTEND_URL}/login?error=Authentication failed")