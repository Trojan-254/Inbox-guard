from fastapi import APIRouter, Request, Depends
from fastapi.responses import RedirectResponse, JSONResponse
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.users.crud import create_user_if_not_exists, get_user_by_email
from app.core.config import settings
from app.api.v1.endpoints.auth import create_access_token
from datetime import timedelta

router = APIRouter()

# Set up OAuth
config = Config('.env')
oauth = OAuth(config)
oauth.register(
    name='google',
    client_id=config('GOOGLE_CLIENT_ID'),
    client_secret=config('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

@router.get('/')
async def login_google(request: Request):
    redirect_uri = request.url_for('auth_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get('/callback', name="auth_callback")
async def auth_callback(request: Request, db: Session = Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = await oauth.google.parse_id_token(request, token)
        
        # Get user email and info
        email = user_info.get('email')
        name = user_info.get('name')
        google_id = user_info.get('sub')
        
        # Check if user exists, if not create them
        user = get_user_by_email(db, email)
        if not user:
            user = create_user(db, email, None, name, google_id)
        
        # Create access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token, expires = create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        
        # Return user data and token
        return JSONResponse({
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user_id": user.id,
            "name": user.name,
            "email": user.email
        })
    except Exception as e:
        print(f"Google OAuth Error: {str(e)}")
        return JSONResponse(
            {"detail": "Authentication failed"},
            status_code=400
        )