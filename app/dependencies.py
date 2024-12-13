from builtins import Exception, dict, str
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import Database
from app.utils.template_manager import TemplateManager
from app.services.email_service import EmailService
from app.services.jwt_service import decode_token
from settings.config import Settings
from fastapi import Depends
from app.schemas.user_schemas import UserProfileUpdate  # Import UserProfileUpdate schema

def get_settings() -> Settings:
    """Return application settings."""
    return Settings()

def get_email_service() -> EmailService:
    template_manager = TemplateManager()
    return EmailService(template_manager=template_manager)

async def get_db() -> AsyncSession:
    """Dependency that provides a database session for each request."""
    async_session_factory = Database.get_session_factory()
    async with async_session_factory() as session:
        try:
            yield session
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_token(token)
    if payload is None:
        raise credentials_exception
    user_id: str = payload.get("sub")
    user_role: str = payload.get("role")
    if user_id is None or user_role is None:
        raise credentials_exception
    return {"user_id": user_id, "role": user_role}

def require_role(role: str):
    def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user["role"] not in role:
            raise HTTPException(status_code=403, detail="Operation not permitted")
        return current_user
    return role_checker

# New Dependency to update profile
async def get_profile_update_data(profile_data: dict = Depends(UserProfileUpdate)):
    """Dependency to validate and provide profile update data."""
    try:
        profile = UserProfileUpdate(**profile_data)  # Use the schema for validation
        return profile
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid profile update data: {str(e)}")
