"""
Session management utilities
"""

import secrets
import logging
from typing import Dict, Optional
from datetime import datetime, timedelta
from fastapi import Cookie, Header
from models.schemas import TokenPayload
from utils.jwt_utils import get_jwt_key_for_verification, get_jwt_algorithm
import jwt
from jwt import InvalidSignatureError, ExpiredSignatureError, DecodeError, InvalidAudienceError, InvalidIssuerError

logger = logging.getLogger(__name__)

# Global session storage (matching original implementation)
sessions: Dict[str, TokenPayload] = {}

# Cookie configuration (matching original)
COOKIE_NAME = "auth_session"
COOKIE_MAX_AGE = 3600  # 1 hour

def create_session(user_data: TokenPayload) -> str:
    """Create a new session for the user (matching original implementation)"""
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = user_data
    logger.info(f"✅ Created session {session_id[:8]}... for {user_data.email}")
    return session_id

def get_session(session_id: str) -> Optional[TokenPayload]:
    """Get session data by session ID (matching original implementation)"""
    return sessions.get(session_id)

def verify_session(session_cookie: Optional[str] = Cookie(default=None, alias=COOKIE_NAME)) -> Optional[TokenPayload]:
    """Verify session cookie (matching original implementation)"""
    if not session_cookie:
        return None
    return get_session(session_cookie)

def verify_jwt_token(authorization: Optional[str] = Header(default=None)) -> Optional[TokenPayload]:
    """Verify JWT token (matching original implementation)"""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    
    token = authorization.split(" ")[1]
    try:
        key = get_jwt_key_for_verification()
        algorithm = get_jwt_algorithm()
        payload = jwt.decode(token, key, algorithms=[algorithm])
        return TokenPayload(**payload)
    except (InvalidSignatureError, ExpiredSignatureError, DecodeError, InvalidAudienceError, InvalidIssuerError) as e:
        logger.debug(f"JWT validation failed: {e}")
        return None

def verify_user_auth(
    session_cookie: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
    authorization: Optional[str] = Header(default=None)
) -> Optional[TokenPayload]:
    """Verify user authentication via session or JWT (matching original implementation)"""
    user = verify_session(session_cookie) or verify_jwt_token(authorization)
    return user

def extract_jwt_token(authorization: Optional[str] = Header(default=None)) -> Optional[str]:
    """Extract raw JWT token from Authorization header (matching original implementation)"""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    return authorization.split(" ")[1]

def verify_session_direct(session_cookie) -> Optional[TokenPayload]:
    """Verify session cookie and return user data - for direct calls"""
    # Extract the actual cookie value if it's a Cookie object
    cookie_value = None
    if session_cookie is not None:
        if hasattr(session_cookie, 'value'):
            cookie_value = session_cookie.value
        elif isinstance(session_cookie, str):
            cookie_value = session_cookie
        else:
            cookie_value = str(session_cookie) if session_cookie else None
    
    if not cookie_value:
        return None
    
    user_data = get_session(cookie_value)
    if user_data:
        logger.debug(f"✅ Valid session for {user_data.email}")
        return user_data
    else:
        logger.debug(f"❌ Invalid session: {cookie_value[:8] if cookie_value else 'None'}...")
        return None

def verify_jwt_token_direct(authorization) -> Optional[TokenPayload]:
    """Verify JWT token from Authorization header - for direct calls"""
    # Extract the actual header value if it's a Header object
    auth_value = None
    if authorization is not None:
        if hasattr(authorization, 'value'):
            auth_value = authorization.value
        elif isinstance(authorization, str):
            auth_value = authorization
        else:
            auth_value = str(authorization) if authorization else None
    
    if not auth_value or not auth_value.startswith("Bearer "):
        return None
    
    try:
        import jwt
        from utils.jwt_utils import get_jwt_key_for_verification, get_jwt_algorithm
        
        token = auth_value.split(" ")[1]
        
        # Decode and verify token
        payload = jwt.decode(
            token,
            get_jwt_key_for_verification(),
            algorithms=[get_jwt_algorithm()]
        )
        
        # Create TokenPayload from decoded data
        user_data = TokenPayload(
            sub=payload['sub'],
            aud=payload['aud'],
            email=payload['email'],
            scope=payload.get('scope', ''),
            exp=payload['exp'],
            iat=payload['iat'],
            iss=payload['iss']
        )
        
        logger.debug(f"✅ Valid JWT token for {user_data.email}")
        return user_data
        
    except Exception as e:
        logger.debug(f"❌ Invalid JWT token: {e}")
        return None

async def verify_user_auth_optional_async(
    session_cookie: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
    authorization: Optional[str] = Header(default=None)
) -> Optional[TokenPayload]:
    """Async version of verify_user_auth_optional with proper FastAPI dependency injection"""
    # Try session first - use direct functions to avoid dependency injection issues
    user = verify_session_direct(session_cookie)
    if user:
        return user
    
    # Try JWT token
    user = verify_jwt_token_direct(authorization)
    if user:
        return user
    
    return None 