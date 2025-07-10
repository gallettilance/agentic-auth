"""
Authentication routes for OAuth, login, logout, etc.
"""

import logging
from fastapi import APIRouter, HTTPException, Request, Response, Form, Depends, Cookie
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from auth.session_manager import create_session, verify_user_auth, COOKIE_NAME, COOKIE_MAX_AGE, sessions
from models.schemas import TokenPayload
from config.settings import SERVER_URI, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_DISCOVERY_URL
from datetime import datetime, timedelta
from database import auth_db
import httpx
import jwt

logger = logging.getLogger(__name__)
router = APIRouter()

# Simple OAuth configuration (matching original)
REDIRECT_URI = f"{SERVER_URI}/auth/callback"

@router.get("/login")
async def login():
    """OAuth login endpoint - redirects to Google OAuth (matching original implementation)"""
    oauth_url = f"https://accounts.google.com/o/oauth2/v2/auth?client_id={GOOGLE_CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope=openid%20email&state=auth_state"
    return RedirectResponse(url=oauth_url)

@router.get("/authorize")
async def oauth_authorize(
    client_id: str,
    response_type: str,
    scope: str = "",
    redirect_uri: str = "",
    state: str = ""
):
    """OAuth authorize endpoint - handle different clients properly"""
    logger.info(f"🔐 OAuth authorize request: client_id={client_id}, redirect_uri={redirect_uri}")
    
    # Store the original OAuth request parameters in the state for the callback
    import urllib.parse
    import json
    
    # Encode the original request in the Google OAuth state parameter
    original_request = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'state': state,
        'scope': scope
    }
    
    # Encode as URL-safe JSON
    encoded_request = urllib.parse.quote(json.dumps(original_request))
    google_state = f"oauth_request:{encoded_request}"
    
    # Redirect to Google OAuth with encoded state
    oauth_url = f"https://accounts.google.com/o/oauth2/v2/auth?client_id={GOOGLE_CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope=openid%20email&state={google_state}"
    return RedirectResponse(url=oauth_url)

@router.get("/callback")
async def oauth_callback(code: str, state: str):
    """OAuth callback handler - redirect back to original client"""
    try:
        # Check if this is an encoded OAuth request
        original_request = None
        if state.startswith("oauth_request:"):
            try:
                import urllib.parse
                import json
                encoded_request = state.replace("oauth_request:", "")
                decoded_request = urllib.parse.unquote(encoded_request)
                original_request = json.loads(decoded_request)
                logger.info(f"🔍 Decoded original OAuth request: {original_request}")
            except Exception as e:
                logger.error(f"❌ Failed to decode OAuth request: {e}")
        
        # Get Google's token endpoint from discovery document
        async with httpx.AsyncClient() as client:
            discovery_response = await client.get(GOOGLE_DISCOVERY_URL)
            discovery_data = discovery_response.json()
            token_endpoint = discovery_data["token_endpoint"]
        
        # Exchange code for token (simplified)
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                token_endpoint,
                data={
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": REDIRECT_URI
                }
            )
            
            if token_response.status_code != 200:
                raise HTTPException(status_code=400, detail="Token exchange failed")
            
            tokens = token_response.json()
            id_token = tokens.get("id_token")
            
            # Verify and decode ID token (simplified)
            payload = jwt.decode(id_token, options={"verify_signature": False})
            
            user_email = payload.get("email")
            if not user_email:
                raise HTTPException(status_code=400, detail="No email in token")
            
            # Create or get user from database
            db_user = auth_db.get_user(user_email)
            user_status = "existing"
            if not db_user:
                # Create new user with default role
                auth_db.create_user(user_email, ["user"])
                db_user = auth_db.get_user(user_email)
                user_status = "new"
                logger.info(f"👤 NEW USER: {user_email} created with role 'user' - will start with empty scope per RFC 8693")
            else:
                logger.info(f"👤 EXISTING USER: {user_email} logged in - permissions reset to empty scope per RFC 8693")
            
            # Create session with EMPTY scope per RFC 8693 Token Exchange protocol
            # Use a timestamp slightly in the past to account for clock skew
            import time
            now_timestamp = int(time.time())  # Always UTC
            iat_timestamp = now_timestamp - 5  # 5 seconds in the past
            exp_timestamp = now_timestamp + 3600  # 1 hour in the future
            
            logger.info(f"🕐 Token Generation Debug - now: {now_timestamp}, iat: {iat_timestamp}, exp: {exp_timestamp}")
            logger.info(f"🕐 Time diff - iat is {now_timestamp - iat_timestamp} seconds in the past")
            
            user_data = TokenPayload(
                sub=user_email,
                aud=SERVER_URI,
                email=user_email,
                scope="",  # Start with no permissions - RFC 8693 compliance
                exp=exp_timestamp,
                iat=iat_timestamp,  # 5 seconds in the past to prevent clock skew
                iss=SERVER_URI
            )
            
            logger.info(f"🔐 User session token created with empty scope (RFC 8693 compliant): {user_email}")
            
            # Generate ONLY Llama Stack token initially
            # MCP tokens will be generated after querying toolgroups
            
            session_id = create_session(user_data)
            
            # Determine where to redirect based on the original request
            if original_request and original_request.get('client_id') == 'chat-ui':
                # For chat-ui, generate authorization code and redirect back to chat
                import secrets
                auth_code = secrets.token_urlsafe(32)
                
                # Store authorization code (in production, use database)
                if not hasattr(oauth_callback, 'auth_codes'):
                    oauth_callback.auth_codes = {}
                
                oauth_callback.auth_codes[auth_code] = {
                    'user_data': user_data,
                    'session_id': session_id,
                    'created_at': now_timestamp
                }
                
                # Redirect back to chat UI with authorization code
                redirect_url = f"{original_request['redirect_uri']}?code={auth_code}&state={original_request['state']}"
                logger.info(f"✅ Redirecting chat-ui back to: {redirect_url}")
                return RedirectResponse(url=redirect_url)
            elif original_request and original_request.get('client_id') == 'admin-dashboard':
                # For admin-dashboard, redirect back to admin dashboard with session cookie
                redirect_url = original_request.get('redirect_uri', 'http://localhost:8003/dashboard')
                if '?' in redirect_url:
                    redirect_url += f"&state={original_request['state']}"
                else:
                    redirect_url += f"?state={original_request['state']}"
                
                response = RedirectResponse(url=redirect_url)
                response.set_cookie(
                    key=COOKIE_NAME,
                    value=session_id,
                    max_age=COOKIE_MAX_AGE,
                    httponly=True,
                    samesite="lax",
                    domain="localhost"
                )
                logger.info(f"✅ Redirecting admin-dashboard back to: {redirect_url}")
                return response
            else:
                # Default behavior - redirect to admin dashboard
                response = RedirectResponse(url="http://localhost:8003/dashboard")
                response.set_cookie(
                    key=COOKIE_NAME,
                    value=session_id,
                    max_age=COOKIE_MAX_AGE,
                    httponly=True,
                    samesite="lax",
                    domain="localhost"
                )
                return response
            
    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed")

@router.get("/logout")
async def logout(session_cookie: str = Cookie(default=None, alias=COOKIE_NAME)):
    """Logout endpoint (matching original implementation)"""
    if session_cookie and session_cookie in sessions:
        user_data = sessions[session_cookie]
        del sessions[session_cookie]
        logger.info(f"👋 User {user_data.email} logged out")
    
    response = RedirectResponse(url="/")
    response.delete_cookie(COOKIE_NAME, domain="localhost")
    return response

@router.post("/token")
async def oauth_token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(default="")
):
    """OAuth token endpoint - exchange authorization code for tokens"""
    
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant type")
    
    # Check if we have authorization codes stored (from callback)
    if hasattr(oauth_callback, 'auth_codes') and code in oauth_callback.auth_codes:
        auth_code_data = oauth_callback.auth_codes[code]
        
        # Check if code is expired (5 minutes)
        import time
        if (time.time() - auth_code_data['created_at']) > 300:
            del oauth_callback.auth_codes[code]
            raise HTTPException(status_code=400, detail="Authorization code expired")
        
        # Get user data and session ID
        session_id = auth_code_data['session_id']
        
        # Clean up used authorization code
        del oauth_callback.auth_codes[code]
        
        # Return session token for chat-ui
        return {
            "session_token": session_id,
            "token_type": "Bearer",
            "expires_in": 3600
        }
    else:
        # Fallback - generate a simple session token
        import secrets
        session_token = secrets.token_urlsafe(32)
        
        return {
            "access_token": session_token,
            "token_type": "Bearer",
            "expires_in": 3600
        } 