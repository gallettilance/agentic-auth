#!/usr/bin/env python3
"""
Chat UI Frontend
A lightweight Flask application that provides the chat interface.
Communicates with backend services (Llama Stack, Auth Server) via API calls.
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
import os
import secrets
import logging
import sys
from datetime import timedelta
import asyncio

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(16))

# Configure session settings to match auth server
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='chat_session',  # Different name to avoid conflicts with auth server
    SESSION_COOKIE_DOMAIN='localhost',
    SESSION_COOKIE_PATH='/',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_REFRESH_EACH_REQUEST=True
)

# Configuration - these will be moved to config files later
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
AUTH_SERVER_URL = os.getenv("AUTH_SERVER_URL", "http://localhost:8002")
LLAMA_STACK_URL = os.getenv("LLAMA_STACK_URL", "http://localhost:8321")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:5001/callback")

# Global variables for MCP token management
mcp_token_cache = {}  # Global cache for MCP tokens by user email
discovered_auth_servers = {}  # Cache for discovered auth servers

# Import API blueprints
from api.chat import chat_bp
from api.auth import auth_bp
from api.tokens import tokens_bp

# Register blueprints
app.register_blueprint(chat_bp, url_prefix='/api')
app.register_blueprint(auth_bp, url_prefix='/api')
app.register_blueprint(tokens_bp, url_prefix='/api')

def check_auth_server_session():
    """Check if user has valid session with auth server"""
    try:
        import httpx
        
        # Get auth session cookie
        auth_session_cookie = request.cookies.get('auth_session')
        if not auth_session_cookie:
            return None
        
        # Verify session with auth server
        with httpx.Client() as client:
            response = client.get(
                f"{AUTH_SERVER_URL}/api/user-status", 
                cookies={'auth_session': auth_session_cookie},
                timeout=5.0
            )
            
            if response.status_code == 200:
                user_data = response.json()
                if user_data.get('authenticated'):
                    return user_data['user']  # Return just the user data
        
        return None
    except Exception as e:
        logger.error(f"Error checking auth server session: {e}")
        return None

async def request_llama_stack_token(auth_cookies: dict = {}, auth_server_url: str | None = None) -> dict:
    """Request a Llama Stack token from auth server"""
    try:
        import httpx
        
        if not auth_server_url:
            auth_server_url = AUTH_SERVER_URL
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{auth_server_url}/api/initial-token",
                json={
                    "resource": LLAMA_STACK_URL,  # Changed from "audience" to "resource"
                    "scopes": []  # Start with empty scopes
                },
                cookies=auth_cookies,
                timeout=10.0
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"❌ Failed to get Llama Stack token: {response.status_code}")
                return {}
                
    except Exception as e:
        logger.error(f"❌ Error requesting Llama Stack token: {e}")
        return {}

@app.route('/')
def index():
    """Main page - check for authentication"""
    logger.info(f"🏠 Index page accessed")
    
    # Check if user has valid auth session cookie
    auth_session_cookie = request.cookies.get('auth_session')
    llama_stack_token = request.cookies.get('llama_stack_token')
    
    if auth_session_cookie and llama_stack_token:
        # User is authenticated with both auth session and Llama Stack token
        try:
            # Verify session with auth server
            import httpx
            with httpx.Client() as client:
                response = client.get(
                    f"{AUTH_SERVER_URL}/api/user-status", 
                    cookies={'auth_session': auth_session_cookie},
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    user_data = response.json()
                    if user_data.get('authenticated'):
                        auth_user = user_data['user']
                        logger.info(f"✅ Found valid session for {auth_user['email']}")
                        
                        # Set up local session
                        user_info = {
                            'sub': auth_user['sub'],
                            'email': auth_user['email'],
                            'name': auth_user['email'].split('@')[0]
                        }
                        
                        session['authenticated'] = True
                        session['bearer_token'] = llama_stack_token
                        session['mcp_tokens'] = {}
                        session['user_info'] = user_info
                        session['user_name'] = user_info['name']
                        session['user_email'] = user_info['email']
                        session.permanent = True
                        
                        return render_template('chat.html',
                                             user_name=session.get('user_name', 'User'),
                                             user_email=session.get('user_email', ''))
        except Exception as e:
            logger.error(f"Error verifying session: {e}")
    
    # No valid session - clear everything and show login
    logger.info("❌ No valid session found")
    session.clear()
    return render_template('login.html')

@app.route('/login')
def login():
    """Start OAuth flow - redirect to auth server with callback to chat app"""
    logger.info(f"🔐 Starting OAuth flow")
    import secrets
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    
    # Redirect to auth server OAuth with callback to chat app
    oauth_url = f"{AUTH_SERVER_URL}/auth/authorize?client_id=chat-ui&response_type=code&redirect_uri=http://localhost:5001/callback&state={state}&scope=llama_stack"
    return redirect(oauth_url)

@app.route('/callback')
def callback():
    """Handle OAuth callback and create Llama Stack token"""
    logger.info(f"🔍 OAuth callback received")
    
    code = request.args.get('code')
    state = request.args.get('state')
    
    # Verify state parameter
    if not state or state != session.get('oauth_state'):
        logger.error("❌ Invalid OAuth state")
        return redirect('/')
    
    if not code:
        logger.error("❌ No authorization code received")
        return redirect('/')
    
    try:
        # Exchange code for tokens via auth server
        import httpx
        with httpx.Client() as client:
            # First, complete OAuth flow with auth server
            response = client.post(
                f"{AUTH_SERVER_URL}/auth/token",
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': 'http://localhost:5001/callback',
                    'client_id': 'chat-ui'
                },
                timeout=10.0
            )
            
            if response.status_code == 200:
                token_data = response.json()
                auth_session_token = token_data.get('session_token')
                
                if auth_session_token:
                    # Now request Llama Stack token
                    llama_response = client.post(
                        f"{AUTH_SERVER_URL}/api/initial-token",
                        json={
                            "resource": LLAMA_STACK_URL,
                            "scopes": []
                        },
                        cookies={'auth_session': auth_session_token},
                        timeout=10.0
                    )
                    
                    if llama_response.status_code == 200:
                        llama_token_data = llama_response.json()
                        # Handle new response format
                        llama_stack_token = llama_token_data.get('token')  # Changed from 'access_token' to 'token'
                        
                        if llama_stack_token:
                            # Set cookies and redirect to chat
                            response = make_response(redirect('/'))
                            response.set_cookie(
                                'auth_session',
                                auth_session_token,
                                max_age=3600,
                                httponly=True,
                                secure=False,
                                samesite='lax'
                            )
                            response.set_cookie(
                                'llama_stack_token',
                                llama_stack_token,
                                max_age=3600,
                                httponly=False,  # Allow JavaScript access for admin dashboard
                                secure=False,
                                samesite='lax'
                            )
                            logger.info("✅ OAuth flow completed successfully")
                            return response
                        else:
                            logger.error(f"❌ No token in response: {llama_token_data}")
                    else:
                        logger.error(f"❌ Failed to get Llama Stack token: {llama_response.status_code} - {llama_response.text}")
                else:
                    logger.error("❌ No auth session token received")
            
            logger.error(f"❌ OAuth token exchange failed: {response.status_code}")
            
    except Exception as e:
        logger.error(f"❌ OAuth callback error: {e}")
    
    # If we get here, something went wrong
    return redirect('/')

@app.route('/logout')
def logout():
    """Logout and clear session"""
    # Clear local session
    session.clear()
    
    # Clear cookies and redirect to auth server logout
    response = make_response(redirect(f"{AUTH_SERVER_URL}/auth/logout"))
    response.set_cookie('auth_session', '', expires=0)
    response.set_cookie('llama_stack_token', '', expires=0)
    return response

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'chat-ui',
        'version': '1.0.0'
    })

def get_base_mcp_url(mcp_server_url: str) -> str:
    """Get base MCP URL by stripping /sse suffix if present"""
    if mcp_server_url.endswith('/sse'):
        return mcp_server_url[:-4]
    return mcp_server_url

def get_mcp_tokens_for_user(user_email: str) -> dict:
    """Get MCP tokens for a user from session or cache"""
    # Try session first
    try:
        session_tokens = session.get('mcp_tokens', {})
        if session_tokens:
            logger.info(f"🔐 Found {len(session_tokens)} MCP tokens in session for {user_email}")
            return session_tokens
    except RuntimeError:
        # Not in request context
        pass
    
    # Fall back to cache
    cache_tokens = mcp_token_cache.get(user_email, {})
    if cache_tokens:
        logger.info(f"🔐 Found {len(cache_tokens)} MCP tokens in cache for {user_email}")
    else:
        logger.info(f"🔐 No MCP tokens found for {user_email}")
    
    return cache_tokens

def store_mcp_token_for_user(user_email: str, server_url: str, token: str):
    """Store MCP token for a user in both session and cache"""
    # Always use base URL as key (strip /sse if present)
    base_server_url = get_base_mcp_url(server_url)
    
    # Store in session if possible
    try:
        if 'mcp_tokens' not in session:
            session['mcp_tokens'] = {}
        session['mcp_tokens'][base_server_url] = token
        logger.info(f"✅ Stored MCP token in session for {user_email} -> {base_server_url}")
        
        # Also store the latest MCP token in a cookie for admin dashboard access
        # Note: This is only done for the primary MCP server configured in environment
        primary_mcp_server = os.getenv('MCP_SERVER_URL')
        if primary_mcp_server and base_server_url == primary_mcp_server:
            from flask import make_response, g
            
            # Check if we're in a request context that can set cookies
            try:
                # Store in a thread-local variable to be set as cookie in the response
                if not hasattr(g, 'mcp_token_to_set'):
                    g.mcp_token_to_set = token
                    logger.info(f"✅ Marked MCP token for cookie storage: {token[:20]}...")
            except Exception as e:
                logger.warning(f"⚠️ Could not mark MCP token for cookie: {e}")
                
    except RuntimeError:
        # Not in request context
        logger.info(f"⚠️ Could not store MCP token in session (no request context)")
    
    # Always store in cache as backup
    if user_email not in mcp_token_cache:
        mcp_token_cache[user_email] = {}
    mcp_token_cache[user_email][base_server_url] = token
    logger.info(f"✅ Stored MCP token in cache for {user_email} -> {base_server_url}")

if __name__ == '__main__':
    logger.info("🚀 Starting Chat UI Frontend...")
    app.run(host='0.0.0.0', port=5001, debug=True) 