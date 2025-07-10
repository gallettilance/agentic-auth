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
from typing import Optional

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

# MCP service discovery now happens dynamically after OAuth

# Import API blueprints
from api.chat import chat_bp
from api.auth import auth_bp
from api.tokens import tokens_bp

# Register blueprints
app.register_blueprint(chat_bp, url_prefix='/api')
app.register_blueprint(auth_bp, url_prefix='/api')
app.register_blueprint(tokens_bp, url_prefix='/api')

# MCP discovery moved to OAuth callback flow - happens dynamically 
# after authentication when we have Llama Stack access

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
        
        # Use default auth server for Llama Stack (MCP discovery only for now)
        if not auth_server_url:
            auth_server_url = AUTH_SERVER_URL
            logger.info(f"🔍 Using default auth server for Llama Stack: {auth_server_url}")
        
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
                            logger.info("✅ Llama Stack token obtained")
                            
                            # Now discover MCP servers from Llama Stack toolgroups
                            try:
                                logger.info("🔍 Starting MCP server discovery from Llama Stack toolgroups")
                                
                                # Query Llama Stack for toolgroups
                                toolgroups_response = client.get(
                                    f"{LLAMA_STACK_URL}/v1/toolgroups",
                                    headers={"Authorization": f"Bearer {llama_stack_token}"},
                                    timeout=10.0
                                )
                                
                                logger.info(f"🔍 DEBUG: Toolgroups response status: {toolgroups_response.status_code}")
                                
                                if toolgroups_response.status_code == 200:
                                    toolgroups_data = toolgroups_response.json()
                                    logger.info(f"✅ Found toolgroups response")
                                    logger.info(f"🔍 DEBUG: Toolgroups data: {toolgroups_data}")
                                    
                                    # Extract toolgroups from the 'data' field
                                    toolgroups_list = toolgroups_data.get('data', [])
                                    logger.info(f"🔍 Found {len(toolgroups_list)} toolgroups in data")
                                    
                                    # Extract MCP server URLs from toolgroups
                                    mcp_server_urls = []
                                    for i, toolgroup in enumerate(toolgroups_list):
                                        logger.info(f"🔍 DEBUG: Processing toolgroup {i}: {toolgroup}")
                                        
                                        # Toolgroup must be a dict with identifier starting with 'mcp::'
                                        if not isinstance(toolgroup, dict):
                                            logger.error(f"❌ CONFIGURATION ERROR: Toolgroup {i} is not a dict: {type(toolgroup)}")
                                            continue
                                        
                                        toolgroup_id = toolgroup.get('identifier', '')
                                        if not toolgroup_id.startswith('mcp::'):
                                            logger.info(f"🔍 DEBUG: Skipping non-MCP toolgroup: {toolgroup_id}")
                                            continue
                                        
                                        logger.info(f"🔍 DEBUG: Found MCP toolgroup: {toolgroup_id}")
                                        
                                        # MCP server URL is in mcp_endpoint.uri
                                        mcp_endpoint = toolgroup.get('mcp_endpoint', {})
                                        if not isinstance(mcp_endpoint, dict):
                                            logger.error(f"❌ CONFIGURATION ERROR: MCP toolgroup '{toolgroup_id}' has invalid mcp_endpoint: {mcp_endpoint}")
                                            continue
                                        
                                        mcp_url = mcp_endpoint.get('uri')
                                        if not mcp_url:
                                            logger.error(f"❌ CONFIGURATION ERROR: MCP toolgroup '{toolgroup_id}' missing 'mcp_endpoint.uri' field")
                                            logger.error(f"❌ Available toolgroup fields: {list(toolgroup.keys())}")
                                            logger.error(f"❌ MCP endpoint fields: {list(mcp_endpoint.keys()) if mcp_endpoint else 'None'}")
                                            continue
                                        
                                        # Strip /sse suffix to get base URL for service discovery
                                        base_mcp_url = mcp_url.rstrip('/sse')
                                        
                                        mcp_server_urls.append(base_mcp_url)
                                        logger.info(f"✅ Found MCP server: {base_mcp_url} (endpoint: {mcp_url})")
                                    
                                    logger.info(f"🔍 Discovered {len(mcp_server_urls)} MCP servers from toolgroups: {mcp_server_urls}")
                                    
                                    # Fail early if no MCP servers found
                                    if not mcp_server_urls:
                                        logger.error("❌ CONFIGURATION ERROR: No MCP servers found in toolgroups")
                                        logger.error("❌ This indicates a fundamental Llama Stack configuration issue")
                                        logger.error("❌ Check your Llama Stack run.yml configuration")
                                        # Continue without MCP discovery
                                    else:
                                        # Run service discovery on each MCP server
                                        logger.info(f"🔍 Running service discovery on {len(mcp_server_urls)} MCP servers")
                                        
                                        import asyncio
                                        from utils.service_discovery import MCPServiceDiscovery
                                        
                                        async def run_discovery():
                                            discovery = MCPServiceDiscovery()
                                            discovered_configs = await discovery.discover_all_mcp_servers(mcp_server_urls)
                                            logger.info(f"🔍 DEBUG: Service discovery results: {discovered_configs}")
                                            return discovered_configs
                                        
                                        # Run service discovery
                                        discovered_configs = asyncio.run(run_discovery())
                                        logger.info(f"✅ Service discovery completed: {len(discovered_configs)} MCP servers configured")
                                        
                                        # Store discovered configs in session for future use
                                        session['discovered_mcp_configs'] = discovered_configs
                                        logger.info(f"🔍 DEBUG: Stored discovered configs in session: {list(discovered_configs.keys())}")
                                        
                                        # Log what we found
                                        for mcp_url, config in discovered_configs.items():
                                            auth_server = config.get('authorization_server', 'Unknown')
                                            logger.info(f"🔍 MCP Server: {mcp_url} -> Auth Server: {auth_server}")
                                        
                                        # Generate MCP tokens immediately while we have request context
                                        logger.info(f"🔍 DEBUG: Generating MCP tokens immediately after discovery")
                                        
                                        # Get user email from auth server
                                        user_response = client.get(
                                            f"{AUTH_SERVER_URL}/api/user-status", 
                                            cookies={'auth_session': auth_session_token},
                                            timeout=5.0
                                        )
                                        
                                        if user_response.status_code == 200:
                                            user_data = user_response.json()
                                            user_email = user_data.get('user', {}).get('email')
                                            
                                            if user_email:
                                                logger.info(f"🔍 DEBUG: Generating MCP tokens for user: {user_email}")
                                                
                                                # Generate tokens for each discovered MCP server
                                                for mcp_server_url, config in discovered_configs.items():
                                                    auth_server_url = config.get('authorization_server')
                                                    if not auth_server_url:
                                                        logger.warning(f"⚠️ No auth server found for MCP server: {mcp_server_url}")
                                                        continue
                                                    
                                                    logger.info(f"🔍 DEBUG: Generating token for MCP server: {mcp_server_url}")
                                                    logger.info(f"🔍 DEBUG: Using auth server: {auth_server_url}")
                                                    
                                                    # Request MCP token with no specific scope (basic access)
                                                    try:
                                                        token_response = client.post(
                                                            f"{auth_server_url}/api/upgrade-scope",
                                                            json={
                                                                "resource": mcp_server_url,
                                                                "scopes": [],  # Empty scopes for basic access
                                                                "current_token": "",
                                                                "justification": "Initial MCP token generation during OAuth flow"
                                                            },
                                                            cookies={'auth_session': auth_session_token},
                                                            timeout=10.0
                                                        )
                                                        
                                                        if token_response.status_code == 200:
                                                            token_data = token_response.json()
                                                            if token_data.get('new_token'):
                                                                logger.info(f"✅ Generated MCP token for {mcp_server_url}: {token_data['new_token'][:20]}...")
                                                            else:
                                                                logger.error(f"❌ No new_token in response for {mcp_server_url}: {token_data}")
                                                        else:
                                                            logger.error(f"❌ Failed to generate MCP token for {mcp_server_url}: {token_response.status_code}")
                                                            logger.error(f"❌ Response: {token_response.text}")
                                                    
                                                    except Exception as token_error:
                                                        logger.error(f"❌ Error generating token for {mcp_server_url}: {token_error}")
                                                
                                                logger.info(f"✅ MCP token generation completed for {user_email}")
                                            else:
                                                logger.error("❌ Could not get user email for MCP token generation")
                                        else:
                                            logger.error(f"❌ Could not get user info for MCP token generation: {user_response.status_code}")
                                
                                else:
                                    logger.error(f"❌ Failed to query toolgroups: {toolgroups_response.status_code}")
                                    logger.error(f"❌ Response body: {toolgroups_response.text}")
                                    
                            except Exception as e:
                                logger.error(f"❌ Error during MCP discovery: {e}")
                                import traceback
                                logger.error(f"❌ Full traceback: {traceback.format_exc()}")
                                # Continue anyway - discovery is optional
                            
                            logger.info("✅ MCP discovery completed - tokens will be generated on-demand")
                            
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
    """Get MCP tokens for a user from auth server database"""
    try:
        import httpx
        # Get tokens from auth server database
        response = httpx.get(
            f"{AUTH_SERVER_URL}/api/user-mcp-tokens",
            params={"user_email": user_email},
            timeout=5.0
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get("success"):
                tokens = result.get("tokens", {})
                logger.info(f"🔐 Found {len(tokens)} MCP tokens for {user_email} from auth server")
                return tokens
            else:
                logger.warning(f"⚠️ Failed to get MCP tokens: {result.get('error', 'Unknown error')}")
                return {}
        else:
            logger.error(f"❌ Failed to retrieve MCP tokens: {response.status_code}")
            return {}
    
    except Exception as e:
        logger.error(f"❌ Error retrieving MCP tokens for {user_email}: {e}")
        return {}

def store_mcp_token_for_user(user_email: str, server_url: str, token: str):
    """Store MCP token for a user in auth server database"""
    # Note: This function is now primarily for backward compatibility
    # MCP tokens are generated on-demand when tools require them
    # But we still provide this for any edge cases that might call it
    logger.info(f"✅ MCP token storage request for {user_email} -> {server_url} (tokens now generated on-demand)")

if __name__ == '__main__':
    logger.info("🚀 Starting Chat UI Frontend...")
    app.run(host='0.0.0.0', port=5001, debug=True) 