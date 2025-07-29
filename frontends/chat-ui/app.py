#!/usr/bin/env python3
"""
Chat UI Frontend (Keycloak Edition)
A lightweight Flask application that provides the chat interface.
Connects directly to Keycloak for OIDC authentication.
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
import os
import secrets
import logging
import sys
from datetime import timedelta
import asyncio
from typing import Optional, List
import urllib.parse
import httpx
import json
from flask_cors import CORS
import base64
import hashlib
import aiohttp

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

# Configure session settings  
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='chat_session',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),  # Longer session lifetime
    SESSION_REFRESH_EACH_REQUEST=True
)

# Enable CORS for development
CORS(app, supports_credentials=True)

# Configuration - Keycloak OIDC
OIDC_ISSUER_URL = os.getenv("OIDC_ISSUER_URL")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET")
LLAMA_STACK_URL = os.getenv("LLAMA_STACK_URL", "http://localhost:8321")
REDIRECT_URI = "http://localhost:5001/callback"

# Validate required configuration
if not all([OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET]):
    logger.error("❌ Missing required OIDC configuration. Please set OIDC_ISSUER_URL, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET")
    sys.exit(1)

# Global variables for token management
token_cache = {}  # Token cache by user email

# Import API blueprints
from api.chat import chat_bp
from api.tokens import tokens_bp

# Register blueprints
app.register_blueprint(chat_bp, url_prefix='/api')
app.register_blueprint(tokens_bp, url_prefix='/api')

async def get_oidc_configuration():
    """Get OIDC configuration from discovery endpoint"""
    try:
        discovery_url = f"{OIDC_ISSUER_URL}/.well-known/openid-configuration"
        async with httpx.AsyncClient() as client:
            response = await client.get(discovery_url, timeout=10.0)
            if response.status_code == 200:
                return response.json()
    except Exception as e:
        logger.error(f"Error getting OIDC configuration: {e}")
    return None

async def exchange_for_llama_stack_token(access_token: str) -> dict:
    """Exchange access token for Llama Stack token using Token Exchange V2 self-exchange"""
    try:
        config = await get_oidc_configuration()
        if not config:
            return {'success': False, 'error': 'OIDC configuration not available'}
        
        token_endpoint = config.get('token_endpoint')
        if not token_endpoint:
            return {'success': False, 'error': 'Token endpoint not found'}
        
        # Token Exchange V2 - Self-exchange for basic OIDC scopes only
        # 🔒 ZERO-TRUST: Start with NO Llama scopes, only basic OIDC scopes
        basic_scopes = [
            'email',      # Basic: User email
            'profile'     # Basic: User profile
            # Note: Llama scopes like 'llama:agent_create', 'llama:inference_chat_completion' 
            # will be exchanged when specific Llama Stack features are used
        ]
        
        # Token exchange request data (RFC 8693)
        data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token': access_token,
            'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'audience': OIDC_CLIENT_ID,  # Self-exchange using same client ID
            'scope': ' '.join(basic_scopes)
        }
        
        # Use Basic Auth for confidential client (consistent approach)
        auth_string = base64.b64encode(f"{OIDC_CLIENT_ID}:{OIDC_CLIENT_SECRET}".encode()).decode()
        headers = {
            'Authorization': f'Basic {auth_string}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        logger.info(f"🔄 Token Exchange V2 - Basic OIDC scopes only: {basic_scopes}")
        logger.info(f"🎯 Using audience: {OIDC_CLIENT_ID} (self-exchange)")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(token_endpoint, data=data, headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"✅ Llama Stack token exchange successful (basic scopes only)")
                    return {
                        'success': True,
                        'token': result['access_token'],
                        'scopes': basic_scopes
                    }
                else:
                    error_data = await response.json()
                    logger.error(f"❌ Llama Stack token exchange failed: {error_data}")
                    return {
                        'success': False,
                        'error': error_data.get('error', 'Unknown error'),
                        'error_description': error_data.get('error_description', '')
                    }
                    
    except Exception as e:
        logger.error(f"❌ Llama Stack token exchange exception: {e}")
        return {'success': False, 'error': str(e)}

async def exchange_for_mcp_token(access_token: str) -> dict:
    """Exchange access token for MCP token using Token Exchange V2 self-exchange"""
    try:
        config = await get_oidc_configuration()
        if not config:
            return {'success': False, 'error': 'OIDC configuration not available'}
        
        token_endpoint = config.get('token_endpoint')
        if not token_endpoint:
            return {'success': False, 'error': 'Token endpoint not found'}
        
        # Token Exchange V2 - Self-exchange for basic OIDC scopes only
        # 🔒 ZERO-TRUST: Start with NO MCP scopes, only basic OIDC scopes
        basic_scopes = [
            'email',      # Basic: User email
            'profile'     # Basic: User profile
            # Note: MCP scopes like 'mcp:health_check', 'mcp:get_server_info' 
            # will be exchanged when specific MCP tools are used
        ]
        
        # Token exchange request data (RFC 8693)
        data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token': access_token,
            'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'audience': OIDC_CLIENT_ID,  # Self-exchange using same client ID  
            'scope': ' '.join(basic_scopes)
        }
        
        # Use Basic Auth for confidential client (consistent approach)
        auth_string = base64.b64encode(f"{OIDC_CLIENT_ID}:{OIDC_CLIENT_SECRET}".encode()).decode()
        headers = {
            'Authorization': f'Basic {auth_string}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        logger.info(f"🔄 Token Exchange V2 - Basic OIDC scopes only: {basic_scopes}")
        logger.info(f"🎯 Using audience: {OIDC_CLIENT_ID} (self-exchange)")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(token_endpoint, data=data, headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    logger.info(f"✅ MCP token exchange successful (basic scopes only)")
                    return {
                        'success': True,
                        'token': result['access_token'],
                        'scopes': basic_scopes
                    }
                else:
                    error_data = await response.json()
                    logger.error(f"❌ MCP token exchange failed: {error_data}")
                    return {
                        'success': False,
                        'error': error_data.get('error', 'Unknown error'),
                        'error_description': error_data.get('error_description', '')
                    }
                    
    except Exception as e:
        logger.error(f"❌ MCP token exchange exception: {e}")
        return {'success': False, 'error': str(e)}

@app.route('/')
def index():
    """Main page - check for authentication"""
    logger.info(f"🏠 Index page accessed")
    
    # Debug: log session contents
    logger.info(f"🔍 Session keys: {list(session.keys())}")
    logger.info(f"🔍 Session contents: {dict(session)}")
    logger.info(f"🔍 Authenticated: {session.get('authenticated')}")
    logger.info(f"🔍 User email: {session.get('user_email')}")
    logger.info(f"🔍 Access token exists: {bool(session.get('access_token'))}")
    
    # Check if user is authenticated
    if session.get('authenticated') and session.get('access_token'):
        logger.info(f"✅ User authenticated: {session.get('user_email')}")
                        
        # Check if we need to generate a Llama Stack token
        if not session.get('llama_stack_token'):
            logger.info("🔄 User has OIDC token but no Llama Stack token - needs exchange")
                        
        return render_template('chat.html',
            user_name=session.get('user_name', 'User'),
            user_email=session.get('user_email', ''))
    
    # No valid session - show login
    logger.info("❌ No valid session found")
    logger.info(f"🔍 Session data before clear: {dict(session)}")
    session.clear()
    return render_template('login.html')

@app.route('/login')
def login():
    """Start OIDC OAuth flow"""
    logger.info(f"🔐 Starting OIDC OAuth flow")
    
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Generate PKCE verifier and challenge
    code_verifier = secrets.token_urlsafe(96)  # Must be between 43-128 chars
    code_verifier_bytes = code_verifier.encode('ascii')
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier_bytes).digest()).decode('ascii').rstrip('=')
    
    # Store verifier in session for later
    session['code_verifier'] = code_verifier
    
    # Build authorization URL
    config = asyncio.run(get_oidc_configuration())
    if not config:
        return "Could not get OIDC configuration", 500
        
    authorization_endpoint = config.get('authorization_endpoint')
    if not authorization_endpoint:
        return "No authorization endpoint found", 500
    
    params = {
        'client_id': OIDC_CLIENT_ID,
        'response_type': 'code',
        'scope': 'openid profile email',  # Only basic OIDC scopes for login
        'redirect_uri': REDIRECT_URI,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    
    oauth_url = f"{authorization_endpoint}?{urllib.parse.urlencode(params)}"
    logger.info(f"🔗 Redirecting to: {oauth_url}")
    return redirect(oauth_url)

@app.route('/callback')
def callback():
    """Handle OIDC OAuth callback"""
    logger.info(f"🔍 OIDC OAuth callback received")
    logger.info(f"🔍 Query params: {dict(request.args)}")
    logger.info(f"🔍 Current session: {dict(session)}")
    
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    
    if error:
        logger.error(f"❌ OAuth error: {error}")
        return redirect('/')
    
    # Verify state parameter
    if not state or state != session.get('oauth_state'):
        logger.error(f"❌ Invalid OAuth state. Got: {state}, Expected: {session.get('oauth_state')}")
        return redirect('/')
    
    if not code:
        logger.error("❌ No authorization code received")
        return redirect('/')
    
    # Get code verifier from session
    code_verifier = session.get('code_verifier')
    if not code_verifier:
        logger.error("❌ No code verifier found in session")
        return redirect('/')
    
    # Exchange code for token
    result = asyncio.run(exchange_code_for_token(code, state, code_verifier))
    logger.info(f"🔍 Token exchange result: {result.get('success')}")
            
    if result['success']:
        user_info = result['user_info']
        access_token = result['access_token']
        
        logger.info(f"🎫 Received access token: {access_token[:50]}...{access_token[-20:]}")
        logger.info(f"👤 User info: {user_info}")
        
        # Store basic user info in session
        session['authenticated'] = True
        session['user_email'] = user_info.get('email', user_info.get('preferred_username', 'unknown'))
        session['user_name'] = user_info.get('name', user_info.get('preferred_username', session['user_email'].split('@')[0]))
        session['access_token'] = access_token
        session['user_info'] = user_info
        session.permanent = True
        session.modified = True
        
        logger.info(f"✅ User authenticated: {session['user_email']}")
        logger.info(f"🔍 Session after auth: {dict(session)}")
        
        # Log environment configuration for debugging
        logger.info(f"🔧 OIDC Config: client_id={OIDC_CLIENT_ID}, issuer={OIDC_ISSUER_URL}")
        logger.info(f"🔧 Client secret configured: {bool(OIDC_CLIENT_SECRET)}")
        
        # 🔒 ZERO-TRUST: Do NOT exchange for specialized tokens immediately
        # Tokens will be exchanged on-demand when services are actually used
        logger.info(f"🔒 Zero-trust login: User has only basic OIDC scopes initially")
        logger.info(f"🔒 Service tokens will be exchanged on-demand when needed")
        
        # Store minimal token cache (no service tokens yet)
        token_cache[session['user_email']] = {
            'access_token': access_token,
            'llama_stack_token': None,  # Will be exchanged when chat is used
            'mcp_token': None,  # Will be exchanged when MCP tools are used
            'user_info': user_info,
            'token_data': result['token_data']
        }
        
        logger.info(f"🔍 Final session keys: {list(session.keys())}")
        logger.info(f"🔍 Final session: {dict(session)}")
        
        response = redirect('/')
        logger.info(f"🔍 Response headers: {dict(response.headers)}")
        return response
    else:
        logger.error(f"❌ Authentication failed: {result['error']}")
        return redirect('/')

@app.route('/logout')
def logout():
    """Logout user and clear session"""
    logger.info(f"🚪 User logout")
    
    # Clear token cache
    user_email = session.get('user_email')
    if user_email and user_email in token_cache:
        del token_cache[user_email]
    
    # Clear session
    session.clear()
    
    # Force logout from Keycloak with proper parameters
    config = asyncio.run(get_oidc_configuration())
    if config and config.get('end_session_endpoint'):
        logout_params = {
            'post_logout_redirect_uri': 'http://localhost:5001',
            'client_id': OIDC_CLIENT_ID
        }
        logout_url = f"{config['end_session_endpoint']}?{urllib.parse.urlencode(logout_params)}"
        logger.info(f"🔗 Keycloak logout URL: {logout_url}")
        return redirect(logout_url)
    
    return redirect('/')

@app.route('/api/user-status')
def user_status():
    """Get current user authentication status"""
    if session.get('authenticated'):
        return jsonify({
            'authenticated': True,
            'user': {
                'email': session.get('user_email'),
                'name': session.get('user_name'),
                'sub': session.get('user_info', {}).get('sub', '')
            }
        })
    else:
        return jsonify({'authenticated': False}), 401

@app.route('/debug/session')
def debug_session():
    """Debug session contents"""
    logger.info("🔍 Debug session accessed")
    logger.info(f"🔍 Session data: {dict(session)}")
    logger.info(f"🔍 Session keys: {list(session.keys())}")
    logger.info(f"🔍 Token cache keys: {list(token_cache.keys()) if token_cache else []}")
    
    if session.get('authenticated'):
        logger.info("🔍 Session shows authenticated - redirecting to main page")
        return redirect('/')
    else:
        logger.info("🔍 Session not authenticated - showing login")
        return redirect('/login')

@app.route('/debug/token')
def debug_token():
    """Debug endpoint to show current access token"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    access_token = session.get('access_token')
    if access_token:
        return jsonify({
            'access_token': access_token,
            'user_email': session.get('user_email'),
            'token_length': len(access_token),
            'token_preview': f"{access_token[:20]}...{access_token[-20:]}"
        })
    else:
        return jsonify({'error': 'No access token in session'}), 404

@app.route('/api/clear-session', methods=['POST'])
def clear_session():
    """Clear session data (for cleanup script) - public endpoint"""
    logger.info(f"🧹 Clearing session data")
    
    # Clear token cache for all users
    global token_cache
    if token_cache:
        logger.info(f"🧹 Clearing token cache ({len(token_cache)} entries)")
        token_cache.clear()
    
    # Clear session
    session.clear()
    logger.info(f"🧹 Session cleared")
    
    return jsonify({'success': True, 'message': 'Session and token cache cleared'})

async def exchange_code_for_token(code: str, state: str, code_verifier: str) -> dict:
    """Exchange authorization code for access token"""
    try:
        config = await get_oidc_configuration()
        if not config:
            return {'success': False, 'error': 'OIDC configuration not available'}
        
        token_endpoint = config.get('token_endpoint')
        userinfo_endpoint = config.get('userinfo_endpoint')
        
        if not token_endpoint or not userinfo_endpoint:
            return {'success': False, 'error': 'Missing OIDC endpoints'}
        
        async with httpx.AsyncClient() as client:
            # Exchange code for token
            response = await client.post(
                token_endpoint,
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_id': OIDC_CLIENT_ID,
                    'client_secret': OIDC_CLIENT_SECRET,
                    'code_verifier': code_verifier
                },
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=10.0
            )
            
            if response.status_code == 200:
                token_data = response.json()
                access_token = token_data.get('access_token')
                
                if access_token:
                    # Get user info
                    user_response = await client.get(
                        userinfo_endpoint,
                        headers={'Authorization': f'Bearer {access_token}'},
                        timeout=10.0
                    )
                    
                    if user_response.status_code == 200:
                        user_info = user_response.json()
                        return {
                            'success': True,
                            'user_info': user_info,
                            'access_token': access_token,
                            'token_data': token_data
                        }
                
                return {'success': False, 'error': 'Invalid token response'}
            else:
                logger.error(f"❌ Token exchange failed: {response.status_code} - {response.text}")
                return {'success': False, 'error': f'Token exchange failed: {response.status_code}'}
                
    except Exception as e:
        logger.error(f"❌ Error exchanging code for token: {e}")
        return {'success': False, 'error': str(e)}

if __name__ == '__main__':
    logger.info("🚀 Starting Chat UI (Keycloak Edition)")
    logger.info(f"🔐 OIDC Issuer: {OIDC_ISSUER_URL}")
    logger.info(f"🔐 OIDC Client: {OIDC_CLIENT_ID}")
    logger.info(f"🦙 Llama Stack: {LLAMA_STACK_URL}")
    
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('CHAT_UI_PORT', 5001)),
        debug=os.getenv('FLASK_ENV') == 'development'
    ) 