#!/usr/bin/env python3
"""
Admin Dashboard (Keycloak Edition)
Administrative interface for approval workflows and user management.
Connects directly to Keycloak for OIDC authentication.
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
import logging
import sys
import secrets
from datetime import timedelta
import urllib.parse
import asyncio
import httpx

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
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='admin_session',
    SESSION_COOKIE_DOMAIN='localhost',
    SESSION_COOKIE_PATH='/',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_REFRESH_EACH_REQUEST=True
)

# Configuration - Keycloak OIDC
OIDC_ISSUER_URL = os.getenv("OIDC_ISSUER_URL")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
REDIRECT_URI = "http://localhost:8003/callback"

# Validate required configuration
if not all([OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, ADMIN_EMAIL]):
    logger.error("❌ Missing required configuration. Please set OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and ADMIN_EMAIL")
    sys.exit(1)

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

def is_admin_user(user_email: str) -> bool:
    """Check if user is an admin"""
    return user_email == ADMIN_EMAIL

@app.route('/')
def index():
    """Root page - redirect to dashboard or login"""
    if session.get('authenticated') and session.get('is_admin'):
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    """Admin dashboard - main page"""
    if not session.get('authenticated') or not session.get('is_admin'):
        return redirect(url_for('login'))
    
    logger.info(f"🎛️ Admin dashboard accessed by {session.get('user_email')}")
    return render_template('dashboard.html', 
                         user_email=session.get('user_email'),
                         user_name=session.get('user_name', 'Admin'))

@app.route('/login')
def login():
    """Start OIDC OAuth flow for admin"""
    logger.info(f"🔐 Starting admin OIDC OAuth flow")
    
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Build authorization URL
    config = asyncio.run(get_oidc_configuration())
    if not config:
        logger.error("❌ OIDC configuration not available")
        return "OIDC configuration not available", 500
    
    authorization_endpoint = config.get('authorization_endpoint')
    if not authorization_endpoint:
        logger.error("❌ Authorization endpoint not found")
        return "Authorization endpoint not found", 500
    
    params = {
        'client_id': OIDC_CLIENT_ID,
        'response_type': 'code',
        'scope': 'openid profile email',
        'redirect_uri': REDIRECT_URI,
        'state': state
    }
    
    oauth_url = f"{authorization_endpoint}?{urllib.parse.urlencode(params)}"
    logger.info(f"🔗 Redirecting admin to: {oauth_url}")
    return redirect(oauth_url)

@app.route('/callback')
def oauth_callback():
    """Handle OIDC OAuth callback for admin"""
    logger.info(f"🔍 Admin OIDC OAuth callback received")
    
    code = request.args.get('code')
    state = request.args.get('state')
    error = request.args.get('error')
    
    if error:
        logger.error(f"❌ OAuth error: {error}")
        return redirect(url_for('login'))
    
    # Verify state parameter
    if not state or state != session.get('oauth_state'):
        logger.error("❌ Invalid OAuth state")
        return redirect(url_for('login'))
    
    if not code:
        logger.error("❌ No authorization code received")
        return redirect(url_for('login'))
    
    try:
        # Exchange code for token
        result = asyncio.run(exchange_code_for_token(code, state))
        
        if result['success']:
            user_info = result['user_info']
            user_email = user_info.get('email', user_info.get('preferred_username', 'unknown'))
            
            # Check if user is admin
            if not is_admin_user(user_email):
                logger.warning(f"⚠️ Non-admin user attempted admin access: {user_email}")
                return "Access denied. Admin privileges required.", 403
            
            # Store admin session
            session['authenticated'] = True
            session['is_admin'] = True
            session['user_email'] = user_email
            session['user_name'] = user_info.get('name', user_info.get('preferred_username', user_email.split('@')[0]))
            session['access_token'] = result['access_token']
            session['user_info'] = user_info
            session.permanent = True
            
            logger.info(f"✅ Admin authenticated: {user_email}")
            return redirect(url_for('dashboard'))
        else:
            logger.error(f"❌ Admin authentication failed: {result['error']}")
            return redirect(url_for('login'))
    
    except Exception as e:
        logger.error(f"❌ Admin OAuth callback error: {e}")
        return redirect(url_for('login'))

async def exchange_code_for_token(code: str, state: str) -> dict:
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
                    'client_secret': OIDC_CLIENT_SECRET
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

@app.route('/logout')
def logout():
    """Logout admin user"""
    logger.info(f"🚪 Admin logout: {session.get('user_email')}")
    
    # Clear session
    session.clear()
    
    # Redirect to OIDC logout endpoint if available
    config = asyncio.run(get_oidc_configuration())
    if config and config.get('end_session_endpoint'):
        logout_url = f"{config['end_session_endpoint']}?post_logout_redirect_uri={urllib.parse.quote('http://localhost:8003')}"
        return redirect(logout_url)
    
    return redirect(url_for('login'))

# API endpoints for dashboard functionality
@app.route('/api/pending-approvals')
def get_pending_approvals():
    """Get pending approval requests"""
    if not session.get('authenticated') or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Note: In the simplified Keycloak version, we'll return empty for now
    # This would need to be connected to a proper approval system
    return jsonify({'approvals': []})

@app.route('/api/approve/<int:approval_id>', methods=['POST'])
def approve_request(approval_id):
    """Approve a request"""
    if not session.get('authenticated') or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Note: In the simplified Keycloak version, we'll return success for now
    # This would need to be connected to a proper approval system
    logger.info(f"✅ Admin {session.get('user_email')} approved request {approval_id}")
    return jsonify({'success': True})

@app.route('/api/deny/<int:approval_id>', methods=['POST'])
def deny_request(approval_id):
    """Deny a request"""
    if not session.get('authenticated') or not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Note: In the simplified Keycloak version, we'll return success for now
    # This would need to be connected to a proper approval system
    logger.info(f"❌ Admin {session.get('user_email')} denied request {approval_id}")
    return jsonify({'success': True})

if __name__ == '__main__':
    logger.info("🚀 Starting Admin Dashboard (Keycloak Edition)")
    logger.info(f"🔐 OIDC Issuer: {OIDC_ISSUER_URL}")
    logger.info(f"🔐 OIDC Client: {OIDC_CLIENT_ID}")
    logger.info(f"👑 Admin Email: {ADMIN_EMAIL}")
    
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('ADMIN_PORT', 8003)),
        debug=os.getenv('FLASK_ENV') == 'development'
    ) 