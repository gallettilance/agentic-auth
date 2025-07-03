"""
Auth API Blueprint
Handles OAuth authentication flow by communicating with the auth server.
"""

from flask import Blueprint, request, jsonify, session, redirect, url_for
import httpx
import asyncio
import logging
import os
import secrets

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)

# Service URLs - will be moved to config later
AUTH_SERVER_URL = os.getenv("AUTH_SERVER_URL", "http://localhost:8002")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:5001/callback")

def get_oauth_url():
    """Get OAuth authorization URL from auth server"""
    try:
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)
        session['oauth_state'] = state
        
        # Build OAuth URL
        oauth_url = f"{AUTH_SERVER_URL}/oauth/authorize"
        params = {
            'client_id': GOOGLE_CLIENT_ID,
            'response_type': 'code',
            'scope': 'openid profile email',
            'redirect_uri': REDIRECT_URI,
            'state': state
        }
        
        # Build query string
        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        return f"{oauth_url}?{query_string}"
        
    except Exception as e:
        logger.error(f"❌ Error building OAuth URL: {e}")
        return None

@auth_bp.route('/login-url')
def get_login_url():
    """Get OAuth login URL"""
    oauth_url = get_oauth_url()
    if oauth_url:
        return jsonify({'login_url': oauth_url})
    else:
        return jsonify({'error': 'Failed to generate login URL'}), 500

def handle_oauth_callback():
    """Handle OAuth callback from auth server"""
    try:
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        
        if error:
            logger.error(f"❌ OAuth error: {error}")
            return redirect(url_for('login', error=error))
        
        if not code:
            logger.error("❌ No authorization code received")
            return redirect(url_for('login', error='no_code'))
        
        # Verify state for CSRF protection
        if state != session.get('oauth_state'):
            logger.error("❌ Invalid state parameter")
            return redirect(url_for('login', error='invalid_state'))
        
        # Exchange code for token
        result = asyncio.run(exchange_code_for_token(code))
        
        if result['success']:
            # Store user info in session
            session['authenticated'] = True
            session['user_email'] = result['user_info']['email']
            session['user_name'] = result['user_info']['name']
            session['bearer_token'] = result['bearer_token']
            session.permanent = True
            
            logger.info(f"✅ User authenticated: {result['user_info']['email']}")
            return redirect(url_for('index'))
        else:
            logger.error(f"❌ Token exchange failed: {result['error']}")
            return redirect(url_for('login', error='token_exchange_failed'))
            
    except Exception as e:
        logger.error(f"❌ OAuth callback error: {e}")
        return redirect(url_for('login', error='callback_error'))

async def exchange_code_for_token(code: str) -> dict:
    """Exchange authorization code for access token"""
    try:
        async with httpx.AsyncClient() as client:
            # Exchange code for token with auth server
            response = await client.post(
                f"{AUTH_SERVER_URL}/oauth/token",
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_id': GOOGLE_CLIENT_ID,
                    'client_secret': GOOGLE_CLIENT_SECRET
                },
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=10.0
            )
            
            if response.status_code == 200:
                token_data = response.json()
                access_token = token_data.get('access_token')
                
                if access_token:
                    # Get user info
                    user_info = await get_user_info(access_token)
                    if user_info:
                        # Get bearer token from auth server
                        bearer_token = await get_bearer_token_from_auth_server(user_info)
                        
                        return {
                            'success': True,
                            'user_info': user_info,
                            'bearer_token': bearer_token
                        }
                
                return {
                    'success': False,
                    'error': 'Invalid token response'
                }
            else:
                logger.error(f"❌ Token exchange failed: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'error': f'Token exchange failed: {response.status_code}'
                }
                
    except Exception as e:
        logger.error(f"❌ Error exchanging code for token: {e}")
        return {
            'success': False,
            'error': str(e)
        }

async def get_user_info(access_token: str) -> dict:
    """Get user info from Google"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=10.0
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"❌ Failed to get user info: {response.status_code}")
                return None
                
    except Exception as e:
        logger.error(f"❌ Error getting user info: {e}")
        return None

async def get_bearer_token_from_auth_server(user_info: dict) -> str:
    """Get bearer token from auth server"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{AUTH_SERVER_URL}/api/get-token",
                json=user_info,
                headers={'Content-Type': 'application/json'},
                timeout=10.0
            )
            
            if response.status_code == 200:
                token_data = response.json()
                return token_data.get('token', '')
            else:
                logger.error(f"❌ Failed to get bearer token: {response.status_code}")
                return ''
                
    except Exception as e:
        logger.error(f"❌ Error getting bearer token: {e}")
        return ''

@auth_bp.route('/check-auth')
def check_auth():
    """Check authentication status"""
    if 'authenticated' in session:
        return jsonify({
            'authenticated': True,
            'user_email': session.get('user_email', ''),
            'user_name': session.get('user_name', '')
        })
    else:
        return jsonify({'authenticated': False})

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """Logout user"""
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'}) 