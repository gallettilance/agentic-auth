#!/usr/bin/env python3
"""
Admin Dashboard Frontend
Separated frontend for the MCP Authentication Server admin interface
"""

import os
import logging
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, make_response
import requests
import jwt

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
AUTH_SERVER_URL = os.getenv("AUTH_SERVER_URL", "http://localhost:8002")
DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "localhost")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8003"))

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your-secret-key-change-this")

def get_tool_icon(tool_name: str) -> str:
    """Get icon for tool name"""
    icons = {
        "list_files": "📁",
        "execute_command": "⚡", 
        "get_server_info": "ℹ️",
        "health_check": "💚",
        "read_file": "📖",
        "write_file": "✏️",
        "delete_file": "🗑️"
    }
    return icons.get(tool_name, "🔧")

# Add the function to Jinja2 global context
app.jinja_env.globals.update(get_tool_icon=get_tool_icon)

@app.route('/')
def index():
    """Redirect to dashboard"""
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    """Main admin dashboard"""
    try:
        # Check if user is authenticated by calling auth server
        auth_cookies = {}
        if request.cookies.get('auth_session'):
            auth_cookies['auth_session'] = request.cookies.get('auth_session')
        
        # Get user status from auth server
        response = requests.get(
            f"{AUTH_SERVER_URL}/api/user-status",
            cookies=auth_cookies,
            timeout=10
        )
        
        if response.status_code != 200:
            # Not authenticated, redirect to our login endpoint
            return redirect(url_for('login'))
        
        user_data = response.json()
        
        # Get tools and approval data
        tools_response = requests.get(
            f"{AUTH_SERVER_URL}/api/tools",
            cookies=auth_cookies,
            timeout=10
        )
        
        tools_data = tools_response.json() if tools_response.status_code == 200 else {}
        
        # Get pending approvals if user is admin
        pending_approvals = []
        if user_data.get('user', {}).get('is_admin'):
            try:
                # This would need to be implemented in the auth server API
                approvals_response = requests.get(
                    f"{AUTH_SERVER_URL}/api/admin/pending-approvals",
                    cookies=auth_cookies,
                    timeout=10
                )
                if approvals_response.status_code == 200:
                    pending_approvals = approvals_response.json().get('approvals', [])
            except Exception as e:
                logger.warning(f"Could not fetch pending approvals: {e}")
        
        return render_template('dashboard.html',
            user=user_data.get('user', {}),
            tools=tools_data.get('tools', {}),
            user_scopes=tools_data.get('user_scopes', []),
            current_token=tools_data.get('current_token'),
            pending_approvals=pending_approvals,
            auth_server_url=AUTH_SERVER_URL
        )
        
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return redirect(url_for('login'))

@app.route('/login')
def login():
    """Admin dashboard login - redirect to auth server with proper client info"""
    # Use the auth server's authorize endpoint with admin-dashboard client_id
    import urllib.parse
    import secrets
    
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Redirect to auth server's authorize endpoint
    redirect_uri = url_for('oauth_callback', _external=True)
    
    params = {
        'client_id': 'admin-dashboard',
        'response_type': 'code',
        'redirect_uri': redirect_uri,
        'state': state,
        'scope': 'admin'
    }
    
    oauth_url = f"{AUTH_SERVER_URL}/auth/authorize?" + urllib.parse.urlencode(params)
    return redirect(oauth_url)

@app.route('/callback')
def oauth_callback():
    """Handle OAuth callback from auth server"""
    try:
        # The auth server should redirect back here with session cookie already set
        # Just verify we have the session cookie and redirect to dashboard
        if request.cookies.get('auth_session'):
            return redirect(url_for('dashboard'))
        else:
            logger.error("No session cookie received from auth server")
            return redirect(url_for('login'))
        
    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        return redirect(url_for('login'))

@app.route('/api/approve/<request_id>', methods=['POST'])
def approve_request(request_id):
    """Proxy approval request to auth server"""
    try:
        auth_cookies = {}
        if request.cookies.get('auth_session'):
            auth_cookies['auth_session'] = request.cookies.get('auth_session')
        
        # Forward the request to auth server
        response = requests.post(
            f"{AUTH_SERVER_URL}/api/approve/{request_id}",
            data=request.form,
            cookies=auth_cookies,
            timeout=10
        )
        
        return jsonify(response.json()), response.status_code
        
    except Exception as e:
        logger.error(f"Approval error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/deny/<request_id>', methods=['POST'])
def deny_request(request_id):
    """Proxy deny request to auth server"""
    try:
        auth_cookies = {}
        if request.cookies.get('auth_session'):
            auth_cookies['auth_session'] = request.cookies.get('auth_session')
        
        # Forward the request to auth server
        response = requests.post(
            f"{AUTH_SERVER_URL}/api/deny/{request_id}",
            data=request.form,
            cookies=auth_cookies,
            timeout=10
        )
        
        return jsonify(response.json()), response.status_code
        
    except Exception as e:
        logger.error(f"Deny error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/tools')
def get_tools():
    """Proxy tools request to auth server"""
    try:
        auth_cookies = {}
        if request.cookies.get('auth_session'):
            auth_cookies['auth_session'] = request.cookies.get('auth_session')
        
        response = requests.get(
            f"{AUTH_SERVER_URL}/api/tools",
            cookies=auth_cookies,
            timeout=10
        )
        
        return jsonify(response.json()), response.status_code
        
    except Exception as e:
        logger.error(f"Tools error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-tool', methods=['POST'])
def test_tool():
    """Proxy tool test request to auth server"""
    try:
        auth_cookies = {}
        if request.cookies.get('auth_session'):
            auth_cookies['auth_session'] = request.cookies.get('auth_session')
        
        response = requests.post(
            f"{AUTH_SERVER_URL}/api/test-tool",
            json=request.get_json(),
            cookies=auth_cookies,
            timeout=10
        )
        
        return jsonify(response.json()), response.status_code
        
    except Exception as e:
        logger.error(f"Tool test error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/approvals')
def get_approvals():
    """Proxy pending approvals request to auth server"""
    try:
        auth_cookies = {}
        if request.cookies.get('auth_session'):
            auth_cookies['auth_session'] = request.cookies.get('auth_session')
        
        response = requests.get(
            f"{AUTH_SERVER_URL}/api/admin/pending-approvals",
            cookies=auth_cookies,
            timeout=10
        )
        
        return jsonify(response.json()), response.status_code
        
    except Exception as e:
        logger.error(f"Approvals error: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    logger.info(f"🚀 Starting Admin Dashboard Frontend on {DASHBOARD_HOST}:{DASHBOARD_PORT}")
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=True) 