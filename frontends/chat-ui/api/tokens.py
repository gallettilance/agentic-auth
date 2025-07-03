"""
Tokens API Blueprint
Handles token management and MCP token operations by communicating with the auth server.
"""

from flask import Blueprint, request, jsonify, session
import httpx
import asyncio
import logging
import os

logger = logging.getLogger(__name__)

tokens_bp = Blueprint('tokens', __name__)

# Service URLs - will be moved to config later
AUTH_SERVER_URL = os.getenv("AUTH_SERVER_URL", "http://localhost:8002")

@tokens_bp.route('/token-info')
def get_token_info():
    """Get information about current tokens"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Get Llama Stack token info
        llama_stack_token = session.get('bearer_token')
        llama_stack_info = None
        
        if llama_stack_token:
            try:
                # Try to decode token to get info (without verification for display purposes)
                import jwt
                decoded = jwt.decode(llama_stack_token, options={"verify_signature": False})
                llama_stack_info = {
                    'token': llama_stack_token,
                    'audience': decoded.get('aud', 'http://localhost:8321'),
                    'scopes': decoded.get('scope', '').split() if decoded.get('scope') else [],
                    'expires': decoded.get('exp'),
                    'issued': decoded.get('iat')
                }
            except Exception as e:
                logger.warning(f"Could not decode Llama Stack token: {e}")
                llama_stack_info = {
                    'token': llama_stack_token,
                    'audience': 'http://localhost:8321',
                    'scopes': [],
                    'error': 'Could not decode token'
                }
        
        # Get MCP tokens info using the helper function
        user_email = session.get('user_email', 'anonymous')
        
        # Import the helper function from main app
        import sys
        import os
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from app import get_mcp_tokens_for_user
        
        mcp_tokens = get_mcp_tokens_for_user(user_email)
        mcp_tokens_info = {}
        
        for server_url, token in mcp_tokens.items():
            if token and token != 'NO_TOKEN_YET':
                try:
                    # Try to decode MCP token to get info
                    import jwt
                    decoded = jwt.decode(token, options={"verify_signature": False})
                    mcp_tokens_info[server_url] = {
                        'token': token,
                        'scopes': decoded.get('scope', '').split() if decoded.get('scope') else [],
                        'expires': decoded.get('exp'),
                        'issued': decoded.get('iat'),
                        'audience': decoded.get('aud', server_url)
                    }
                except Exception as e:
                    logger.warning(f"Could not decode MCP token for {server_url}: {e}")
                    mcp_tokens_info[server_url] = {
                        'token': token,
                        'scopes': [],
                        'error': 'Could not decode token'
                    }
            else:
                mcp_tokens_info[server_url] = {
                    'token': token or '',
                    'scopes': [],
                    'status': 'missing'
                }
        
        return jsonify({
            'llama_stack_token': llama_stack_info,
            'mcp_tokens': mcp_tokens_info
        })
        
    except Exception as e:
        logger.error(f"❌ Error getting token info: {e}")
        return jsonify({'error': str(e)}), 500

@tokens_bp.route('/check-token-update')
def check_token_update():
    """Check if tokens have been updated and return new scopes"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Get auth cookies for the request
        auth_cookies = {}
        if request.cookies.get('auth_session'):
            auth_cookies['auth_session'] = request.cookies.get('auth_session')
        
        # Get all known auth servers to check
        auth_servers_to_check = set()
        
        # Add the default auth server
        auth_servers_to_check.add(AUTH_SERVER_URL)
        
        logger.info(f"🔍 Checking for token updates across {len(auth_servers_to_check)} auth servers: {list(auth_servers_to_check)}")
        
        # Check each auth server for token updates
        all_new_scopes = []
        all_total_scopes = []
        updated_tokens = {}
        update_messages = []
        
        for auth_server_url in auth_servers_to_check:
            try:
                # Make request to auth server
                import requests
                response = requests.get(
                    f"{auth_server_url}/api/check-token-update",
                    cookies=auth_cookies,
                    timeout=10
                )
                
                if response.status_code == 200:
                    auth_data = response.json()
                    
                    # Check if there are token updates from this server
                    if auth_data.get('has_updates', False):
                        logger.info(f"✅ Found token updates from {auth_server_url}")
                        
                        # Collect new scopes
                        new_scopes = auth_data.get('new_scopes', [])
                        total_scopes = auth_data.get('total_scopes', [])
                        new_token = auth_data.get('new_token')
                        audience = auth_data.get('audience', 'http://localhost:8001')
                        
                        all_new_scopes.extend(new_scopes)
                        all_total_scopes.extend(total_scopes)
                        update_messages.append(auth_data.get('message', f'Token updated from {auth_server_url}'))
                        
                        if new_token:
                            # Update the session with new token
                            session['bearer_token'] = new_token
                            logger.info(f"🎫 Updated session token from {auth_server_url} for {session.get('user_email', 'unknown')}")
                            
                            # Also update MCP tokens if this affects MCP scopes
                            user_email = session.get('user_email', 'anonymous')
                            
                            # If the audience is an MCP server, update the MCP token as well
                            if audience.startswith('http://localhost:8001'):
                                # Import helper functions
                                import sys
                                import os
                                sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                                from app import store_mcp_token_for_user
                                from utils.mcp_tokens_utils import get_base_mcp_url
                                
                                base_url = get_base_mcp_url(audience)
                                store_mcp_token_for_user(user_email, base_url, new_token)
                                
                                logger.info(f"🎫 Updated MCP token for {base_url} from {auth_server_url}")
                            
                            updated_tokens[auth_server_url] = new_token
                    else:
                        logger.debug(f"🔍 No updates from {auth_server_url}")
                else:
                    logger.warning(f"⚠️ Auth server {auth_server_url} returned {response.status_code}: {response.text}")
                    
            except Exception as e:
                logger.warning(f"⚠️ Failed to check {auth_server_url} for token updates: {e}")
                continue
        
        # Return aggregated results
        if all_new_scopes or updated_tokens:
            # Remove duplicates while preserving order
            unique_new_scopes = list(dict.fromkeys(all_new_scopes))
            unique_total_scopes = list(dict.fromkeys(all_total_scopes))
            
            logger.info(f"✅ Token updates found: new_scopes={unique_new_scopes}, total_scopes={unique_total_scopes}")
            
            return jsonify({
                'token_updated': True,
                'new_scopes': unique_new_scopes,
                'total_scopes': unique_total_scopes,
                'updated_tokens': updated_tokens,
                'auth_servers_checked': list(auth_servers_to_check),
                'message': '; '.join(update_messages) if update_messages else 'Tokens updated with new permissions'
            })
        else:
            # No updates from any server
            return jsonify({
                'token_updated': False,
                'new_scopes': [],
                'auth_servers_checked': list(auth_servers_to_check)
            })
            
    except Exception as e:
        logger.error(f"❌ Error checking token updates: {e}")
        return jsonify({
            'token_updated': False,
            'new_scopes': [],
            'error': str(e)
        })

@tokens_bp.route('/refresh-llama-stack-token', methods=['POST'])
def refresh_llama_stack_token():
    """Refresh the Llama Stack token"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # This will be implemented to refresh token from auth server
        return jsonify({
            'success': True,
            'message': 'Token refresh not yet implemented'
        })
        
    except Exception as e:
        logger.error(f"❌ Error refreshing token: {e}")
        return jsonify({'error': str(e)}), 500

@tokens_bp.route('/refresh-mcp-token', methods=['POST'])
def refresh_mcp_token():
    """Refresh an MCP token"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        server_url = data.get('server_url', '')
        
        if not server_url:
            return jsonify({'error': 'Server URL required'}), 400
        
        # This will be implemented to refresh MCP token from auth server
        return jsonify({
            'success': True,
            'message': f'MCP token refresh for {server_url} not yet implemented'
        })
        
    except Exception as e:
        logger.error(f"❌ Error refreshing MCP token: {e}")
        return jsonify({'error': str(e)}), 500

@tokens_bp.route('/request-mcp-token', methods=['POST'])
def request_mcp_token():
    """Request a new MCP token"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        server_url = data.get('server_url', '')
        
        if not server_url:
            return jsonify({'error': 'Server URL required'}), 400
        
        # This will be implemented to request MCP token from auth server
        return jsonify({
            'success': True,
            'message': f'MCP token request for {server_url} not yet implemented'
        })
        
    except Exception as e:
        logger.error(f"❌ Error requesting MCP token: {e}")
        return jsonify({'error': str(e)}), 500

@tokens_bp.route('/request-approval', methods=['POST'])
def request_approval():
    """Request approval for a tool/scope"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        tool_name = data.get('tool_name', '')
        required_scope = data.get('required_scope', '')
        justification = data.get('justification', '')
        
        if not tool_name or not required_scope:
            return jsonify({'error': 'Tool name and required scope are required'}), 400
        
        user_email = session.get('user_email', '')
        
        # This will be implemented to request approval from auth server
        return jsonify({
            'success': True,
            'status': 'pending',
            'message': f'Approval request for {tool_name} not yet implemented'
        })
        
    except Exception as e:
        logger.error(f"❌ Error requesting approval: {e}")
        return jsonify({'error': str(e)}), 500

@tokens_bp.route('/check-approval/<request_id>')
def check_approval(request_id: str):
    """Check approval status"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # This will be implemented to check approval status from auth server
        return jsonify({
            'request_id': request_id,
            'status': 'pending',
            'message': 'Approval check not yet implemented'
        })
        
    except Exception as e:
        logger.error(f"❌ Error checking approval: {e}")
        return jsonify({'error': str(e)}), 500

@tokens_bp.route('/auto-retry', methods=['POST'])
def auto_retry():
    """Auto-retry a message with updated token after approval"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        original_message = data.get('original_message', '')
        
        if not original_message:
            return jsonify({'error': 'No message provided'}), 400
        
        # This will be implemented to auto-retry with updated tokens
        return jsonify({
            'success': True,
            'response': 'Auto-retry not yet implemented',
            'user': session.get('user_name', 'User'),
            'auto_retried': True
        })
        
    except Exception as e:
        logger.error(f"❌ Error during auto-retry: {e}")
        return jsonify({'error': f'Auto-retry failed: {str(e)}'}), 500

@tokens_bp.route('/update-mcp-token-cookie', methods=['POST'])
def update_mcp_token_cookie():
    """Update MCP token cookie for sharing with admin dashboard"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        server_url = data.get('server_url', 'http://localhost:8001')
        token = data.get('token')
        
        if not token:
            return jsonify({'error': 'Token is required'}), 400
        
        # Only set cookie for the primary MCP server to avoid cookie size issues
        base_server_url = server_url.rstrip('/sse') if server_url.endswith('/sse') else server_url
        if base_server_url == 'http://localhost:8001':
            response = jsonify({'success': True, 'message': 'MCP token cookie updated'})
            response.set_cookie(
                'mcp_token',
                token,
                max_age=3600,
                httponly=False,  # Allow JavaScript access for admin dashboard
                secure=False,
                samesite='lax'
            )
            logger.info(f"✅ Set MCP token cookie for {session.get('user_email', 'unknown')}: {token[:20]}...")
            return response
        else:
            return jsonify({'success': True, 'message': 'Token stored but no cookie set (non-primary server)'})
        
    except Exception as e:
        logger.error(f"❌ Error updating MCP token cookie: {e}")
        return jsonify({'error': str(e)}), 500 