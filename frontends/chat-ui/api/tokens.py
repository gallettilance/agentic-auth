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
        has_manual_approvals = False
        has_auto_approvals = False
        
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
                        audience = auth_data.get('audience')
                        
                        if not audience:
                            logger.error("❌ No audience found in auth data - cannot process token update")
                            continue
                        
                        # Collect approval type information
                        if auth_data.get('has_manual_approvals', False):
                            has_manual_approvals = True
                        if auth_data.get('has_auto_approvals', False):
                            has_auto_approvals = True
                        
                        all_new_scopes.extend(new_scopes)
                        all_total_scopes.extend(total_scopes)
                        update_messages.append(auth_data.get('message', f'Token updated from {auth_server_url}'))
                        
                        if new_token:
                            # Update the session with new token
                            session['bearer_token'] = new_token
                            logger.info(f"🎫 Updated session token from {auth_server_url} for {session.get('user_email', 'unknown')}")
                            
                            # Also update MCP tokens if this affects MCP scopes
                            user_email = session.get('user_email', 'anonymous')
                            
                            # Check if there's a separate MCP token in the response
                            mcp_token = auth_data.get('mcp_token')
                            mcp_audience = auth_data.get('mcp_audience')
                            
                            if mcp_token and mcp_audience:
                                # Import helper functions
                                import sys
                                import os
                                sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                                from app import store_mcp_token_for_user
                                from utils.mcp_tokens_utils import get_base_mcp_url
                                
                                base_url = get_base_mcp_url(mcp_audience)
                                store_mcp_token_for_user(user_email, base_url, mcp_token)
                                
                                logger.info(f"🎫 Updated MCP token for {base_url} from {auth_server_url}")
                            elif audience:
                                # Check if this is an MCP server token by checking if audience looks like an MCP server URL
                                # MCP server URLs typically have patterns like localhost:8001, contain 'mcp', etc.
                                if (audience.startswith(('http://localhost:', 'https://localhost:')) and 
                                    audience.find(':800') != -1) or 'mcp' in audience.lower():
                                    # This looks like an MCP server token - store it as MCP token
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
                'has_manual_approvals': has_manual_approvals,
                'has_auto_approvals': has_auto_approvals,
                'auth_servers_checked': list(auth_servers_to_check),
                'message': '; '.join(update_messages) if update_messages else 'Tokens updated with new permissions'
            })
        else:
            # No updates from any server
            return jsonify({
                'token_updated': False,
                'new_scopes': [],
                'has_manual_approvals': False,
                'has_auto_approvals': False,
                'auth_servers_checked': list(auth_servers_to_check)
            })
            
    except Exception as e:
        logger.error(f"❌ Error checking token updates: {e}")
        return jsonify({
            'token_updated': False,
            'new_scopes': [],
            'error': str(e)
        })

@tokens_bp.route('/update-token', methods=['POST'])
def update_token():
    """Update the session bearer token"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        new_token = data.get('new_token')
        
        if not new_token:
            return jsonify({'error': 'No token provided'}), 400
        
        # Update the session with the new token
        session['bearer_token'] = new_token
        
        user_email = session.get('user_email', 'unknown')
        logger.info(f"🎫 Updated session bearer token for {user_email}: {new_token[:20]}...")
        
        return jsonify({
            'success': True,
            'message': 'Session token updated successfully'
        })
        
    except Exception as e:
        logger.error(f"❌ Error updating session token: {e}")
        return jsonify({'error': str(e)}), 500

@tokens_bp.route('/refresh-llama-stack-token', methods=['POST'])
def refresh_llama_stack_token():
    """Refresh the Llama Stack token"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Get auth cookies for the request
        auth_cookies = {}
        if request.cookies.get('auth_session'):
            auth_cookies['auth_session'] = request.cookies.get('auth_session')
        
        # Get current user info
        user_email = session.get('user_email', 'unknown')
        
        # Request a new Llama Stack token from the auth server
        import requests
        
        # Get the user's current approved scopes from the auth server
        user_status_response = requests.get(
            f"{AUTH_SERVER_URL}/api/user-status",
            cookies=auth_cookies,
            timeout=10
        )
        
        if user_status_response.status_code != 200:
            raise Exception("Failed to get user status from auth server")
        
        user_data = user_status_response.json()
        user_scopes = user_data.get('scopes', [])
        
        # IMPORTANT: Filter out MCP tool scopes - Llama Stack tokens should only have general user permissions
        # MCP tool scopes like execute_command, list_files, etc. should not be in Llama Stack tokens
        common_tool_scopes = {'execute_command', 'list_files', 'read_file', 'write_file', 'delete_file', 'search_files', 'get_system_info'}
        llama_stack_scopes = [scope for scope in user_scopes if scope not in common_tool_scopes]
        
        logger.info(f"🔍 Filtered scopes for Llama Stack token - All: {user_scopes}, Llama Stack: {llama_stack_scopes}")
        
        # Request a new Llama Stack token with current scopes
        llama_stack_url = "http://localhost:8321"  # Llama Stack audience
        
        token_response = requests.post(
            f"{AUTH_SERVER_URL}/api/initial-token",
            json={
                "resource": llama_stack_url,
                "scopes": llama_stack_scopes  # Use filtered scopes
            },
            cookies=auth_cookies,
            timeout=10
        )
        
        if token_response.status_code == 200:
            token_data = token_response.json()
            new_token = token_data.get('token')
            
            if new_token:
                # Update the session with the new token
                session['bearer_token'] = new_token
                logger.info(f"🎫 Refreshed Llama Stack token for {user_email} with scopes: {llama_stack_scopes}")
                
                return jsonify({
                    'success': True,
                    'message': f'Llama Stack token refreshed with scopes: {", ".join(llama_stack_scopes)}',
                    'scopes': llama_stack_scopes
                })
            else:
                raise Exception("No token received from auth server")
        else:
            raise Exception(f"Auth server returned {token_response.status_code}: {token_response.text}")
        
    except Exception as e:
        logger.error(f"❌ Error refreshing Llama Stack token: {e}")
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
        
        # Import the streaming utilities
        import sys
        import os
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from utils.streaming_utils import stream_agent_response_with_auth_detection
        
        # Get user info from session
        user_email = session.get('user_email', 'anonymous')
        bearer_token = session.get('bearer_token', '')
        
        # Get auth cookies
        auth_cookies = {}
        if request.cookies.get('auth_session'):
            auth_cookies['auth_session'] = request.cookies.get('auth_session')
        
        logger.info(f"🔄 Auto-retrying message for {user_email}: {original_message}")
        
        # Stream the response and collect it
        response_content = ""
        try:
            for chunk in stream_agent_response_with_auth_detection(
                original_message, 
                bearer_token, 
                user_email, 
                original_message,
                auth_cookies,
                retry_count=0
            ):
                response_content += chunk
            
            # Return the collected response
            return jsonify({
                'success': True,
                'response': response_content,
                'user': session.get('user_name', 'User'),
                'auto_retried': True
            })
            
        except Exception as streaming_error:
            logger.error(f"❌ Streaming error during auto-retry: {streaming_error}")
            return jsonify({
                'success': False,
                'error': f'Auto-retry failed: {str(streaming_error)}',
                'response': f'❌ Auto-retry failed: {str(streaming_error)}'
            }), 500
        
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
        server_url = data.get('server_url')
        token = data.get('token')
        
        if not server_url:
            return jsonify({'error': 'Server URL is required'}), 400
        
        if not token:
            return jsonify({'error': 'Token is required'}), 400
        
        # For now, skip setting cookies to avoid cookie size issues with multiple MCP servers
        # Cookies are not essential for MCP token functionality - tokens are stored in session/database
        base_server_url = server_url.rstrip('/sse') if server_url.endswith('/sse') else server_url
        
        # Skip cookie setting since we now support multiple dynamically discovered MCP servers
        # and cookies have size limitations
        logger.info(f"📋 MCP token stored for {base_server_url} (cookie skipped for {session.get('user_email', 'unknown')})")
        return jsonify({'success': True, 'message': 'MCP token stored (cookie skipped for multi-server support)'})
        
    except Exception as e:
        logger.error(f"❌ Error updating MCP token cookie: {e}")
        return jsonify({'error': str(e)}), 500

@tokens_bp.route('/test-service-discovery', methods=['GET'])
def test_service_discovery():
    """Test MCP service discovery functionality"""
    try:
        import asyncio
        from utils.service_discovery import discover_mcp_auth_configs, get_configured_mcp_servers
        
        # Get configured MCP servers
        mcp_servers = get_configured_mcp_servers()
        
        # Run MCP discovery
        configs = asyncio.run(discover_mcp_auth_configs())
        
        return jsonify({
            'success': True,
            'configured_mcp_servers': mcp_servers,
            'discovered_configs': configs,
            'message': f'Discovered {len(configs)} MCP server configurations'
        })
        
    except Exception as e:
        logger.error(f"❌ MCP service discovery test failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500 