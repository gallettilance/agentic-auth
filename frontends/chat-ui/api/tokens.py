"""
Tokens API Blueprint (Keycloak Edition)
Handles token management using Keycloak OIDC directly.
"""

from flask import Blueprint, request, jsonify, session
import httpx
import asyncio
import logging
import os
import urllib.parse
from typing import Optional
import aiohttp
import base64

logger = logging.getLogger(__name__)

tokens_bp = Blueprint('tokens', __name__)

# Configuration
OIDC_ISSUER_URL = os.getenv("OIDC_ISSUER_URL")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET")
LLAMA_STACK_URL = os.getenv("LLAMA_STACK_URL", "http://localhost:8321")
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8001")

# Client IDs for token exchange (audiences)
LLAMA_STACK_CLIENT_ID = "llama-stack"
MCP_SERVER_CLIENT_ID = "mcp-server"

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

async def exchange_token_for_audience(access_token: str, audience: str, scopes: Optional[list] = None) -> dict:
    """Exchange access token for specific scopes using Token Exchange V2 self-exchange (audience parameter kept for compatibility)"""
    try:
        if scopes is None:
            scopes = []
            
        config = await get_oidc_configuration()
        if not config:
            return {'success': False, 'error': 'OIDC configuration not available'}
        
        token_endpoint = config.get('token_endpoint')
        if not token_endpoint:
            return {'success': False, 'error': 'Token endpoint not found'}
        
        # Token Exchange V2 - Self-exchange request (RFC 8693)
        data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token': access_token,
            'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'audience': OIDC_CLIENT_ID  # Always use self-exchange for Token Exchange V2
        }
        
        if scopes:
            data['scope'] = ' '.join(scopes)
            
        # Use Basic Auth for confidential client (consistent approach)
        auth = base64.b64encode(f"{OIDC_CLIENT_ID}:{OIDC_CLIENT_SECRET}".encode()).decode()
        headers = {
            'Authorization': f'Basic {auth}',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        logger.info(f"🔄 Token Exchange V2 - Self-exchange for scopes: {scopes}")
            
        # Make token exchange request
        async with aiohttp.ClientSession() as session:
            async with session.post(token_endpoint, data=data, headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    return {
                        'success': True,
                        'access_token': result['access_token'],
                        'token_type': result.get('token_type', 'Bearer'),
                        'expires_in': result.get('expires_in'),
                        'scope': result.get('scope', ' '.join(scopes) if scopes else ''),
                        'granted_scopes': result.get('scope', '').split() if result.get('scope') else []
                    }
                else:
                    error_data = await response.json()
                    logger.error(f"Token exchange failed: {error_data}")
                    return {
                        'success': False,
                        'error': error_data.get('error', 'Unknown error'),
                        'error_description': error_data.get('error_description', '')
                    }
                    
    except Exception as e:
        logger.error(f"Exception during token exchange: {e}")
        return {'success': False, 'error': str(e)}

@tokens_bp.route('/token-info')
def get_token_info():
    """Display current tokens - tokens should be automatically exchanged during login"""
    if 'authenticated' not in session:
        logger.warning("❌ Token info requested but user not authenticated")
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Get tokens from session (exchanged automatically during login callback)
        access_token = session.get('access_token')
        llama_stack_token = session.get('llama_stack_token')
        mcp_token = session.get('mcp_token')
        
        logger.info(f"🔍 Displaying tokens for {session.get('user_email')}: access_token={bool(access_token)}, llama_stack_token={bool(llama_stack_token)}, mcp_token={bool(mcp_token)}")
        
        # Helper function to decode and format token info
        def get_token_info_helper(token, token_type, audience_default):
            if not token:
                return {
                    'token': None,
                    'audience': audience_default,
                    'scopes': [],
                    'status': 'missing',
                    'message': f'{token_type} token not obtained during login - check logs for errors'
                }
            
            try:
                import jwt
                decoded = jwt.decode(token, options={"verify_signature": False})
                # Log full token for debugging
                logger.info(f"🎫 {token_type} token decoded: aud={decoded.get('aud')}, scope={decoded.get('scope')}, exp={decoded.get('exp')}")
                return {
                    'token': token,
                    'audience': decoded.get('aud', audience_default),
                    'scopes': decoded.get('scope', '').split() if decoded.get('scope') else [],
                    'expires': decoded.get('exp'),
                    'issued': decoded.get('iat'),
                    'roles': decoded.get('realm_access', {}).get('roles', []),
                    'status': 'available',
                    'message': f'{token_type} token ready for use'
                }
            except Exception as e:
                logger.error(f"❌ Error decoding {token_type} token: {e}")
                logger.info(f"🎫 {token_type} token (raw): {token}")  # Log full token for debugging
                return {
                    'token': token,
                    'audience': audience_default,
                    'scopes': [],
                    'status': 'invalid',
                    'message': f'{token_type} token invalid: {str(e)}'
                }
        
        # Get token information
        llama_stack_info = get_token_info_helper(llama_stack_token, 'Llama Stack', LLAMA_STACK_CLIENT_ID)
        mcp_info = get_token_info_helper(mcp_token, 'MCP', MCP_SERVER_CLIENT_ID)
        
        response_data = {
            'llama_stack_token': llama_stack_info,
            'mcp_token': mcp_info
        }
        
        logger.info(f"📊 Token status: llama_stack={llama_stack_info['status']}, mcp={mcp_info['status']}")
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"❌ Error getting token info: {e}")
        return jsonify({'error': str(e)}), 500

@tokens_bp.route('/refresh-llama-stack-token', methods=['POST'])
def refresh_llama_stack_token():
    """Get or refresh Llama Stack token using Keycloak token exchange"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        access_token = session.get('access_token')
        if not access_token:
            return jsonify({'error': 'No access token available'}), 400
        
        # Validate required configuration
        if not OIDC_CLIENT_ID:
            return jsonify({'error': 'OIDC client ID not configured'}), 500
        
        # Exchange token for Llama Stack scopes - using proper prefixes
        llama_scopes = [
            'llama:agent_create',
            'llama:agent_session_create', 
            'llama:inference_chat_completion'
        ]
        
        result = asyncio.run(exchange_token_for_audience(
            access_token=access_token,
            audience=OIDC_CLIENT_ID,  # Self-exchange
            scopes=llama_scopes
        ))
        
        if result['success']:
            llama_stack_token = result['access_token'] # Use access_token from result
            session['llama_stack_token'] = llama_stack_token
            
            logger.info(f"🎫 Generated Llama Stack token for {session.get('user_email')} with scopes: {llama_scopes}")
            
            return jsonify({
                'success': True,
                'message': 'Llama Stack token generated successfully',
                'token_preview': llama_stack_token[:20] + '...' if llama_stack_token else None,
                'scopes': llama_scopes
            })
        else:
            return jsonify({'error': result['error'], 'details': result.get('error_description')}), 400
        
    except Exception as e:
        logger.error(f"❌ Error generating Llama Stack token: {e}")
        return jsonify({'error': str(e)}), 500

@tokens_bp.route('/refresh-mcp-token', methods=['POST'])
def refresh_mcp_token():
    """Generate or refresh MCP token using Keycloak token exchange"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        access_token = session.get('access_token')
        if not access_token:
            return jsonify({'error': 'No access token available'}), 400
        
        # Validate required configuration
        if not OIDC_CLIENT_ID:
            return jsonify({'error': 'OIDC client ID not configured'}), 500
        
        # Get current scopes or request basic ones - using proper MCP prefixes
        request_data = request.json if request.json else {}
        current_scopes = request_data.get('scopes', [
            'mcp:list_files', 
            'mcp:get_server_info', 
            'mcp:health_check', 
            'mcp:list_tool_scopes'
        ])
        
        result = asyncio.run(exchange_token_for_audience(
            access_token=access_token,
            audience=OIDC_CLIENT_ID,  # Self-exchange
            scopes=current_scopes
        ))
        
        if result['success']:
            mcp_token = result['access_token'] # Use access_token from result
            session['mcp_token'] = mcp_token
            
            logger.info(f"🎫 Generated MCP token for {session.get('user_email')} with scopes: {current_scopes}")
            
            return jsonify({
                'success': True,
                'message': 'MCP token generated successfully',
                'token_preview': mcp_token[:20] + '...' if mcp_token else None,
                'scopes': current_scopes
            })
        else:
            return jsonify({'error': result['error'], 'details': result.get('error_description')}), 400
        
    except Exception as e:
        logger.error(f"❌ Error generating MCP token: {e}")
        return jsonify({'error': str(e)}), 500

@tokens_bp.route('/exchange-mcp-token-scope', methods=['POST'])
def exchange_mcp_token_scope():
    """Exchange MCP token for additional scopes (for insufficient scope errors)"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No request data provided'}), 400
            
        required_scope = data.get('required_scope')
        if not required_scope:
            return jsonify({'error': 'No required_scope provided'}), 400
        
        # Ensure scope has proper prefix
        if not required_scope.startswith('mcp:'):
            required_scope = f'mcp:{required_scope}'
        
        access_token = session.get('access_token')
        current_mcp_token = session.get('mcp_token')
        
        if not access_token:
            return jsonify({'error': 'No access token available'}), 400
        
        # Validate required configuration
        if not OIDC_CLIENT_ID:
            return jsonify({'error': 'OIDC client ID not configured'}), 500
        
        # Get current scopes from existing MCP token
        current_scopes = []
        if current_mcp_token:
            try:
                import jwt
                decoded = jwt.decode(current_mcp_token, options={"verify_signature": False})
                current_scopes = decoded.get('scope', '').split() if decoded.get('scope') else []
            except Exception:
                pass
        
        # Add the required scope to current scopes
        if required_scope not in current_scopes:
            current_scopes.append(required_scope)
        
        # Exchange token for new scopes
        result = asyncio.run(exchange_token_for_audience(
            access_token=access_token,
            audience=OIDC_CLIENT_ID,  # Self-exchange
            scopes=current_scopes
        ))
        
        if result['success']:
            new_mcp_token = result['access_token'] # Use access_token from result
            session['mcp_token'] = new_mcp_token
            
            logger.info(f"🎫 Exchanged MCP token for {session.get('user_email')} with new scopes: {current_scopes}")
            
            return jsonify({
                'success': True,
                'message': f'MCP token updated with scope: {required_scope}',
                'token_preview': new_mcp_token[:20] + '...' if new_mcp_token else None,
                'scopes': current_scopes
            })
        else:
            # Let Keycloak's error message through - it will indicate if scope requires approval
            logger.error(f"❌ Keycloak rejected scope '{required_scope}': {result.get('error')}")
            return jsonify({
                'success': False,
                'error': result['error'],
                'error_description': result.get('error_description'),
                'required_scope': required_scope,
                'message': f"Keycloak rejected the scope '{required_scope}'. This may require administrator approval or the scope may not be available to your user."
            }), 403
            
    except Exception as e:
        logger.error(f"❌ Error exchanging MCP token scope: {e}")
        return jsonify({'error': str(e)}), 500

@tokens_bp.route('/request-mcp-token', methods=['POST'])
def request_mcp_token():
    """Request a new MCP token (simplified for Keycloak)"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        server_url = data.get('server_url', MCP_SERVER_URL)
        required_scope = data.get('required_scope', 'mcp_basic_access')
        
        if not server_url:
            return jsonify({'error': 'Server URL required'}), 400
        
        # Use the MCP token refresh endpoint
        return refresh_mcp_token()
        
    except Exception as e:
        logger.error(f"❌ Error requesting MCP token: {e}")
        return jsonify({'error': str(e)}), 500

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
        session['llama_stack_token'] = new_token
        
        user_email = session.get('user_email', 'unknown')
        logger.info(f"🎫 Updated Llama Stack token for {user_email}")
        
        return jsonify({
            'success': True,
            'message': 'Session token updated successfully'
        })
        
    except Exception as e:
        logger.error(f"❌ Error updating session token: {e}")
        return jsonify({'error': str(e)}), 500

@tokens_bp.route('/check-token-update')
def check_token_update():
    """Check if tokens have been updated and return new scopes (Keycloak version)"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # In Keycloak mode, we don't have a separate auth server with token update endpoints
        # Token updates happen through the standard Keycloak token exchange flow
        # This endpoint now just returns the current token status
        
        logger.info("🔍 Checking Keycloak token status")
        
        # Check if we have current tokens
        access_token = session.get('access_token')
        llama_stack_token = session.get('llama_stack_token')
        
        if not access_token:
                return jsonify({
                'token_updated': False,
                'new_scopes': [],
                'error': 'No OIDC access token available'
            })
        
        # For Keycloak, tokens don't get "updated" by external servers
        # Instead, users refresh them via the dedicated refresh endpoints
        return jsonify({
            'token_updated': False,
            'new_scopes': [],
            'has_manual_approvals': False,
            'has_auto_approvals': False,
            'message': 'Keycloak tokens managed via standard OIDC flow - use refresh endpoints',
            'current_tokens': {
                'has_access_token': bool(access_token),
                'has_llama_stack_token': bool(llama_stack_token)
            }
        })
        
    except Exception as e:
        logger.error(f"❌ Error checking token status: {e}")
        return jsonify({
            'token_updated': False,
            'new_scopes': [],
            'error': str(e)
        })

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
        bearer_token = session.get('llama_stack_token', '')
        
        # Get auth cookies
        auth_cookies = {}
        if request.cookies.get('auth_session'):
            auth_cookies['auth_session'] = request.cookies.get('auth_session')
        
        logger.info(f"🔄 Auto-retrying message for {user_email}: {original_message}")
        
        # Stream the response and collect it
        response_content = ""
        try:
            mcp_token = session.get('mcp_token')  # Get MCP token from session while in request context
            for chunk in stream_agent_response_with_auth_detection(
                original_message, 
                bearer_token, 
                user_email, 
                original_message,
                auth_cookies,
                retry_count=0,
                mcp_token=mcp_token  # Pass MCP token to avoid context issues
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