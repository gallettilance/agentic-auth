"""
MCP token management utilities
Handles MCP token storage, retrieval, and scope upgrades.
"""

import httpx
import asyncio
import logging
import json
import os
import sys
from typing import Dict, Optional
from utils.service_discovery import get_auth_server_for_mcp_server

logger = logging.getLogger(__name__)

# Configuration - these can be overridden by service discovery
AUTH_SERVER_URL = "http://localhost:8002"  # Default fallback
# MCP_SERVER_URL removed - will be discovered from Llama Stack toolgroups

def get_base_mcp_url(mcp_server_url: str) -> str:
    """Get base MCP URL by stripping /sse suffix if present"""
    if mcp_server_url.endswith('/mcp'):
        return mcp_server_url[:-4]
    return mcp_server_url

def get_mcp_tokens_for_user_direct(user_email: str) -> dict:
    """Get MCP tokens for a user directly from auth server"""
    logger.info(f"🔍 === get_mcp_tokens_for_user_direct START for {user_email} ===")
    
    try:
        # Use synchronous httpx client
        import httpx
        
        response = httpx.get(
            f"{AUTH_SERVER_URL}/api/user-mcp-tokens",
            params={"user_email": user_email},
            timeout=5.0
        )
        
        logger.info(f"🔍 DEBUG: Auth server response status: {response.status_code}")
        logger.info(f"🔍 DEBUG: Auth server response headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            result = response.json()
            logger.info(f"🔍 DEBUG: Auth server response data: {result}")
            
            if result.get("success"):
                tokens = result.get("tokens", {})
                logger.info(f"🔐 Retrieved {len(tokens)} MCP tokens for {user_email} from auth server")
                
                # Log each token
                for server_url, token in tokens.items():
                    logger.info(f"🔍 DEBUG: Token for {server_url}: {token[:20] if token else 'None'}...")
                
                logger.info(f"🔍 === get_mcp_tokens_for_user_direct END for {user_email} (success) ===")
                return tokens
            else:
                error_msg = result.get("error", "Unknown error")
                logger.warning(f"⚠️ Auth server returned error: {error_msg}")
                logger.info(f"🔍 === get_mcp_tokens_for_user_direct END for {user_email} (auth error) ===")
                return {}
        else:
            logger.error(f"❌ Failed to retrieve MCP tokens: {response.status_code}")
            logger.error(f"❌ Response body: {response.text}")
            logger.info(f"🔍 === get_mcp_tokens_for_user_direct END for {user_email} (http error) ===")
            return {}
    
    except Exception as e:
        logger.error(f"❌ Error retrieving MCP tokens for {user_email}: {e}")
        import traceback
        logger.error(f"❌ Full traceback: {traceback.format_exc()}")
        logger.info(f"🔍 === get_mcp_tokens_for_user_direct END for {user_email} (exception) ===")
        return {}

def store_mcp_token_for_user_direct(user_email: str, server_url: str, token: str):
    """Store MCP token for user (direct implementation)"""
    # Import helper function from main app
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import store_mcp_token_for_user
    
    return store_mcp_token_for_user(user_email, server_url, token)

def generate_initial_no_scope_token(user_email: str, bearer_token: str) -> bool:
    """
    Generate initial no-scope token for MCP server access
    
    DEPRECATED: This function is deprecated. MCP tokens are now generated
    dynamically from Llama Stack toolgroups discovery after OAuth callback.
    """
    logger.info(f"🎫 === generate_initial_no_scope_token START for {user_email} ===")
    logger.info(f"🎫 generate_initial_no_scope_token is deprecated - MCP tokens now generated via discovery")
    logger.info(f"🎫 === generate_initial_no_scope_token END for {user_email} (DEPRECATED) ===")
    
    # Return True to maintain compatibility with existing code
    return True

def prepare_mcp_headers_for_user(user_email: str) -> dict:
    """
    Prepare MCP headers for a user by getting their existing MCP tokens
    Tokens are generated during OAuth callback, so this just retrieves them
    """
    logger.info(f"🔍 === prepare_mcp_headers_for_user START for {user_email} ===")
    
    try:
        # Get existing MCP tokens for the user (generated during OAuth callback)
        mcp_tokens = get_mcp_tokens_for_user_direct(user_email)
        logger.info(f"🔍 DEBUG: Found {len(mcp_tokens)} existing MCP tokens: {list(mcp_tokens.keys())}")
        
        # Build headers for each MCP server
        mcp_headers = {}
        for mcp_server_url, mcp_token in mcp_tokens.items():
            logger.info(f"🔍 DEBUG: Processing MCP server: {mcp_server_url}")
            logger.info(f"🔍 DEBUG: Token present: {bool(mcp_token)}")
            logger.info(f"🔍 DEBUG: Token length: {len(mcp_token) if mcp_token else 0}")
            
            if mcp_token and mcp_token != "NO_TOKEN_YET":
                # Convert base URL to SSE endpoint URL for Llama Stack
                mcp_endpoint_url = mcp_server_url
                if not mcp_endpoint_url.endswith('/mcp'):
                    mcp_endpoint_url = f"{mcp_server_url}/mcp"
                
                mcp_headers[mcp_endpoint_url] = {
                    "Authorization": f"Bearer {mcp_token}"
                }
                logger.info(f"🔐 Added MCP header for {mcp_endpoint_url}: Bearer {mcp_token[:20]}...")
            else:
                logger.info(f"🔍 DEBUG: Skipping {mcp_server_url} - no valid token")
        
        logger.info(f"🔍 Final mcp_headers: {list(mcp_headers.keys())}")
        
        if mcp_headers:
            # Format headers for Llama Stack
            headers = {
                "X-LlamaStack-Provider-Data": json.dumps({
                    "mcp_headers": mcp_headers
                })
            }
            logger.info(f"🔐 Returning MCP headers for {len(mcp_headers)} servers")
            logger.info(f"🔍 === prepare_mcp_headers_for_user END for {user_email} (with headers) ===")
            return headers
        else:
            logger.info(f"🔐 No MCP tokens for {user_email} - agent will call MCP tools without auth")
            logger.info(f"🔍 === prepare_mcp_headers_for_user END for {user_email} (no headers) ===")
            return {}
    
    except Exception as e:
        logger.error(f"❌ Error preparing MCP headers for {user_email}: {e}")
        import traceback
        logger.error(f"❌ Full traceback: {traceback.format_exc()}")
        logger.info(f"🔍 === prepare_mcp_headers_for_user END for {user_email} (error) ===")
        return {}

async def request_scope_upgrade(required_scope: str, user_token: str, auth_cookies: dict = {}, auth_server_url: str | None = None, resource: str | None = None, current_token: str | None = None) -> dict:
    """Request scope upgrade from auth server"""
    try:
        if not auth_server_url:
            auth_server_url = AUTH_SERVER_URL
        
        upgrade_data = {
            "scopes": [required_scope],
            "justification": f"Agent requires {required_scope} scope to execute user request"
        }
        
        if resource:
            upgrade_data["resource"] = resource
        
        # Include current MCP token so auth server can extract current scopes
        if current_token:
            upgrade_data["current_token"] = current_token
            logger.info(f"🔄 Including current MCP token for scope upgrade: {current_token[:20]}...")
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(
                f"{auth_server_url}/api/upgrade-scope",
                json=upgrade_data,
                cookies=auth_cookies,
                timeout=10.0
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Check if there are pending approvals
                pending_scopes = result.get('pending_approval_scopes', [])
                auto_approved = result.get('auto_approved_scopes', [])
                new_token = result.get('new_token')
                
                if pending_scopes:
                    logger.info(f"🔔 Scope upgrade requires admin approval: {pending_scopes}")
                    return {
                        'success': True,
                        'status': 'pending_admin_approval',
                        'pending_scopes': pending_scopes,
                        'auto_approved_scopes': auto_approved,
                        'approval_request_ids': result.get('approval_request_ids', []),
                        'new_token': new_token,
                        'message': f"Approval request submitted for scopes: {', '.join(pending_scopes)}"
                    }
                elif auto_approved:
                    logger.info(f"✅ Scope upgrade auto-approved: {auto_approved}")
                    return {
                        'success': True,
                        'status': 'approved',
                        'auto_approved_scopes': auto_approved,
                        'token': new_token,
                        'access_token': new_token,  # Backward compatibility
                        'message': f"Scopes auto-approved: {', '.join(auto_approved)}"
                    }
                else:
                    logger.warning(f"⚠️ Scope upgrade returned success but no scopes processed")
                    return {
                        'success': True,
                        'status': 'no_change',
                        'message': 'No scope changes needed'
                    }
                
            else:
                logger.error(f"❌ Scope upgrade failed: {response.status_code} - {response.text}")
                return {
                    'error': f'Scope upgrade failed: {response.status_code}',
                    'status': 'failed'
                }
                
    except Exception as e:
        logger.error(f"❌ Error requesting scope upgrade: {e}")
        return {
            'error': str(e),
            'status': 'failed'
        }

async def request_mcp_token(required_scope: str, mcp_server_url: str, current_token: str = '', 
                           auth_cookies: dict = {}, auth_server_url: Optional[str] = None) -> dict:
    """Request an MCP token from the auth server"""
    try:
        # Use service discovery to get auth server URL if not provided
        if not auth_server_url:
            auth_server_url = await get_discovered_auth_server_url(mcp_server_url)
        
        logger.info(f"🔐 Requesting MCP token for scope: {required_scope}")
        logger.info(f"🎯 Target MCP server: {mcp_server_url}")
        logger.info(f"🔗 Using auth server: {auth_server_url}")
        
        # Get base URL for consistent token storage
        base_mcp_url = get_base_mcp_url(mcp_server_url)
        
        async with httpx.AsyncClient(verify=False) as client:
            # Use the dedicated MCP token endpoint
            response = await client.post(
                f"{auth_server_url}/api/request-mcp-token",
                json={
                    "resource": base_mcp_url,
                    "scopes": [required_scope],
                    "current_token": current_token
                },
                cookies=auth_cookies,
                timeout=10.0
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"✅ MCP token request successful: {result.get('status', 'unknown')}")
                return result
            else:
                logger.error(f"❌ MCP token request failed: {response.status_code}")
                try:
                    error_data = response.json()
                    logger.error(f"❌ Error details: {error_data}")
                    return {'error': error_data.get('error', 'Unknown error')}
                except:
                    return {'error': f'HTTP {response.status_code}'}
                
    except Exception as e:
        logger.error(f"❌ Exception during MCP token request: {e}")
        return {'error': str(e)}

async def get_discovered_auth_server_url(mcp_server_url: str) -> str:
    """
    Get the auth server URL for an MCP server using service discovery
    
    Args:
        mcp_server_url: URL of the MCP server
        
    Returns:
        Auth server URL (discovered or fallback)
    """
    try:
        discovered_auth_server = await get_auth_server_for_mcp_server(mcp_server_url)
        if discovered_auth_server:
            logger.info(f"🔍 Discovered auth server for {mcp_server_url}: {discovered_auth_server}")
            return discovered_auth_server
        else:
            logger.warning(f"⚠️ Could not discover auth server for {mcp_server_url}, using default")
            return AUTH_SERVER_URL
    except Exception as e:
        logger.error(f"❌ Error discovering auth server for {mcp_server_url}: {e}")
        return AUTH_SERVER_URL 