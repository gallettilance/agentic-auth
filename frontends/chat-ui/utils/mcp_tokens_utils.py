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

logger = logging.getLogger(__name__)

# Configuration
AUTH_SERVER_URL = os.getenv("AUTH_SERVER_URL", "http://localhost:8002")

def get_base_mcp_url(mcp_server_url: str) -> str:
    """Get base MCP URL by stripping /sse suffix if present"""
    if mcp_server_url.endswith('/sse'):
        return mcp_server_url[:-4]
    return mcp_server_url

def get_mcp_tokens_for_user_direct(user_email: str) -> dict:
    """Get MCP tokens for user from auth server database"""
    try:
        # Get tokens from auth server database via API
        # This is better than local storage since tokens are now generated during OAuth
        response = httpx.get(
            f"{AUTH_SERVER_URL}/api/user-mcp-tokens",
            params={"user_email": user_email},
            timeout=5.0
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get("success"):
                tokens = result.get("tokens", {})
                logger.info(f"🔐 Retrieved {len(tokens)} MCP tokens for {user_email} from auth server")
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

def store_mcp_token_for_user_direct(user_email: str, server_url: str, token: str):
    """Store MCP token for user (direct implementation)"""
    # Import helper function from main app
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import store_mcp_token_for_user
    
    return store_mcp_token_for_user(user_email, server_url, token)

def generate_initial_no_scope_token(user_email: str, bearer_token: str) -> bool:
    """Generate initial no-scope token for MCP server access"""
    logger.info(f"🎫 === generate_initial_no_scope_token START for {user_email} ===")
    
    try:
        # Check if user already has MCP tokens
        mcp_tokens = get_mcp_tokens_for_user_direct(user_email)
        if mcp_tokens:
            logger.info(f"🎫 User {user_email} already has MCP tokens, skipping generation")
            return True
        
        mcp_server_url = "http://localhost:8001"
        logger.info(f"🎫 Generating no-scope token for MCP server: {mcp_server_url}")
        
        # Make request to auth server to generate no-scope token
        response = httpx.post(
            f"{AUTH_SERVER_URL}/api/initial-token",
            json={
                "resource": mcp_server_url,
                "scopes": []  # No scopes - empty token
            },
            headers={
                "Authorization": f"Bearer {bearer_token}",
                "Content-Type": "application/json"
            },
            timeout=5.0
        )
        
        logger.info(f"🔗 Auth server response: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            logger.info(f"🔗 Auth server result: {result}")
            
            if result.get("success") and result.get("token"):
                no_scope_token = result["token"]
                logger.info(f"✅ Generated initial no-scope token for {user_email}: {no_scope_token[:20]}...")
                
                # Store token for the user
                store_mcp_token_for_user_direct(user_email, mcp_server_url, no_scope_token)
                logger.info(f"🔐 Stored no-scope token for {user_email} -> {mcp_server_url}")
                
                logger.info(f"🎫 === generate_initial_no_scope_token END for {user_email} (SUCCESS) ===")
                return True
            else:
                logger.warning(f"⚠️ Failed to generate no-scope token: {result}")
                return False
        else:
            logger.warning(f"⚠️ No-scope token request failed: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Error generating no-scope token for {user_email}: {e}")
        return False

def prepare_mcp_headers_for_user(user_email: str) -> dict:
    """Prepare MCP authentication headers for a specific user"""
    logger.info(f"🔍 === prepare_mcp_headers_for_user START for {user_email} ===")
    
    mcp_tokens = get_mcp_tokens_for_user_direct(user_email)
    
    # DEBUG: Log what tokens we found
    logger.info(f"🔍 DEBUG: prepare_mcp_headers_for_user called for {user_email}")
    logger.info(f"🔍 DEBUG: Found {len(mcp_tokens)} MCP tokens: {list(mcp_tokens.keys())}")
    for url, token in mcp_tokens.items():
        logger.info(f"🔍 DEBUG: Token for {url}: {token[:20] if token else 'NONE'}...")
    
    mcp_headers = {}
    for mcp_server_url, mcp_token in mcp_tokens.items():
        logger.info(f"🔍 Processing token for {mcp_server_url}: {mcp_token[:20] if mcp_token else 'NONE'}...")
        
        if mcp_token and mcp_token != "NO_TOKEN_YET":
            # Convert base URL to full MCP endpoint URL for Llama Stack
            # Llama Stack expects the full endpoint URL including /sse
            mcp_endpoint_url = mcp_server_url
            if not mcp_endpoint_url.endswith('/sse'):
                mcp_endpoint_url = f"{mcp_server_url}/sse"
            
            mcp_headers[mcp_endpoint_url] = {
                "Authorization": f"Bearer {mcp_token}"
            }
            logger.info(f"🔐 Added MCP header for {user_email} -> {mcp_endpoint_url}: {mcp_token[:20]}...")
    
    logger.info(f"🔍 Final mcp_headers: {list(mcp_headers.keys())}")
    
    if mcp_headers:
        logger.info(f"🔐 Configured MCP headers for {user_email}: {len(mcp_headers)} servers")
        logger.info(f"🔍 DEBUG: MCP header endpoints: {list(mcp_headers.keys())}")
        
        result = {
            "X-LlamaStack-Provider-Data": json.dumps({
                "mcp_headers": mcp_headers
            })
        }
        logger.info(f"🔍 Returning headers: {result}")
        logger.info(f"🔍 === prepare_mcp_headers_for_user END for {user_email} ===")
        return result
    else:
        logger.info(f"🔐 No MCP tokens for {user_email} - agent will call MCP tools without auth")
        logger.info(f"🔍 === prepare_mcp_headers_for_user END for {user_email} (no headers) ===")
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
        
        async with httpx.AsyncClient() as client:
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

async def request_mcp_token(required_scope: str, mcp_server_url: str, current_token: str = "", auth_cookies: dict = {}, auth_server_url: str | None= None) -> dict:
    """Request MCP token from auth server"""
    try:
        if not auth_server_url:
            auth_server_url = AUTH_SERVER_URL
        
        token_data = {
            "resource": mcp_server_url,
            "scopes": [required_scope]
        }
        
        if current_token:
            token_data["current_token"] = current_token
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{auth_server_url}/api/initial-token",
                json=token_data,
                cookies=auth_cookies,
                timeout=10.0
            )
            
            if response.status_code == 200:
                response_data = response.json()
                if response_data.get('success') and response_data.get('token'):
                    return {
                        'access_token': response_data['token'],
                        'token_type': 'Bearer',
                        'expires_in': 3600,
                        'scope': ' '.join(response_data.get('scopes', [])),
                        'resource': response_data.get('resource'),
                        'success': True
                    }
                else:
                    return response_data
            else:
                logger.error(f"❌ MCP token request failed: {response.status_code} - {response.text}")
                return {
                    'error': f'MCP token request failed: {response.status_code}'
                }
                
    except Exception as e:
        logger.error(f"❌ Error requesting MCP token: {e}")
        return {
            'error': str(e)
        } 