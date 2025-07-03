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
    """Get MCP tokens for user (direct implementation)"""
    # Import helper function from main app
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import get_mcp_tokens_for_user
    
    return get_mcp_tokens_for_user(user_email)

def store_mcp_token_for_user_direct(user_email: str, server_url: str, token: str):
    """Store MCP token for user (direct implementation)"""
    # Import helper function from main app
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import store_mcp_token_for_user
    
    return store_mcp_token_for_user(user_email, server_url, token)

def prepare_mcp_headers_for_user(user_email: str) -> dict:
    """Prepare MCP authentication headers for a specific user"""
    mcp_tokens = get_mcp_tokens_for_user_direct(user_email)
    
    # DEBUG: Log what tokens we found
    logger.info(f"🔍 DEBUG: prepare_mcp_headers_for_user called for {user_email}")
    logger.info(f"🔍 DEBUG: Found {len(mcp_tokens)} MCP tokens: {list(mcp_tokens.keys())}")
    for url, token in mcp_tokens.items():
        logger.info(f"🔍 DEBUG: Token for {url}: {token[:20] if token else 'NONE'}...")
    
    mcp_headers = {}
    for mcp_server_url, mcp_token in mcp_tokens.items():
        if mcp_token and mcp_token != "NO_TOKEN_YET":
            # Convert base URL to full MCP endpoint URL for Llama Stack
            # Llama Stack expects the full endpoint URL including /sse
            mcp_endpoint_url = mcp_server_url
            if not mcp_endpoint_url.endswith('/sse'):
                mcp_endpoint_url = f"{mcp_server_url}/sse"
            
            mcp_headers[mcp_endpoint_url] = {
                "Authorization": f"Bearer {mcp_token}"
            }
            logger.info(f"🔐 Using MCP token for {user_email} -> {mcp_endpoint_url}: {mcp_token[:20]}...")
    
    if mcp_headers:
        logger.info(f"🔐 Configured MCP headers for {user_email}: {len(mcp_headers)} servers")
        logger.info(f"🔍 DEBUG: MCP header endpoints: {list(mcp_headers.keys())}")
        return {
            "X-LlamaStack-Provider-Data": json.dumps({
                "mcp_headers": mcp_headers
            })
        }
    else:
        logger.info(f"🔐 No MCP tokens for {user_email} - agent will call MCP tools without auth")
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
                return response.json()
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
            "audience": mcp_server_url,
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
                return response.json()
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