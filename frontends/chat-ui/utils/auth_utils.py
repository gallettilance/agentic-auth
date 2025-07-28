"""
Authentication utilities for chat API
Handles auth server communication and error parsing.
"""

from flask import request
import httpx
import logging
import re
import os

logger = logging.getLogger(__name__)

# Configuration
AUTH_SERVER_URL = os.getenv("AUTH_SERVER_URL", "http://localhost:8002")

def check_auth_server_session_direct():
    """Check if user has valid session with auth server (direct implementation)"""
    try:
        # Get auth session cookie
        auth_session_cookie = request.cookies.get('auth_session')
        logger.info(f"🔍 Auth session cookie: {auth_session_cookie[:20] if auth_session_cookie else 'None'}...")
        
        if not auth_session_cookie:
            logger.warning("🔍 No auth session cookie found")
            return None
        
        # Verify session with auth server
        with httpx.Client() as client:
            response = client.get(
                f"{AUTH_SERVER_URL}/api/user-status", 
                cookies={'auth_session': auth_session_cookie},
                timeout=5.0
            )
            
            logger.info(f"🔍 Auth server response status: {response.status_code}")
            
            if response.status_code == 200:
                user_data = response.json()
                logger.info(f"🔍 Auth server response data: {user_data}")
                
                if user_data.get('authenticated'):
                    logger.info(f"🔍 User is authenticated: {user_data['user']}")
                    return user_data['user']  # Return just the user data
                else:
                    logger.warning(f"🔍 User not authenticated according to auth server: {user_data}")
            else:
                logger.error(f"🔍 Auth server returned non-200 status: {response.status_code}")
                try:
                    error_data = response.json()
                    logger.error(f"🔍 Auth server error data: {error_data}")
                except:
                    logger.error(f"🔍 Auth server error text: {response.text}")
        
        return None
    except Exception as e:
        logger.error(f"Error checking auth server session: {e}")
        import traceback
        traceback.print_exc()
        return None

def is_authorization_error(error_message: str) -> bool:
    """Check if error message indicates an authorization issue"""
    error_lower = error_message.lower()
    
    authorization_indicators = [
        "authorizationerror",
        "authorization required",
        "insufficientscopeerror", 
        "insufficient scope",
        "insufficient oauth2 scopes",  # Llama Stack specific
        "access denied",
        "unauthorized",
        "permission denied",
        "forbidden",
        "401",
        "403"
    ]
    
    return any(indicator in error_lower for indicator in authorization_indicators)

def extract_authorization_error_details(error_message: str) -> dict:
    """Extract details from authorization error messages"""
    error_lower = error_message.lower()
    
    # Default values
    tool_name = "unknown_tool"
    required_scope = "execute_command"  # Most common restricted scope (now using tool name)
    error_type = "authorization"
    approval_status = "unknown"
    approval_requested = False
    mcp_server_url = None
    auth_server_url = None
    
    # Check if this is the new AuthorizationError from auth agent (HTTP 401)
    if "AuthorizationError" in error_message:
        error_type = "authorization_required"
        approval_requested = False  # This is a 401, need to get initial token
        
        # Try to extract tool name and MCP server URL from the error message
        # Format: AuthorizationError: Authorization required for tool 'execute_command' on server 'http://localhost:8000'
        tool_match = re.search(r"tool ['\"]?(\w+)['\"]?", error_message)
        if tool_match:
            tool_name = tool_match.group(1)
        
        # Try to extract required scope from the error message
        # Format: "requires scope 'mcp:list_files'" or similar
        scope_match = re.search(r"requires scope ['\"]?([^'\"]+)['\"]?", error_message)
        if scope_match:
            required_scope = scope_match.group(1)
            logger.info(f"🔍 Parsed exact required scope from AuthorizationError: '{required_scope}'")
        else:
            # Fallback: use tool name with mcp: prefix if it's an MCP tool
            # Check if this is an MCP server error by looking for MCP server URL
            if "localhost:8001" in error_message or "mcp" in error_message.lower():
                required_scope = f"mcp:{tool_name}"
                logger.info(f"🔍 Using MCP fallback scope: '{required_scope}' (tool: {tool_name})")
            else:
                required_scope = tool_name
                logger.info(f"🔍 Using generic fallback scope: '{required_scope}' (tool: {tool_name})")
            logger.info(f"🔍 Using fallback scope for AuthorizationError: '{required_scope}' (tool: {tool_name})")
        
        mcp_server_match = re.search(r"server ['\"]?([^'\"]+)['\"]?", error_message)
        if mcp_server_match:
            mcp_server_url = mcp_server_match.group(1)
        
        return {
            "error_type": error_type,
            "tool_name": tool_name,
            "required_scope": required_scope,
            "mcp_server_url": mcp_server_url,
            "auth_server_url": None,  # Will be discovered by chat app
            "original_error": error_message,
            "approval_requested": approval_requested,
            "approval_status": "needs_discovery_and_token"
        }
    
    # Check if this is the new InsufficientScopeError from auth agent
    if "InsufficientScopeError" in error_message:
        error_type = "insufficient_scope"
        approval_requested = True  # Auth agent automatically requests approval
        
        # Try to extract tool name from the error message
        # Format: InsufficientScopeError: Tool 'execute_command' requires scope 'execute_command' on server 'http://localhost:8001/sse' but current scopes are ['list_files']
        tool_match = re.search(r"Tool ['\"]?([^'\"]+)['\"]?", error_message)
        if tool_match:
            tool_name = tool_match.group(1)
            # Default required_scope to tool name initially
            required_scope = tool_name
        
        # Try to extract required scope (should be more specific than tool name)
        scope_match = re.search(r"requires scope ['\"]?([^'\"]+)['\"]?", error_message)
        if scope_match:
            # Use the exact scope as specified by the MCP server - don't modify it
            required_scope = scope_match.group(1)
            logger.info(f"🔍 Parsed exact required scope from MCP error: '{required_scope}'")
        
        # Try to extract MCP server URL from the error message
        # Format: "on server 'http://localhost:8001/sse'" or "on server 'http://localhost:8001'"
        mcp_server_match = re.search(r"on server ['\"]?([^'\"]+)['\"]?", error_message)
        if mcp_server_match:
            mcp_server_url = mcp_server_match.group(1)
            logger.info(f"🔍 Parsed MCP server URL from error: '{mcp_server_url}'")
        
        return {
            "error_type": error_type,
            "tool_name": tool_name,
            "required_scope": required_scope,
            "mcp_server_url": mcp_server_url,
            "auth_server_url": None,
            "original_error": error_message,
            "approval_requested": approval_requested,
            "approval_status": "pending_admin_approval"
        }
    
    # Check if this is a Llama Stack OAuth2 scope error
    # Format: "Insufficient OAuth2 scopes for models API. Required: llama:models:write, llama:admin"
    if "insufficient oauth2 scopes" in error_message.lower():
        error_type = "llama_insufficient_scope"
        approval_requested = True
        
        # Extract required scopes from error message
        # Format: "Required: llama:models:write, llama:admin"
        scope_match = re.search(r"Required: (.+)$", error_message, re.IGNORECASE)
        if scope_match:
            required_scopes_str = scope_match.group(1)
            # Split by comma and clean up
            required_scopes = [scope.strip() for scope in required_scopes_str.split(',')]
            logger.info(f"🔍 Parsed Llama Stack required scopes: {required_scopes}")
            
            # For now, use the first scope as the primary required scope
            # In the future, we might want to handle multiple scopes
            required_scope = required_scopes[0] if required_scopes else "llama:agent_create"
        else:
            # Fallback to basic agent scope
            required_scope = "llama:agent_create"
            logger.info(f"🔍 Using fallback Llama Stack scope: '{required_scope}'")
        
        # Extract API endpoint from error message
        # Format: "for models API" or "for agents API"
        api_match = re.search(r"for (\w+) API", error_message, re.IGNORECASE)
        if api_match:
            api_name = api_match.group(1)
            tool_name = f"llama:{api_name.lower()}"
        else:
            tool_name = "llama_stack_api"
        
        return {
            "error_type": error_type,
            "tool_name": tool_name,
            "required_scope": required_scope,
            "mcp_server_url": None,  # Not applicable for Llama Stack
            "auth_server_url": None,
            "original_error": error_message,
            "approval_requested": approval_requested,
            "approval_status": "pending_token_exchange",
            "llama_scopes": required_scopes if 'required_scopes' in locals() else [required_scope]
        }
    
    # Fallback for unrecognized error formats
    return {
        "error_type": error_type,
        "tool_name": tool_name,
        "required_scope": required_scope,
        "mcp_server_url": mcp_server_url,
        "auth_server_url": auth_server_url,
        "original_error": error_message,
        "approval_requested": approval_requested,
        "approval_status": approval_status
    } 