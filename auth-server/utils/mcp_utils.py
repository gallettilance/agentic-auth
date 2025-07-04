"""
MCP (Model Context Protocol) utilities - Decoupled from specific MCP servers
"""

import logging
from typing import Dict, List, Any, Optional
from models.schemas import TokenPayload
from database import auth_db

logger = logging.getLogger(__name__)

async def get_registered_tools() -> Dict[str, Any]:
    """
    Get tools from the database registry instead of connecting to a specific MCP server.
    This allows the auth server to be decoupled from any specific MCP server.
    """
    try:
        # Get all permissions from database which represent available tools
        all_permissions = auth_db.get_all_permissions()
        
        tools_info = []
        for permission in all_permissions:
            tools_info.append({
                "name": permission.scope,  # scope == tool name convention
                "description": permission.description or f"Access to {permission.scope}",
                "required_scope": permission.scope,
                "risk_level": permission.risk_level.value
            })
        
        logger.info(f"✅ Loaded {len(tools_info)} tools from database registry")
        return {"tools": tools_info}
        
    except Exception as e:
        logger.error(f"❌ Error loading tools from database: {e}")
        # Return fallback tools if database fails
        return await _get_fallback_tools()

async def _get_fallback_tools() -> Dict[str, Any]:
    """Fallback static tool list when database is not available"""
    return {
        "tools": [
            {"name": "list_files", "description": "List files in a directory", "required_scope": "list_files", "risk_level": "low"},
            {"name": "execute_command", "description": "Execute a safe system command", "required_scope": "execute_command", "risk_level": "high"},
            {"name": "get_server_info", "description": "Get server information and authentication status", "required_scope": "get_server_info", "risk_level": "low"},
            {"name": "get_oauth_metadata", "description": "Get OAuth 2.0 Protected Resource Metadata", "required_scope": "get_oauth_metadata", "risk_level": "low"},
            {"name": "health_check", "description": "Perform a health check of the server", "required_scope": "health_check", "risk_level": "low"},
            {"name": "list_tool_scopes", "description": "List all available tools and their required scopes", "required_scope": "list_tool_scopes", "risk_level": "low"},
            {"name": "verify_domain", "description": "Verify domain ownership for MCP server registration", "required_scope": "verify_domain", "risk_level": "medium"}
        ]
    }

def get_user_tool_access(user_scopes: List[str], available_tools: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Get user tool access based on actual token scopes (scope == tool name convention)"""
    tool_access = {}
    
    # Get all permissions from database
    all_permissions = {perm.scope: perm for perm in auth_db.get_all_permissions()}
    
    for tool in available_tools.get("tools", []):
        tool_name = tool.get("name", "unknown")
        
        # Use the required_scope from the tool definition
        required_scope = tool.get("required_scope", tool_name)
        
        # Scope == tool name convention: tool requires exact scope match
        has_access = required_scope in user_scopes
        
        permission_info = all_permissions.get(required_scope, None)
        
        tool_access[tool_name] = {
            "has_access": has_access,
            "required_scope": required_scope,
            "risk_level": permission_info.risk_level.value if permission_info else tool.get("risk_level", "low"),
            "description": tool.get("description", "No description available")
        }
    
    return tool_access

async def validate_tool_access(tool_name: str, user_scopes: List[str]) -> Dict[str, Any]:
    """Validate if user has access to a specific tool"""
    try:
        # Check if user has required scope
        required_scope = tool_name  # Default mapping: scope == tool name
        
        if required_scope not in user_scopes:
            return {
                'success': False,
                'error': f'Insufficient permissions. Required scope: {required_scope}',
                'user_scopes': user_scopes,
                'tool_name': tool_name
            }
        
        # Tool access is valid
        return {
            "success": True,
            "tool_name": tool_name,
            "result": f"✅ User has access to {tool_name}",
            "message": f"Access granted to {tool_name} with scope {required_scope}"
        }
        
    except Exception as e:
        logger.error(f"❌ Tool access validation failed for {tool_name}: {e}")
        return {
            'success': False,
            'error': str(e),
            'tool_name': tool_name
        } 