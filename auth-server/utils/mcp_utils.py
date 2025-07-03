"""
MCP (Model Context Protocol) utilities
"""

import logging
from typing import Dict, List, Any, Optional
from models.schemas import TokenPayload
from config.settings import MCP_SERVER_URI
from database import auth_db

logger = logging.getLogger(__name__)

async def fetch_mcp_tools(user: TokenPayload) -> Dict[str, Any]:
    """Fetch available MCP tools from the actual MCP server using proper MCP client"""
    try:
        logger.info(f"🔍 Connecting to MCP server at {MCP_SERVER_URI}/sse via MCP client")
        
        # Import proper MCP client libraries
        try:
            from mcp.client.sse import sse_client
            from mcp import ClientSession
            import asyncio
        except ImportError as e:
            logger.error(f"❌ MCP client libraries not available: {e}")
            return await _get_fallback_tools()
        
        try:
            # Connect to MCP server using proper SSE transport
            async with sse_client(f"{MCP_SERVER_URI}/sse") as (read_stream, write_stream):
                # Create MCP client session
                async with ClientSession(read_stream, write_stream) as session:
                    # Initialize the session
                    await session.initialize()
                    
                    # List tools using proper MCP protocol
                    tools_result = await session.list_tools()
                    logger.info(f"✅ Got MCP tools: {tools_result}")
                    
                    # Extract tools from the MCP result
                    if hasattr(tools_result, 'tools') and tools_result.tools:
                        tools_info = []
                        
                        for tool in tools_result.tools:
                            tool_name = tool.name
                            tool_description = getattr(tool, 'description', 'No description')
                            
                            # Skip the public get_available_tools endpoint
                            if tool_name != "get_available_tools":
                                tools_info.append({
                                    "name": tool_name,
                                    "description": tool_description,
                                    "required_scope": tool_name  # scope == tool name convention
                                })
                        
                        logger.info(f"✅ Successfully loaded {len(tools_info)} MCP tools from server")
                        return {"tools": tools_info}
                    else:
                        logger.warning(f"⚠️ No tools found in MCP response: {tools_result}")
            
        except Exception as e:
            logger.error(f"❌ Error connecting to MCP server: {e}")
            logger.error(f"🔍 Error type: {type(e).__name__}")
                
    except Exception as e:
        logger.error(f"❌ Error in fetch_mcp_tools: {e}")
    
    # Fallback to static tool list
    logger.warning("⚠️ Using fallback static tool list")
    return await _get_fallback_tools()

async def _get_fallback_tools() -> Dict[str, Any]:
    """Fallback static tool list when MCP server is not available"""
    return {
        "tools": [
            {"name": "list_files", "description": "List files in a directory", "required_scope": "list_files"},
            {"name": "execute_command", "description": "Execute a safe system command", "required_scope": "execute_command"},
            {"name": "get_server_info", "description": "Get server information and authentication status", "required_scope": "get_server_info"},
            {"name": "get_oauth_metadata", "description": "Get OAuth 2.0 Protected Resource Metadata", "required_scope": "get_oauth_metadata"},
            {"name": "health_check", "description": "Perform a health check of the server", "required_scope": "health_check"},
            {"name": "list_tool_scopes", "description": "List all available tools and their required scopes", "required_scope": "list_tool_scopes"},
            {"name": "verify_domain", "description": "Verify domain ownership for MCP server registration", "required_scope": "verify_domain"}
        ]
    }

def get_user_tool_access(user_scopes: List[str], mcp_tools: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Get user tool access based on actual token scopes (scope == tool name convention)"""
    tool_access = {}
    
    # Get all permissions from database
    all_permissions = {perm.scope: perm for perm in auth_db.get_all_permissions()}
    
    for tool in mcp_tools.get("tools", []):
        tool_name = tool.get("name", "unknown")
        
        # Use the required_scope from the tool definition
        required_scope = tool.get("required_scope", tool_name)
        
        # Scope == tool name convention: tool requires exact scope match
        has_access = required_scope in user_scopes
        
        permission_info = all_permissions.get(required_scope, None)
        
        tool_access[tool_name] = {
            "has_access": has_access,
            "required_scope": required_scope,
            "risk_level": permission_info.risk_level.value if permission_info else "low",
            "description": tool.get("description", "No description available")
        }
    
    return tool_access

async def test_mcp_tool(tool_name: str, user_scopes: List[str]) -> Dict[str, Any]:
    """Test an MCP tool (simplified implementation for demo purposes)"""
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
        
        # For testing, we'll just return a success message
        # In a real implementation, you would call the actual MCP tool
        return {
            "success": True,
            "tool_name": tool_name,
            "result": f"✅ Tool {tool_name} test successful",
            "message": f"Tool {tool_name} executed successfully with scope {required_scope}"
        }
        
    except Exception as e:
        logger.error(f"❌ Tool test failed for {tool_name}: {e}")
        return {
            'success': False,
            'error': str(e),
            'tool_name': tool_name
        } 