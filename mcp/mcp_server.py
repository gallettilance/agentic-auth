#!/usr/bin/env python3

import logging
import os
import subprocess
import shlex
from datetime import datetime
from typing import Dict, Any

from fastmcp import FastMCP
from fastmcp.server.auth import BearerAuthProvider
from fastmcp.server.middleware.error_handling import ErrorHandlingMiddleware

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
SERVER_NAME = "poc-mcp-server"
SERVER_VERSION = "1.0.0"
SERVER_HOST = "localhost"
SERVER_PORT = 8001
SERVER_URI = f"http://{SERVER_HOST}:{SERVER_PORT}"

# Keycloak Configuration (updated for Token Exchange V2)
KEYCLOAK_REALM_URL = "http://localhost:8002/realms/authentication-demo"
JWKS_URI = f"{KEYCLOAK_REALM_URL}/protocol/openid-connect/certs"
ISSUER = KEYCLOAK_REALM_URL
CLIENT_ID = "authentication-demo"  # Token Exchange V2 uses client ID as audience

# Create Bearer Auth Provider for Keycloak
auth = BearerAuthProvider(
    jwks_uri=JWKS_URI,
    issuer=ISSUER,
    algorithm="RS256",
    audience=CLIENT_ID  # Token Exchange V2: tokens have client ID as audience
)

# Create FastMCP instance with native scope enforcement
mcp = FastMCP(
    name=SERVER_NAME,
    version=SERVER_VERSION,
    auth=auth,
    middleware=[ErrorHandlingMiddleware()]
)

logger.info(f"🔐 MCP Server using Keycloak authentication")
logger.info(f"🔑 JWKS URI: {JWKS_URI}")
logger.info(f"🎯 Expected Audience: {CLIENT_ID}")
logger.info(f"🏢 Expected Issuer: {ISSUER}")
logger.info(f"📝 Algorithm: RS256")

# ============================================================================
# MCP TOOLS - Using FastMCP's native required_scope parameter
# ============================================================================

@mcp.tool(required_scope="mcp:list_files")
async def list_files(directory: str = ".") -> Dict[str, Any]:
    """
    List files in a directory.
    
    Args:
        directory: Directory path to list (default: current directory)
        
    Returns:
        Dictionary containing directory listing with file information
    """
    logger.info(f"🔧 Tool called: list_files(directory='{directory}')")
    logger.info(f"📁 Listing files in directory: {directory}")
    
    if not os.path.exists(directory):
        logger.error(f"❌ Directory not found: {directory}")
        return {
            "success": False,
            "error": "Directory not found",
            "directory": directory
        }
    
    files = []
    for item in os.listdir(directory):
        item_path = os.path.join(directory, item)
        try:
            stat_info = os.stat(item_path)
            files.append({
                "name": item,
                "type": "directory" if os.path.isdir(item_path) else "file",
                "size": stat_info.st_size if os.path.isfile(item_path) else None,
                "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            })
        except (OSError, IOError) as e:
            files.append({
                "name": item,
                "type": "unknown",
                "error": str(e)
            })
    
    logger.info(f"✅ Successfully listed {len(files)} files in directory: {directory}")
    
    return {
        "success": True,
        "directory": os.path.abspath(directory),
        "files": files,
        "count": len(files)
    }

@mcp.tool(required_scope="mcp:execute_command")
async def execute_command(command: str) -> Dict[str, Any]:
    """
    Execute a safe system command.
    
    Args:
        command: Command to execute (will be shell-escaped for safety)
        
    Returns:
        Dictionary containing command execution results
    """
    logger.info(f"🔧 Tool called: execute_command(command='{command}')")
    logger.info(f"⚡ Executing command: {command}")
    
    # Basic command validation - reject dangerous commands
    dangerous_commands = ['rm', 'del', 'format', 'mkfs', 'dd', 'fdisk', 'shutdown', 'reboot']
    cmd_parts = shlex.split(command)
    if any(dangerous in cmd_parts[0].lower() for dangerous in dangerous_commands):
        logger.error(f"❌ Command rejected for security reasons: {command}")
        return {
            "success": False,
            "error": "Command rejected for security reasons",
            "command": command
        }
    
    # Execute command with timeout
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30  # 30 second timeout
        )
        
        logger.info(f"✅ Command executed successfully - Exit code: {result.returncode}")
        
        return {
            "success": True,
            "command": command,
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
        
    except subprocess.TimeoutExpired:
        logger.error(f"❌ Command timed out: {command}")
        return {
            "success": False,
            "error": "Command timed out",
            "command": command
        }

@mcp.tool(required_scope="mcp:get_server_info")
async def get_server_info() -> Dict[str, Any]:
    """
    Get server information and authentication status.
    
    Returns:
        Dictionary containing server information
    """
    logger.info(f"🔧 Tool called: get_server_info()")
    
    return {
        "server_name": SERVER_NAME,
        "server_version": SERVER_VERSION,
        "server_uri": SERVER_URI,
        "keycloak_realm": KEYCLOAK_REALM_URL,
        "timestamp": datetime.now().isoformat(),
        "auth_method": "Keycloak OIDC with FastMCP",
        "message": "Authentication successful - you have access to this MCP server"
    }

@mcp.tool(required_scope="mcp:health_check")
async def health_check() -> Dict[str, Any]:
    """
    Check server health and authentication status.
    
    Returns:
        Dictionary containing health check information
    """
    logger.info(f"🔧 Tool called: health_check()")
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "server_name": SERVER_NAME,
        "server_version": SERVER_VERSION,
        "auth_method": "Keycloak OIDC with FastMCP",
        "keycloak_realm": KEYCLOAK_REALM_URL
    }

@mcp.tool(required_scope="mcp:list_tool_scopes")
async def list_tool_scopes() -> Dict[str, Any]:
    """
    List all available tools and their required scopes.
    
    Returns:
        Dictionary containing tool scope mappings
    """
    logger.info(f"🔧 Tool called: list_tool_scopes()")
    
    tool_scopes = {
        "list_files": {
            "description": "List files in a directory",
            "required_scope": "mcp:list_files"
        },
        "execute_command": {
            "description": "Execute a safe system command",
            "required_scope": "mcp:execute_command"
        },
        "get_server_info": {
            "description": "Get server information and authentication status",
            "required_scope": "mcp:get_server_info"
        },
        "health_check": {
            "description": "Check server health and authentication status",
            "required_scope": "mcp:health_check"
        },
        "list_tool_scopes": {
            "description": "List all available tools and their required scopes",
            "required_scope": "mcp:list_tool_scopes"
        }
    }
    
    return {
        "auth_method": "Keycloak OIDC with FastMCP",
        "tool_scopes": tool_scopes,
        "total_tools": len(tool_scopes)
    }


if __name__ == "__main__":
    logger.info("="*80)
    logger.info(f"🚀 Starting {SERVER_NAME} v{SERVER_VERSION}")
    logger.info(f"🌐 Server URI: {SERVER_URI}")
    logger.info(f"🔐 Keycloak realm: {KEYCLOAK_REALM_URL}")
    logger.info("🔒 Auth method: Keycloak OIDC with FastMCP")
    logger.info("🛠️ Available tools: list_files, execute_command, get_server_info, health_check, list_tool_scopes")
    logger.info("="*80)
    
    mcp.run("sse") 