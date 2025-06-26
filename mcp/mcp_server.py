#!/usr/bin/env python3

import logging
import os
import subprocess
import shlex
from datetime import datetime
from typing import Dict, Any
import json

import jwt

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import Context

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
SERVER_NAME = "poc-mcp-server"
SERVER_VERSION = "1.0.0"
SERVER_HOST = "localhost"
SERVER_PORT = 8001
SERVER_URI = f"http://{SERVER_HOST}:{SERVER_PORT}"

# Auth Server Configuration
AUTH_SERVER_URI = "http://localhost:8002"  # The authentication server
JWT_SECRET = os.getenv("JWT_SECRET", "demo-secret-key-change-in-production")

# Create FastMCP instance
mcp = FastMCP(
    name=SERVER_NAME,
    version=SERVER_VERSION
)

# Helper function to verify token from context
def verify_token_from_context(ctx: Context) -> dict:
    """Extract and verify JWT token from MCP context"""
    try:
        # Get Authorization header from request
        auth_header = ctx.request_context.request.headers.get("authorization")  # type: ignore
        logger.info(f"🔑 Auth header received: {auth_header[:50] if auth_header else 'None'}...")
        
        if not auth_header or not auth_header.startswith("Bearer "):
            logger.error("❌ Missing or invalid Authorization header")
            raise Exception("Missing or invalid Authorization header")
        
        token = auth_header.split(" ")[1]
        logger.info(f"🎫 JWT token: {token[:50]}...")
        
        payload = jwt.decode(
            token, 
            JWT_SECRET, 
            algorithms=["HS256"],
            options={"verify_aud": False},
            leeway=21600  # 6 hours leeway for clock skew
        )
        
        logger.info(f"📋 JWT payload: {payload}")
        
        # Validate audience - token must be for this MCP server
        if payload.get("aud") != SERVER_URI:
            logger.error(f"❌ Invalid audience: expected {SERVER_URI}, got {payload.get('aud')}")
            raise Exception(f"Invalid audience: expected {SERVER_URI}, got {payload.get('aud')}")
        
        # Validate issuer
        if payload.get("iss") != AUTH_SERVER_URI:
            logger.error(f"❌ Invalid issuer: expected {AUTH_SERVER_URI}, got {payload.get('iss')}")
            raise Exception(f"Invalid issuer: expected {AUTH_SERVER_URI}, got {payload.get('iss')}")
        
        logger.info(f"✅ Token validated for user: {payload.get('email')}")
        return payload
        
    except jwt.ExpiredSignatureError:
        logger.error("❌ Token expired")
        raise Exception("Token expired")
    except jwt.InvalidTokenError as e:
        logger.error(f"❌ Invalid token: {e}")
        raise Exception("Invalid token")

def check_scope(ctx: Context, required_scope: str) -> dict:
    """Check if user has required scope, return upgrade info if insufficient"""
    user = verify_token_from_context(ctx)
    user_scopes = user.get("scope", "").split()
    
    logger.info(f"🔐 Scope check: required='{required_scope}', user_scopes={user_scopes}, user_email={user.get('email')}")
    
    if required_scope not in user_scopes:
        error_info = {
            "error_type": "insufficient_scope",
            "error": f"Insufficient scope. Required: {required_scope}",
            "required_scope": required_scope,
            "user_scopes": user_scopes,
            "scope_upgrade_endpoint": f"{AUTH_SERVER_URI}/api/upgrade-scope",
            "scope_description": get_scope_description(required_scope),
            "upgrade_instructions": "Use the scope_upgrade_endpoint to request additional permissions"
        }
        logger.error(f"❌ Scope check failed: {error_info}")
        # Return scope upgrade information instead of raising exception
        raise Exception(json.dumps(error_info))
    
    logger.info(f"✅ Scope check passed for {user.get('email')}")
    return user

def get_scope_description(scope: str) -> str:
    """Get human-readable description for a scope"""
    scope_descriptions = {
        "read:files": "Read file system information and list directory contents",
        "execute:commands": "Execute system commands with safety restrictions"
    }
    return scope_descriptions.get(scope, f"Access to {scope}")

# Helper function to handle scope errors in tools
async def handle_scope_error(ctx: Context, error_msg: str) -> Dict[str, Any]:
    """Handle scope-related errors and return upgrade information"""
    try:
        error_data = json.loads(error_msg)
        if error_data.get("error_type") == "insufficient_scope":
            await ctx.info(f"Scope upgrade required: {error_data['required_scope']}")
            return {
                "success": False,
                "error_type": "insufficient_scope",
                "error": error_data["error"],
                "required_scope": error_data["required_scope"],
                "user_scopes": error_data["user_scopes"],
                "scope_upgrade_endpoint": error_data["scope_upgrade_endpoint"],
                "scope_description": error_data["scope_description"],
                "upgrade_instructions": error_data["upgrade_instructions"],
                "upgrade_example": {
                    "method": "POST",
                    "url": error_data["scope_upgrade_endpoint"],
                    "headers": {"Content-Type": "application/json"},
                    "body": {"scopes": [error_data["required_scope"]]}
                }
            }
    except (json.JSONDecodeError, KeyError):
        pass
    
    # Fallback for other errors
    return {
        "success": False,
        "error": error_msg
    }

# MCP Tools with proper Context-based authentication
@mcp.tool()
async def list_files(ctx: Context, directory: str = ".") -> Dict[str, Any]:
    """
    List files in a directory.
    
    **Required Scope:** read:files
    **Description:** Provides read-only access to list directory contents and file metadata.
    
    Args:
        ctx: MCP context for authentication
        directory: Directory path to list (default: current directory)
        
    Returns:
        Dictionary containing directory listing with file information
    """
    try:
        # Verify authentication and scope
        user = check_scope(ctx, "read:files")
        await ctx.info(f"User {user.get('email')} listing files in directory: {directory}")
        
        if not os.path.exists(directory):
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
        
        return {
            "success": True,
            "directory": os.path.abspath(directory),
            "files": files,
            "count": len(files),
            "user": user.get('email')
        }
    except Exception as e:
        return await handle_scope_error(ctx, str(e))

@mcp.tool()
async def execute_command(ctx: Context, command: str) -> Dict[str, Any]:
    """
    Execute a safe system command.
    
    **Required Scope:** execute:commands
    **Description:** Allows execution of system commands with safety restrictions.
    **Security:** Dangerous commands (rm, del, format, etc.) are blocked for safety.
    
    Args:
        ctx: MCP context for authentication
        command: Command to execute (will be shell-escaped for safety)
        
    Returns:
        Dictionary containing command execution results
    """
    try:
        # Verify authentication and scope
        user = check_scope(ctx, "execute:commands")
        await ctx.info(f"User {user.get('email')} executing command: {command}")
        
        # Basic command validation - reject dangerous commands
        dangerous_commands = ['rm', 'del', 'format', 'mkfs', 'dd', 'fdisk', 'shutdown', 'reboot']
        cmd_parts = shlex.split(command)
        if any(dangerous in cmd_parts[0].lower() for dangerous in dangerous_commands):
            return {
                "success": False,
                "error": "Command rejected for security reasons",
                "command": command
            }
        
        # Execute command with timeout
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30  # 30 second timeout
        )
        
        return {
            "success": True,
            "command": command,
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "user": user.get('email')
        }
        
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Command timed out",
            "command": command
        }
    except Exception as e:
        return await handle_scope_error(ctx, str(e))

@mcp.tool()
async def get_server_info(ctx: Context) -> Dict[str, Any]:
    """
    Get server information and authentication status.
    
    **Required Scope:** Any valid token (no specific scope required)
    **Description:** Provides basic server information and user authentication details.
    
    Args:
        ctx: MCP context for authentication
    
    Returns:
        Dictionary containing server and authentication information
    """
    # Verify authentication (any valid token)
    user = verify_token_from_context(ctx)
    await ctx.info(f"User {user.get('email')} requested server info")
    
    return {
        "server_name": SERVER_NAME,
        "server_version": SERVER_VERSION,
        "server_uri": SERVER_URI,
        "auth_server_uri": AUTH_SERVER_URI,
        "timestamp": datetime.now().isoformat(),
        "authenticated_user": user.get('email'),
        "user_scopes": user.get('scope', '').split(),
        "message": "Authentication successful - you have access to this MCP server"
    }

@mcp.tool()
async def get_oauth_metadata(ctx: Context) -> Dict[str, Any]:
    """
    Get OAuth 2.0 Protected Resource Metadata (RFC 9728).
    
    **Required Scope:** Any valid token (no specific scope required)
    **Description:** Returns OAuth 2.0 metadata for this protected resource.
    
    Args:
        ctx: MCP context for authentication
    
    Returns:
        OAuth 2.0 Protected Resource Metadata
    """
    # Verify authentication (any valid token)
    user = verify_token_from_context(ctx)
    await ctx.info(f"User {user.get('email')} requested OAuth metadata")
    
    return {
        "resource": SERVER_URI,
        "authorization_servers": [AUTH_SERVER_URI],
        "scopes_supported": ["read:files", "execute:commands"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{SERVER_URI}/docs"
    }

@mcp.tool()
async def health_check(ctx: Context) -> Dict[str, Any]:
    """
    Perform a health check of the server.
    
    **Required Scope:** Any valid token (no specific scope required)
    **Description:** Verifies server health and user authentication status.
    
    Args:
        ctx: MCP context for authentication
    
    Returns:
        Health status information
    """
    # Verify authentication (any valid token)
    user = verify_token_from_context(ctx)
    await ctx.info(f"User {user.get('email')} requested health check")
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "server_name": SERVER_NAME,
        "server_version": SERVER_VERSION,
        "checked_by": user.get('email')
    }

@mcp.tool()
async def list_tool_scopes(ctx: Context) -> Dict[str, Any]:
    """
    List all available tools and their required scopes.
    
    **Required Scope:** Any valid token (no specific scope required)
    **Description:** Provides a mapping of tools to their required scopes for authorization planning.
    
    Args:
        ctx: MCP context for authentication
    
    Returns:
        Dictionary mapping tool names to their scope requirements
    """
    # Verify authentication (any valid token)
    user = verify_token_from_context(ctx)
    await ctx.info(f"User {user.get('email')} requested tool scope information")
    
    tool_scopes = {
        "list_files": {
            "required_scope": "read:files",
            "description": "List files in a directory",
            "scope_description": "Provides read-only access to list directory contents and file metadata"
        },
        "execute_command": {
            "required_scope": "execute:commands", 
            "description": "Execute a safe system command",
            "scope_description": "Allows execution of system commands with safety restrictions"
        },
        "get_server_info": {
            "required_scope": "none",
            "description": "Get server information and authentication status",
            "scope_description": "Any valid token (no specific scope required)"
        },
        "get_oauth_metadata": {
            "required_scope": "none",
            "description": "Get OAuth 2.0 Protected Resource Metadata",
            "scope_description": "Any valid token (no specific scope required)"
        },
        "health_check": {
            "required_scope": "none",
            "description": "Perform a health check of the server",
            "scope_description": "Any valid token (no specific scope required)"
        },
        "list_tool_scopes": {
            "required_scope": "none",
            "description": "List all available tools and their required scopes",
            "scope_description": "Any valid token (no specific scope required)"
        }
    }
    
    return {
        "server_name": SERVER_NAME,
        "server_version": SERVER_VERSION,
        "available_scopes": ["read:files", "execute:commands"],
        "tool_scope_mapping": tool_scopes,
        "user_scopes": user.get('scope', '').split(),
        "timestamp": datetime.now().isoformat(),
        "checked_by": user.get('email')
    }

if __name__ == "__main__":
    logger.info(f"Starting {SERVER_NAME} v{SERVER_VERSION}")
    logger.info(f"Server URI: {SERVER_URI}")
    logger.info(f"Auth server: {AUTH_SERVER_URI}")
    logger.info("Available tools: list_files, execute_command, get_server_info, get_oauth_metadata, health_check, list_tool_scopes")
    
    mcp.run("sse") 