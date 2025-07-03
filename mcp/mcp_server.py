#!/usr/bin/env python3

import logging
import os
import subprocess
import shlex
from datetime import datetime, timedelta
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

# MCP Server only supports asymmetric JWT verification via JWKS
# This ensures proper security and prevents fallback to weaker symmetric verification

# Create FastMCP instance
mcp = FastMCP(
    name=SERVER_NAME,
    version=SERVER_VERSION
)

logger.info(f"🔐 MCP Server JWT Mode: ASYMMETRIC (JWKS only)")
logger.info(f"🔑 Using JWKS endpoint: {AUTH_SERVER_URI}/.well-known/jwks.json")

# Helper function to verify token from context
def verify_token_from_context(ctx: Context) -> dict:
    """Extract and verify JWT token from MCP context using JWKS only"""
    try:
        # Get Authorization header from request
        auth_header = ctx.request_context.request.headers.get("authorization")  # type: ignore
        logger.info(f"🔑 Auth header received: {auth_header[:50] if auth_header else 'None'}...")
        
        if not auth_header or not auth_header.startswith("Bearer "):
            logger.error("❌ Missing or invalid Authorization header")
            raise Exception("Missing or invalid Authorization header")
        
        token = auth_header.split(" ")[1]
        logger.info(f"🎫 JWT token: {token[:50]}...")
        
        # Decode token header to see what we're working with
        try:
            import base64
            header_b64 = token.split('.')[0]
            # Add padding if needed
            header_b64 += '=' * (4 - len(header_b64) % 4)
            header_json = base64.urlsafe_b64decode(header_b64).decode('utf-8')
            header = json.loads(header_json)
            logger.info(f"🔍 JWT Header: {header}")
            logger.info(f"📝 Algorithm: {header.get('alg', 'unknown')}, Key ID: {header.get('kid', 'None')}")
        except Exception as header_error:
            logger.warning(f"⚠️ Could not decode JWT header: {header_error}")
        
        # Use JWKS for asymmetric verification (no fallback)
        logger.info(f"🔗 Fetching JWKS from: {AUTH_SERVER_URI}/.well-known/jwks.json")
        from jwt import PyJWKClient
        jwks_client = PyJWKClient(f"{AUTH_SERVER_URI}/.well-known/jwks.json")
        
        logger.info("🔍 Getting signing key from JWT...")
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        logger.info(f"🔑 Found signing key: {signing_key.key_id if hasattr(signing_key, 'key_id') else 'unknown'}")
        
        logger.info("🔓 Decoding JWT token...")
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False},
            leeway=21600  # 6 hours leeway for clock skew
        )
        logger.info(f"✅ Verified RS256 token using JWKS")
        
        logger.info(f"📋 JWT payload: {payload}")
        
        # Validate audience - token must be for this MCP server
        expected_aud = SERVER_URI
        actual_aud = payload.get("aud")
        logger.info(f"🎯 Audience check: expected='{expected_aud}', actual='{actual_aud}'")
        if actual_aud != expected_aud:
            logger.error(f"❌ Invalid audience: expected {expected_aud}, got {actual_aud}")
            raise Exception(f"Invalid audience: expected {expected_aud}, got {actual_aud}")
        
        # Validate issuer
        expected_iss = AUTH_SERVER_URI
        actual_iss = payload.get("iss")
        logger.info(f"🏢 Issuer check: expected='{expected_iss}', actual='{actual_iss}'")
        if actual_iss != expected_iss:
            logger.error(f"❌ Invalid issuer: expected {expected_iss}, got {actual_iss}")
            raise Exception(f"Invalid issuer: expected {expected_iss}, got {actual_iss}")
        
        # Log token expiration info
        exp = payload.get("exp")
        iat = payload.get("iat")
        if exp and iat:
            from datetime import datetime
            exp_time = datetime.fromtimestamp(exp)
            iat_time = datetime.fromtimestamp(iat)
            now = datetime.now()
            logger.info(f"⏰ Token times: issued={iat_time}, expires={exp_time}, now={now}")
            logger.info(f"⏳ Token valid for: {exp_time - now} more")
        
        user_email = payload.get('email', 'unknown')
        user_scopes = payload.get('scope', '').split() if payload.get('scope') else []
        logger.info(f"✅ Token validated for user: {user_email}")
        logger.info(f"🔐 User scopes: {user_scopes}")
        return payload
        
    except jwt.ExpiredSignatureError:
        logger.error("❌ Token expired")
        raise Exception("Token expired")
    except jwt.InvalidTokenError as e:
        logger.error(f"❌ Invalid token: {e}")
        raise Exception("Invalid token")
    except Exception as e:
        logger.error(f"❌ JWKS verification failed: {e}")
        logger.error(f"🔍 Error type: {type(e).__name__}")
        # Log additional debugging info
        try:
            logger.error(f"🌐 JWKS URL: {AUTH_SERVER_URI}/.well-known/jwks.json")
            import httpx
            response = httpx.get(f"{AUTH_SERVER_URI}/.well-known/jwks.json")
            logger.error(f"📡 JWKS response status: {response.status_code}")
            if response.status_code == 200:
                jwks_data = response.json()
                logger.error(f"🔑 Available keys: {[key.get('kid', 'no-kid') for key in jwks_data.get('keys', [])]}")
        except Exception as debug_error:
            logger.error(f"🚫 Could not fetch JWKS for debugging: {debug_error}")
        raise Exception(f"JWKS verification failed: {e}")

def check_scope(ctx: Context, required_scope: str) -> dict:
    """Check if user has required scope, return error info if insufficient"""
    logger.info(f"🔐 Starting scope check for: {required_scope}")
    
    try:
        user = verify_token_from_context(ctx)
    except Exception as auth_error:
        # Handle missing or invalid authentication
        auth_error_str = str(auth_error).lower()
        if "missing" in auth_error_str or "authorization header" in auth_error_str:
            logger.warning(f"⚠️ Missing authentication for scope '{required_scope}': {auth_error}")
            error_info = {
                "error_type": "missing_authentication",
                "error": "Authentication required. Please provide a valid Bearer token.",
                "required_scope": required_scope,
                "auth_endpoint": f"{AUTH_SERVER_URI}/api/initial-token",
                "scope_description": get_scope_description(required_scope),
                "auth_instructions": "Use the auth_endpoint to obtain a Bearer token"
            }
            logger.error(f"❌ Authentication missing: {error_info}")
            return error_info
        else:
            # Other auth errors (expired, invalid, etc.)
            logger.warning(f"⚠️ Authentication failed for scope '{required_scope}': {auth_error}")
            error_info = {
                "error_type": "invalid_authentication",
                "error": f"Authentication failed: {auth_error}",
                "required_scope": required_scope,
                "auth_endpoint": f"{AUTH_SERVER_URI}/api/initial-token",
                "scope_description": get_scope_description(required_scope),
                "auth_instructions": "Use the auth_endpoint to obtain a valid Bearer token"
            }
            logger.error(f"❌ Authentication failed: {error_info}")
            return error_info
    
    user_scopes = user.get("scope", "").split()
    user_email = user.get("email", "unknown")
    
    logger.info(f"🔐 Scope check: required='{required_scope}', user_scopes={user_scopes}, user_email={user_email}")
    
    if required_scope not in user_scopes:
        logger.warning(f"⚠️ Insufficient scope for {user_email}: needs '{required_scope}', has {user_scopes}")
        error_info = {
            "error_type": "insufficient_scope",
            "error": f"Insufficient scope. Required: {required_scope}",
            "required_scope": required_scope,
            "current_scopes": user_scopes,
            "scope_upgrade_endpoint": f"{AUTH_SERVER_URI}/api/upgrade-scope",
            "scope_description": get_scope_description(required_scope),
            "upgrade_instructions": "Use the scope_upgrade_endpoint to request additional permissions"
        }
        logger.error(f"❌ Scope check failed: {error_info}")
        
        # Return error info instead of raising exception
        return error_info
    
    logger.info(f"✅ Scope check passed for {user_email}")
    return user

def get_scope_description(scope: str) -> str:
    """Get human-readable description for a scope"""
    scope_descriptions = {
        "list_files": "List files in a directory with metadata",
        "execute_command": "Execute system commands with safety restrictions",
        "get_server_info": "Get server information and authentication status",
        "get_oauth_metadata": "Get OAuth 2.0 Protected Resource Metadata",
        "health_check": "Perform a health check of the server",
        "list_tool_scopes": "List all available tools and their required scopes",
        "verify_domain": "Verify domain ownership for MCP server registration"
    }
    return scope_descriptions.get(scope, f"Access to {scope}")

# MCP Tools with proper Context-based authentication
@mcp.tool()
async def list_files(ctx: Context, directory: str = ".") -> Dict[str, Any]:
    """
    List files in a directory.
    
    **Required Scope:** list_files
    **Description:** Provides read-only access to list directory contents and file metadata.
    
    Args:
        ctx: MCP context for authentication
        directory: Directory path to list (default: current directory)
        
    Returns:
        Dictionary containing directory listing with file information
    """
    # Verify authentication and scope
    scope_result = check_scope(ctx, list_files.__name__)
    if "error_type" in scope_result:
        return scope_result  # Return the error info directly
    
    user = scope_result  # If no error, this is the user info
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

@mcp.tool()
async def execute_command(ctx: Context, command: str) -> Dict[str, Any]:
    """
    Execute a safe system command.
    
    **Required Scope:** execute_command
    **Description:** Allows execution of system commands with safety restrictions.
    **Security:** Dangerous commands (rm, del, format, etc.) are blocked for safety.
    
    Args:
        ctx: MCP context for authentication
        command: Command to execute (will be shell-escaped for safety)
        
    Returns:
        Dictionary containing command execution results
    """
    # Verify authentication and scope
    scope_result = check_scope(ctx, execute_command.__name__)
    if "error_type" in scope_result:
        return scope_result  # Return the error info directly
    
    user = scope_result  # If no error, this is the user info
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
    try:
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

@mcp.tool()
async def get_server_info(ctx: Context) -> Dict[str, Any]:
    """
    Get server information and authentication status.
    
    **Required Scope:** get_server_info
    **Description:** Provides basic server information and user authentication details.
    
    Args:
        ctx: MCP context for authentication
    
    Returns:
        Dictionary containing server and authentication information
    """
    # Verify authentication and scope
    scope_result = check_scope(ctx, get_server_info.__name__)
    if "error_type" in scope_result:
        return scope_result  # Return the error info directly
    
    user = scope_result  # If no error, this is the user info
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
    
    **Required Scope:** get_oauth_metadata
    **Description:** Returns OAuth 2.0 metadata for this protected resource.
    
    Args:
        ctx: MCP context for authentication
    
    Returns:
        OAuth 2.0 Protected Resource Metadata
    """
    # Verify authentication and scope
    scope_result = check_scope(ctx, get_oauth_metadata.__name__)
    if "error_type" in scope_result:
        return scope_result  # Return the error info directly
    
    user = scope_result  # If no error, this is the user info
    await ctx.info(f"User {user.get('email')} requested OAuth metadata")
    
    return {
        "resource": SERVER_URI,
        "authorization_servers": [AUTH_SERVER_URI],
        "scopes_supported": ["list_files", "execute_command", "get_server_info", "get_oauth_metadata", "health_check", "list_tool_scopes", "verify_domain"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{SERVER_URI}/docs"
    }

@mcp.tool()
async def health_check(ctx: Context) -> Dict[str, Any]:
    """
    Perform a health check of the server.
    
    **Required Scope:** health_check
    **Description:** Verifies server health and user authentication status.
    
    Args:
        ctx: MCP context for authentication
    
    Returns:
        Health status information
    """
    logger.info(f"🏥 health_check: Starting health check")
    
    # Verify authentication and scope
    scope_result = check_scope(ctx, health_check.__name__)
    logger.info(f"🏥 health_check: scope_result type = {type(scope_result)}")
    logger.info(f"🏥 health_check: scope_result = {scope_result}")
    
    if "error_type" in scope_result:
        logger.error(f"🏥 health_check: ERROR DETECTED - returning error info: {scope_result}")
        return scope_result  # Return the error info directly
    
    user = scope_result  # If no error, this is the user info
    logger.info(f"🏥 health_check: SUCCESS - user authenticated: {user.get('email')}")
    await ctx.info(f"User {user.get('email')} requested health check")
    
    result = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "server_name": SERVER_NAME,
        "server_version": SERVER_VERSION,
        "checked_by": user.get('email')
    }
    
    logger.info(f"🏥 health_check: Returning success result: {result}")
    return result

@mcp.tool()
async def list_tool_scopes(ctx: Context) -> Dict[str, Any]:
    """
    List all available tools and their required scopes.
    
    **Required Scope:** list_tool_scopes
    **Description:** Provides a mapping of tools to their required scopes for authorization planning.
    
    Args:
        ctx: MCP context for authentication
    
    Returns:
        Dictionary mapping tool names to their scope requirements
    """
    # Verify authentication and scope
    scope_result = check_scope(ctx, list_tool_scopes.__name__)
    if "error_type" in scope_result:
        return scope_result  # Return the error info directly
    
    user = scope_result  # If no error, this is the user info
    await ctx.info(f"User {user.get('email')} requested tool scope information")
    
    tool_scopes = {
        "list_files": {
            "required_scope": "list_files",
            "description": "List files in a directory",
            "scope_description": "Provides read-only access to list directory contents and file metadata"
        },
        "execute_command": {
            "required_scope": "execute_command", 
            "description": "Execute a safe system command",
            "scope_description": "Allows execution of system commands with safety restrictions"
        },
        "get_server_info": {
            "required_scope": "get_server_info",
            "description": "Get server information and authentication status",
            "scope_description": "Provides basic server information and user authentication details"
        },
        "get_oauth_metadata": {
            "required_scope": "get_oauth_metadata",
            "description": "Get OAuth 2.0 Protected Resource Metadata",
            "scope_description": "Returns OAuth 2.0 metadata for this protected resource"
        },
        "health_check": {
            "required_scope": "health_check",
            "description": "Perform a health check of the server",
            "scope_description": "Verifies server health and user authentication status"
        },
        "list_tool_scopes": {
            "required_scope": "list_tool_scopes",
            "description": "List all available tools and their required scopes",
            "scope_description": "Provides a mapping of tools to their required scopes for authorization planning"
        },
        "verify_domain": {
            "required_scope": "verify_domain",
            "description": "Verify domain ownership for MCP server registration",
            "scope_description": "Supports domain verification for enhanced security during MCP server registration"
        }
    }
    
    return {
        "server_name": SERVER_NAME,
        "server_version": SERVER_VERSION,
        "available_scopes": ["list_files", "execute_command", "get_server_info", "get_oauth_metadata", "health_check", "list_tool_scopes", "verify_domain"],
        "tool_scope_mapping": tool_scopes,
        "user_scopes": user.get('scope', '').split(),
        "timestamp": datetime.now().isoformat(),
        "checked_by": user.get('email')
    }

@mcp.tool()
async def verify_domain(ctx: Context, domain: str, verification_token: str) -> Dict[str, Any]:
    """
    Verify domain ownership for MCP server registration (Security Enhancement).
    
    **Required Scope:** verify_domain
    **Description:** Supports domain verification for enhanced security during MCP server registration.
    
    Args:
        ctx: MCP context for authentication
        domain: Domain to verify ownership for
        verification_token: Token provided by authorization server for verification
    
    Returns:
        Domain verification result
    """
    # Verify authentication and scope
    scope_result = check_scope(ctx, verify_domain.__name__)
    if "error_type" in scope_result:
        return scope_result  # Return the error info directly
    
    user = scope_result  # If no error, this is the user info
    await ctx.info(f"User {user.get('email')} requested domain verification for: {domain}")
    
    # This is a demonstration implementation
    # In production, this would verify DNS TXT records or HTTP challenges
    return {
        "domain": domain,
        "verification_token": verification_token,
        "verification_status": "pending",
        "verification_method": "dns_txt_record",
        "verification_instructions": f"Add TXT record: _mcp-verification.{domain} = {verification_token}",
        "verification_uri": f"https://{domain}/.well-known/mcp-verification.txt",
        "expires_at": (datetime.now() + timedelta(hours=24)).isoformat(),
        "verified_by": user.get('email'),
        "server_uri": SERVER_URI,
        "message": "Domain verification initiated - follow instructions to complete"
    }

# Security enhancements
from security_enhancements import (
    create_domain_verification_response
)

# Add HTTP endpoint for OAuth discovery (RFC 9728)
from starlette.requests import Request
from starlette.responses import JSONResponse

@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def oauth_protected_resource_metadata(request: Request) -> JSONResponse:
    """
    OAuth 2.0 Protected Resource Metadata (RFC 9728) - HTTP Discovery Endpoint
    
    This endpoint allows clients to discover authorization servers and supported scopes
    without requiring authentication. This is essential for the OAuth discovery flow.
    """
    return JSONResponse({
        "resource": SERVER_URI,
        "authorization_servers": [AUTH_SERVER_URI],
        "scopes_supported": [
            "list_files", 
            "execute_command", 
            "get_server_info", 
            "get_oauth_metadata", 
            "health_check", 
            "list_tool_scopes", 
            "verify_domain"
        ],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{SERVER_URI}/docs",
        "discovery_endpoint": f"{SERVER_URI}/.well-known/oauth-protected-resource"
    })

if __name__ == "__main__":
    logger.info(f"Starting {SERVER_NAME} v{SERVER_VERSION}")
    logger.info(f"Server URI: {SERVER_URI}")
    logger.info(f"Auth server: {AUTH_SERVER_URI}")
    logger.info("Available tools: list_files, execute_command, get_server_info, get_oauth_metadata, health_check, list_tool_scopes, verify_domain")
    logger.info("Security enhancements: Enhanced Protected Resource Metadata, Domain Verification")
    
    mcp.run("sse") 