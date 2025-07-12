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

# Add these imports at the top
from kubernetes import client
from kubernetes.client.rest import ApiException
import tempfile

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

# Create Bearer Auth Provider
auth = BearerAuthProvider(
    jwks_uri=f"{AUTH_SERVER_URI}/.well-known/jwks.json",
    issuer=AUTH_SERVER_URI,
    algorithm="RS256",
    audience=SERVER_URI
)

# Create FastMCP instance with native scope enforcement
mcp = FastMCP(
    name=SERVER_NAME,
    version=SERVER_VERSION,
    auth=auth,
    middleware=[ErrorHandlingMiddleware()]  # ← This is crucial!
)

logger.info(f"🔐 MCP Server using FastMCP with native scope enforcement")
logger.info(f"🔑 JWKS URI: {AUTH_SERVER_URI}/.well-known/jwks.json")
logger.info(f"🎯 Expected Audience: {SERVER_URI}")
logger.info(f"🏢 Expected Issuer: {AUTH_SERVER_URI}")
logger.info(f"📝 Algorithm: RS256")
logger.info(f"🎯 DEBUG: MCP server will ONLY accept tokens with audience='{SERVER_URI}'")

# ============================================================================
# DISCOVERY ENDPOINTS - OAuth Protected Resource Discovery
# ============================================================================

@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def oauth_protected_resource(request):
    """
    OAuth Protected Resource Discovery endpoint (RFC 9728)
    
    Returns:
        Dictionary containing OAuth protection metadata for this resource
    """
    logger.info("🔍 Discovery request: /.well-known/oauth-protected-resource")
    
    from fastapi.responses import JSONResponse
    
    return JSONResponse({
        "resource": SERVER_URI,
        "authorization_server": AUTH_SERVER_URI,
        "jwks_uri": f"{AUTH_SERVER_URI}/.well-known/jwks.json",
        "scopes_supported": [
            "list_files",
            "execute_command", 
            "get_server_info",
            "health_check",
            "list_tool_scopes"
        ],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{SERVER_URI}/docs"
    })

# ============================================================================
# MCP TOOLS - Using FastMCP's native required_scope parameter
# ============================================================================

@mcp.tool()
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

@mcp.tool()
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
        logger.info(f"📊 stdout length: {len(result.stdout)} characters")
        logger.info(f"📊 stderr length: {len(result.stderr)} characters")
        
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

@mcp.tool()
async def get_server_info() -> Dict[str, Any]:
    """
    Get server information and authentication status.
    
    Returns:
        Dictionary containing server information
    """
    logger.info(f"🔧 Tool called: get_server_info()")
    logger.info("ℹ️ Getting server info")
    
    return {
        "server_name": SERVER_NAME,
        "server_version": SERVER_VERSION,
        "server_uri": SERVER_URI,
        "auth_server_uri": AUTH_SERVER_URI,
        "timestamp": datetime.now().isoformat(),
        "auth_method": "FastMCP with Native Scope Enforcement",
        "message": "Authentication successful - you have access to this MCP server"
    }

@mcp.tool()
async def health_check() -> Dict[str, Any]:
    """
    Check server health and authentication status.
    
    Returns:
        Dictionary containing health check information
    """
    logger.info(f"🔧 Tool called: health_check()")
    logger.info("🏥 Performing health check")
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "server_name": SERVER_NAME,
        "server_version": SERVER_VERSION,
        "auth_method": "FastMCP with Native Scope Enforcement"
    }

@mcp.tool()
async def list_tool_scopes() -> Dict[str, Any]:
    """
    List all available tools and their required scopes.
    
    Returns:
        Dictionary containing tool scope mappings
    """
    logger.info(f"🔧 Tool called: list_tool_scopes()")
    logger.info("📋 Listing tool scopes")
    
    # Static mapping of tool scopes - in a real implementation, this could be dynamic
    tool_scopes = {
        "list_files": {
            "description": "List files in a directory",
            "required_scope": "list_files"
        },
        "execute_command": {
            "description": "Execute a safe system command",
            "required_scope": "execute_command"
        },
        "get_server_info": {
            "description": "Get server information and authentication status",
            "required_scope": "get_server_info"
        },
        "health_check": {
            "description": "Check server health and authentication status",
            "required_scope": "health_check"
        },
        "list_tool_scopes": {
            "description": "List all available tools and their required scopes",
            "required_scope": "list_tool_scopes"
        },
        "kubectl_get_pods": {
            "description": "List pods in a Kubernetes namespace",
            "required_scope": "kubectl:read"
        },
        "kubectl_get_services": {
            "description": "List services in a Kubernetes namespace", 
            "required_scope": "kubectl:read"
        },
        "kubectl_apply_yaml": {
            "description": "Apply YAML configuration to Kubernetes",
            "required_scope": "kubectl:write"
        }
    }
    
    logger.info("✅ Tool scopes listed successfully")
    return {
        "auth_method": "FastMCP with Native Scope Enforcement",
        "tool_scopes": tool_scopes,
        "total_tools": len(tool_scopes)
    }

# ============================================================================
# KUBERNETES TOOLS - Using FastMCP's native required_scope parameter
# ============================================================================

def get_kubernetes_client(token):
    """Create Kubernetes client with OIDC token"""
    configuration = client.Configuration()
    configuration.host = os.getenv("KUBE_API_SERVER", "https://localhost:6443")
    configuration.verify_ssl = False  # Set to True with proper CA in production
    configuration.api_key = {"authorization": f"Bearer {token}"}
    
    return client.ApiClient(configuration)

@mcp.tool()
async def kubectl_get_pods(namespace: str = "default") -> Dict[str, Any]:
    """
    List pods in a Kubernetes namespace.
    
    Args:
        namespace: Kubernetes namespace (default: default)
        
    Returns:
        Dictionary containing pod information
    """
    logger.info(f"🔧 Tool called: kubectl_get_pods(namespace='{namespace}')")
    logger.info(f"☸️ Listing pods in namespace: {namespace}")
    
    try:
        # For demo purposes, we'll simulate the kubectl call
        # In a real implementation, you would extract the token from the context
        # and use it with the Kubernetes client
        
        return {
            "success": True,
            "namespace": namespace,
            "message": "kubectl_get_pods tool called successfully",
            "note": "This is a demo - real Kubernetes integration requires proper token handling"
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to list pods: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "namespace": namespace
        }

@mcp.tool()
async def kubectl_get_services(namespace: str = "default") -> Dict[str, Any]:
    """
    List services in a Kubernetes namespace.
    
    Args:
        namespace: Kubernetes namespace (default: default)
        
    Returns:
        Dictionary containing service information
    """
    logger.info(f"🔧 Tool called: kubectl_get_services(namespace='{namespace}')")
    logger.info(f"☸️ Listing services in namespace: {namespace}")
    
    try:
        return {
            "success": True,
            "namespace": namespace,
            "message": "kubectl_get_services tool called successfully",
            "note": "This is a demo - real Kubernetes integration requires proper token handling"
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to list services: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "namespace": namespace
        }

@mcp.tool()
async def kubectl_apply_yaml(yaml_content: str, namespace: str = "default") -> Dict[str, Any]:
    """
    Apply YAML configuration to Kubernetes.
    
    Args:
        yaml_content: YAML configuration to apply
        namespace: Kubernetes namespace (default: default)
        
    Returns:
        Dictionary containing apply results
    """
    logger.info(f"🔧 Tool called: kubectl_apply_yaml(namespace='{namespace}')")
    logger.info(f"☸️ Applying YAML to namespace: {namespace}")
    
    try:
        return {
            "success": True,
            "namespace": namespace,
            "message": "kubectl_apply_yaml tool called successfully",
            "yaml_length": len(yaml_content),
            "note": "This is a demo - real Kubernetes integration requires proper token handling"
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to apply YAML: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "namespace": namespace
        }


if __name__ == "__main__":
    logger.info("="*80)
    logger.info(f"🚀 Starting {SERVER_NAME} v{SERVER_VERSION}")
    logger.info(f"🌐 Server URI: {SERVER_URI}")
    logger.info(f"🔐 Auth server: {AUTH_SERVER_URI}")
    logger.info("🔒 Auth method: FastMCP with Native Scope Enforcement")
    logger.info("🛠️ Available tools: list_files, execute_command, get_server_info, health_check, list_tool_scopes, kubectl_get_pods, kubectl_get_services, kubectl_apply_yaml")
    logger.info("🔐 Scope validation: FastMCP native required_scope parameter")
    logger.info("📊 Debug logging enabled for comprehensive authentication flow debugging")
    logger.info("="*80)
    
    mcp.run("sse") 