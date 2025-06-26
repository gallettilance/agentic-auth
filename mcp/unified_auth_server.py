#!/usr/bin/env python3
"""
Unified Authentication & Authorization Server
Handles OAuth, JWT tokens, scope management, approval workflows, and admin dashboard
"""

import json
import logging
import os
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import asyncio
import re
import uuid
from dataclasses import dataclass, asdict
from enum import Enum
import signal
import atexit
import sys

import uvicorn
import httpx
from fastapi import FastAPI, HTTPException, Depends, Request, Response, Cookie, Form, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from pydantic import BaseModel
import jwt
from jwt.exceptions import InvalidTokenError
from fastmcp import Client

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
SERVER_NAME = "unified-auth-server"
SERVER_VERSION = "2.0.0"
SERVER_HOST = "localhost"
SERVER_PORT = 8002
SERVER_URI = f"http://{SERVER_HOST}:{SERVER_PORT}"

# MCP Server Configuration
MCP_SERVER_URI = "http://localhost:8001"

# Google OAuth 2.0 Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "your-google-client-id")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "your-google-client-secret")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
GOOGLE_ISSUER = "https://accounts.google.com"
REDIRECT_URI = f"{SERVER_URI}/auth/callback"

# Session management
COOKIE_NAME = "auth_session"
COOKIE_MAX_AGE = 3600  # 1 hour

# JWT Secret (use environment variable in production)
JWT_SECRET = os.getenv("JWT_SECRET", "demo-secret-key-change-in-production")

# Define scopes for our MCP tools with risk levels
SCOPES = {
    "read:files": {
        "description": "Read file system information",
        "risk_level": "low",
        "requires_admin": False,
        "auto_approve_roles": ["user", "developer", "manager", "admin"]
    },
    "execute:commands": {
        "description": "Execute system commands",
        "risk_level": "critical",
        "requires_admin": True,
        "auto_approve_roles": ["admin"]
    },
    "admin:users": {
        "description": "Manage user accounts and permissions",
        "risk_level": "critical",
        "requires_admin": True,
        "auto_approve_roles": []
    }
}

# User roles (in production, get from your identity provider)
USER_ROLES = {
    "gallettilance@gmail.com": ["admin", "developer"],
    "user@example.com": ["user"],
    "demo@example.com": ["developer"],
    "manager@example.com": ["manager", "user"],
    "lgallett@redhat.com": ["user"]
}

# Approval system classes
class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ApprovalRequest:
    """Approval request data structure"""
    request_id: str
    user_email: str
    user_id: str
    tool_name: str
    required_scope: str
    risk_level: RiskLevel
    justification: str
    requested_at: datetime
    expires_at: datetime
    status: ApprovalStatus
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    denied_by: Optional[str] = None
    denied_at: Optional[datetime] = None
    denial_reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

# Pydantic models
class TokenPayload(BaseModel):
    sub: str
    aud: str
    email: str
    scope: str
    exp: int
    iat: int
    iss: str

class ProtectedResourceMetadata(BaseModel):
    resource: str
    authorization_servers: List[str]
    scopes_supported: Optional[List[str]] = None
    bearer_methods_supported: Optional[List[str]] = None
    resource_documentation: Optional[str] = None

class GoogleDiscoveryDocument(BaseModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str

class ApprovalRequestModel(BaseModel):
    user_email: str
    user_id: str
    tool_name: str
    required_scope: str
    risk_level: str
    justification: str
    callback_url: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

# Global variables
google_config: Optional[GoogleDiscoveryDocument] = None
google_jwks: Optional[Dict] = None

# In-memory storage (use Redis/database in production)
sessions: Dict[str, Dict[str, Any]] = {}
scope_upgrade_requests: Dict[str, Dict[str, Any]] = {}
approval_requests: Dict[str, ApprovalRequest] = {}

# FastAPI app
app = FastAPI(title=SERVER_NAME, version=SERVER_VERSION)
security = HTTPBearer(auto_error=False)

class AuthorizationError(Exception):
    def __init__(self, status_code: int, detail: str, headers: Optional[Dict[str, str]] = None):
        self.status_code = status_code
        self.detail = detail
        self.headers = headers or {}

# Authentication functions
async def load_google_config():
    global google_config, google_jwks
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(GOOGLE_DISCOVERY_URL)
            response.raise_for_status()
            config_data = response.json()
            google_config = GoogleDiscoveryDocument(**config_data)
            
            jwks_response = await client.get(google_config.jwks_uri)
            jwks_response.raise_for_status()
            google_jwks = jwks_response.json()
            
        logger.info(f"Loaded Google OAuth config: {google_config.authorization_endpoint}")
    except Exception as e:
        logger.warning(f"Failed to load Google OAuth config: {e}")

def create_session(user_data: TokenPayload) -> str:
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = {
        "user": user_data.dict(),
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(seconds=COOKIE_MAX_AGE)
    }
    
    logger.info(f"🎫 Created session {session_id[:20]}... for user {user_data.email}")
    logger.info(f"📊 Total sessions: {len(sessions)}")
    logger.info(f"🕐 Session expires at: {sessions[session_id]['expires_at']}")
    
    return session_id

def get_session(session_id: str) -> Optional[TokenPayload]:
    if session_id not in sessions:
        logger.warning(f"❌ Session {session_id[:20]}... not found in sessions dict")
        return None
    
    session = sessions[session_id]
    current_time = datetime.utcnow()
    expires_at = session["expires_at"]
    
    if current_time > expires_at:
        logger.warning(f"⏰ Session {session_id[:20]}... expired at {expires_at}, current time: {current_time}")
        del sessions[session_id]
        return None
    
    logger.info(f"✅ Session {session_id[:20]}... is valid, expires at: {expires_at}")
    return TokenPayload(**session["user"])

def verify_session(session_cookie: Optional[str] = Cookie(default=None, alias=COOKIE_NAME)) -> Optional[TokenPayload]:
    if session_cookie:
        logger.info(f"🔍 Verifying session cookie: {session_cookie[:20]}...")
        user = get_session(session_cookie)
        if user:
            logger.info(f"✅ Session valid for user: {user.email}")
        else:
            logger.warning(f"❌ Session not found or expired for cookie: {session_cookie[:20]}...")
            logger.info(f"📋 Available sessions: {list(sessions.keys())}")
        return user
    logger.info("🔍 No session cookie provided")
    return None

def verify_jwt_token(authorization: Optional[str] = Header(default=None)) -> Optional[TokenPayload]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    
    token = authorization.split(" ")[1]
    
    try:
        payload = jwt.decode(
            token, 
            JWT_SECRET, 
            algorithms=["HS256"],
            options={"verify_aud": False},
            leeway=21600
        )
        return TokenPayload(**payload)
    except jwt.InvalidTokenError as e:
        logger.warning(f"JWT token validation failed: {e}")
        return None

def verify_user_auth(
    session_cookie: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
    authorization: Optional[str] = Header(default=None)
) -> Optional[TokenPayload]:
    """Verify user authentication via session or JWT token"""
    user = verify_session(session_cookie)
    if user:
        return user
    
    return verify_jwt_token(authorization)

def get_user_roles(email: str) -> List[str]:
    return USER_ROLES.get(email, ["user"])

def is_admin_user(email: str) -> bool:
    return "admin" in get_user_roles(email)

# Approval system functions
def create_approval_request(
    user_email: str,
    user_id: str,
    tool_name: str,
    required_scope: str,
    risk_level: str,
    justification: str,
    metadata: Optional[Dict[str, Any]] = None
) -> ApprovalRequest:
    """Create a new approval request"""
    request_id = str(uuid.uuid4())
    
    approval_request = ApprovalRequest(
        request_id=request_id,
        user_email=user_email,
        user_id=user_id,
        tool_name=tool_name,
        required_scope=required_scope,
        risk_level=RiskLevel(risk_level),
        justification=justification,
        requested_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(hours=24),  # 24 hour expiry
        status=ApprovalStatus.PENDING,
        metadata=metadata
    )
    
    approval_requests[request_id] = approval_request
    logger.info(f"Created approval request {request_id} for {user_email} - {tool_name}")
    
    return approval_request

def evaluate_approval_policy(user_email: str, requested_scopes: List[str]) -> Dict[str, Any]:
    """Evaluate approval policy for requested scopes"""
    user_roles = get_user_roles(user_email)
    auto_approved_scopes = []
    admin_scopes = []
    
    for scope in requested_scopes:
        scope_config = SCOPES.get(scope, {})
        auto_approve_roles = scope_config.get("auto_approve_roles", [])
        requires_admin = scope_config.get("requires_admin", False)
        
        # Check if user has auto-approval role for this scope
        if any(role in auto_approve_roles for role in user_roles):
            auto_approved_scopes.append(scope)
        elif requires_admin:
            admin_scopes.append(scope)
        else:
            # Low risk scopes can be auto-approved for most users
            auto_approved_scopes.append(scope)
    
    return {
        "auto_approved": auto_approved_scopes,
        "requires_admin_approval": admin_scopes
    }

# Utility functions
def get_tool_icon(tool_name: str) -> str:
    """Get emoji icon for tool"""
    icons = {
        "execute_command": "⚡",
        "file_reader": "📁",
        "list_directory": "📂",
        "create_file": "📝",
        "edit_file": "✏️",
        "delete_file": "🗑️"
    }
    return icons.get(tool_name, "🔧")

def extract_scope_from_description(description: str) -> str:
    """Extract required scope from tool description"""
    if "execute" in description.lower() or "command" in description.lower():
        return "execute:commands"
    elif "read" in description.lower() or "file" in description.lower():
        return "read:files"
    elif "admin" in description.lower():
        return "admin:users"
    else:
        return "none"  # Default - no scope required

def get_scope_risk_level(scope: str) -> str:
    """Get risk level for scope"""
    return SCOPES.get(scope, {}).get("risk_level", "medium")

async def fetch_mcp_tools(user: TokenPayload) -> Dict[str, Any]:
    """Fetch available MCP tools from the MCP server using user's JWT token"""
    try:
        from fastmcp import Client
        
        # Create JWT token for the user to authenticate with MCP server
        user_token_payload = {
            "sub": user.sub,
            "aud": MCP_SERVER_URI,
            "email": user.email,
            "scope": user.scope or "read:files",  # Use user's current scopes
            "exp": int((datetime.utcnow() + timedelta(minutes=5)).timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
            "iss": SERVER_URI
        }
        user_token = jwt.encode(user_token_payload, JWT_SECRET, algorithm="HS256")
        
        # Use proper FastMCP client config format
        config = {
            "mcpServers": {
                "server": {
                    "transport": "sse",
                    "url": f"{MCP_SERVER_URI}/sse",
                    "headers": {"Authorization": f"Bearer {user_token}"}
                }
            }
        }
        
        client = Client(config)
        async with client:
            # Get list of tools using proper MCP protocol
            tools = await client.list_tools()
            
            tool_info = {}
            for tool in tools:
                # Extract scope requirement from tool description
                required_scope = extract_scope_from_description(tool.description or "")
                
                tool_info[tool.name] = {
                    "name": tool.name,
                    "description": tool.description or "No description available",
                    "required_scope": required_scope,
                    "risk_level": get_scope_risk_level(required_scope),
                    "icon": get_tool_icon(tool.name)
                }
            
            return tool_info
            
    except Exception as e:
        logger.warning(f"Failed to fetch MCP tools for user {user.email}: {e}")
        # Fallback to basic tool set if MCP server is not available
        return {
            "get_server_info": {
                "name": "get_server_info", 
                "description": "Get server information (fallback)",
                "required_scope": "none",
                "risk_level": "none",
                "icon": "ℹ️"
            }
        }

def get_user_tool_access(user_scopes: List[str], mcp_tools: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Get user's access to each MCP tool"""
    tool_access = {}
    
    for tool_name, tool_data in mcp_tools.items():
        # The tool_data now already contains the processed information
        required_scope = tool_data.get("required_scope", "none")
        has_access = required_scope == "none" or required_scope in user_scopes
        
        tool_access[tool_name] = {
            "tool_data": tool_data,
            "has_access": has_access,
            "required_scope": required_scope,
            "risk_level": tool_data.get("risk_level", "unknown")
        }
    
    return tool_access

# Startup event
@app.on_event("startup")
async def startup_event():    
    await load_google_config()
    logger.info(f"🚀 {SERVER_NAME} v{SERVER_VERSION} started on {SERVER_URI}")
    logger.info(f"🔧 Session storage initialized - COOKIE_MAX_AGE: {COOKIE_MAX_AGE}s ({COOKIE_MAX_AGE/3600:.1f}h)")
    logger.info(f"📊 Current sessions count: {len(sessions)}")

# Main routes
@app.get("/", response_class=HTMLResponse)
async def home():
    return RedirectResponse(url="/dashboard")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(user: TokenPayload = Depends(verify_user_auth)):
    logger.info(f"🏠 Dashboard accessed, user: {user.email if user else 'None'}")
    if not user:
        logger.warning("❌ No user found, redirecting to login")
        return RedirectResponse(url="/auth/login")
    
    user_roles = get_user_roles(user.email)
    is_admin = is_admin_user(user.email)
    
    # Fetch MCP tools
    try:
        mcp_tools = await fetch_mcp_tools(user)
    except Exception as e:
        logger.error(f"Failed to fetch MCP tools: {e}")
        mcp_tools = {}
    
    # Get user's current scopes
    user_scopes = user.scope.split() if user.scope else []
    
    # Get tool access information
    tool_access = get_user_tool_access(user_scopes, mcp_tools)
    
    # Get pending approvals for admin users
    pending_approvals = []
    if is_admin:
        pending_approvals = [
            req for req in approval_requests.values() 
            if req.status == ApprovalStatus.PENDING
        ]
    
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MCP Auth Dashboard</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .header {{ background: white; padding: 20px; border-radius: 16px; margin-bottom: 20px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            .user-info {{ display: flex; justify-content: space-between; align-items: center; }}
            .logout-btn {{ background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: white; padding: 10px 20px; border: none; border-radius: 8px; text-decoration: none; font-weight: 600; }}
            .tools-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 20px; margin-bottom: 20px; }}
            .tool-card {{ background: white; padding: 20px; border-radius: 16px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); transition: transform 0.2s ease; }}
            .tool-card:hover {{ transform: translateY(-5px); }}
            .tool-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }}
            .tool-name {{ font-weight: bold; font-size: 16px; color: #2c3e50; }}
            .access-status {{ padding: 6px 12px; border-radius: 8px; font-size: 12px; font-weight: bold; }}
            .access-granted {{ background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%); color: #155724; }}
            .access-denied {{ background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%); color: #721c24; }}
            .tool-description {{ color: #666; margin-bottom: 12px; line-height: 1.4; }}
            .required-scope {{ font-family: monospace; background: #f8f9fa; padding: 6px 10px; border-radius: 6px; font-size: 12px; border: 1px solid #e9ecef; }}
            .test-btn {{ background: linear-gradient(135deg, #007bff 0%, #0056b3 100%); color: white; padding: 8px 16px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; margin-top: 10px; }}
            .test-btn:disabled {{ background: #6c757d; cursor: not-allowed; }}
            .admin-section {{ background: white; padding: 20px; border-radius: 16px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); margin-bottom: 20px; }}
            .pending-approval {{ background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%); border: none; padding: 16px; border-radius: 12px; margin: 12px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
            .approval-actions {{ margin-top: 12px; }}
            .approve-btn {{ background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 8px 16px; border: none; border-radius: 8px; margin-right: 10px; font-weight: 600; }}
            .deny-btn {{ background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: white; padding: 8px 16px; border: none; border-radius: 8px; font-weight: 600; }}
            .title {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); background-clip: text; -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: bold; }}
            .role-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; margin-left: 10px; }}
            .admin-role {{ background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: white; }}
            .user-role {{ background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="user-info">
                    <div>
                        <h1 class="title">🔐 Unified MCP Auth Dashboard</h1>
                        <p>Welcome, <strong>{user.email}</strong> 
                           <span class="role-badge {'admin-role' if is_admin else 'user-role'}">{', '.join(user_roles)}</span>
                        </p>
                        <p>Current Scopes: <code id="current-scopes">{user.scope or 'None'}</code></p>
                    </div>
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <a href="http://localhost:5001" style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 10px 20px; border: none; border-radius: 8px; text-decoration: none; font-weight: 600;">💬 Chat App</a>
                        <a href="/auth/logout" class="logout-btn">🚪 Logout</a>
                    </div>
                </div>
            </div>
            
            {'<div class="admin-section"><h2>🛡️ Admin: Pending Approvals (' + str(len(pending_approvals)) + ')</h2>' + 
             (''.join([f'''
                <div class="pending-approval">
                    <strong>{req.user_email}</strong> requests access to <strong>{req.tool_name}</strong>
                    <br>Required scope: <code>{req.required_scope}</code>
                    <br>Risk level: <strong>{req.risk_level.value}</strong>
                    <br>Justification: {req.justification}
                    <br>Requested: {req.requested_at.strftime("%Y-%m-%d %H:%M:%S")}
                    <div class="approval-actions">
                        <button class="approve-btn" onclick="approveRequest('{req.request_id}')">✅ Approve</button>
                        <button class="deny-btn" onclick="denyRequest('{req.request_id}')">❌ Deny</button>
                    </div>
                </div>
             ''' for req in pending_approvals]) if pending_approvals else '<p>No pending approvals</p>') + '</div>' if is_admin else ''}
            
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2>🔧 Available MCP Tools</h2>
                <button onclick="refreshTools()" style="background: linear-gradient(135deg, #17a2b8 0%, #138496 100%); color: white; padding: 10px 20px; border: none; border-radius: 8px; font-weight: 600; cursor: pointer;">🔄 Refresh Tools</button>
            </div>
            <div id="tools-grid" class="tools-grid">
                {''.join([f'''
                    <div class="tool-card">
                        <div class="tool-header">
                            <span class="tool-name">{get_tool_icon(tool_name)} {tool_name}</span>
                            <span class="access-status {'access-granted' if access['has_access'] else 'access-denied'}">
                                {'✅ Access Granted' if access['has_access'] else '🔒 Access Denied'}
                            </span>
                        </div>
                        <div class="tool-description">{access['tool_data'].get('description', 'No description available')}</div>
                        <div class="required-scope">Required: {access['required_scope']}</div>
                        <div>
                            <button class="test-btn" {'disabled' if not access['has_access'] else ''} 
                                    onclick="testTool('{tool_name}')">
                                🧪 Test Tool
                            </button>
                        </div>
                    </div>
                ''' for tool_name, access in tool_access.items()])}
            </div>
        </div>
        
        <script>
            async function testTool(toolName) {{
                try {{
                    const response = await fetch('/api/test-tool', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ tool_name: toolName }})
                    }});
                    const result = await response.json();
                    alert(JSON.stringify(result, null, 2));
                }} catch (error) {{
                    alert('Error testing tool: ' + error.message);
                }}
            }}
            
            async function refreshTools() {{
                let button = null;
                try {{
                    // Get button reference more reliably
                    button = document.querySelector('button[onclick="refreshTools()"]');
                    if (button) {{
                        button.disabled = true;
                        button.textContent = '🔄 Refreshing...';
                    }}
                    
                    console.log('Fetching tools from /api/tools...');
                    const response = await fetch('/api/tools');
                    console.log('Response status:', response.status);
                    
                    if (!response.ok) {{
                        throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
                    }}
                    
                    const data = await response.json();
                    console.log('Tools data received:', data);
                    
                    if (data.tools) {{
                        // Update current scopes display
                        const scopesElement = document.getElementById('current-scopes');
                        if (scopesElement) {{
                            scopesElement.textContent = data.user_scope || 'None';
                            console.log('Updated scopes to:', data.user_scope);
                        }}
                        
                        // Update tools grid
                        const toolsGrid = document.getElementById('tools-grid');
                        if (toolsGrid) {{
                            toolsGrid.innerHTML = '';
                            
                            Object.entries(data.tools).forEach(([toolName, access]) => {{
                                const toolCard = document.createElement('div');
                                toolCard.className = 'tool-card';
                                toolCard.innerHTML = `
                                    <div class="tool-header">
                                        <span class="tool-name">${{getToolIcon(toolName)}} ${{toolName}}</span>
                                        <span class="access-status ${{access.has_access ? 'access-granted' : 'access-denied'}}">
                                            ${{access.has_access ? '✅ Access Granted' : '🔒 Access Denied'}}
                                        </span>
                                    </div>
                                    <div class="tool-description">${{access.tool_data?.description || 'No description available'}}</div>
                                    <div class="required-scope">Required: ${{access.required_scope}}</div>
                                    <div>
                                        <button class="test-btn" ${{!access.has_access ? 'disabled' : ''}} 
                                                onclick="testTool('${{toolName}}')">
                                            🧪 Test Tool
                                        </button>
                                    </div>
                                `;
                                toolsGrid.appendChild(toolCard);
                            }});
                            
                            console.log('Tools grid updated with', Object.keys(data.tools).length, 'tools');
                        }} else {{
                            console.error('Tools grid element not found');
                        }}
                        
                        alert('Tools refreshed successfully!');
                    }} else {{
                        console.error('No tools data in response:', data);
                        alert('Failed to refresh tools: ' + (data.error || 'No tools data received'));
                    }}
                }} catch (error) {{
                    console.error('Error refreshing tools:', error);
                    alert('Error refreshing tools: ' + error.message);
                }} finally {{
                    if (button) {{
                        button.disabled = false;
                        button.textContent = '🔄 Refresh Tools';
                    }}
                }}
            }}
            
            function getToolIcon(toolName) {{
                const icons = {{
                    'execute_command': '⚡',
                    'file_reader': '📁',
                    'list_directory': '📂',
                    'create_file': '📝',
                    'edit_file': '✏️',
                    'delete_file': '🗑️'
                }};
                return icons[toolName] || '🔧';
            }}
            
            async function approveRequest(requestId) {{
                if (confirm('Approve this request?')) {{
                    try {{
                        const response = await fetch(`/api/approve/${{requestId}}`, {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
                            body: `admin_email={user.email}`
                        }});
                        if (response.ok) {{
                            location.reload();
                        }} else {{
                            alert('Failed to approve request');
                        }}
                    }} catch (error) {{
                        alert('Error: ' + error.message);
                    }}
                }}
            }}
            
            async function denyRequest(requestId) {{
                const reason = prompt('Reason for denial:');
                if (reason) {{
                    try {{
                        const response = await fetch(`/api/deny/${{requestId}}`, {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
                            body: `reason=${{encodeURIComponent(reason)}}&admin_email={user.email}`
                        }});
                        if (response.ok) {{
                            location.reload();
                        }} else {{
                            alert('Failed to deny request');
                        }}
                    }} catch (error) {{
                        alert('Error: ' + error.message);
                    }}
                }}
            }}
            
            // Auto-refresh tools every 30 seconds to catch token updates
            setInterval(async () => {{
                try {{
                    const response = await fetch('/api/user-status');
                    if (response.ok) {{
                        const data = await response.json();
                        const scopesElement = document.getElementById('current-scopes');
                        if (scopesElement && data.user) {{
                            const currentScopes = scopesElement.textContent.trim();
                            const newScopes = data.user.scopes?.join(' ') || 'None';
                            
                            // If scopes changed, refresh tools
                            if (currentScopes !== newScopes) {{
                                console.log('Scopes changed from "' + currentScopes + '" to "' + newScopes + '", refreshing tools automatically');
                                await refreshTools();
                            }}
                        }}
                    }}
                }} catch (error) {{
                    console.log('Auto-refresh check failed:', error);
                }}
            }}, 30000);
        </script>
    </body>
    </html>
    """)

# OAuth routes
@app.get("/auth/login")
async def login():
    if not GOOGLE_CLIENT_ID or GOOGLE_CLIENT_ID == "your-google-client-id":
        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>OAuth Not Configured</title>
            <style>
                body { font-family: Arial, sans-serif; max-width: 600px; margin: 100px auto; padding: 20px; text-align: center; }
                .demo-btn { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 8px; text-decoration: none; font-size: 16px; }
            </style>
        </head>
        <body>
            <h1>🔐 OAuth Not Configured</h1>
            <p>Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables.</p>
            <p>For demo purposes, you can use the demo login below:</p>
            <a href="/auth/demo-login" class="demo-btn">🚀 Demo Login</a>
        </body>
        </html>
        """)
    
    try:
        async with httpx.AsyncClient() as client:
            discovery_response = await client.get(GOOGLE_DISCOVERY_URL)
            discovery_data = discovery_response.json()
            auth_endpoint = discovery_data["authorization_endpoint"]
        
        state = secrets.token_urlsafe(32)
        oauth_url = f"{auth_endpoint}?" + "&".join([
            f"client_id={GOOGLE_CLIENT_ID}",
            f"redirect_uri={REDIRECT_URI}",
            "response_type=code",
            "scope=openid email profile",
            f"state={state}"
        ])
        
        return RedirectResponse(url=oauth_url)
    except Exception as e:
        logger.error(f"OAuth setup error: {e}")
        return RedirectResponse(url="/auth/demo-login")

@app.get("/auth/demo-login", response_class=HTMLResponse)
async def demo_login_page():
    return HTMLResponse("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Demo Login</title>
        <style>
            body { 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0; padding: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
            }
            .login-card { 
                background: white; padding: 40px; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); 
                max-width: 400px; width: 100%;
            }
            .form-group { margin-bottom: 20px; }
            label { display: block; margin-bottom: 8px; font-weight: 600; color: #2c3e50; }
            input { 
                width: 100%; padding: 12px; border: 1px solid #e9ecef; border-radius: 8px; 
                font-size: 16px; transition: border-color 0.3s ease;
            }
            input:focus { border-color: #667eea; outline: none; }
            button { 
                width: 100%; padding: 12px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer;
            }
            .title { text-align: center; margin-bottom: 30px; color: #2c3e50; }
            .demo-users { margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px; font-size: 14px; }
        </style>
    </head>
    <body>
        <div class="login-card">
            <h2 class="title">🔐 Demo Login</h2>
            <form method="post">
                <div class="form-group">
                    <label>Email:</label>
                    <input type="email" name="email" value="gallettilance@gmail.com" required>
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" value="demo" required>
                </div>
                <button type="submit">🚀 Login</button>
            </form>
            <div class="demo-users">
                <strong>Demo Users:</strong><br>
                • gallettilance@gmail.com (admin)<br>
                • demo@example.com (developer)<br>
                • lgallett@redhat.com (user)<br>
                Password: <code>demo</code>
            </div>
        </div>
    </body>
    </html>
    """)

@app.post("/auth/demo-login")
async def demo_login_submit(email: str = Form(...), password: str = Form(...)):
    if password != "demo":
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create user token
    token_payload = TokenPayload(
        sub=email,
        aud=MCP_SERVER_URI,
        email=email,
        scope="",  # Start with no scopes
        exp=int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
        iat=int(datetime.utcnow().timestamp()),
        iss=SERVER_URI
    )
    
    session_id = create_session(token_payload)
    
    response = RedirectResponse(url="/dashboard", status_code=302)
    response.set_cookie(
        key=COOKIE_NAME,
        value=session_id,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        domain="localhost",  # Share cookies across localhost ports
        path="/"
    )
    
    return response

@app.get("/auth/callback")
async def oauth_callback(code: str, state: str):
    """Handle OAuth callback from Google"""
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        logger.error("OAuth not configured properly")
        raise HTTPException(status_code=500, detail="OAuth not configured")
    
    try:
        # Exchange code for token
        async with httpx.AsyncClient() as client:
            # Get Google's discovery document
            discovery_response = await client.get(GOOGLE_DISCOVERY_URL)
            discovery_data = discovery_response.json()
            token_endpoint = discovery_data["token_endpoint"]
            
            # Exchange authorization code for access token
            token_data = {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": REDIRECT_URI,
            }
            
            token_response = await client.post(token_endpoint, data=token_data)
            token_info = token_response.json()
            
            if "access_token" not in token_info:
                logger.error(f"Failed to get access token: {token_info}")
                raise HTTPException(status_code=400, detail="Failed to get access token")
            
            # Get user info
            userinfo_endpoint = discovery_data["userinfo_endpoint"]
            userinfo_response = await client.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {token_info['access_token']}"}
            )
            user_info = userinfo_response.json()
            
            logger.info(f"OAuth user info: {user_info}")
            
            # Create user session
            token_payload = TokenPayload(
                sub=user_info.get("sub", ""),
                aud=MCP_SERVER_URI,
                email=user_info.get("email", ""),
                scope="",  # Start with no scopes
                exp=int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
                iat=int(datetime.utcnow().timestamp()),
                iss=SERVER_URI
            )
            
            session_id = create_session(token_payload)
            
            response = RedirectResponse(url="/dashboard", status_code=302)
            response.set_cookie(
                key=COOKIE_NAME,
                value=session_id,
                max_age=COOKIE_MAX_AGE,
                httponly=True,
                secure=False,  # Set to True in production with HTTPS
                samesite="lax",
                domain="localhost",  # Share cookies across localhost ports
                path="/"
            )
            
            return response
            
    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        import traceback
        traceback.print_exc()
        return RedirectResponse(url="/auth/demo-login?error=oauth_failed")

@app.get("/auth/logout")
async def logout(session_cookie: Optional[str] = Cookie(default=None, alias=COOKIE_NAME)):
    if session_cookie and session_cookie in sessions:
        del sessions[session_cookie]
    
    response = RedirectResponse(url="/auth/login", status_code=302)
    response.delete_cookie(key=COOKIE_NAME, domain="localhost", path="/")
    return response

# API routes
@app.post("/api/upgrade-scope")
async def api_upgrade_scope(
    request: Request,
    user: TokenPayload = Depends(verify_user_auth)
):
    """Handle scope upgrade requests"""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        request_data = await request.json()
        requested_scopes = request_data.get("scopes", [])
        
        if not requested_scopes:
            raise HTTPException(status_code=400, detail="No scopes requested")
        
        logger.info(f"Scope upgrade request from {user.email}: {requested_scopes}")
        
        # Evaluate approval policy
        policy_result = evaluate_approval_policy(user.email, requested_scopes)
        auto_approved_scopes = policy_result["auto_approved"]
        admin_scopes = policy_result["requires_admin_approval"]
        
        # Handle auto-approved scopes
        if auto_approved_scopes:
            # Update user's token with new scopes
            current_scopes = set(user.scope.split()) if user.scope else set()
            current_scopes.update(auto_approved_scopes)
            user.scope = " ".join(current_scopes)
            
            # Create new JWT token
            token_data = {
                "sub": user.sub,
                "aud": user.aud,
                "email": user.email,
                "scope": user.scope,
                "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
                "iat": int(datetime.utcnow().timestamp()),
                "iss": user.iss
            }
            
            new_token = jwt.encode(token_data, JWT_SECRET, algorithm="HS256")
            
            # Update session data with new scopes so dashboard can see them
            for session_id, session_data in sessions.items():
                if session_data.get("user", {}).get("email") == user.email:
                    session_data["user"]["scope"] = user.scope
                    logger.info(f"🔄 Updated session {session_id[:20]}... with new scopes: {user.scope}")
                    break
            
            if not admin_scopes:
                # All scopes auto-approved
                return JSONResponse({
                    "status": "approved",
                    "auto_approved": True,
                    "approved_scopes": auto_approved_scopes,
                    "new_token": new_token,
                    "message": "All requested scopes have been automatically approved"
                })
        
        # Handle admin approval required scopes
        if admin_scopes:
            # First check if there's already an approved request for this user and scope
            approved_admin_scopes = []
            for approval_request in approval_requests.values():
                if (approval_request.user_email == user.email and 
                    approval_request.status == ApprovalStatus.APPROVED and
                    approval_request.required_scope in admin_scopes):
                    approved_admin_scopes.append(approval_request.required_scope)
            
            # If we found approved admin scopes, generate new token with them
            if approved_admin_scopes:
                current_scopes = set(user.scope.split()) if user.scope else set()
                current_scopes.update(approved_admin_scopes)
                # Also include any auto-approved scopes from this request
                current_scopes.update(auto_approved_scopes)
                
                token_data = {
                    "sub": user.sub,
                    "aud": user.aud,
                    "email": user.email,
                    "scope": " ".join(current_scopes),
                    "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
                    "iat": int(datetime.utcnow().timestamp()),
                    "iss": user.iss
                }
                
                new_token = jwt.encode(token_data, JWT_SECRET, algorithm="HS256")
                
                # Update session data with new scopes so dashboard can see them
                for session_id, session_data in sessions.items():
                    if session_data.get("user", {}).get("email") == user.email:
                        session_data["user"]["scope"] = " ".join(current_scopes)
                        logger.info(f"🔄 Updated session {session_id[:20]}... with approved admin scopes: {' '.join(current_scopes)}")
                        break
                
                logger.info(f"Found approved admin scopes for {user.email}: {approved_admin_scopes}")
                
                return JSONResponse({
                    "status": "approved",
                    "new_token": new_token,
                    "approved_scopes": approved_admin_scopes + auto_approved_scopes,
                    "message": f"Admin approval found for scopes: {', '.join(approved_admin_scopes)}"
                })
            
            # No approved requests found, create new approval request
            approval_request = create_approval_request(
                user_email=user.email,
                user_id=user.sub,
                tool_name=request_data.get("tool_name", "unknown"),
                required_scope=admin_scopes[0],  # Take first scope for simplicity
                risk_level="high",
                justification=f"User requested access to scopes: {', '.join(admin_scopes)}",
                metadata={"requested_scopes": admin_scopes}
            )
            
            response_data = {
                "status": "pending_admin_approval",
                "approval_request_id": approval_request.request_id,
                "message": f"Approval required for high-risk scopes: {', '.join(admin_scopes)}"
            }
            
            # Include auto-approved token if any scopes were auto-approved
            if auto_approved_scopes:
                current_scopes = set(user.scope.split()) if user.scope else set()
                current_scopes.update(auto_approved_scopes)
                user.scope = " ".join(current_scopes)
                
                token_data = {
                    "sub": user.sub,
                    "aud": user.aud,
                    "email": user.email,
                    "scope": user.scope,
                    "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
                    "iat": int(datetime.utcnow().timestamp()),
                    "iss": user.iss
                }
                
                response_data["new_token"] = jwt.encode(token_data, JWT_SECRET, algorithm="HS256")
                response_data["auto_approved_scopes"] = auto_approved_scopes
                
                # Update session data with new scopes so dashboard can see them
                for session_id, session_data in sessions.items():
                    if session_data.get("user", {}).get("email") == user.email:
                        session_data["user"]["scope"] = user.scope
                        logger.info(f"🔄 Updated session {session_id[:20]}... with auto-approved scopes in admin flow: {user.scope}")
                        break
            
            return JSONResponse(response_data)
        
        # Fallback - should not reach here
        return JSONResponse({
            "status": "no_action_needed",
            "message": "No scopes to process"
        })
        
    except Exception as e:
        logger.error(f"Error in scope upgrade: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Approval API routes
@app.post("/api/request-approval")
async def request_approval(request: ApprovalRequestModel):
    """Create a new approval request"""
    try:
        approval_request = create_approval_request(
            user_email=request.user_email,
            user_id=request.user_id,
            tool_name=request.tool_name,
            required_scope=request.required_scope,
            risk_level=request.risk_level,
            justification=request.justification,
            metadata=request.metadata
        )
        
        return JSONResponse({
            "success": True,
            "request_id": approval_request.request_id,
            "status": approval_request.status.value,
            "message": "Approval request created successfully"
        })
        
    except Exception as e:
        logger.error(f"Error creating approval request: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/approve/{request_id}")
async def approve_request(
    request_id: str, 
    admin_email: str = Form(...),
    session: Optional[TokenPayload] = Depends(verify_session)
):
    """Approve an approval request and generate new token"""
    if not session or not is_admin_user(session.email):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if request_id not in approval_requests:
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    approval_request = approval_requests[request_id]
    
    if approval_request.status != ApprovalStatus.PENDING:
        raise HTTPException(status_code=400, detail="Request is not pending")
    
    # Update approval request
    approval_request.status = ApprovalStatus.APPROVED
    approval_request.approved_by = admin_email
    approval_request.approved_at = datetime.utcnow()
    
    # Generate new token with approved scope for the user
    try:
        # Find user's current session data
        user_session = None
        session_id_to_update = None
        for session_id, stored_session in sessions.items():
            if stored_session["user"]["email"] == approval_request.user_email:
                user_session = stored_session
                session_id_to_update = session_id
                break
        
        if user_session:
            # Get current user token data
            user_token_data = TokenPayload(**user_session["user"])
            
            # Add approved scope to user's existing scopes
            current_scopes = set(user_token_data.scope.split()) if user_token_data.scope else set()
            current_scopes.add(approval_request.required_scope)
            
            # Update user session with new scopes
            user_session["user"]["scope"] = " ".join(current_scopes)
            logger.info(f"🔄 Updated user session with approved scope: {' '.join(current_scopes)}")
            if session_id_to_update:
                logger.info(f"📊 Session {session_id_to_update[:20]}... now has scopes: {user_session['user']['scope']}")
            
            # Generate new token with approved scopes
            new_token_payload = {
                "sub": user_token_data.sub,
                "aud": user_token_data.aud,
                "email": user_token_data.email,
                "scope": " ".join(current_scopes),
                "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
                "iat": int(datetime.utcnow().timestamp()),
                "iss": SERVER_URI
            }
            
            new_token = jwt.encode(new_token_payload, JWT_SECRET, algorithm="HS256")
            
            logger.info(f"Approval request {request_id} approved by {admin_email}, new token generated for {approval_request.user_email}")
            
            return JSONResponse({
                "success": True,
                "message": "Request approved successfully",
                "new_token": new_token,
                "approved_scope": approval_request.required_scope,
                "user_email": approval_request.user_email
            })
        else:
            logger.warning(f"Could not find user session for {approval_request.user_email}")
            return JSONResponse({
                "success": True,
                "message": "Request approved but user session not found for token generation"
            })
            
    except Exception as e:
        logger.error(f"Error generating new token after approval: {e}")
        return JSONResponse({
            "success": True,
            "message": "Request approved but token generation failed"
        })
    
    logger.info(f"Approval request {request_id} approved by {admin_email}")
    
    return JSONResponse({
        "success": True,
        "message": "Request approved successfully"
    })

@app.post("/api/deny/{request_id}")
async def deny_request(
    request_id: str,
    reason: str = Form(...),
    admin_email: str = Form(...)
):
    """Deny an approval request"""
    if request_id not in approval_requests:
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    approval_request = approval_requests[request_id]
    
    if approval_request.status != ApprovalStatus.PENDING:
        raise HTTPException(status_code=400, detail="Request is not pending")
    
    # Update approval request
    approval_request.status = ApprovalStatus.DENIED
    approval_request.denied_by = admin_email
    approval_request.denied_at = datetime.utcnow()
    approval_request.denial_reason = reason
    
    logger.info(f"Approval request {request_id} denied by {admin_email}: {reason}")
    
    return JSONResponse({
        "success": True,
        "message": "Request denied successfully"
    })

@app.get("/api/status/{request_id}")
async def get_request_status(request_id: str):
    """Get approval request status"""
    if request_id not in approval_requests:
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    approval_request = approval_requests[request_id]
    
    return JSONResponse({
        "request_id": request_id,
        "status": approval_request.status.value,
        "approved_by": approval_request.approved_by,
        "approved_at": approval_request.approved_at.isoformat() if approval_request.approved_at else None,
        "denied_by": approval_request.denied_by,
        "denied_at": approval_request.denied_at.isoformat() if approval_request.denied_at else None,
        "denial_reason": approval_request.denial_reason
    })

@app.post("/api/test-tool")
async def api_test_tool(
    request: Request,
    user: TokenPayload = Depends(verify_user_auth)
):
    """Test MCP tool access"""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        request_data = await request.json()
        tool_name = request_data.get("tool_name")
        
        if not tool_name:
            raise HTTPException(status_code=400, detail="Tool name required")
        
        # Create JWT token for MCP server
        token_data = {
            "sub": user.sub,
            "aud": MCP_SERVER_URI,
            "email": user.email,
            "scope": user.scope,
            "exp": int((datetime.utcnow() + timedelta(minutes=5)).timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
            "iss": SERVER_URI
        }
        
        test_token = jwt.encode(token_data, JWT_SECRET, algorithm="HS256")
        
        # Test the tool
        test_args = {"path": "/tmp"} if tool_name == "list_directory" else {}
        result = await call_mcp_tool_via_sse(tool_name, test_args, test_token)
        
        return JSONResponse({
            "success": True,
            "tool_name": tool_name,
            "result": result
        })
        
    except Exception as e:
        logger.error(f"Error testing tool: {e}")
        return JSONResponse({
            "success": False,
            "error": str(e)
        })

async def call_mcp_tool_via_sse(tool_name: str, arguments: dict, user_token: str) -> dict:
    """Call MCP tool via SSE endpoint"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{MCP_SERVER_URI}/sse",
                json={
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": arguments
                    }
                },
                headers={
                    "Authorization": f"Bearer {user_token}",
                    "Content-Type": "application/json"
                },
                timeout=30.0
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    "error": f"HTTP {response.status_code}",
                    "details": response.text
                }
                
    except Exception as e:
        return {
            "error": "Request failed",
            "details": str(e)
        }

@app.get("/api/user-status")
async def get_user_status(user: TokenPayload = Depends(verify_user_auth)):
    """Get current user authentication status and scopes"""
    if not user:
        return JSONResponse({"authenticated": False}, status_code=401)
    
    return JSONResponse({
        "authenticated": True,
        "user": {
            "email": user.email,
            "sub": user.sub,
            "scopes": user.scope.split() if user.scope else [],
            "roles": get_user_roles(user.email),
            "is_admin": is_admin_user(user.email)
        }
    })

@app.get("/api/check-token-update")
async def check_token_update(user: TokenPayload = Depends(verify_user_auth)):
    """Check if user has an updated token with new scopes"""
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    try:
        # Find user's current session data by email (not session ID)
        # This handles both cookie-based sessions and JWT token-based requests
        user_session = None
        for session_id, stored_session in sessions.items():
            if stored_session["user"]["email"] == user.email:
                user_session = stored_session
                break
        
        if user_session:
            # Get the latest user data from session
            latest_user_data = TokenPayload(**user_session["user"])
            
            # Compare current token scopes with session scopes
            current_scopes = set(user.scope.split()) if user.scope else set()
            latest_scopes = set(latest_user_data.scope.split()) if latest_user_data.scope else set()
            
            logger.info(f"🔍 Token update check for {user.email}: current={current_scopes}, latest={latest_scopes}")
            
            # If scopes have been updated, generate a new token
            if latest_scopes != current_scopes:
                logger.info(f"🔄 Scope update detected for {user.email}: {current_scopes} → {latest_scopes}")
                
                # Generate new token with updated scopes
                new_token_payload = {
                    "sub": latest_user_data.sub,
                    "aud": latest_user_data.aud,
                    "email": latest_user_data.email,
                    "scope": latest_user_data.scope,
                    "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
                    "iat": int(datetime.utcnow().timestamp()),
                    "iss": SERVER_URI
                }
                
                new_token = jwt.encode(new_token_payload, JWT_SECRET, algorithm="HS256")
                
                return JSONResponse({
                    "token_updated": True,
                    "new_token": new_token,
                    "new_scopes": list(latest_scopes),
                    "previous_scopes": list(current_scopes),
                    "message": "Token updated with new scopes"
                })
            else:
                logger.info(f"✅ Token is up to date for {user.email}")
                return JSONResponse({
                    "token_updated": False,
                    "current_scopes": list(current_scopes),
                    "message": "Token is up to date"
                })
        else:
            logger.warning(f"❌ No session found for {user.email}")
            return JSONResponse({
                "token_updated": False,
                "message": f"No session found for user {user.email}"
            })
            
    except Exception as e:
        logger.error(f"Error checking token update for {user.email}: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

@app.get("/api/tools")
async def get_user_tools(user: TokenPayload = Depends(verify_user_auth)):
    """Get user's tool access information (for dashboard refresh)"""
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    try:
        # Fetch MCP tools
        mcp_tools = await fetch_mcp_tools(user)
        
        # Get user's current scopes
        user_scopes = user.scope.split() if user.scope else []
        
        # Get tool access information
        tool_access = get_user_tool_access(user_scopes, mcp_tools)
        
        return JSONResponse({
            "tools": tool_access,
            "user_scopes": user_scopes,
            "user_email": user.email,
            "user_scope": user.scope
        })
    except Exception as e:
        logger.error(f"Failed to fetch tools for user {user.email}: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

# OAuth metadata
@app.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata():
    return ProtectedResourceMetadata(
        resource=MCP_SERVER_URI,
        authorization_servers=[SERVER_URI],
        scopes_supported=list(SCOPES.keys()),
        bearer_methods_supported=["header"],
        resource_documentation=f"{SERVER_URI}/dashboard"
    )

def cleanup_on_shutdown():
    """Clean up resources when the auth server shuts down."""
    logger.info("🧹 Cleaning up auth server resources...")
    try:
        # Clear in-memory sessions and approval requests
        global sessions, approval_requests, scope_upgrade_requests
        sessions.clear()
        approval_requests.clear()
        scope_upgrade_requests.clear()
        
        # Clean up any database files if they exist
        import os
        db_files = ["responses.db", "kvstore.db"]
        for db_file in db_files:
            if os.path.exists(db_file):
                os.remove(db_file)
                logger.info(f"Cleaned up database: {db_file}")
                
        logger.info("Auth server cleanup completed")
    except Exception as e:
        logger.error(f"Error during auth server cleanup: {e}")

def signal_handler(signum, frame):
    """Handle shutdown signals."""
    logger.info(f"Auth server received signal {signum}, shutting down gracefully...")
    cleanup_on_shutdown()
    sys.exit(0)

# Register cleanup functions
atexit.register(cleanup_on_shutdown)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == "__main__":
    try:
        logger.info("🚀 Starting unified auth server...")
        uvicorn.run(app, host=SERVER_HOST, port=SERVER_PORT)
    except KeyboardInterrupt:
        logger.info("Auth server interrupted by user")
    finally:
        cleanup_on_shutdown() 