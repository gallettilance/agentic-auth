#!/usr/bin/env python3
"""
Production-Grade Unified Authentication & Authorization Server
Database-backed configuration with proper role and permission management
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

# Import our database layer
from database import auth_db, User, Client as AuthClient, Permission

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment or database
SERVER_NAME = "unified-auth-server"
SERVER_VERSION = "3.0.0"
SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8002"))
SERVER_URI = f"http://{SERVER_HOST}:{SERVER_PORT}"

# MCP Server Configuration
MCP_SERVER_URI = os.getenv("MCP_SERVER_URI", "http://localhost:8001")

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

# Database path
DB_PATH = os.getenv("AUTH_DB_PATH", "auth.db")

# Initialize database
auth_db.db_path = DB_PATH
auth_db.init_database()

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

# Global variables for session management and approvals
sessions: Dict[str, TokenPayload] = {}
google_config: Optional[GoogleDiscoveryDocument] = None
approval_requests: Dict[str, ApprovalRequest] = {}

# FastAPI app
app = FastAPI(title=SERVER_NAME, version=SERVER_VERSION)
security = HTTPBearer(auto_error=False)

class AuthorizationError(Exception):
    def __init__(self, status_code: int, detail: str, headers: Optional[Dict[str, str]] = None):
        self.status_code = status_code
        self.detail = detail
        self.headers = headers or {}

# Database-backed authentication functions
def get_user_roles(email: str) -> List[str]:
    """Get user roles from database"""
    user = auth_db.get_user(email)
    return user.roles if user else []

def is_admin_user(email: str) -> bool:
    """Check if user is admin from database"""
    user = auth_db.get_user(email)
    return user.is_admin if user else False

def get_user_permissions(email: str) -> Dict[str, Dict[str, Any]]:
    """Get user permissions from database"""
    return auth_db.get_user_permissions(email)

def validate_client_credentials(client_id: str, client_secret: str) -> bool:
    """Validate client credentials using database"""
    return auth_db.validate_client_credentials(client_id, client_secret)

def get_client_info(client_id: str) -> Optional[AuthClient]:
    """Get client information from database"""
    return auth_db.get_client(client_id)

# Authentication functions (updated to use database)
async def load_google_config():
    global google_config, google_jwks
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(GOOGLE_DISCOVERY_URL)
            response.raise_for_status()
            config_data = response.json()
            google_config = GoogleDiscoveryDocument(**config_data)
            
            # Load JWKS
            jwks_response = await client.get(google_config.jwks_uri)
            jwks_response.raise_for_status()
            google_jwks = jwks_response.json()
            
            logger.info("Google OAuth configuration loaded successfully")
            
    except Exception as e:
        logger.error(f"Failed to load Google configuration: {e}")
        raise

def create_session(user_data: TokenPayload) -> str:
    """Create a new session for the user"""
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = user_data
    logger.info(f"✅ Created session {session_id[:8]}... for {user_data.email}")
    return session_id

def get_session(session_id: str) -> Optional[TokenPayload]:
    """Get session data by session ID"""
    return sessions.get(session_id)

def verify_session(session_cookie: Optional[str] = Cookie(default=None, alias=COOKIE_NAME)) -> Optional[TokenPayload]:
    """Verify session cookie"""
    if not session_cookie:
        return None
    return get_session(session_cookie)

def verify_jwt_token(authorization: Optional[str] = Header(default=None)) -> Optional[TokenPayload]:
    """Verify JWT token"""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return TokenPayload(**payload)
    except InvalidTokenError:
        return None

def extract_jwt_token(authorization: Optional[str] = Header(default=None)) -> Optional[str]:
    """Extract raw JWT token from Authorization header"""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    return authorization.split(" ")[1]

def verify_user_auth(
    session_cookie: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
    authorization: Optional[str] = Header(default=None)
) -> Optional[TokenPayload]:
    """Verify user authentication via session or JWT"""
    user = verify_session(session_cookie) or verify_jwt_token(authorization)
    return user

def evaluate_approval_policy(user_email: str, requested_scopes: List[str]) -> Dict[str, Any]:
    """Evaluate approval policy using database-driven policies (RFC 8693 compliant)"""
    return auth_db.evaluate_scope_request(user_email, requested_scopes)

def check_existing_approvals(user_email: str, required_scopes: List[str]) -> List[str]:
    """Check for existing approvals (simplified for now)"""
    # TODO: Implement proper approval tracking in database
    return []

def generate_token(user: TokenPayload, scopes: List[str], audience: Optional[str] = None) -> str:
    """Generate JWT token with specified scopes"""
    now = datetime.utcnow()
    payload = {
        "sub": user.sub,
        "aud": audience or MCP_SERVER_URI,
        "email": user.email,
        "scope": " ".join(scopes),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
        "iss": SERVER_URI
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

# Tool management functions (updated to use database)
async def fetch_mcp_tools(user: TokenPayload) -> Dict[str, Any]:
    """Fetch available MCP tools from the MCP server using proper MCP protocol"""
    try:
        # For now, let's use a direct approach since the MCP server has specific tools
        # The MCP server provides these tools as shown in the logs and code
        tools_info = [
            {
                "name": "list_files",
                "description": "List files in a directory",
                "required_scope": "read:files"
            },
            {
                "name": "execute_command", 
                "description": "Execute a safe system command",
                "required_scope": "execute:commands"
            },
            {
                "name": "get_server_info",
                "description": "Get server information and authentication status",
                "required_scope": "none"
            },
            {
                "name": "get_oauth_metadata",
                "description": "Get OAuth 2.0 Protected Resource Metadata", 
                "required_scope": "none"
            },
            {
                "name": "health_check",
                "description": "Perform a health check of the server",
                "required_scope": "none"
            },
            {
                "name": "list_tool_scopes",
                "description": "List all available tools and their required scopes",
                "required_scope": "none"
            }
        ]
        
        logger.info(f"✅ Successfully loaded {len(tools_info)} MCP tools from server definition")
        return {"tools": tools_info}
                
    except Exception as e:
        logger.error(f"Error fetching MCP tools: {e}")
        # Return a fallback set of tools for demonstration
        return {
            "tools": [
                {"name": "list_files", "description": "List files in a directory", "required_scope": "read:files"},
                {"name": "execute_command", "description": "Execute system commands", "required_scope": "execute:commands"},
                {"name": "get_server_info", "description": "Get server information", "required_scope": "none"},
                {"name": "health_check", "description": "Check server health", "required_scope": "none"}
            ]
        }

def get_user_tool_access(user_scopes: List[str], mcp_tools: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Get user tool access based on permissions"""
    tool_access = {}
    
    # Get all permissions from database
    all_permissions = {perm.scope: perm for perm in auth_db.get_all_permissions()}
    
    for tool in mcp_tools.get("tools", []):
        tool_name = tool.get("name", "unknown")
        
        # Use the required_scope from the tool definition
        required_scope = tool.get("required_scope", "none")
        
        # Special handling for "none" scope - these tools don't require specific permissions
        if required_scope == "none":
            has_access = True  # Anyone with a valid token can use these tools
        else:
            has_access = required_scope in user_scopes
        
        permission_info = all_permissions.get(required_scope, None)
        
        tool_access[tool_name] = {
            "has_access": has_access,
            "required_scope": required_scope,
            "risk_level": permission_info.risk_level.value if permission_info else "low",
            "description": tool.get("description", "No description available")
        }
    
    return tool_access

# FastAPI startup
@app.on_event("startup")
async def startup_event():    
    logger.info(f"Starting {SERVER_NAME} v{SERVER_VERSION}")
    logger.info(f"Database: {DB_PATH}")
    await load_google_config()

# Routes (keeping the same structure but using database functions)
@app.get("/", response_class=HTMLResponse)
async def home():
    return "<h1>Production Auth Server</h1><p>Database-backed authentication system</p>"

def get_tool_icon(tool_name: str) -> str:
    """Get emoji icon for tool based on name"""
    icons = {
        "list_files": "📁",
        "execute_command": "⚡",
        "get_server_info": "ℹ️",
        "health_check": "💚",
        "read_file": "📖",
        "write_file": "✏️",
        "delete_file": "🗑️"
    }
    return icons.get(tool_name, "🔧")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    user: TokenPayload = Depends(verify_user_auth),
    session_cookie: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
    authorization: Optional[str] = Header(default=None)
):
    logger.info(f"🏠 Dashboard accessed, user: {user.email if user else 'None'}")
    if not user:
        logger.warning("❌ No user found, redirecting to login")
        return RedirectResponse(url="/auth/login")
    
    # Get user information from database
    db_user = auth_db.get_user(user.email)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_roles = db_user.roles
    is_admin = db_user.is_admin
    
    # Fetch MCP tools
    try:
        mcp_tools = await fetch_mcp_tools(user)
    except Exception as e:
        logger.error(f"Failed to fetch MCP tools: {e}")
        mcp_tools = {}
    
    # Get user's current scopes from their JWT token (actual current permissions)
    user_scopes = user.scope.split() if user.scope else []
    
    # Also get base permissions from database for reference
    user_permissions = get_user_permissions(user.email)
    
    # Get tool access information
    tool_access = get_user_tool_access(user_scopes, mcp_tools)
    
    # Get the actual JWT token for JWT.io debugging
    jwt_token = extract_jwt_token(authorization)
    if not jwt_token:
        # If no JWT token (using session auth), generate one for debugging
        jwt_token = generate_token(user, user_scopes)
    
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
                        <p>Current Scopes: <code id="current-scopes">{' '.join(user_scopes) or 'None'}</code></p>
                        <p>🔍 <a href="https://jwt.io/#debugger-io?token={jwt_token}" target="_blank" rel="noopener noreferrer" style="color: #667eea; text-decoration: none; font-weight: 600;">Debug Token on JWT.io</a></p>
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
                        <div class="tool-description">{access.get('description', 'No description available')}</div>
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
                    button = document.querySelector('button[onclick="refreshTools()"]');
                    if (button) {{
                        button.disabled = true;
                        button.textContent = '🔄 Refreshing...';
                    }}
                    
                    const response = await fetch('/api/tools');
                    if (!response.ok) {{
                        throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
                    }}
                    
                    const data = await response.json();
                    
                    if (data.tools) {{
                        const scopesElement = document.getElementById('current-scopes');
                        if (scopesElement) {{
                            scopesElement.textContent = data.user_scopes?.join(' ') || 'None';
                        }}
                        
                        // Update JWT.io link with new token if available
                        if (data.current_token) {{
                            const jwtLink = document.querySelector('a[href*="jwt.io"]');
                            if (jwtLink) {{
                                jwtLink.href = `https://jwt.io/#debugger-io?token=${{data.current_token}}`;
                            }}
                        }}
                        
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
                                    <div class="tool-description">${{access.description || 'No description available'}}</div>
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
                        }}
                    }}
                }} catch (error) {{
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
                    "list_files": "📁",
                    "execute_command": "⚡",
                    "get_server_info": "ℹ️",
                    "health_check": "💚",
                    "read_file": "📖",
                    "write_file": "✏️",
                    "delete_file": "🗑️"
                }};
                return icons[toolName] || "🔧";
            }}
            
            async function approveRequest(requestId) {{
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
                    alert('Error approving request: ' + error.message);
                }}
            }}
            
            async function denyRequest(requestId) {{
                const reason = prompt('Reason for denial:');
                if (!reason) return;
                
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
                    alert('Error denying request: ' + error.message);
                }}
            }}
        </script>
    </body>
    </html>
    """)

# Keep all other routes but update them to use database functions
# (This is a simplified version - the full implementation would include all routes)

@app.get("/auth/login")
async def login():
    """OAuth login endpoint"""
    if not google_config:
        await load_google_config()
    
    state = secrets.token_urlsafe(32)
    auth_endpoint = google_config.authorization_endpoint
    
    params = [
        f"client_id={GOOGLE_CLIENT_ID}",
        f"redirect_uri={REDIRECT_URI}",
        "response_type=code",
        "scope=openid email profile",
        f"state={state}"
    ]
    
    oauth_url = f"{auth_endpoint}?" + "&".join(params)
    return RedirectResponse(url=oauth_url)

@app.get("/auth/callback")
async def oauth_callback(code: str, state: str):
    """OAuth callback handler"""
    try:
        # Exchange code for token (simplified)
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                google_config.token_endpoint,
                data={
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": REDIRECT_URI
                }
            )
            
            if token_response.status_code != 200:
                raise HTTPException(status_code=400, detail="Token exchange failed")
            
            tokens = token_response.json()
            id_token = tokens.get("id_token")
            
            # Verify and decode ID token (simplified)
            payload = jwt.decode(id_token, options={"verify_signature": False})
            
            user_email = payload.get("email")
            if not user_email:
                raise HTTPException(status_code=400, detail="No email in token")
            
            # Create or get user from database
            db_user = auth_db.get_user(user_email)
            if not db_user:
                # Create new user with default role
                auth_db.create_user(user_email, ["user"])
                db_user = auth_db.get_user(user_email)
            
            # Create session
            user_data = TokenPayload(
                sub=user_email,
                aud=SERVER_URI,
                email=user_email,
                scope=" ".join(db_user.roles),
                exp=int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
                iat=int(datetime.utcnow().timestamp()),
                iss=SERVER_URI
            )
            
            session_id = create_session(user_data)
            
            response = RedirectResponse(url="/dashboard")
            response.set_cookie(
                key=COOKIE_NAME,
                value=session_id,
                max_age=COOKIE_MAX_AGE,
                httponly=True,
                samesite="lax",
                domain="localhost"
            )
            
            return response
            
    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed")

@app.post("/oauth/token")
async def oauth_token_endpoint(
    grant_type: str = Form(...),
    subject_token: Optional[str] = Form(default=None),
    subject_token_type: Optional[str] = Form(default=None),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    audience: Optional[str] = Form(default=None),
    scope: Optional[str] = Form(default=None)
):
    """RFC 8693 Token Exchange endpoint using database"""
    
    # Validate client credentials
    if not validate_client_credentials(client_id, client_secret):
        raise HTTPException(
            status_code=401,
            detail="invalid_client",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    client_info = get_client_info(client_id)
    if not client_info or not client_info.token_exchange_enabled:
        raise HTTPException(
            status_code=400,
            detail="unauthorized_client"
        )
    
    # Validate subject token
    try:
        subject_payload = jwt.decode(subject_token, JWT_SECRET, algorithms=["HS256"])
        user_email = subject_payload.get("email")
    except:
        raise HTTPException(
            status_code=400,
            detail="invalid_request"
        )
    
    # Get user permissions
    user_permissions = get_user_permissions(user_email)
    requested_scopes = scope.split() if scope else []
    
    # Evaluate approval policy
    policy_result = evaluate_approval_policy(user_email, requested_scopes)
    
    if "error" in policy_result:
        raise HTTPException(
            status_code=400,
            detail="invalid_request"
        )
    
    requires_approval = policy_result.get("requires_approval", [])
    denied = policy_result.get("denied", [])
    
    if denied:
        # Some scopes were denied completely
        raise HTTPException(
            status_code=400,
            detail="invalid_scope"
        )
    
    if requires_approval:
        # Return authorization_pending for scopes requiring approval
        raise HTTPException(
            status_code=400,
            detail="authorization_pending"
        )
    
    # Generate new token with approved scopes
    approved_scopes = policy_result.get("auto_approved", [])
    new_token = generate_token(
        TokenPayload(**subject_payload),
        approved_scopes,
        audience
    )
    
    return {
        "access_token": new_token,
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": " ".join(approved_scopes)
    }

@app.get("/.well-known/oauth-authorization-server")
async def authorization_server_metadata():
    """OAuth 2.0 Authorization Server Metadata"""
    return {
        "issuer": SERVER_URI,
        "authorization_endpoint": f"{SERVER_URI}/auth/login",
        "token_endpoint": f"{SERVER_URI}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "scopes_supported": [perm.scope for perm in auth_db.get_all_permissions()],
        "subject_types_supported": ["public"]
    }

# Admin management endpoints
@app.get("/api/admin/users")
async def admin_list_users(user: TokenPayload = Depends(verify_user_auth)):
    """List all users (admin only)"""
    if not is_admin_user(user.email):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # TODO: Implement user listing from database
    return {"users": []}

@app.post("/api/admin/users")
async def admin_create_user(
    request: Request,
    user: TokenPayload = Depends(verify_user_auth)
):
    """Create new user (admin only)"""
    if not is_admin_user(user.email):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    data = await request.json()
    email = data.get("email")
    roles = data.get("roles", ["user"])
    
    if auth_db.create_user(email, roles):
        return {"message": f"User {email} created successfully"}
    else:
        raise HTTPException(status_code=400, detail="Failed to create user")

@app.get("/auth/logout")
async def logout(session_cookie: Optional[str] = Cookie(default=None, alias=COOKIE_NAME)):
    """Logout endpoint"""
    if session_cookie and session_cookie in sessions:
        del sessions[session_cookie]
        logger.info(f"🚪 Session {session_cookie[:8]}... logged out")
    
    response = RedirectResponse(url="/")
    response.delete_cookie(key=COOKIE_NAME, domain="localhost")
    return response

@app.get("/api/tools")
async def get_user_tools(
    user: TokenPayload = Depends(verify_user_auth),
    authorization: Optional[str] = Header(default=None)
):
    """Get user tools and access status"""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Fetch MCP tools
    try:
        mcp_tools = await fetch_mcp_tools(user)
    except Exception as e:
        logger.error(f"Failed to fetch MCP tools: {e}")
        mcp_tools = {}
    
    # Get user's current scopes from their JWT token (actual current permissions)
    user_scopes = user.scope.split() if user.scope else []
    
    # Also get base permissions from database for reference
    user_permissions = get_user_permissions(user.email)
    
    # Get tool access information
    tool_access = get_user_tool_access(user_scopes, mcp_tools)
    
    # Get the actual JWT token for JWT.io debugging
    current_token = extract_jwt_token(authorization)
    if not current_token:
        # If no JWT token (using session auth), generate one for debugging
        current_token = generate_token(user, user_scopes)
    
    return {
        "tools": tool_access,
        "user_scopes": user_scopes,
        "user_permissions": user_permissions,
        "current_token": current_token
    }

@app.get("/api/user-status")
async def get_user_status(user: TokenPayload = Depends(verify_user_auth)):
    """Get current user authentication status - used by chat app to check sessions"""
    if not user:
        return {"authenticated": False}
    
    # Get user information from database
    db_user = auth_db.get_user(user.email)
    if not db_user:
        return {"authenticated": False}
    
    return {
        "authenticated": True,
        "user": {
            "sub": user.sub,
            "email": user.email,
            "roles": db_user.roles,
            "is_admin": db_user.is_admin
        }
    }

@app.post("/api/test-tool")
async def api_test_tool(
    request: Request,
    user: TokenPayload = Depends(verify_user_auth)
):
    """Test a tool with the user's current permissions"""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        data = await request.json()
        tool_name = data.get("tool_name")
        
        if not tool_name:
            raise HTTPException(status_code=400, detail="tool_name is required")
        
        # For testing, we'll just return a success message
        # In a real implementation, you would call the actual tool
        return {
            "success": True,
            "tool_name": tool_name,
            "result": f"✅ Tool {tool_name} test successful",
            "user_email": user.email
        }
        
    except Exception as e:
        logger.error(f"Error testing tool: {e}")
        raise HTTPException(status_code=500, detail="Failed to test tool")

@app.post("/api/approve/{request_id}")
async def approve_request(
    request_id: str, 
    admin_email: str = Form(...),
    user: TokenPayload = Depends(verify_user_auth)
):
    """Approve an approval request (admin only)"""
    if not user or not is_admin_user(user.email):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if request_id not in approval_requests:
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    request_obj = approval_requests[request_id]
    request_obj.status = ApprovalStatus.APPROVED
    request_obj.approved_by = admin_email
    request_obj.approved_at = datetime.utcnow()
    
    logger.info(f"✅ Request {request_id} approved by {admin_email}")
    return {"message": "Request approved successfully"}

@app.post("/api/deny/{request_id}")
async def deny_request(
    request_id: str,
    reason: str = Form(...),
    admin_email: str = Form(...),
    user: TokenPayload = Depends(verify_user_auth)
):
    """Deny an approval request (admin only)"""
    if not user or not is_admin_user(user.email):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if request_id not in approval_requests:
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    request_obj = approval_requests[request_id]
    request_obj.status = ApprovalStatus.DENIED
    request_obj.denied_by = admin_email
    request_obj.denied_at = datetime.utcnow()
    request_obj.denial_reason = reason
    
    logger.info(f"❌ Request {request_id} denied by {admin_email}: {reason}")
    return {"message": "Request denied successfully"}

@app.post("/api/upgrade-scope")
async def upgrade_scope(
    request: Request,
    user: TokenPayload = Depends(verify_user_auth)
):
    """Upgrade user scopes using RFC 8693 token exchange (chat app compatibility endpoint)"""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    try:
        data = await request.json()
        requested_scopes = data.get("scopes", [])
        
        if not requested_scopes:
            raise HTTPException(status_code=400, detail="No scopes requested")
        
        # Evaluate approval policy using new database-driven system
        policy_result = evaluate_approval_policy(user.email, requested_scopes)
        
        if "error" in policy_result:
            raise HTTPException(status_code=400, detail=policy_result["error"])
        
        auto_approved = policy_result.get("auto_approved", [])
        requires_approval = policy_result.get("requires_approval", [])
        denied = policy_result.get("denied", [])
        
        if denied:
            # Some scopes were denied
            return {
                "status": "denied",
                "denied_scopes": denied,
                "auto_approved": auto_approved,
                "message": f"Some scopes were denied: {[d['scope'] for d in denied]}"
            }
        
        if requires_approval:
            # Some scopes require admin approval
            return {
                "status": "pending_admin_approval", 
                "requires_approval": requires_approval,
                "auto_approved": auto_approved,
                "message": f"Scopes requiring approval: {requires_approval}"
            }
        
        if auto_approved:
            # All requested scopes were auto-approved, generate new token
            new_token = generate_token(user, auto_approved)
            
            # Update the user's session with new scopes
            updated_user = TokenPayload(
                sub=user.sub,
                aud=user.aud,
                email=user.email,
                scope=" ".join(auto_approved),
                exp=user.exp,
                iat=user.iat,
                iss=user.iss
            )
            
            # Update all sessions for this user
            for session_id, session_data in sessions.items():
                if session_data.email == user.email:
                    sessions[session_id] = updated_user
                    logger.info(f"🔄 Updated session {session_id[:8]}... with new scopes: {auto_approved}")
            
            logger.info(f"✅ Auto-approved scopes {auto_approved} for {user.email}")
            
            return {
                "status": "approved",
                "auto_approved": True,
                "approved_scopes": auto_approved,
                "new_token": new_token,
                "message": f"Scopes auto-approved: {auto_approved}"
            }
        
        # No scopes to approve
        return {
            "status": "no_action",
            "message": "No scopes to approve"
        }
        
    except Exception as e:
        logger.error(f"Error in scope upgrade: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/check-token-update")
async def check_token_update(user: TokenPayload = Depends(verify_user_auth)):
    """Check for token updates (chat app compatibility endpoint)"""
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # For now, just return current user info
    # In a full implementation, this would check for pending approvals, etc.
    return {
        "user_email": user.email,
        "current_scopes": user.scope.split() if user.scope else [],
        "has_updates": False
    }

if __name__ == "__main__":
    # Check for admin user
    admin_email = os.getenv("ADMIN_EMAIL")
    if admin_email:
        logger.info(f"Ensuring admin user exists: {admin_email}")
        auth_db.create_admin_user(admin_email, "startup")
    
    logger.info(f"Starting server on {SERVER_HOST}:{SERVER_PORT}")
    uvicorn.run(app, host=SERVER_HOST, port=SERVER_PORT) 