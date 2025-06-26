#!/usr/bin/env python3
"""
Simple MCP Chat Web App with Google OAuth
A Flask application that integrates Google OAuth with Llama Stack agents and MCP tools.
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
import os
import json
import base64
import secrets
import asyncio
from datetime import datetime, timedelta
import httpx
import re
import logging
import sys
import signal
import atexit
import time

# Llama Stack imports
from llama_stack_client import LlamaStackClient
from llama_stack_client.lib.agents.agent import Agent
from llama_stack_client.types import UserMessage
from httpx import Client

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Configure logging for shell redirection
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(16))

# Configure session settings - use different cookie name to avoid conflicts
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='chat_session',  # Different name to avoid conflicts with auth server
    SESSION_COOKIE_DOMAIN='localhost',  # Share cookies across localhost ports
    SESSION_COOKIE_PATH='/',  # Ensure cookie works for all paths
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_REFRESH_EACH_REQUEST=True  # Keep session active
)

# Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
MCP_SERVER_URL = "http://localhost:8001/sse"
LLAMA_STACK_URL = "http://localhost:8321"
REDIRECT_URI = "http://127.0.0.1:5001/callback"
AUTH_SERVER_URL = "http://localhost:8002"  # Unified auth server URL

# Agent configuration
AGENT_SYSTEM_PROMPT = """You are an AI assistant with access to MCP (Model Context Protocol) tools.

You can help users with:
- File operations (reading, listing, searching files)
- System commands (when safe and appropriate)
- Data analysis and processing
- General questions and tasks

When using MCP tools, always:
1. Check if you have the required permissions/scopes
2. Use tools safely and appropriately
3. Provide clear explanations of what you're doing
4. Handle errors gracefully

Available MCP tools are automatically provided through the authenticated connection.
"""

# Global variables for agent management
llama_client = None
user_agents = {}  # Dictionary to store per-user agents: {user_email: {'agent': agent, 'session_id': session_id}}

# Store for pending messages (for retry after approval)
pending_messages = {}

def extract_authorization_error_details(error_message: str) -> dict:
    """Extract details from authorization error messages"""
    error_lower = error_message.lower()
    
    # Default values
    tool_name = "unknown_tool"
    required_scope = "execute:commands"  # Most common restricted scope
    error_type = "authorization"
    approval_status = "unknown"
    approval_requested = False
    
    # Check if this is the new InsufficientScopeError from auth agent
    if "InsufficientScopeError" in error_message:
        error_type = "insufficient_scope"
        approval_requested = True  # Auth agent automatically requests approval
        
        # Try to extract tool name from the error message
        # Format: InsufficientScopeError: Tool 'execute_command' requires scope 'execute:commands'
        tool_match = re.search(r"Tool ['\"]?(\w+)['\"]?", error_message)
        if tool_match:
            tool_name = tool_match.group(1)
        
        # Try to extract required scope
        scope_match = re.search(r"requires scope ['\"]?([^'\"]+)['\"]?", error_message)
        if scope_match:
            required_scope = scope_match.group(1)
        
        return {
            "error_type": error_type,
            "tool_name": tool_name,
            "required_scope": required_scope,
            "original_error": error_message,
            "approval_requested": approval_requested,
            "approval_status": "automatically_requested"
        }
    
    # Fallback to old parsing logic for other error formats
    # Try to extract tool name
    tool_match = re.search(r"tool ['\"]?(\w+)['\"]?", error_lower)
    if tool_match:
        tool_name = tool_match.group(1)
    
    # Try to extract required scope 
    scope_match = re.search(r"requires scope ['\"]?(\w+)['\"]?", error_lower)
    if scope_match:
        required_scope = scope_match.group(1)
    
    # Determine error type
    if any(keyword in error_lower for keyword in ["insufficient scope", "scope required"]):
        error_type = "insufficient_scope"
    elif any(keyword in error_lower for keyword in ["unauthorized", "forbidden", "access denied"]):
        error_type = "unauthorized"
    elif "invalid token" in error_lower:
        error_type = "invalid_token"
    
    return {
        "error_type": error_type,
        "tool_name": tool_name,
        "required_scope": required_scope,
        "original_error": error_message,
        "approval_requested": approval_requested,
        "approval_status": approval_status
    }

def is_authorization_error(error_message: str) -> bool:
    """Check if error message indicates an authorization issue"""
    error_lower = error_message.lower()
    authorization_keywords = [
        "insufficient scope", "unauthorized", "forbidden", 
        "access denied", "invalid token", "scope required",
        "insufficientscopeerror", "permission denied"
    ]
    
    # Check for the new InsufficientScopeError from auth agent
    if "insufficientscopeerror" in error_lower:
        return True
    
    # Check for the class name in the error traceback
    if "InsufficientScopeError" in error_message:
        return True
        
    return any(keyword in error_lower for keyword in authorization_keywords)

async def request_scope_upgrade(required_scope: str, user_token: str) -> dict:
    """Request scope upgrade through the auth server's upgrade-scope endpoint"""
    payload = {
        "scopes": [required_scope]
    }
    
    headers = {
        "Authorization": f"Bearer {user_token}",
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(f"{AUTH_SERVER_URL}/api/upgrade-scope", json=payload, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Scope upgrade request failed: {response.status_code} - {response.text}")
                return {"error": f"Request failed with status {response.status_code}"}
        except Exception as e:
            logger.error(f"Error requesting scope upgrade: {e}")
            return {"error": str(e)}

async def request_approval_for_tool(tool_name: str, required_scope: str, user_email: str, justification: str) -> dict:
    """Legacy function - kept for compatibility"""
    # This is now a wrapper around the new scope upgrade function
    # We'll need a token to call the new endpoint, but this is a legacy function
    # so we'll return an error directing to use the new flow
    return {"error": "This approval method is deprecated. Use the new scope upgrade flow."}


async def check_approval_status(request_id: str) -> dict:
    """Check the status of an approval request"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{AUTH_SERVER_URL}/api/status/{request_id}")
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Status check failed with status {response.status_code}"}
        except Exception as e:
            logger.error(f"Error checking approval status: {e}")
            return {"error": str(e)}

def get_oauth_url():
    """Get Google OAuth URL using known endpoints"""
    # Google OAuth endpoints (well-known and stable)
    auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    
    # Build OAuth URL with longer state token
    state = secrets.token_urlsafe(64)  # Longer state token
    oauth_url = f"{auth_endpoint}?" + "&".join([
        f"client_id={GOOGLE_CLIENT_ID}",
        f"redirect_uri={REDIRECT_URI}",
        "response_type=code",
        "scope=openid email",
        f"state={state}"
    ])
    
    return oauth_url, state

async def exchange_code_for_token(code: str):
    """Exchange authorization code for access token"""
    # Google token endpoint (well-known and stable)
    token_endpoint = "https://oauth2.googleapis.com/token"
    
    async with httpx.AsyncClient() as client:
        # Exchange code for token
        token_response = await client.post(
            token_endpoint,
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": REDIRECT_URI,
            }
        )
        
        if token_response.status_code != 200:
            raise Exception(f"Token exchange failed: {token_response.status_code} - {token_response.text}")
            
        return token_response.json()

async def get_user_info(access_token: str):
    """Get user info from Google using access token"""
    async with httpx.AsyncClient() as client:
        userinfo_response = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        return userinfo_response.json()

def create_jwt_token(user_info: dict) -> str:
    """Create a JWT token similar to the working format"""
    import jwt
    
    # Create payload to match MCP server expectations (no scopes initially)
    payload = {
        "sub": user_info.get("id", ""),  # Google user ID
        "aud": "http://localhost:8001",  # MCP server URI
        "email": user_info.get("email", ""),
        "scope": "",  # No scopes initially - user will request them later
        "exp": int((datetime.now() + timedelta(hours=1)).timestamp()),
        "iat": int(datetime.now().timestamp()),
        "iss": "http://localhost:8002"  # Unified auth server URI
    }
    
    # Use the same secret as the MCP server
    secret = "demo-secret-key-change-in-production"
    
    # Create JWT token
    jwt_token = jwt.encode(payload, secret, algorithm="HS256")
    return jwt_token

def get_or_create_user_agent(user_email: str, bearer_token: str):
    """Get or create a Llama Stack agent and session for a specific user"""
    global llama_client, user_agents
    
    try:
        # Initialize Llama Stack client if not already done
        if not llama_client:
            llama_client = LlamaStackClient(
                base_url=LLAMA_STACK_URL,
                http_client=Client(verify=False),
            )
            logger.info("✅ Initialized Llama Stack client")
        
        # Check if user already has an agent
        if user_email in user_agents:
            user_data = user_agents[user_email]
            agent = user_data['agent']
            session_id = user_data['session_id']
            
            logger.info(f"🔄 Reusing existing agent for {user_email} with session: {session_id}")
            return agent, session_id
        
        # Get available models
        models = llama_client.models.list()
        if not models:
            logger.error("❌ No models available")
            return None, None
        
        model_id = models[0].identifier
        logger.info(f"🤖 Using model: {model_id}")
        
        # Create user-specific agent
        agent = Agent(
            client=llama_client,
            tools=["mcp::mcp-auth"],  # MCP tool group from run.yml
            model=model_id,
            instructions=AGENT_SYSTEM_PROMPT,
            enable_session_persistence=True,
        )
        
        # Check if user has an existing session ID in Flask session
        existing_session_id = session.get('llama_session_id')
        
        if existing_session_id:
            logger.info(f"🔄 Found existing session ID for {user_email}: {existing_session_id}")
            session_id = existing_session_id
            
            # Verify the session still exists by trying to use it
            try:
                # We'll verify it works when we actually use it
                logger.info(f"✅ Reusing session: {existing_session_id}")
            except Exception as e:
                logger.warning(f"⚠️ Existing session may be invalid: {e}")
                existing_session_id = None
        
        if not existing_session_id:
            # Create new session with user-specific name
            session_name = f"chat-{user_email}-{int(time.time())}"
            session_id = agent.create_session(session_name)
            
            # Store session ID in Flask session for persistence
            session['llama_session_id'] = session_id
            session.permanent = True  # Make session persistent
            
            logger.info(f"✅ Created new session for {user_email}: {session_id}")
        
        # Store user agent and session
        user_agents[user_email] = {
            'agent': agent,
            'session_id': session_id
        }
        
        logger.info(f"✅ Agent ready for {user_email}")
        return agent, session_id
        
    except Exception as e:
        logger.error(f"❌ Failed to get/create agent for {user_email}: {e}")
        import traceback
        traceback.print_exc()
        return None, None

def cleanup_user_agent(user_email: str):
    """Clean up user agent when user logs out"""
    global user_agents
    
    if user_email in user_agents:
        logger.info(f"🧹 Cleaning up agent for {user_email}")
        del user_agents[user_email]
        
        # Also clear session data
        if 'llama_session_id' in session:
            del session['llama_session_id']

# Legacy functions for backward compatibility - now use per-user agents
def initialize_agent(bearer_token: str):
    """Initialize agent for current user (legacy function)"""
    user_email = session.get('user_email', 'anonymous')
    agent, session_id = get_or_create_user_agent(user_email, bearer_token)
    return agent is not None

def send_message_to_agent(message: str, bearer_token: str) -> dict:
    """Send message to the user's specific Llama Stack agent"""
    user_email = session.get('user_email', 'anonymous')
    
    try:
        logger.info(f"🤖 Sending message to agent for {user_email}: {message}")
        
        # Get or create user-specific agent
        agent, agent_session_id = get_or_create_user_agent(user_email, bearer_token)
        
        if not agent or not agent_session_id:
            return {
                "success": False,
                "response": "❌ Failed to initialize agent. Please check if Llama Stack is running on port 8321.",
                "error_type": "initialization_error"
            }
        
        # Create the message
        user_message = UserMessage(content=message, role="user")
        logger.info(f"📤 Created user message for {user_email}: {user_message}")
        
        # Send to user's agent with MCP authentication headers
        logger.info(f"🔐 Sending with bearer token: {bearer_token[:20]}...")
        response = agent.create_turn(
            messages=[user_message],
            session_id=agent_session_id,
            stream=True,  # Enable streaming for proper event handling
            extra_headers={
                "X-LlamaStack-Provider-Data": json.dumps({
                    "mcp_headers": {
                        MCP_SERVER_URL: {
                            "Authorization": f"Bearer {bearer_token}",
                        },
                    },
                })
            }
        )
        
        logger.info(f"📥 Got streaming response from agent: {type(response)}")
        
        # Extract readable content and tool calls from streaming response
        try:
            from llama_stack_client.lib.agents.event_logger import EventLogger
            
            response_content = ""
            tool_calls = []
            
            # Process the streaming response using EventLogger
            for log in EventLogger().log(response):
                # Extract content from the log events
                if hasattr(log, 'event') and log.event:
                    event = log.event
                    
                    # Handle different event types
                    if hasattr(event, 'delta') and hasattr(event.delta, 'content'):
                        # Streaming content delta
                        if event.delta.content:
                            response_content += event.delta.content
                    elif hasattr(event, 'content'):
                        # Complete content
                        if event.content:
                            response_content += event.content
                    elif hasattr(event, 'tool_call'):
                        # Tool call event
                        tool_call = event.tool_call
                        tool_calls.append({
                            "tool_name": tool_call.tool_name,
                            "arguments": str(tool_call.arguments)
                        })
                        logger.info(f"🔧 Found tool call: {tool_call.tool_name}")
                
                # Also check the log object itself for content
                if hasattr(log, 'content') and log.content:
                    response_content += log.content
            
            # If we didn't get content from streaming, try to extract from the final response
            if not response_content:
                logger.info("📝 No content from streaming, trying to extract from response object...")
                
                # Try to access response attributes directly
                if hasattr(response, 'output_message') and hasattr(response.output_message, 'content'):
                    response_content = response.output_message.content
                    logger.info(f"✅ Extracted content from response.output_message.content")
                elif hasattr(response, 'content'):
                    response_content = response.content
                    logger.info(f"✅ Extracted content from response.content")
                else:
                    # Fallback to string parsing
                    response_str = str(response)
                    logger.info(f"📝 Raw response string: {response_str[:200]}...")
                    
                    # Look for tool calls in the response string
                    import re
                    tool_call_matches = re.findall(r"ToolCall\(tool_name='([^']+)', arguments=({[^}]*}|\[[^\]]*\]|'[^']*'|\"[^\"]*\"|\w+)\)", response_str)
                    for tool_name, arguments in tool_call_matches:
                        tool_calls.append({
                            "tool_name": tool_name,
                            "arguments": arguments
                        })
                    
                    # Try to extract content from string
                    output_content_match = re.search(r"output_message=CompletionMessage\(content='([^']*)'", response_str)
                    if output_content_match:
                        response_content = output_content_match.group(1)
                        logger.info(f"✅ Extracted output message content from string")
                    else:
                        response_content = "Unable to extract response content"
                        logger.warning("⚠️ Could not extract response content")
            
            # Clean up the response content
            if response_content:
                # Handle escaped characters
                response_content = response_content.replace('\\n', '\n')
                response_content = response_content.replace('\\t', '\t')
                response_content = response_content.replace('\\"', '"')
                
            logger.info(f"✅ Final response content: {response_content[:100]}...")
            logger.info(f"🔧 Found {len(tool_calls)} tool calls")
            for i, tool_call in enumerate(tool_calls):
                logger.info(f"  Tool {i+1}: {tool_call['tool_name']} with args {tool_call['arguments'][:50]}...")
                
        except Exception as e:
            logger.error(f"❌ Error processing streaming response: {e}")
            import traceback
            traceback.print_exc()
            response_content = f"Response processing error: {str(e)}"
            tool_calls = []
        
        return {
            "success": True,
            "response": response_content,
            "tool_calls": tool_calls,
            "error_type": None
        }
        
    except Exception as e:
        error_message = str(e)
        logger.error(f"❌ Agent communication error: {error_message}")
        
        # Check if this is an authorization error
        if is_authorization_error(error_message):
            logger.info("🔐 Detected authorization error")
            error_details = extract_authorization_error_details(error_message)
            logger.info(f"📋 Error details: {error_details}")
            
            # Automatically request scope upgrade through auth server
            logger.info("🔄 Automatically requesting scope upgrade...")
            required_scope = error_details.get('required_scope', 'execute:commands')
            
            try:
                upgrade_result = asyncio.run(request_scope_upgrade(required_scope, bearer_token))
                
                if upgrade_result and not upgrade_result.get('error'):
                    status = upgrade_result.get('status')
                    logger.info(f"Scope upgrade result: {status}")
                    
                    if status == 'approved':
                        # Approved (either auto or admin) - update token and suggest retry
                        new_token = upgrade_result.get('new_token')
                        if new_token:
                            error_details['auto_approved'] = upgrade_result.get('auto_approved', False)
                            error_details['new_token'] = new_token
                            logger.info(f"✅ Scope approved - new token available (auto: {error_details['auto_approved']})")
                    
                    error_details['approval_requested'] = True
                    error_details['approval_status'] = status
                    
                    if status in ['pending_admin_approval', 'pending_user_approval']:
                        error_details['approval_request_id'] = upgrade_result.get('approval_request_id')
                        logger.info(f"⏳ Approval pending with request ID: {upgrade_result.get('approval_request_id')}")
                else:
                    logger.error(f"Scope upgrade failed: {upgrade_result}")
                    
            except Exception as e:
                logger.error(f"Failed to request scope upgrade: {e}")
            
            return {
                "success": False,
                "response": f"🔐 Authorization required for {error_details.get('tool_name', 'unknown tool')}",
                "error_type": "authorization_required",
                "error_details": error_details,
                "original_message": message,  # Store for retry
                "message_id": secrets.token_urlsafe(16)
            }
        else:
            # Check for common connection errors
            if "Connection refused" in error_message or "Failed to connect" in error_message:
                return {
                    "success": False,
                    "response": "❌ Cannot connect to Llama Stack server. Please check if it's running on port 8321.",
                    "error_type": "connection_error"
                }
            elif "timeout" in error_message.lower():
                return {
                    "success": False,
                    "response": "⏰ Request timed out. The server may be overloaded.",
                    "error_type": "timeout_error"
                }
            else:
                return {
                    "success": False,
                    "response": f"❌ Agent error: {error_message}",
                    "error_type": "general_error"
                }

def check_auth_server_session():
    """Check if user has valid session with auth server"""
    try:
        auth_session_cookie = request.cookies.get('auth_session')
        if not auth_session_cookie:
            return None
        
        # Verify session with auth server
        import httpx
        with httpx.Client() as client:
            response = client.get(
                f"{AUTH_SERVER_URL}/api/user-status", 
                cookies={'auth_session': auth_session_cookie},
                timeout=5.0
            )
            
            if response.status_code == 200:
                user_data = response.json()
                if user_data.get('authenticated'):
                    return user_data['user']
        
        return None
    except Exception as e:
        logger.error(f"Error checking auth server session: {e}")
        return None

def get_user_roles(email: str) -> list:
    """Get user roles from auth server or default roles"""
    # Default role mappings (same as auth server)
    USER_ROLES = {
        "gallettilance@gmail.com": ["admin"],
        "demo@example.com": ["developer"],
        "lgallett@redhat.com": ["user"],
    }
    return USER_ROLES.get(email, ["user"])

@app.route('/')
def index():
    """Main page - always check auth server session first"""
    logger.info(f"🏠 Index page accessed")
    
    # Always check auth server session first (this is the source of truth)
    auth_user = check_auth_server_session()
    
    if auth_user:
        # User is authenticated via auth server
        logger.info(f"✅ Found valid auth server session for {auth_user['email']}")
        
        # Check if we need to update local session
        current_user_email = session.get('user_email')
        if current_user_email != auth_user['email'] or not session.get('bearer_token'):
            # Set up/update local session for this user
            logger.info(f"🔄 Setting up local session for {auth_user['email']}")
            
            # Create JWT token for this user to use with MCP
            user_info = {
                'sub': auth_user['sub'],
                'email': auth_user['email'],
                'name': auth_user['email'].split('@')[0]  # Use email prefix as name
            }
            bearer_token = create_jwt_token(user_info)
            
            # Update local session (don't clear to preserve other data)
            session['authenticated'] = True
            session['bearer_token'] = bearer_token
            session['user_info'] = user_info
            session['user_name'] = user_info['name']
            session['user_email'] = user_info['email']
            session['auth_server_user'] = True
            session.permanent = True
            
            # Initialize agent
            initialize_agent(bearer_token)
        else:
            logger.info(f"✅ Local session already valid for {auth_user['email']}")
        
        # Get user roles for display
        user_email = session.get('user_email', '')
        user_roles = get_user_roles(user_email)
        is_admin = 'admin' in user_roles
        
        return render_template('chat.html', 
                             user_name=session.get('user_name', 'User'),
                             user_email=user_email,
                             user_roles=user_roles,
                             is_admin=is_admin)
    
    # No valid auth server session - clear local session and redirect to login
    logger.info("❌ No valid auth server session found")
    session.clear()
    return render_template('login.html')

@app.route('/login')
def login():
    """Redirect to auth server for login"""
    logger.info(f"🔐 Redirecting to auth server for login")
    return redirect(f"{AUTH_SERVER_URL}/auth/login")

@app.route('/callback')
def callback():
    """Legacy OAuth callback - redirect to auth server"""
    logger.info(f"🔍 Legacy callback hit - redirecting to auth server")
    return redirect(f"{AUTH_SERVER_URL}/auth/login")

@app.route('/logout')
def logout():
    """Logout and clear session"""
    user_email = session.get('user_email')
    
    # Clean up user agent before clearing session
    if user_email:
        cleanup_user_agent(user_email)
    
    # Clear local session first
    session.clear()
    global llama_client, user_agents
    
    # Only clear global client if no other users are active
    if not user_agents:
        llama_client = None
    
    # Redirect to auth server logout to clear auth server session
    return redirect(f"{AUTH_SERVER_URL}/auth/logout")

@app.route('/clear-session')
def clear_session():
    """Clear session for debugging OAuth issues"""
    session.clear()
    return "Session cleared. <a href='/'>Return to home</a>"

@app.route('/chat', methods=['POST'])
def chat():
    """Handle chat messages with streaming support"""
    try:
        # Always verify auth server session first
        auth_user = check_auth_server_session()
        if not auth_user:
            return jsonify({'error': 'Not authenticated - please login', 'success': False}), 401
        
        # Ensure local session is up to date
        if session.get('user_email') != auth_user['email'] or not session.get('bearer_token'):
            return jsonify({'error': 'Session mismatch - please refresh page', 'success': False}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data', 'success': False}), 400
            
        message = data.get('message', '').strip()
        
        if not message:
            return jsonify({'error': 'Empty message', 'success': False}), 400
        
        # Check if streaming is requested
        stream = data.get('stream', False)
        
        # User message will be automatically saved by Llama Stack session
        
        if stream:
            # Stream the response, but include special markers for authorization errors
            try:
                return Response(
                    stream_agent_response_with_auth_detection(
                        message, 
                        session['bearer_token'],
                        session.get('user_email', ''),
                        message
                    ),
                    mimetype='text/plain'
                )
            except Exception as e:
                error_message = str(e)
                logger.error(f"❌ Streaming failed: {error_message}")
                
                # Check if this is an authorization error and handle it properly
                if is_authorization_error(error_message):
                    logger.info("🔐 Detected authorization error in streaming")
                    error_details = extract_authorization_error_details(error_message)
                    
                    # Handle scope upgrade like in regular flow
                    required_scope = error_details.get('required_scope', 'execute:commands')
                    try:
                        upgrade_result = asyncio.run(request_scope_upgrade(required_scope, session['bearer_token']))
                        
                        if upgrade_result and not upgrade_result.get('error'):
                            status = upgrade_result.get('status')
                            if status == 'approved' and upgrade_result.get('auto_approved'):
                                new_token = upgrade_result.get('new_token')
                                if new_token:
                                    session['bearer_token'] = new_token
                                    error_details['auto_approved'] = True
                                    error_details['new_token'] = new_token
                            
                            error_details['approval_requested'] = True
                            error_details['approval_status'] = status
                    except Exception as upgrade_error:
                        logger.error(f"Failed to request scope upgrade: {upgrade_error}")
                    
                    # Store the pending message for retry
                    message_id = secrets.token_urlsafe(16)
                    pending_messages[message_id] = {
                        'message': message,
                        'user_email': session.get('user_email', ''),
                        'bearer_token': session['bearer_token'],
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Return structured authorization error response
                    return jsonify({
                        'response': f"🔐 Authorization required for {error_details.get('tool_name', 'unknown tool')}",
                        'user': session.get('user_name', 'User'),
                        'success': False,
                        'error_type': 'authorization_required',
                        'error_details': error_details,
                        'original_message': message,
                        'message_id': message_id
                    })
                else:
                    # Other streaming errors - return as regular error
                    return jsonify({
                        'error': f'Streaming error: {error_message}',
                        'success': False,
                        'error_type': 'streaming_error'
                    }), 500
        else:
            # Return traditional JSON response
            logger.info(f"💬 Processing message: {message}")
            
            # Send to agent
            result = send_message_to_agent(message, session['bearer_token'])
            
            if result['success']:
                # Assistant response automatically saved by Llama Stack session
                
                return jsonify({
                    'response': result['response'],
                    'tool_calls': result.get('tool_calls', []),
                    'user': session.get('user_name', 'User'),
                    'success': True
                })
            else:
                response_data = {
                    'response': result['response'],
                    'user': session.get('user_name', 'User'),
                    'success': False,
                    'error_type': result['error_type']
                }
                
                # If it's an authorization error, include additional details
                if result['error_type'] == 'authorization_required':
                    response_data['error_details'] = result['error_details']
                    response_data['original_message'] = result['original_message']
                    
                    # Check if scope was auto-approved
                    error_details = result['error_details']
                    if error_details.get('auto_approved') and error_details.get('new_token'):
                        # Update session with new token
                        session['bearer_token'] = error_details['new_token']
                        logger.info(f"🎫 Updated session token after auto-approval")
                        
                        # Mark as auto-approved for UI
                        response_data['auto_approved'] = True
                        response_data['message'] = "✅ Access automatically approved! You can retry your request now."
                    
                    # Store the pending message for potential retry
                    message_id = secrets.token_urlsafe(16)
                    pending_messages[message_id] = {
                        'message': result['original_message'],
                        'user_email': session.get('user_email', ''),
                        'bearer_token': session['bearer_token'],  # Use updated token if available
                        'timestamp': datetime.now().isoformat()
                    }
                    response_data['message_id'] = message_id
                
                # Error response automatically handled by Llama Stack session
                
                return jsonify(response_data)
    
    except Exception as e:
        logger.error(f"❌ Unexpected error in /chat endpoint: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': f'Server error: {str(e)}',
            'success': False,
            'error_type': 'server_error'
        }), 500

def stream_agent_response_with_auth_detection(message: str, bearer_token: str, user_email: str, original_message: str):
    """Stream agent response with special handling for authorization errors"""
    global llama_client, user_agents
    
    try:
        logger.info(f"🌊 Streaming message to agent: {message}")
        
        # Get or create user-specific agent
        agent, agent_session_id = get_or_create_user_agent(user_email, bearer_token)
        
        if not agent or not agent_session_id:
            logger.info("🔄 Agent not initialized, initializing...")
            if not initialize_agent(bearer_token):
                yield "❌ Failed to initialize agent. Please check if Llama Stack is running on port 8321.\n"
                return
        
        # Create the message
        user_message = UserMessage(content=message, role="user")
        
        # Send to agent with streaming enabled
        response = agent.create_turn(
            messages=[user_message],
            session_id=agent_session_id,
            stream=True,
            extra_headers={
                "X-LlamaStack-Provider-Data": json.dumps({
                    "mcp_headers": {
                        MCP_SERVER_URL: {
                            "Authorization": f"Bearer {bearer_token}",
                        },
                    },
                })
            }
        )
        
        # Process streaming response with authorization error detection
        from llama_stack_client.lib.agents.event_logger import EventLogger
        import re
        
        prev_role, ok = None, False
        full_content = ""
        tool_name = None
        tool_already_printed = {}
        inference = ""
        show_shield = False
        shield_buffer = ""
        
        # Track the complete response for saving to database
        complete_response = ""
        tool_calls = []
        has_auth_error = False
        
        for log in EventLogger().log(response):
            # Track all content for error detection
            if hasattr(log, 'content') and log.content:
                full_content += log.content
                
                # Check for authorization errors immediately when we see tool responses
                if log.role == "tool_execution" and "InsufficientScopeError" in log.content:
                    logger.warning(f"🔐 Authorization error detected in tool execution")
                    has_auth_error = True
                    
                    # Extract error details from the content
                    error_details = extract_authorization_error_details(log.content)
                    
                    # Store the pending message for retry
                    message_id = secrets.token_urlsafe(16)
                    pending_messages[message_id] = {
                        'message': message,
                        'user_email': user_email,
                        'bearer_token': bearer_token,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Request scope upgrade automatically
                    required_scope = error_details.get('required_scope', 'read:files')
                    try:
                        upgrade_result = asyncio.run(request_scope_upgrade(required_scope, bearer_token))
                        if upgrade_result and not upgrade_result.get('error'):
                            error_details['approval_requested'] = True
                            error_details['approval_status'] = upgrade_result.get('status')
                            
                            # Check if scope was auto-approved
                            if upgrade_result.get('status') == 'approved' and upgrade_result.get('auto_approved'):
                                new_token = upgrade_result.get('new_token')
                                if new_token:
                                    logger.info(f"🎫 Scope auto-approved, showing message and retrying")
                                    
                                    # Store the pending message for retry
                                    message_id = secrets.token_urlsafe(16)
                                    pending_messages[message_id] = {
                                        'message': message,
                                        'user_email': user_email,
                                        'bearer_token': new_token,  # Use the new token
                                        'timestamp': datetime.now().isoformat()
                                    }
                                    
                                                        # Auto-approval message will be handled by Llama Stack session
                                    
                                    # Emit auto-approval message that persists in chat
                                    auto_approval_json = json.dumps({
                                        'error_type': 'auto_approved',
                                        'tool_name': error_details.get('tool_name', 'unknown'),
                                        'required_scope': required_scope,
                                        'message_id': message_id,
                                        'new_token': new_token,
                                        'original_message': message,
                                        'auto_approved': True
                                    })
                                    yield f"__AUTH_ERROR_START__{auto_approval_json}__AUTH_ERROR_END__"
                                    return
                    except Exception as e:
                        logger.error(f"Failed to request scope upgrade: {e}")
                    
                    # Authorization error will be handled by Llama Stack session
                    
                    # Emit special authorization error marker that frontend can detect
                    auth_error_json = json.dumps({
                        'error_type': 'authorization_required',
                        'tool_name': error_details.get('tool_name', 'unknown'),
                        'required_scope': required_scope,
                        'message_id': message_id,
                        'approval_status': error_details.get('approval_status', 'pending'),
                        'original_message': message
                    })
                    yield f"__AUTH_ERROR_START__{auth_error_json}__AUTH_ERROR_END__"
                    return
            
                elif log.role == "tool_execution":
                    match = re.search(r"Tool:(\w+)", log.content)
                    if match:
                        tool_name = match.group(1)
                        if tool_name not in tool_already_printed:
                            tool_info = f"🛠 **Used Tool:** `{tool_name}`  \n"
                            yield tool_info
                            complete_response += tool_info
                            tool_calls.append(tool_name)
                            tool_already_printed[tool_name] = True

                elif log.role == "inference":
                    # Stream inference content as it arrives
                    if log.content:
                        yield log.content
                        complete_response += log.content

                elif log.role is None:
                    # Stream any other content
                    if log.content:
                        yield log.content
                        complete_response += log.content
        
        # Streaming response automatically saved by Llama Stack session
            
    except Exception as e:
        error_message = str(e)
        logger.error(f"❌ Streaming error: {error_message}")
        
        # Streaming error automatically handled by Llama Stack session
        
        yield f"❌ Error: {error_message}"

def stream_agent_response(message: str, bearer_token: str):
    """Stream agent response as it arrives"""
    global llama_client, user_agents
    
    try:
        logger.info(f"🌊 Streaming message to agent: {message}")
        
        # Get or create user-specific agent
        agent, agent_session_id = get_or_create_user_agent(session.get('user_email', 'anonymous'), bearer_token)
        
        if not agent or not agent_session_id:
            logger.info("🔄 Agent not initialized, initializing...")
            if not initialize_agent(bearer_token):
                yield "❌ Failed to initialize agent. Please check if Llama Stack is running on port 8321.\n"
                return
        
        # Create the message
        user_message = UserMessage(content=message, role="user")
        
        # Send to agent with streaming enabled
        response = agent.create_turn(
            messages=[user_message],
            session_id=agent_session_id,
            stream=True,
            extra_headers={
                "X-LlamaStack-Provider-Data": json.dumps({
                    "mcp_headers": {
                        MCP_SERVER_URL: {
                            "Authorization": f"Bearer {bearer_token}",
                        },
                    },
                })
            }
        )
        
        # Process streaming response with improved tool handling
        from llama_stack_client.lib.agents.event_logger import EventLogger
        import re
        
        prev_role, ok = None, False
        full_content = ""  # Track full content for error detection
        
        for log in EventLogger().log(response):
            # Log the event for debugging
            logger.debug(f"EventLogger: role={getattr(log, 'role', 'unknown')}, content={getattr(log, 'content', '')[:100]}...")
            
            # Track all content for error detection
            if hasattr(log, 'content') and log.content:
                full_content += log.content
                
                # Check for authorization errors immediately when we see tool responses
                if log.role == "tool_execution" and "InsufficientScopeError" in log.content:
                    logger.warning(f"🔐 Authorization error detected in tool execution: {log.content[:200]}...")
                    # Raise exception immediately to prevent streaming
                    raise Exception(full_content)
            
            if ok:
                # Stream the inference content
                yield log.content
            elif prev_role is None and log.role == "tool_execution":
                # Tool execution started
                yield "🛠 **Used Tool:** "
                match = re.search(r"Tool:(\w+)", log.content)
                if match:
                    tool_name = match.group(1)
                    yield f"`{tool_name}`"
                yield "  \n"
                prev_role = log.role
            elif prev_role == 'tool_execution' and log.role == "inference":
                # Switch to inference output - but check for auth errors first
                if is_authorization_error(log.content):
                    logger.warning(f"🔐 Authorization error detected in inference content: {log.content[:200]}...")
                    raise Exception(full_content)
                    
                ok = True
                prev_role = log.role
                yield log.content
        
        # Check if we got authorization errors in the final content (fallback)
        if is_authorization_error(full_content):
            logger.warning(f"🔐 Authorization error detected in final streaming content: {full_content[:200]}...")
            # Raise exception to trigger the try/catch in the calling function
            raise Exception(full_content)
                
    except Exception as e:
        error_message = str(e)
        logger.error(f"❌ Streaming error: {error_message}")
        
        # Re-raise the exception so the calling function can handle authorization errors properly
        raise e

@app.route('/request-approval', methods=['POST'])
def request_approval():
    """Request scope upgrade through the auth server"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    tool_name = data.get('tool_name', '')
    required_scope = data.get('required_scope', 'execute:commands')
    
    if not required_scope:
        return jsonify({'error': 'Required scope not specified'}), 400
    
    # Use the auth server's upgrade-scope endpoint
    upgrade_result = asyncio.run(request_scope_upgrade(required_scope, session['bearer_token']))
    
    if 'error' in upgrade_result:
        return jsonify({'error': upgrade_result['error']}), 500
    
    status = upgrade_result.get('status')
    
    if status == 'approved' and upgrade_result.get('auto_approved'):
        # Auto-approved - update the user's token
        new_token = upgrade_result.get('new_token')
        if new_token:
            session['bearer_token'] = new_token
            logger.info(f"🎫 Updated bearer token after auto-approval")
    
        return jsonify({
            'success': True,
            'status': 'approved',
            'auto_approved': True,
            'message': f'Access to {tool_name} has been automatically approved. You can retry your request.',
            'approval_url': f"{AUTH_SERVER_URL}/admin"
        })
    
    elif status in ['pending_admin_approval', 'pending_user_approval']:
        approval_type = upgrade_result.get('approval_type', 'admin')
        dashboard_url = upgrade_result.get('approval_dashboard_url', f"{AUTH_SERVER_URL}/admin")
        consent_url = upgrade_result.get('consent_url')
        
        response_data = {
            'success': True,
            'status': status,
            'approval_type': approval_type,
            'message': upgrade_result.get('message', 'Approval required'),
            'approval_url': dashboard_url
        }
        
        if consent_url:
            response_data['consent_url'] = consent_url
            
        return jsonify(response_data)
    
    else:
        return jsonify({
            'success': False,
            'error': f'Unexpected upgrade status: {status}',
            'message': upgrade_result.get('message', 'Unknown error occurred')
        })

@app.route('/check-approval/<request_id>')
def check_approval(request_id: str):
    """Check the status of an approval request"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    status_result = asyncio.run(check_approval_status(request_id))
    
    if 'error' in status_result:
        return jsonify({'error': status_result['error']}), 500
    
    return jsonify(status_result)

@app.route('/retry-message', methods=['POST'])
def retry_message():
    """Retry a message after approval has been granted"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    message_id = data.get('message_id', '')
    required_scope = data.get('required_scope', 'read:files')
    
    if not message_id or message_id not in pending_messages:
        return jsonify({'error': 'Invalid or expired message ID'}), 400
    
    pending_data = pending_messages[message_id]
    
    logger.info(f"🔄 Retrying message after admin approval, requesting new token with scope: {required_scope}")
    
    # Request a new token with the approved scope from the auth server
    try:
        upgrade_result = asyncio.run(request_scope_upgrade(required_scope, session['bearer_token']))
        
        if upgrade_result and not upgrade_result.get('error'):
            status = upgrade_result.get('status')
            
            if status == 'approved':
                # Get the new token with approved scopes
                new_token = upgrade_result.get('new_token')
                if new_token:
                    # Update session with the new token
                    session['bearer_token'] = new_token
                    logger.info(f"🎫 Updated session token after admin approval: {new_token[:20]}...")
                    
                    # Retry the original message with the new token
                    result = send_message_to_agent(pending_data['message'], new_token)
                    
                    # Clean up the pending message
                    del pending_messages[message_id]
                    
                    if result['success']:
                        # Retry result automatically saved by Llama Stack session
                        
                        return jsonify({
                            'response': result['response'],
                            'user': session.get('user_name', 'User'),
                            'success': True,
                            'retried': True,
                            'token_updated': True
                        })
                    else:
                        # Retry failure automatically handled by Llama Stack session
                        
                        return jsonify({
                            'response': result['response'],
                            'user': session.get('user_name', 'User'),
                            'success': False,
                            'error_type': result['error_type'],
                            'retried': True,
                            'token_updated': True
                        })
                else:
                    logger.error("No new token received from auth server")
                    return jsonify({'error': 'Failed to get updated token from auth server'}), 500
            else:
                logger.error(f"Scope upgrade not approved, status: {status}")
                return jsonify({'error': f'Scope upgrade not approved: {status}'}), 403
        else:
            error_msg = upgrade_result.get('error', 'Unknown error') if upgrade_result else 'No response from auth server'
            logger.error(f"Failed to upgrade scope: {error_msg}")
            return jsonify({'error': f'Failed to upgrade scope: {error_msg}'}), 500
            
    except Exception as e:
        logger.error(f"Error during token upgrade for retry: {e}")
        return jsonify({'error': f'Token upgrade failed: {str(e)}'}), 500

@app.route('/update-token', methods=['POST'])
def update_token():
    """Update the session token after auto-approval"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    new_token = data.get('new_token')
    
    if not new_token:
        return jsonify({'error': 'No token provided'}), 400
    
    # Update the session token
    session['bearer_token'] = new_token
    logger.info(f"🎫 Session token updated via /update-token endpoint")
    
    return jsonify({'success': True, 'message': 'Token updated successfully'})

@app.route('/auto-retry', methods=['POST'])
def auto_retry():
    """Auto-retry a message with updated permissions (for frontend auto-retry)"""
    if 'authenticated' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    original_message = data.get('original_message', '')
    
    if not original_message:
        return jsonify({'error': 'No message provided'}), 400
    
    logger.info(f"🔄 Auto-retrying message with updated token: {original_message[:50]}...")
    
    try:
        # Send to agent with current (updated) token
        result = send_message_to_agent(original_message, session['bearer_token'])
        
        if result['success']:
            # Auto-retry result automatically saved by Llama Stack session
            
            return jsonify({
                'response': result['response'],
                'user': session.get('user_name', 'User'),
                'success': True,
                'auto_retried': True,
                'tool_calls': result.get('tool_calls', [])
            })
        else:
            # Auto-retry failure automatically handled by Llama Stack session
            
            return jsonify({
                'response': result['response'],
                'user': session.get('user_name', 'User'),
                'success': False,
                'error_type': result['error_type'],
                'auto_retried': True
            })
            
    except Exception as e:
        logger.error(f"Error during auto-retry: {e}")
        return jsonify({'error': f'Auto-retry failed: {str(e)}'}), 500

@app.route('/api/chat-history')
def get_chat_history_api():
    """Get chat history from Llama Stack session"""
    try:
        # Check if user is authenticated
        user_email = session.get('user_email')
        if not user_email:
            return jsonify({"error": "Not authenticated"}), 401
        
        global llama_client, user_agents
        
        # Check if we have an active agent session
        if not llama_client or not user_agents.get(user_email):
            logger.info("No active agent session found")
            return jsonify({
                "status": "success",
                "messages": [],
                "count": 0
            })
        
        try:
            # Retrieve session from Llama Stack's kvstore database directly
            user_data = user_agents.get(user_email)
            if not user_data:
                return jsonify({
                    "status": "success",
                    "messages": [],
                    "count": 0
                })
            
            agent = user_data['agent']
            session_id = user_data['session_id']
            
            # Query kvstore.db directly for turn data
            import sqlite3
            import json
            import os
            
            try:
                # Connect to Llama Stack's kvstore database (use absolute path)
                db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'kvstore.db')
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Find all turn keys for this session
                session_pattern = f"session:{agent.agent_id}:{session_id}:%"
                cursor.execute("""
                    SELECT key, value FROM kvstore 
                    WHERE key LIKE ? AND key NOT LIKE '%num_infer_iters_in_turn%'
                """, (session_pattern,))
                
                turn_data = cursor.fetchall()
                conn.close()
                
                # Convert turn data to our message format and collect with timestamps for sorting
                turns_with_timestamps = []
                
                for key, value_str in turn_data:
                    try:
                        turn_json = json.loads(value_str)
                        # Get the earliest timestamp from steps for sorting
                        earliest_timestamp = None
                        steps = turn_json.get('steps', [])
                        for step in steps:
                            if step.get('started_at'):
                                if not earliest_timestamp or step.get('started_at') < earliest_timestamp:
                                    earliest_timestamp = step.get('started_at')
                        
                        turns_with_timestamps.append({
                            'key': key,
                            'turn_json': turn_json,
                            'timestamp': earliest_timestamp or '1900-01-01T00:00:00Z'  # Fallback for sorting
                        })
                    except Exception as parse_error:
                        logger.warning(f"Failed to parse turn data from key {key}: {parse_error}")
                        continue
                
                # Sort turns by timestamp (oldest first)
                turns_with_timestamps.sort(key=lambda x: x['timestamp'])
                
                # Convert sorted turns to message format
                messages = []
                
                for turn_data in turns_with_timestamps:
                    turn_json = turn_data['turn_json']
                    try:
                        turn_id = turn_json.get('turn_id', 'unknown')
                        
                        # Add user messages
                        input_messages = turn_json.get('input_messages', [])
                        for input_msg in input_messages:
                            content = input_msg.get('content', '')
                            
                            messages.append({
                                'id': f"turn_{turn_id}_input",
                                'type': 'user',
                                'content': content,
                                'timestamp': None,  # Input messages don't have timestamps in kvstore
                                'metadata': {}
                            })
                        
                        # Add assistant response from steps
                        steps = turn_json.get('steps', [])
                        assistant_content = ""
                        tool_calls_info = []
                        latest_timestamp = None
                        
                        for step in steps:
                            # Get timestamp from step
                            if step.get('completed_at'):
                                latest_timestamp = step.get('completed_at')
                            
                            # Check for model response
                            model_response = step.get('model_response', {})
                            if model_response:
                                # Get content from model response
                                step_content = model_response.get('content', '')
                                if step_content:
                                    assistant_content += step_content
                                
                                # Get tool calls from model response
                                tool_calls = model_response.get('tool_calls', [])
                                for tool_call in tool_calls:
                                    tool_call_info = {
                                        'tool_name': tool_call.get('tool_name', 'unknown'),
                                        'arguments': tool_call.get('arguments', {}),
                                        'call_id': tool_call.get('call_id')
                                    }
                                    tool_calls_info.append(tool_call_info)
                            
                            # Check for tool response content
                            tool_response = step.get('tool_response')
                            if tool_response and isinstance(tool_response, dict):
                                tool_content = tool_response.get('content', '')
                                if tool_content and isinstance(tool_content, str):
                                    assistant_content += f"\n{tool_content}"
                        
                        # Add assistant message if we have content
                        if assistant_content or tool_calls_info:
                            messages.append({
                                'id': f"turn_{turn_id}_output",
                                'type': 'assistant',
                                'content': assistant_content.strip(),
                                'timestamp': latest_timestamp,
                                'metadata': {
                                    'tool_calls': tool_calls_info
                                }
                            })
                            
                    except Exception as turn_error:
                        logger.warning(f"Failed to process turn data from key {turn_data['key']}: {turn_error}")
                        continue
                
                return jsonify({
                    "status": "success",
                    "messages": messages,
                    "count": len(messages)
                })
                
            except Exception as db_error:
                logger.error(f"Failed to query kvstore database: {db_error}")
                return jsonify({
                    "status": "success",
                    "messages": [],
                    "count": 0
                })
            
        except Exception as e:
            logger.error(f"Failed to retrieve session from Llama Stack: {e}")
            return jsonify({
                "status": "success",
                "messages": [],
                "count": 0
            })
        
    except Exception as e:
        logger.error(f"Error retrieving chat history: {e}")
        return jsonify({"error": "Failed to retrieve chat history"}), 500

@app.route('/api/clear-chat-history', methods=['POST'])
def clear_chat_history_api():
    """Clear chat history by creating a new Llama Stack session"""
    try:
        # Check if user is authenticated
        user_email = session.get('user_email')
        if not user_email:
            return jsonify({"error": "Not authenticated"}), 401
        
        global llama_client, user_agents
        
        # Get user's current agent or create one
        bearer_token = session.get('bearer_token')
        if not bearer_token:
            return jsonify({"error": "No bearer token found"}), 401
        
        agent, current_session_id = get_or_create_user_agent(user_email, bearer_token)
        if not agent:
            return jsonify({"error": "Failed to get user agent"}), 500
        
        # Create a new session to effectively "clear" history
        try:
            # Create new session with user-specific name
            session_name = f"chat-{user_email}-{int(time.time())}"
            new_session_id = agent.create_session(session_name)
            
            # Update the user's agent data with new session ID
            user_agents[user_email]['session_id'] = new_session_id
            
            # Update the Flask session with new session ID
            session['llama_session_id'] = new_session_id
            
            logger.info(f"🗑️ Created new session for {user_email}: {new_session_id}")
            
            return jsonify({
                "status": "success",
                "message": "Chat history cleared - new session created",
                "new_session_id": new_session_id
            })
            
        except Exception as e:
            logger.error(f"Failed to create new session: {e}")
            return jsonify({"error": "Failed to clear chat history"}), 500
        
    except Exception as e:
        logger.error(f"Error clearing chat history: {e}")
        return jsonify({"error": f"Failed to clear chat history: {str(e)}"}), 500


@app.route('/api/check-token-update')
def check_token_update_api():
    """Check if there's an updated token available from the auth server"""
    try:
        # Check if user is authenticated
        if 'authenticated' not in session or not session.get('bearer_token'):
            return jsonify({"error": "Not authenticated"}), 401
        
        # Call auth server to check for token updates
        headers = {
            "Authorization": f"Bearer {session['bearer_token']}",
            "Content-Type": "application/json"
        }
        
        response = httpx.get(f"{AUTH_SERVER_URL}/api/check-token-update", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            logger.info(f"🔍 Token update check response for {session.get('user_email')}: {data}")
            
            if data.get('token_updated'):
                # Update session with new token
                new_token = data.get('new_token')
                if new_token:
                    session['bearer_token'] = new_token
                    logger.info(f"🎫 Updated chat app token after admin approval for {session.get('user_email')}")
                    logger.info(f"🔄 New scopes: {data.get('new_scopes', [])}")
                    
                    return jsonify({
                        "token_updated": True,
                        "new_scopes": list(data.get('new_scopes', [])),
                        "previous_scopes": list(data.get('previous_scopes', [])),
                        "message": "Token updated with new scopes"
                    })
            
            logger.info(f"✅ Token already up to date for {session.get('user_email')}")
            return jsonify({
                "token_updated": False,
                "current_scopes": data.get('current_scopes', []),
                "message": "Token is up to date"
            })
        else:
            logger.error(f"Failed to check token update: {response.status_code} - {response.text}")
            return jsonify({"error": "Failed to check token update"}), 500
            
    except Exception as e:
        logger.error(f"Error checking token update: {e}")
        return jsonify({"error": "Failed to check token update"}), 500

def cleanup_on_shutdown():
    """Clean up resources when the app shuts down."""
    logger.info("🧹 Cleaning up chat app resources...")
    try:
        # Llama Stack handles its own database cleanup
        logger.info("Chat app cleanup completed (using Llama Stack storage)")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

def signal_handler(signum, frame):
    """Handle shutdown signals."""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    cleanup_on_shutdown()
    sys.exit(0)

# Register cleanup functions
atexit.register(cleanup_on_shutdown)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == '__main__':
    try:
        logger.info("🚀 Starting chat app...")
        app.run(debug=True, port=5001)
    except KeyboardInterrupt:
        logger.info("Chat app interrupted by user")
    finally:
        cleanup_on_shutdown() 