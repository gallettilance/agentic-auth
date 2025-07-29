"""
Llama Stack agent management utilities
Handles agent creation, session management, and communication.
"""

from llama_stack_client import LlamaStackClient
from llama_stack_client.types import UserMessage
from llama_stack_client.lib.agents.agent import Agent
from llama_stack_client.types.auth_types import OAuth2Config
from httpx import Client
from flask import session
import logging
import time
import json
import os
import asyncio
from utils.mcp_tokens_utils import get_mcp_tokens_for_user_direct
from typing import Optional

logger = logging.getLogger(__name__)

# Configuration
LLAMA_STACK_URL = os.getenv("LLAMA_STACK_URL", "http://localhost:8321")
OIDC_ISSUER_URL = os.getenv("OIDC_ISSUER_URL", "http://localhost:8002/realms/authentication-demo")
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "authentication-demo")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET")

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
user_agents = {}  # Dictionary to store per-user agents: {user_email: {'agent': agent, 'created_at': timestamp}}

# Global cache for user sessions - simplified to store only session IDs per user
user_sessions = {}  # {user_email: session_id}

# Global token cache to track updated tokens from LlamaStackClient
llama_stack_tokens = {}  # {user_email: current_token}

def update_llama_stack_token(user_email: str, token: str):
    """Update the Llama Stack token cache for a user"""
    global llama_stack_tokens
    llama_stack_tokens[user_email] = token
    logger.info(f"🔄 Updated Llama Stack token cache for {user_email}")
    
    # Also try to update Flask session if in request context
    try:
        from flask import session
        session['llama_stack_token'] = token
        logger.info(f"🔄 Updated Flask session with Llama Stack token for {user_email}")
    except RuntimeError:
        # Not in request context, skip session update
        logger.info(f"🔄 Llama Stack token updated (not in request context)")

def get_current_llama_stack_token(user_email: str) -> Optional[str]:
    """Get the current Llama Stack token for a user"""
    global llama_stack_tokens
    token = llama_stack_tokens.get(user_email)
    
    logger.debug(f"🔍 get_current_llama_stack_token for {user_email}: type={type(token)}, value={token}")
    
    if token:
        logger.debug(f"🔍 Retrieved Llama Stack token from cache for {user_email}: {token[:20]}...")
    else:
        logger.debug(f"🔍 No Llama Stack token in cache for {user_email}")
    
    return token

def capture_llama_stack_token_update(user_email: str, llama_client):
    """Attempt to capture the current token from LlamaStackClient after potential exchange"""
    try:
        # Use the inspect_current_token() method
        if hasattr(llama_client, 'inspect_current_token'):
            try:
                token_info = llama_client.inspect_current_token()
                logger.info(f"🔍 Captured token info via inspect_current_token() for {user_email}")
                logger.debug(f"🔍 inspect_current_token() returned: type={type(token_info)}, value={token_info}")
                
                if token_info and isinstance(token_info, dict):
                    # Extract the actual token from the dictionary
                    current_token = token_info.get('current_token')
                    logger.debug(f"🔍 Extracted current_token: type={type(current_token)}, value={current_token}")
                    
                    if current_token and isinstance(current_token, str):
                        update_llama_stack_token(user_email, current_token)
                        logger.info(f"✅ Successfully captured Llama Stack token for {user_email}")
                        return True
                    else:
                        logger.warning(f"⚠️ No valid current_token in token_info: {current_token}")
                        return False
                else:
                    logger.warning(f"⚠️ inspect_current_token() returned invalid format: {type(token_info)}")
                    return False
            except Exception as e:
                logger.warning(f"inspect_current_token() failed for {user_email}: {e}")
                return False
        else:
            logger.warning(f"LlamaStackClient has no inspect_current_token() method for {user_email}")
            return False
            
    except Exception as e:
        logger.warning(f"Error capturing LlamaStackClient token for {user_email}: {e}")
        return False

def get_or_create_user_agent(user_email: str, bearer_token: str):
    """Get or create a user-specific Llama Stack agent with per-user isolation"""
    global llama_client, user_agents
    
    try:
        # Initialize Llama Stack client if not already done or if we need to update the token
        if not llama_client or (bearer_token and bearer_token != "NO_TOKEN_YET"):
            # Use the bearer token for Llama Stack authentication
            api_key = bearer_token if bearer_token and bearer_token != "NO_TOKEN_YET" else None
            
            # Configure OAuth2 settings for token exchange
            oauth2_config = None
            if OIDC_CLIENT_SECRET:
                oauth2_config = OAuth2Config(
                    token_endpoint=f"{OIDC_ISSUER_URL}/protocol/openid-connect/token",
                    client_id=OIDC_CLIENT_ID,
                    client_secret=OIDC_CLIENT_SECRET,
                    realm="authentication-demo"
                )
                logger.info(f"🔧 OAuth2 configuration available for token exchange")
            
            llama_client = LlamaStackClient(
                base_url=LLAMA_STACK_URL,
                api_key=api_key,
                http_client=Client(verify=False),
                oauth2_config=oauth2_config,
            )
            
            # Note: LlamaStackClient handles its own token exchange
            # The session will be updated when the client performs token exchange
            logger.info(f"✅ Initialized Llama Stack client with authentication: {'Yes' if api_key else 'No'}")
            if OIDC_CLIENT_SECRET:
                logger.info(f"🔧 OAuth2 configuration available for future token exchange")
        
        # Check if user already has an agent in memory
        if user_email in user_agents:
            user_data = user_agents[user_email]
            agent = user_data['agent']
            llama_client = user_data.get('client')
            logger.info(f"🔄 Reusing existing agent for {user_email}")
            
            # Capture any token updates from the existing client
            if llama_client:
                logger.info(f"🔄 Capturing Llama Stack token from existing agent for {user_email}")
                capture_llama_stack_token_update(user_email, llama_client)
            
            # MCP tokens will be generated on-demand when tools require them
            logger.info(f"🎫 MCP tokens will be generated on-demand when tools require them")
            
            return agent
        
        # Get available models
        # TODO: When cache refresh is available, use @with_cache_refresh decorator
        # to handle JWKS key ID issues automatically
        models = llama_client.models.list()
        if not models:
            logger.error("❌ No models available")
            return None
        
        # Capture any token updates that may have occurred during the API call
        capture_llama_stack_token_update(user_email, llama_client)
        
        model_id = models[0].identifier
        logger.info(f"🤖 Using model: {model_id}")
        
        # Create new agent for this user
        agent = Agent(
            client=llama_client,
            tools=["mcp::mcp-auth"],  # MCP tool group from run.yml
            model=model_id,
            instructions=AGENT_SYSTEM_PROMPT,
            enable_session_persistence=True,
        )
        
        # Store user agent for reuse
        user_agents[user_email] = {
            'agent': agent,
            'client': llama_client,  # Store the client reference for token queries
            'created_at': time.time()
        }
        
        # Capture any token updates after agent creation
        logger.info(f"🔄 Capturing Llama Stack token after agent creation for {user_email}")
        capture_llama_stack_token_update(user_email, llama_client)
        
        logger.info(f"✅ Created new agent for {user_email}")
        
        # MCP tokens will be generated on-demand when needed by tools
        logger.info(f"🎫 MCP tokens will be generated on-demand when tools require them")
        
        # Log token status
        if bearer_token and bearer_token != "NO_TOKEN_YET":
            logger.info(f"✅ Agent ready for {user_email} with Llama Stack token")
        else:
            logger.info(f"✅ Agent ready for {user_email} - no token yet (will be created on-demand)")
            
        return agent
        
    except Exception as e:
        logger.error(f"❌ Failed to get/create agent for {user_email}: {e}")
        import traceback
        traceback.print_exc()
        return None

def get_or_create_session_for_user(user_email: str, bearer_token: str, conversation_id: str | None = None):
    """Get or create a session for a user's conversation - optimized version"""
    
    try:
        logger.info(f"🔄 get_or_create_session_for_user called for {user_email}")
        
        # Get the user's agent
        agent = get_or_create_user_agent(user_email, bearer_token)
        if not agent:
            logger.error(f"❌ Failed to get agent for {user_email}")
            return None, None
        
        # For now, we only support one session per user (conversation_id is ignored)
        # This simplifies the session management significantly
        existing_session_id = user_sessions.get(user_email)
        
        if existing_session_id:
            logger.info(f"🔍 Found cached session ID for {user_email}: {existing_session_id}")
            
            # Capture any token updates when reusing existing session
            if user_email in user_agents:
                user_data = user_agents[user_email]
                llama_client = user_data.get('client')
                if llama_client:
                    logger.info(f"🔄 Capturing Llama Stack token when reusing session for {user_email}")
                    capture_llama_stack_token_update(user_email, llama_client)
            
            return agent, existing_session_id
        
        # Try to get session ID from Flask session if in request context
        try:
            existing_session_id = session.get('llama_session_id')
            if existing_session_id:
                logger.info(f"🔍 Found Flask session ID for {user_email}: {existing_session_id}")
                # Store in cache for future use
                user_sessions[user_email] = existing_session_id
                return agent, existing_session_id
        except RuntimeError:
            # Not in request context, skip Flask session access
            logger.info(f"🔄 Not in request context, will create new session")
        
        # Create new session
        session_name = f"chat-{user_email}-{int(time.time())}"
        logger.info(f"🔄 Creating new session with name: {session_name}")
        
        session_id = agent.create_session(session_name)
        
        if not session_id:
            logger.error(f"❌ Failed to create session for {user_email}")
            return None, None
        
        logger.info(f"✅ Created new session ID: {session_id}")
        
        # Store session ID in cache
        user_sessions[user_email] = session_id
        logger.info(f"✅ Stored session ID in cache: {session_id}")
        
        # Store in Flask session if in request context
        try:
            session['llama_session_id'] = session_id
            session.permanent = True  # Make session persistent
            logger.info(f"✅ Stored session ID in Flask session: {session_id}")
        except RuntimeError:
            logger.info(f"🔄 Not in request context, session ID stored in cache only")
        
        # Capture any token updates after session creation
        if user_email in user_agents:
            user_data = user_agents[user_email]
            llama_client = user_data.get('client')
            if llama_client:
                logger.info(f"🔄 Capturing Llama Stack token after session creation for {user_email}")
                capture_llama_stack_token_update(user_email, llama_client)
        
        logger.info(f"✅ Created new session for {user_email}: {session_id}")
        return agent, session_id
        
    except Exception as e:
        logger.error(f"❌ Failed to get/create session for {user_email}: {e}")
        import traceback
        traceback.print_exc()
        return None, None

def clear_user_session(user_email: str):
    """Clear a user's session from both cache and Flask session"""
    try:
        # Remove from session cache
        if user_email in user_sessions:
            del user_sessions[user_email]
            logger.info(f"🗑️ Removed session from cache for {user_email}")
        
        # Clear from Flask session if in request context
        try:
            if 'llama_session_id' in session:
                del session['llama_session_id']
                logger.info(f"🗑️ Cleared llama_session_id from Flask session")
        except RuntimeError:
            # Not in request context, cache clearing is sufficient
            logger.info(f"🔄 Not in request context, cleared cache only")
            
    except Exception as e:
        logger.error(f"❌ Error clearing session for {user_email}: {e}")

def send_message_to_llama_stack(message: str, bearer_token: str, user_email: str, mcp_token: Optional[str] = None) -> dict:
    """Send message to the user's specific Llama Stack agent"""
    
    try:
        logger.info(f"🤖 Sending message to agent for {user_email}: {message}")
        
        # Get or create user-specific agent
        agent, agent_session_id = get_or_create_session_for_user(user_email, bearer_token)
        
        if not agent or not agent_session_id:
            return {
                "success": False,
                "response": "❌ Failed to initialize agent. Please check if Llama Stack is running on port 8321.",
                "error_type": "initialization_error"
            }
        
        # Create the message
        user_message = UserMessage(content=message, role="user")
        logger.info(f"📤 Created user message for {user_email}: {user_message}")
        
        # Get MCP token from Flask session if not provided
        if not mcp_token:
            try:
                from flask import session
                mcp_token = session.get('mcp_token')
                if mcp_token:
                    logger.info(f"🔐 Using MCP token from session for {user_email}")
                else:
                    logger.info(f"🔍 No MCP token in session for {user_email}")
            except RuntimeError:
                # Not in request context
                logger.info("🔍 Not in request context, using provided tokens")
        
        # Prepare extra headers for agent with MCP authentication
        extra_headers = {}
        if mcp_token:
            # Build MCP headers for Llama Stack
            mcp_headers = {}
            if mcp_token and mcp_token != "NO_TOKEN_YET":
                mcp_headers["http://localhost:8001/sse"] = {
                    "Authorization": f"Bearer {mcp_token}"
                }
                logger.info(f"🔐 Added MCP header for http://localhost:8001/sse: Bearer {mcp_token[:20]}...")
            
            if mcp_headers:
                extra_headers["X-LlamaStack-Provider-Data"] = json.dumps({
                    "mcp_headers": mcp_headers
                })
                logger.info(f"🔐 Configured MCP headers for {len(mcp_headers)} servers")
        
        # Create the turn and get streaming response
        response = agent.create_turn(
            messages=[user_message],
            session_id=agent_session_id,
            stream=True,
            extra_headers=extra_headers
        )
        
        # Capture any token updates after create_turn ends
        if user_email in user_agents:
            user_data = user_agents[user_email]
            llama_client = user_data.get('client')
            if llama_client:
                logger.info(f"🔄 Capturing Llama Stack token after create_turn for {user_email}")
                capture_llama_stack_token_update(user_email, llama_client)
        
        # Process the streaming response with simple iteration
        response_content = ""
        
        try:
            # Iterate through the streaming response 
            for chunk in response:
                # Try to extract content from various possible attributes
                chunk_text = ""
                
                # Use getattr with defaults to safely access attributes
                if hasattr(chunk, 'event'):
                    event = getattr(chunk, 'event', None)
                    if event:
                        # Try different content attributes on the event
                        chunk_text = (getattr(event, 'text', '') or 
                                    getattr(event, 'content', '') or 
                                    str(getattr(getattr(event, 'delta', None), 'text', '') or ''))
                
                # Try direct attributes on chunk
                if not chunk_text:
                    chunk_text = (getattr(chunk, 'text', '') or 
                                getattr(chunk, 'content', '') or
                                str(getattr(getattr(chunk, 'delta', None), 'text', '') or ''))
                
                if chunk_text:
                    response_content += str(chunk_text)
                        
        except Exception as stream_error:
            logger.warning(f"⚠️ Error processing streaming response: {stream_error}")
            # Fallback: try to get content from the response object itself
            response_content = str(getattr(response, 'content', getattr(response, 'text', 'Received response but could not extract content')))
        
        # Clean up the response content
        if response_content:
            # Handle escaped characters
            response_content = response_content.replace('\\n', '\n')
            response_content = response_content.replace('\\t', '\t')
            response_content = response_content.replace('\\"', '"')
        
        if not response_content:
            response_content = "Response received but no content available"
        
        logger.info(f"✅ Agent response for {user_email}: {response_content[:100]}...")
        
        # Capture any token updates that may have occurred during the API call
        if user_email in user_agents:
            user_data = user_agents[user_email]
            llama_client = user_data.get('client')
            if llama_client:
                logger.info(f"🔄 Capturing Llama Stack token after API call for {user_email}")
                capture_llama_stack_token_update(user_email, llama_client)
        
        return {
            "success": True,
            "response": response_content
        }
        
    except Exception as e:
        error_message = str(e)
        logger.error(f"❌ Error sending message to agent for {user_email}: {error_message}")
        
        # Check for MCP authorization errors
        if "Authorization required" in error_message or "insufficient scope" in error_message.lower():
            return {
                "success": False,
                "response": f"🔐 MCP Authorization Error: {error_message}",
                "error_type": "mcp_authorization_error",
                "requires_scope_upgrade": True
            }
        
        # Check for Llama Stack authorization errors
        if "llama" in error_message.lower() and ("authorization" in error_message.lower() or "scope" in error_message.lower()):
            # Use the auth utils to parse the error details
            from utils.auth_utils import extract_authorization_error_details
            error_details = extract_authorization_error_details(error_message)
            
            tool_name = error_details.get('tool_name', 'llama_stack_api')
            required_scope = error_details.get('required_scope', 'llama:agent_create')
            llama_scopes = error_details.get('llama_scopes', [required_scope])
            
            logger.info(f"🔍 Llama Stack scope error details: tool_name={tool_name}, required_scope={required_scope}, llama_scopes={llama_scopes}")
            
            return {
                "success": False,
                "response": f"🔐 Llama Stack Authorization Error: {error_message}",
                "error_type": "llama_authorization_error",
                "requires_scope_upgrade": True,
                "error_details": error_details,
                "tool_name": tool_name,
                "required_scope": required_scope,
                "llama_scopes": llama_scopes
            }
        
        return {
            "success": False,
            "response": f"Error: {error_message}",
            "error_type": "agent_error"
        } 