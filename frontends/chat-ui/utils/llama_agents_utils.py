"""
Llama Stack agent management utilities
Handles agent creation, session management, and communication.
"""

from llama_stack_client import LlamaStackClient
from llama_stack_client.types import UserMessage
from llama_stack_client.lib.agents.agent import Agent
from httpx import Client
from flask import session
import logging
import time
import json
import os
from utils.mcp_tokens_utils import get_mcp_tokens_for_user_direct

logger = logging.getLogger(__name__)

# Configuration
LLAMA_STACK_URL = os.getenv("LLAMA_STACK_URL", "http://localhost:8321")

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

def get_or_create_user_agent(user_email: str, bearer_token: str):
    """Get or create a user-specific Llama Stack agent with per-user isolation"""
    global llama_client, user_agents
    
    try:
        # Initialize Llama Stack client if not already done or if we need to update the token
        if not llama_client or (bearer_token and bearer_token != "NO_TOKEN_YET"):
            # Use the bearer token for Llama Stack authentication
            api_key = bearer_token if bearer_token and bearer_token != "NO_TOKEN_YET" else None
            llama_client = LlamaStackClient(
                base_url=LLAMA_STACK_URL,
                api_key=api_key,
                http_client=Client(verify=False),
            )
            logger.info(f"✅ Initialized Llama Stack client with authentication: {'Yes' if api_key else 'No'}")
        
        # Check if user already has an agent in memory
        if user_email in user_agents:
            user_data = user_agents[user_email]
            agent = user_data['agent']
            logger.info(f"🔄 Reusing existing agent for {user_email}")
            return agent
        
        # Get available models
        models = llama_client.models.list()
        if not models:
            logger.error("❌ No models available")
            return None
        
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
            'created_at': time.time()
        }
        
        logger.info(f"✅ Created new agent for {user_email}")
        
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
            # Not in request context, cache storage is sufficient
            logger.info(f"🔄 Not in request context, session ID stored in cache only")
        
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

def send_message_to_llama_stack(message: str, bearer_token: str, user_email: str, mcp_tokens: dict = {}) -> dict:
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
        
        # Get MCP tokens from helper function using the provided user_email
        mcp_tokens = get_mcp_tokens_for_user_direct(user_email)
        logger.info(f"🔐 Found {len(mcp_tokens)} MCP tokens for user {user_email}")
        
        # Build MCP headers with appropriate tokens for each MCP server
        mcp_headers = {}
        for mcp_server_url, mcp_token in mcp_tokens.items():
            if mcp_token and mcp_token != "NO_TOKEN_YET":
                mcp_headers[mcp_server_url] = {
                    "Authorization": f"Bearer {mcp_token}"
                }
                logger.info(f"🔐 Using MCP token for {mcp_server_url}: {mcp_token[:20]}...")
        
        # Prepare extra headers for agent
        extra_headers = {}
        if mcp_headers:
            extra_headers["X-LlamaStack-Provider-Data"] = json.dumps({
                "mcp_headers": mcp_headers
            })
            logger.info(f"🔐 Configured MCP headers for {len(mcp_headers)} servers")
        
        # Send to agent with streaming enabled (like original)
        response = agent.create_turn(
            messages=[user_message],
            session_id=agent_session_id,
            stream=True,
            extra_headers=extra_headers
        )
        
        # Extract response content using EventLogger (like original)
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
        
        # Clean up the response content
        if response_content:
            # Handle escaped characters
            response_content = response_content.replace('\\n', '\n')
            response_content = response_content.replace('\\t', '\t')
            response_content = response_content.replace('\\"', '"')
        
        response_text = response_content if response_content else "No response content"
        
        logger.info(f"✅ Agent response for {user_email}: {response_text[:100]}...")
        
        return {
            "success": True,
            "response": response_text
        }
        
    except Exception as e:
        error_message = str(e)
        logger.error(f"❌ Error sending message to agent for {user_email}: {error_message}")
        
        return {
            "success": False,
            "response": f"Error: {error_message}",
            "error_type": "agent_error"
        } 