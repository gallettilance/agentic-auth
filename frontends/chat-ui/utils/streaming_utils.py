"""
Streaming utilities for chat responses
Handles streaming agent responses with authorization error detection and automatic token exchange.
"""

import asyncio
import logging
import re
from flask import session
import json
import secrets
from datetime import datetime
import time
from utils.auth_utils import extract_authorization_error_details, is_authorization_error
from utils.mcp_tokens_utils import (
    get_mcp_tokens_for_user_direct, 
    store_mcp_token_for_user_direct,
    get_base_mcp_url,
    prepare_mcp_headers_for_user
)
from utils.llama_agents_utils import get_or_create_session_for_user
from typing import Optional

# Global variable for simple consent mechanism
user_consent_response = None

logger = logging.getLogger(__name__)

def process_streaming_log(log, tool_already_printed: dict, full_content_buffer: list) -> tuple[str, bool]:
    """Process a single streaming log entry and return content to yield and whether auth error was detected"""
    
    # Extract content from the log events (handle both old and new EventLogger formats)
    content = ""
    role = None
    
    # Try the new format first (with event attribute)
    if hasattr(log, 'event') and log.event:
        event = log.event
        
        # Handle different event types
        if hasattr(event, 'delta') and hasattr(event.delta, 'content'):
            # Streaming content delta
            if event.delta.content:
                content = event.delta.content
        elif hasattr(event, 'content'):
            # Complete content
            if event.content:
                content = event.content
        elif hasattr(event, 'tool_call'):
            # Tool call event
            tool_call = event.tool_call
            content = f"Tool:{tool_call.tool_name}"
            role = "tool_execution"
    
    # Fall back to old format (direct attributes on log)
    if not content and hasattr(log, 'content') and log.content:
        content = log.content
    
    if not role and hasattr(log, 'role'):
        role = log.role
    
    # Track all content for error detection
    if content:
        full_content_buffer.append(content)
        
        # Check for authorization errors immediately when we see tool responses
        if role == "tool_execution" and ("InsufficientScopeError" in content or "AuthorizationError" in content):
            logger.warning(f"🔐 Authorization error detected in tool execution")
            return "", True  # Return empty content and auth error flag
    
    # Handle different types of streaming content
    if role == "tool_execution":
        match = re.search(r"Tool:(\w+)", content)
        if match:
            tool_name = match.group(1)
            if tool_name not in tool_already_printed:
                tool_info = f"🛠 **Used Tool:** `{tool_name}`  \n"
                tool_already_printed[tool_name] = True
                return tool_info, False
    
    elif role == "inference":
        # Stream inference content as it arrives
        if content:
            return content, False
    
    elif role is None:
        # Stream any other content
        if content:
            return content, False
    
    return "", False

def create_auth_error_response(error_details: dict, message: str, user_email: str, bearer_token: str) -> str:
    """Create a structured authorization error response with proper markers for frontend"""
    tool_name = error_details.get('tool_name', 'unknown')
    required_scope = error_details.get('required_scope', tool_name)
    mcp_server_url = error_details.get('mcp_server_url')
    
    if not mcp_server_url:
        logger.error("❌ No MCP server URL found in error details - cannot create auth error response")
        raise ValueError("MCP server URL is required for authorization error response")
    
    # Generate a unique message ID
    message_id = secrets.token_urlsafe(16)
    
    # Determine error type and create appropriate response
    if error_details.get('error_type') == 'insufficient_scope':
        # User needs scope upgrade (admin approval required)
        auth_error_json = json.dumps({
            'error_type': 'scope_upgrade_required',
            'tool_name': tool_name,
            'required_scope': required_scope,
            'mcp_server_url': mcp_server_url,
            'message_id': message_id,
            'original_message': message,
            'approval_status': 'pending_admin_approval',
            'approval_requested': True
        })
    else:
        # User needs initial MCP token
        auth_error_json = json.dumps({
            'error_type': 'mcp_token_required',
            'tool_name': tool_name,
            'required_scope': required_scope,
            'mcp_server_url': mcp_server_url,
            'message_id': message_id,
            'original_message': message,
            'approval_status': 'pending_admin_approval',
            'approval_requested': True
        })
    
    return f"__AUTH_ERROR_START__{auth_error_json}__AUTH_ERROR_END__"

def stream_agent_response_with_auth_detection(message: str, bearer_token: str, user_email: str, original_message: str, auth_cookies: dict = {}, retry_count: int = 0, mcp_token: Optional[str] = None):
    """Stream agent response with clean authorization error detection and automatic token exchange"""
    # Import here to avoid circular imports
    from utils.llama_agents_utils import get_or_create_session_for_user
    import time
    
    try:
        logger.info(f"🌊 Streaming message to agent: {message} (retry_count: {retry_count})")
        
        # Get or create user-specific agent and session
        agent, agent_session_id = get_or_create_session_for_user(user_email, bearer_token)
        
        if not agent or not agent_session_id:
            yield "❌ Failed to initialize agent. Please check if Llama Stack is running on port 8321.\n"
            return
        
        # Create the message
        from llama_stack_client.types import UserMessage
        user_message = UserMessage(content=message, role="user")
        
        # Prepare MCP authentication headers using provided token
        extra_headers = prepare_mcp_headers_for_user(user_email, mcp_token)
        
        # Send to agent with streaming enabled
        response = agent.create_turn(
            messages=[user_message],
            session_id=agent_session_id,
            stream=True,
            extra_headers=extra_headers
        )
        
        # Process streaming response with clean error detection
        from llama_stack_client.lib.agents.event_logger import EventLogger
        
        tool_already_printed = {}
        full_content_buffer = []
        
        for log in EventLogger().log(response):
            content_to_yield, auth_error_detected = process_streaming_log(log, tool_already_printed, full_content_buffer)
            
            if auth_error_detected:
                # Authorization error detected - attempt automatic token exchange and retry
                full_content = "".join(full_content_buffer)
                logger.warning(f"🔐 Authorization error detected, attempting automatic token exchange and retry")
                
                # Extract error details
                error_details = extract_authorization_error_details(full_content)
                tool_name = error_details.get('tool_name', 'unknown')
                required_scope = error_details.get('required_scope', tool_name)
                mcp_server_url = error_details.get('mcp_server_url')
                
                # Safety check: if mcp_server_url is None, fail fast
                if not mcp_server_url:
                    logger.error("❌ No MCP server URL found in error details - cannot process authorization error")
                    yield "❌ Cannot determine MCP server URL from error - unable to process authorization\n\n"
                    return
                
                # DEBUG: Log the extracted error details
                logger.info(f"🔍 DEBUG: Full error content: {full_content}")
                logger.info(f"🔍 DEBUG: Extracted error details: {error_details}")
                logger.info(f"🔍 DEBUG: tool_name={tool_name}, required_scope={required_scope}, mcp_server_url={mcp_server_url}")
                
                # Prevent infinite retry loops
                if retry_count >= 2:
                    logger.error(f"❌ Maximum retry attempts reached ({retry_count}), giving up")
                    yield f"❌ Authorization failed after {retry_count} attempts. Please check permissions in the admin dashboard."
                    return
                
                # For Keycloak: Use token exchange API to get additional scope
                logger.info(f"🔄 Attempting Keycloak token exchange for scope: {required_scope}")
                    
                # Ensure scope has proper prefix
                if not required_scope.startswith('mcp:'):
                    required_scope = f'mcp:{required_scope}'
                
                try:
                    # Import the token exchange function from our API
                    import sys
                    import os
                    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                    
                    # Use the existing Keycloak token exchange endpoint
                    from api.tokens import exchange_token_for_audience
                    import asyncio
                    
                    access_token = session.get('access_token')
                    if not access_token:
                        logger.error("❌ No access token available for token exchange")
                        yield f"❌ Authentication error - please re-login\n"
                        return
                    
                    # Get current MCP token scopes
                    current_mcp_token = session.get('mcp_token')
                    current_scopes = []
                    if current_mcp_token:
                        try:
                            import jwt
                            decoded = jwt.decode(current_mcp_token, options={"verify_signature": False})
                            current_scopes = decoded.get('scope', '').split() if decoded.get('scope') else []
                        except Exception:
                            pass
                    
                    # Add the required scope to current scopes
                    if required_scope not in current_scopes:
                        current_scopes.append(required_scope)
                    
                    # Exchange token for new scopes using Keycloak
                    OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "authentication-demo")
                    result = asyncio.run(exchange_token_for_audience(
                        access_token=access_token,
                        audience=OIDC_CLIENT_ID,  # Self-exchange
                        scopes=current_scopes
                    ))
                    
                    if result.get('success'):
                        # Store the new MCP token
                        new_mcp_token = result['access_token']
                        session['mcp_token'] = new_mcp_token
                        logger.info(f"✅ Successfully exchanged token for scope: {required_scope}")
                        
                        # Retry the original request with new token
                        yield f"🔄 **Acquired permission for `{tool_name}` - retrying...**\n\n"
                    
                        # Recursive retry with incremented count
                        for retry_chunk in stream_agent_response_with_auth_detection(
                            message, bearer_token, user_email, original_message, auth_cookies, retry_count + 1, new_mcp_token
                        ):
                            yield retry_chunk
                        return
                    else:
                        error_msg = result.get('error', 'Unknown error')
                        logger.error(f"❌ Keycloak token exchange failed: {error_msg}")
                        yield f"❌ Permission denied for `{tool_name}`. {error_msg}\n"
                        return
                        
                except Exception as e:
                    logger.error(f"❌ Exception during token exchange: {e}")
                    yield f"❌ Failed to acquire permission for `{tool_name}`: {str(e)}\n"
                    return
            
            if content_to_yield:
                yield content_to_yield
        
        # If we reach here, the response completed successfully
        logger.info(f"✅ Response completed successfully")
            
    except Exception as e:
        error_message = str(e)
        logger.error(f"❌ Streaming error: {error_message}")
        
        # Check if this is an authorization error and handle it properly
        if is_authorization_error(error_message):
            logger.info("🔐 Detected authorization error in streaming exception")
            
            # Extract error details
            error_details = extract_authorization_error_details(error_message)
            tool_name = error_details.get('tool_name', 'unknown')
            required_scope = error_details.get('required_scope', tool_name)
            mcp_server_url = error_details.get('mcp_server_url')
            
            # Safety check: if mcp_server_url is None, fail fast
            if not mcp_server_url:
                logger.error("❌ No MCP server URL found in error details - cannot process authorization error")
                yield "❌ Cannot determine MCP server URL from error - unable to process authorization\n\n"
                return
            
            # DEBUG: Log the extracted error details
            logger.info(f"🔍 DEBUG: Full error content: {error_message}")
            logger.info(f"🔍 DEBUG: Extracted error details: {error_details}")
            logger.info(f"🔍 DEBUG: tool_name={tool_name}, required_scope={required_scope}, mcp_server_url={mcp_server_url}")
            
            # Prevent infinite retry loops
            if retry_count >= 2:
                logger.error(f"❌ Maximum retry attempts reached ({retry_count}), giving up")
                yield f"❌ Authorization failed after {retry_count} attempts. Please check permissions in the admin dashboard."
                return
            
            # For Keycloak: Use token exchange API to get additional scope
            logger.info(f"🔄 Attempting Keycloak token exchange for scope: {required_scope}")
                
            # Ensure scope has proper prefix
            if not required_scope.startswith('mcp:'):
                required_scope = f'mcp:{required_scope}'
            
            try:
                # Import the token exchange function from our API
                import sys
                import os
                sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                
                # Use the existing Keycloak token exchange endpoint
                from api.tokens import exchange_token_for_audience
                import asyncio
                
                access_token = session.get('access_token')
                if not access_token:
                    logger.error("❌ No access token available for token exchange")
                    yield f"❌ Authentication error - please re-login\n"
                    return
                
                # Get current MCP token scopes
                current_mcp_token = session.get('mcp_token')
                current_scopes = []
                if current_mcp_token:
                    try:
                        import jwt
                        decoded = jwt.decode(current_mcp_token, options={"verify_signature": False})
                        current_scopes = decoded.get('scope', '').split() if decoded.get('scope') else []
                    except Exception:
                        pass
                
                # Add the required scope to current scopes
                if required_scope not in current_scopes:
                    current_scopes.append(required_scope)
                
                # Exchange token for new scopes using Keycloak
                OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "authentication-demo")
                result = asyncio.run(exchange_token_for_audience(
                    access_token=access_token,
                    audience=OIDC_CLIENT_ID,  # Self-exchange
                    scopes=current_scopes
                ))
                
                if result.get('success'):
                    # Store the new MCP token
                    new_mcp_token = result['access_token']
                    session['mcp_token'] = new_mcp_token
                    logger.info(f"✅ Successfully exchanged token for scope: {required_scope}")
                    
                    # Retry the original request with new token
                    yield f"🔄 **Acquired permission for `{tool_name}` - retrying...**\n\n"
                
                    # Recursive retry with incremented count
                    for retry_chunk in stream_agent_response_with_auth_detection(
                        message, bearer_token, user_email, original_message, auth_cookies, retry_count + 1, new_mcp_token
                    ):
                        yield retry_chunk
                    return
                else:
                    error_msg = result.get('error', 'Unknown error')
                    logger.error(f"❌ Keycloak token exchange failed: {error_msg}")
                    yield f"❌ Permission denied for `{tool_name}`. {error_msg}\n"
                    return
                    
            except Exception as e:
                logger.error(f"❌ Exception during token exchange: {e}")
                yield f"❌ Failed to acquire permission for `{tool_name}`: {str(e)}\n"
                return
        
        # For other errors, yield error message
        yield f"❌ Error: {error_message}" 