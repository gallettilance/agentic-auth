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
    request_scope_upgrade,
    request_mcp_token,
    prepare_mcp_headers_for_user
)
from utils.llama_agents_utils import get_or_create_user_agent, send_message_to_llama_stack

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
    mcp_server_url = error_details.get('mcp_server_url', 'http://localhost:8001')
    
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

def stream_agent_response_with_auth_detection(message: str, bearer_token: str, user_email: str, original_message: str, auth_cookies: dict = {}, retry_count: int = 0):
    """Stream agent response with clean authorization error detection and automatic token exchange"""
    # Import here to avoid circular imports
    from utils.llama_agents_utils import get_or_create_user_agent
    
    try:
        logger.info(f"🌊 Streaming message to agent: {message} (retry_count: {retry_count})")
        
        # Get or create user-specific agent
        agent, agent_session_id = get_or_create_user_agent(user_email, bearer_token)
        
        if not agent or not agent_session_id:
            yield "❌ Failed to initialize agent. Please check if Llama Stack is running on port 8321.\n"
            return
        
        # Create the message
        from llama_stack_client.types import UserMessage
        user_message = UserMessage(content=message, role="user")
        
        # Prepare MCP authentication headers
        extra_headers = prepare_mcp_headers_for_user(user_email)
        
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
                mcp_server_url = error_details.get('mcp_server_url', 'http://localhost:8001')
                
                # Safety check: if mcp_server_url is None, use default
                if mcp_server_url is None:
                    mcp_server_url = 'http://localhost:8001'
                    logger.warning(f"⚠️ MCP server URL was None, using default: {mcp_server_url}")
                
                # DEBUG: Log the extracted error details
                logger.info(f"🔍 DEBUG: Full error content: {full_content}")
                logger.info(f"🔍 DEBUG: Extracted error details: {error_details}")
                logger.info(f"🔍 DEBUG: tool_name={tool_name}, required_scope={required_scope}, mcp_server_url={mcp_server_url}")
                
                # Prevent infinite retry loops
                if retry_count >= 2:
                    logger.error(f"❌ Maximum retry attempts reached ({retry_count}), giving up")
                    yield f"❌ Authorization failed after {retry_count} attempts. Please check permissions in the auth dashboard."
                    return
                
                # Attempt to exchange MCP token
                token_exchanged = False
                try:
                    logger.info(f"🔄 Attempting to exchange MCP token for scope: {required_scope}, server: {mcp_server_url}")
                    
                    # Get auth cookies - use passed cookies or try to get from request context
                    request_auth_cookies = auth_cookies
                    if not request_auth_cookies:
                        try:
                            from flask import request
                            request_auth_cookies = {'auth_session': request.cookies.get('auth_session')} if request.cookies.get('auth_session') else {}
                        except RuntimeError:
                            # Not in request context, use empty dict
                            request_auth_cookies = {}
                    
                    # Get current MCP token to upgrade rather than create new one
                    current_mcp_tokens = get_mcp_tokens_for_user_direct(user_email)
                    # Use base URL for token lookup since tokens are stored with base URLs as keys
                    base_mcp_url = get_base_mcp_url(mcp_server_url)
                    current_token = current_mcp_tokens.get(base_mcp_url, '')
                    
                    if current_token:
                        logger.info(f"🔄 Found existing MCP token for {base_mcp_url}, will upgrade it")
                    else:
                        logger.info(f"🔐 No existing MCP token for {base_mcp_url}, requesting initial token")
                    
                    # Try to get upgraded MCP token
                    # For InsufficientScopeError, we need to request approval, not just exchange existing tokens
                    if error_details.get('error_type') == 'insufficient_scope':
                        logger.info(f"🔐 Insufficient scope detected - requesting approval for scope: {required_scope}")
                        # Use request_scope_upgrade to actually request approval from admin
                        from utils.mcp_tokens_utils import AUTH_SERVER_URL
                        token_result = asyncio.run(request_scope_upgrade(required_scope, bearer_token, request_auth_cookies, auth_server_url=AUTH_SERVER_URL, resource=base_mcp_url, current_token=current_token))
                    else:
                        logger.info(f"🔐 Authorization error - requesting MCP token for scope: {required_scope}")
                        # Use request_mcp_token for other authorization errors (use base_mcp_url for correct audience)
                        from utils.mcp_tokens_utils import AUTH_SERVER_URL
                        token_result = asyncio.run(request_mcp_token(required_scope, base_mcp_url, current_token, request_auth_cookies, AUTH_SERVER_URL))
                    
                    if token_result and not token_result.get('error'):
                        # Check if this was an approval request that needs admin approval FIRST
                        status = token_result.get('status')
                        if status == 'pending_admin_approval':
                            logger.info(f"🔔 Approval request submitted to admin for scope: {required_scope}")
                            # Generate proper authorization error response for frontend
                            auth_error_response = create_auth_error_response(error_details, original_message, user_email, bearer_token)
                            yield auth_error_response
                            return  # Don't retry immediately, wait for admin approval
                        
                        new_token = token_result.get('access_token') or token_result.get('new_token')
                        if new_token:
                            # Store MCP token using helper function (use base_mcp_url for consistency)
                            store_mcp_token_for_user_direct(user_email, base_mcp_url, new_token)
                            logger.info(f"✅ Stored MCP token for {base_mcp_url} via helper function")
                            
                            # Update MCP token cookie for admin dashboard access
                            try:
                                import httpx
                                async def update_cookie():
                                    async with httpx.AsyncClient() as client:
                                        await client.post(
                                            'http://localhost:5001/api/update-mcp-token-cookie',
                                            json={
                                                'server_url': base_mcp_url,
                                                'token': new_token
                                            },
                                            timeout=5.0
                                        )
                                asyncio.run(update_cookie())
                                logger.info(f"✅ Updated MCP token cookie for admin dashboard")
                            except Exception as cookie_error:
                                logger.warning(f"⚠️ Failed to update MCP token cookie: {cookie_error}")
                            
                            # DEBUG: Verify the token was stored correctly
                            stored_tokens = get_mcp_tokens_for_user_direct(user_email)
                            base_mcp_url = get_base_mcp_url(mcp_server_url)
                            stored_token = stored_tokens.get(base_mcp_url, '')
                            logger.info(f"🔍 DEBUG: Stored token verification for {user_email} -> {base_mcp_url}: {stored_token[:20] if stored_token else 'NONE'}...")
                            logger.info(f"🔍 DEBUG: All stored tokens for {user_email}: {list(stored_tokens.keys())}")
                            
                            token_exchanged = True
                            
                            if status == 'approved':
                                logger.info(f"✅ Scope {required_scope} approved, proceeding with retry")
                        else:
                            logger.warning(f"⚠️ Token request returned success but no token: {token_result}")
                    else:
                        logger.warning(f"⚠️ Token request failed: {token_result.get('error', 'Unknown error')}")
                        
                        # Check if this was a pending approval case
                        if 'pending' in str(token_result.get('error', '')).lower():
                            logger.info(f"🔔 Approval request is pending for scope: {required_scope}")
                            yield f"🔔 Approval request for {tool_name} ({required_scope}) is pending administrator approval.\n\n"
                            return  # Don't retry immediately, wait for admin approval
                        
                except Exception as token_error:
                    logger.error(f"❌ Token exchange failed with exception: {token_error}")
                
                # If token exchange succeeded, retry the request
                if token_exchanged:
                    logger.info(f"🔄 Token exchanged successfully, retrying request (attempt {retry_count + 1})")
                    yield f"🔐 Obtained authorization for {tool_name}, retrying request...\n\n"
                    
                    # DEBUG: Check what tokens are available before retry
                    debug_tokens = get_mcp_tokens_for_user_direct(user_email)
                    logger.info(f"🔍 DEBUG: Before retry - available tokens for {user_email}: {list(debug_tokens.keys())}")
                    
                    # Retry the request with the new token
                    try:
                        for retry_chunk in stream_agent_response_with_auth_detection(
                            message, bearer_token, user_email, original_message, request_auth_cookies, retry_count + 1
                        ):
                            yield retry_chunk
                        return
                    except Exception as retry_error:
                        logger.error(f"❌ Retry failed: {retry_error}")
                        yield f"❌ Retry failed: {str(retry_error)}"
                        return
                else:
                    # Token exchange failed, return error response for manual handling
                    logger.warning(f"⚠️ Automatic token exchange failed, returning error for manual handling")
                    yield f"❌ Authorization failed for {tool_name}. Please check permissions in the auth dashboard."
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
            mcp_server_url = error_details.get('mcp_server_url', 'http://localhost:8001')
            
            # Safety check: if mcp_server_url is None, use default
            if mcp_server_url is None:
                mcp_server_url = 'http://localhost:8001'
                logger.warning(f"⚠️ MCP server URL was None, using default: {mcp_server_url}")
            
            # DEBUG: Log the extracted error details
            logger.info(f"🔍 DEBUG: Full error content: {error_message}")
            logger.info(f"🔍 DEBUG: Extracted error details: {error_details}")
            logger.info(f"🔍 DEBUG: tool_name={tool_name}, required_scope={required_scope}, mcp_server_url={mcp_server_url}")
            
            # Prevent infinite retry loops
            if retry_count >= 2:
                logger.error(f"❌ Maximum retry attempts reached ({retry_count}), giving up")
                yield f"❌ Authorization failed after {retry_count} attempts. Please check permissions in the auth dashboard."
                return
            
            # Attempt to exchange MCP token
            token_exchanged = False
            try:
                logger.info(f"🔄 Attempting to exchange MCP token for scope: {required_scope}, server: {mcp_server_url}")
                
                # Get auth cookies - use passed cookies or try to get from request context
                request_auth_cookies = auth_cookies
                if not request_auth_cookies:
                    try:
                        from flask import request
                        request_auth_cookies = {'auth_session': request.cookies.get('auth_session')} if request.cookies.get('auth_session') else {}
                    except RuntimeError:
                        # Not in request context, use empty dict
                        request_auth_cookies = {}
                
                # Get current MCP token to upgrade rather than create new one
                current_mcp_tokens = get_mcp_tokens_for_user_direct(user_email)
                # Use base URL for token lookup since tokens are stored with base URLs as keys
                base_mcp_url = get_base_mcp_url(mcp_server_url)
                current_token = current_mcp_tokens.get(base_mcp_url, '')
                
                if current_token:
                    logger.info(f"🔄 Found existing MCP token for {base_mcp_url}, will upgrade it")
                else:
                    logger.info(f"🔐 No existing MCP token for {base_mcp_url}, requesting initial token")
                
                # Try to get upgraded MCP token
                # For InsufficientScopeError, we need to request approval, not just exchange existing tokens
                if error_details.get('error_type') == 'insufficient_scope':
                    logger.info(f"🔐 Insufficient scope detected - requesting approval for scope: {required_scope}")
                    # Use request_scope_upgrade to actually request approval from admin
                    from utils.mcp_tokens_utils import AUTH_SERVER_URL
                    token_result = asyncio.run(request_scope_upgrade(required_scope, bearer_token, request_auth_cookies, auth_server_url=AUTH_SERVER_URL, resource=base_mcp_url, current_token=current_token))
                else:
                    logger.info(f"🔐 Authorization error - requesting MCP token for scope: {required_scope}")
                    # Use request_mcp_token for other authorization errors (use base_mcp_url for correct audience)
                    from utils.mcp_tokens_utils import AUTH_SERVER_URL
                    token_result = asyncio.run(request_mcp_token(required_scope, base_mcp_url, current_token, request_auth_cookies, AUTH_SERVER_URL))
                
                if token_result and not token_result.get('error'):
                    # Check if this was an approval request that needs admin approval FIRST
                    status = token_result.get('status')
                    if status == 'pending_admin_approval':
                        logger.info(f"🔔 Approval request submitted to admin for scope: {required_scope}")
                        # Generate proper authorization error response for frontend
                        auth_error_response = create_auth_error_response(error_details, original_message, user_email, bearer_token)
                        yield auth_error_response
                        return  # Don't retry immediately, wait for admin approval
                    
                    new_token = token_result.get('access_token') or token_result.get('new_token')
                    if new_token:
                        # Store MCP token using helper function (use base_mcp_url for consistency)
                        store_mcp_token_for_user_direct(user_email, base_mcp_url, new_token)
                        logger.info(f"✅ Stored MCP token for {base_mcp_url} via helper function")
                        
                        # Update MCP token cookie for admin dashboard access
                        try:
                            import httpx
                            async def update_cookie():
                                async with httpx.AsyncClient() as client:
                                    await client.post(
                                        'http://localhost:5001/api/update-mcp-token-cookie',
                                        json={
                                            'server_url': base_mcp_url,
                                            'token': new_token
                                        },
                                        timeout=5.0
                                    )
                            asyncio.run(update_cookie())
                            logger.info(f"✅ Updated MCP token cookie for admin dashboard")
                        except Exception as cookie_error:
                            logger.warning(f"⚠️ Failed to update MCP token cookie: {cookie_error}")
                        
                        # DEBUG: Verify the token was stored correctly
                        stored_tokens = get_mcp_tokens_for_user_direct(user_email)
                        base_mcp_url = get_base_mcp_url(mcp_server_url)
                        stored_token = stored_tokens.get(base_mcp_url, '')
                        logger.info(f"🔍 DEBUG: Stored token verification for {user_email} -> {base_mcp_url}: {stored_token[:20] if stored_token else 'NONE'}...")
                        logger.info(f"🔍 DEBUG: All stored tokens for {user_email}: {list(stored_tokens.keys())}")
                        
                        token_exchanged = True
                        
                        if status == 'approved':
                            logger.info(f"✅ Scope {required_scope} approved, proceeding with retry")
                    else:
                        logger.warning(f"⚠️ Token request returned success but no token: {token_result}")
                else:
                    logger.warning(f"⚠️ Token request failed: {token_result.get('error', 'Unknown error')}")
                    
                    # Check if this was a pending approval case
                    if 'pending' in str(token_result.get('error', '')).lower():
                        logger.info(f"🔔 Approval request is pending for scope: {required_scope}")
                        yield f"🔔 Approval request for {tool_name} ({required_scope}) is pending administrator approval.\n\n"
                        return  # Don't retry immediately, wait for admin approval
                        
            except Exception as token_error:
                logger.error(f"❌ Token exchange failed with exception: {token_error}")
                
            # If token exchange succeeded, retry the request
            if token_exchanged:
                logger.info(f"🔄 Token exchanged successfully, retrying request (attempt {retry_count + 1})")
                yield f"🔐 Obtained authorization for {tool_name}, retrying request...\n\n"
                
                # DEBUG: Check what tokens are available before retry
                debug_tokens = get_mcp_tokens_for_user_direct(user_email)
                logger.info(f"🔍 DEBUG: Before retry - available tokens for {user_email}: {list(debug_tokens.keys())}")
                
                # Retry the request with the new token
                try:
                    for retry_chunk in stream_agent_response_with_auth_detection(
                        message, bearer_token, user_email, original_message, request_auth_cookies, retry_count + 1
                    ):
                        yield retry_chunk
                    return
                except Exception as retry_error:
                    logger.error(f"❌ Retry failed: {retry_error}")
                    yield f"❌ Retry failed: {str(retry_error)}"
                    return
            else:
                # Token exchange failed, return error response for manual handling
                logger.warning(f"⚠️ Automatic token exchange failed, returning error for manual handling")
                yield f"❌ Authorization failed for {tool_name}. Please check permissions in the auth dashboard."
                return
        
        # For other errors, yield error message
        yield f"❌ Error: {error_message}" 