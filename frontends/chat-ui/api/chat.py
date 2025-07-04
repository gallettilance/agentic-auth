"""
Chat API Blueprint
Handles chat communication with Llama Stack and MCP servers.
"""

from flask import Blueprint, request, jsonify, session, Response
import logging
import secrets
from datetime import datetime

# Import from our utility modules using absolute imports
from utils.auth_utils import check_auth_server_session_direct, is_authorization_error, extract_authorization_error_details
from utils.streaming_utils import stream_agent_response_with_auth_detection
from utils.llama_agents_utils import send_message_to_llama_stack, get_or_create_user_agent

logger = logging.getLogger(__name__)

chat_bp = Blueprint('chat', __name__)

# Store for pending messages (for retry after approval)
pending_messages = {}

@chat_bp.route('/chat', methods=['POST'])
def chat():
    """Handle chat messages with streaming support"""
    try:
        # Always verify auth server session first
        auth_user = check_auth_server_session_direct()
        if not auth_user:
            return jsonify({'error': 'Not authenticated - please login', 'success': False}), 401
        
        # Ensure local session is up to date
        if session.get('user_email') != auth_user['email']:
            return jsonify({'error': 'Session mismatch - please refresh page', 'success': False}), 401
    
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data', 'success': False}), 400
            
        message = data.get('message', '').strip()
        
        if not message:
            return jsonify({'error': 'Empty message', 'success': False}), 400
        
        # Check if streaming is requested
        stream = data.get('stream', False)
        
        # Get or create bearer token on-demand (only when actually needed)
        bearer_token = session.get('bearer_token')
        if not bearer_token:
            logger.info("🔐 No bearer token found - will create on-demand when agent needs MCP tools")
            # Use a placeholder token that will trigger proper error handling
            bearer_token = "NO_TOKEN_YET"
        
        # User message will be automatically saved by Llama Stack session
        
        if stream:
            # Stream the response, but include special markers for authorization errors
            try:
                auth_cookies = {'auth_session': request.cookies.get('auth_session')} if request.cookies.get('auth_session') else {}
                return Response(
                    stream_agent_response_with_auth_detection(
                        message, 
                        bearer_token,
                        session.get('user_email', ''),
                        message,
                        auth_cookies,
                        0  # retry_count
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
                    
                    # Extract error details from the error message
                    tool_name = error_details.get('tool_name', 'unknown')
                    required_scope = error_details.get('required_scope', tool_name)
                    mcp_server_url = error_details.get('mcp_server_url')
                    
                    if not mcp_server_url:
                        logger.error("❌ No MCP server URL found in error details - cannot process authorization error")
                        return jsonify({'error': 'Cannot determine MCP server URL from error'}), 400
                    
                    # Store the pending message for retry
                    message_id = secrets.token_urlsafe(16)
                    pending_messages[message_id] = {
                        'message': message,
                        'user_email': session.get('user_email', ''),
                        'bearer_token': session.get('bearer_token', 'NO_TOKEN_YET'),
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
                
                # For other errors, return generic error response
                return jsonify({
                    'response': f"❌ Error: {error_message}",
                    'user': session.get('user_name', 'User'),
                    'success': False
                })
        else:
            # Non-streaming response
            result = send_message_to_llama_stack(message, bearer_token, session.get('user_email', ''))
            
            if result['success']:
                return jsonify({
                    'response': result['response'],
                    'user': session.get('user_name', 'User'),
                    'success': True
                })
            else:
                return jsonify({
                    'response': f"❌ {result.get('error', 'Unknown error')}",
                    'user': session.get('user_name', 'User'),
                    'success': False
                })
    
    except Exception as e:
        logger.error(f"❌ Chat endpoint error: {e}")
        return jsonify({
            'response': f"❌ Server error: {str(e)}",
            'user': session.get('user_name', 'User'),
            'success': False
        }), 500

@chat_bp.route('/chat-history')
def get_chat_history():
    """Get chat history for the current user"""
    try:
        # Check authentication
        if not session.get('authenticated'):
            return jsonify({'error': 'Not authenticated'}), 401
        
        user_email = session.get('user_email')
        bearer_token = session.get('bearer_token')
        llama_session_id = session.get('llama_session_id')
        
        if not user_email:
            return jsonify({'error': 'User email not found in session'}), 400
        
        if not bearer_token:
            return jsonify({'error': 'Bearer token not found in session'}), 400
        
        if not llama_session_id:
            # No session ID means no chat history yet
            return jsonify({
                'status': 'success',
                'messages': [],
                'message': 'No chat history - new session'
            })
        
        # Get agent and retrieve session messages
        agent, session_id = get_or_create_user_agent(user_email, bearer_token)
        
        if not agent or session_id != llama_session_id:
            logger.warning(f"⚠️ Session mismatch or agent not available for {user_email}")
            return jsonify({
                'status': 'success',
                'messages': [],
                'message': 'Session not available'
            })
        
        # Get session messages from Llama Stack
        try:
            # Use the agent's session to get messages
            session_messages = agent.sessions.get(session_id=session_id)
            
            if hasattr(session_messages, 'turns') and session_messages.turns:
                # Convert Llama Stack turns to our chat format
                messages = []
                for turn in session_messages.turns:
                    # Each turn has input_messages and output_message
                    if hasattr(turn, 'input_messages'):
                        for msg in turn.input_messages:
                            if hasattr(msg, 'content') and hasattr(msg, 'role'):
                                messages.append({
                                    'type': msg.role,  # 'user' or 'assistant'
                                    'content': msg.content,
                                    'timestamp': getattr(msg, 'timestamp', None),
                                    'metadata': {}
                                })
                    
                    if hasattr(turn, 'output_message') and turn.output_message:
                        msg = turn.output_message
                        if hasattr(msg, 'content'):
                            # Extract tool calls and other metadata if available
                            metadata = {}
                            if hasattr(turn, 'tool_calls') and turn.tool_calls:
                                metadata['tool_calls'] = [
                                    {
                                        'tool_name': tc.tool_name,
                                        'arguments': tc.arguments if hasattr(tc, 'arguments') else {}
                                    }
                                    for tc in turn.tool_calls
                                ]
                            
                            messages.append({
                                'type': 'assistant',
                                'content': msg.content,
                                'timestamp': getattr(msg, 'timestamp', None),
                                'metadata': metadata
                            })
                
                logger.info(f"✅ Retrieved {len(messages)} messages from session {session_id}")
                return jsonify({
                    'status': 'success',
                    'messages': messages,
                    'session_id': session_id
                })
            else:
                return jsonify({
                    'status': 'success',
                    'messages': [],
                    'message': 'No messages in session'
                })
                
        except Exception as session_error:
            logger.error(f"❌ Error retrieving session messages: {session_error}")
            return jsonify({
                'status': 'success',
                'messages': [],
                'message': f'Could not retrieve session: {str(session_error)}'
            })
        
    except Exception as e:
        logger.error(f"❌ Error getting chat history: {e}")
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/clear-chat-history', methods=['POST'])
def clear_chat_history():
    """Clear chat history for the current user"""
    try:
        # Check authentication
        if not session.get('authenticated'):
            return jsonify({'error': 'Not authenticated'}), 401
        
        # TODO: Implement chat history clearing in Llama Stack
        return jsonify({
            'success': True,
            'message': 'Chat history cleared (not yet implemented)'
        })
        
    except Exception as e:
        logger.error(f"❌ Error clearing chat history: {e}")
        return jsonify({'error': str(e)}), 500 