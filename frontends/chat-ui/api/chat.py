"""
Chat API Blueprint
Handles chat communication with Llama Stack and MCP servers.
"""

from flask import Blueprint, request, jsonify, session, Response
import logging
import secrets
from datetime import datetime
import os
import json
import sqlite3
import time

# Import from our utility modules using absolute imports
from utils.auth_utils import is_authorization_error, extract_authorization_error_details
from utils.streaming_utils import stream_agent_response_with_auth_detection
from utils.llama_agents_utils import send_message_to_llama_stack, get_or_create_user_agent, get_or_create_session_for_user

# Configure logging
logger = logging.getLogger(__name__)

# Global variable for kvstore database path (in project root)
KVSTORE_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), '..', '..', 'kvstore.db')

chat_bp = Blueprint('chat', __name__)

# Store for pending messages (for retry after approval)
pending_messages = {}

@chat_bp.route('/chat', methods=['POST'])
def chat():
    """Handle chat messages with streaming support"""
    try:
        # Check authentication using Flask session (Keycloak authenticated)
        if not session.get('authenticated'):
            return jsonify({'error': 'Not authenticated - please login', 'success': False}), 401
    
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data', 'success': False}), 400
            
        message = data.get('message', '').strip()
        
        if not message:
            return jsonify({'error': 'Empty message', 'success': False}), 400
        
        # Check if streaming is requested
        stream = data.get('stream', False)
        
        # 🔒 ZERO-TRUST: Exchange for Llama Stack token only when actually needed
        bearer_token = session.get('llama_stack_token')
        if not bearer_token:
            logger.info("🔒 Zero-trust: No Llama Stack token found - exchanging for minimal scopes on-demand")
            access_token = session.get('access_token')
            if not access_token:
                return jsonify({'error': 'No access token available', 'success': False}), 401
            
            # Exchange for minimal Llama scopes needed for basic chat
            from app import exchange_for_llama_stack_token
            import asyncio
            
            llama_result = asyncio.run(exchange_for_llama_stack_token(access_token))
            if llama_result['success']:
                bearer_token = llama_result['token']
                session['llama_stack_token'] = bearer_token
                logger.info(f"🦙 Zero-trust: Obtained minimal Llama Stack token on first chat use")
            else:
                error_msg = llama_result.get('error', 'Unknown error')
                logger.error(f"❌ Failed to exchange for Llama Stack token: {error_msg}")
                return jsonify({
                    'error': f'Failed to obtain chat permissions: {error_msg}', 
                    'success': False
                }), 403
        
        # 🔒 ZERO-TRUST: Exchange for MCP token only when actually needed
        mcp_token = session.get('mcp_token')
        if not mcp_token:
            logger.info("🔒 Zero-trust: No MCP token found - exchanging for minimal scopes on-demand")
            access_token = session.get('access_token')
            if not access_token:
                return jsonify({'error': 'No access token available', 'success': False}), 401
            
            # Exchange for minimal MCP scopes needed for basic MCP server authentication
            from app import exchange_for_mcp_token
            import asyncio
            
            mcp_result = asyncio.run(exchange_for_mcp_token(access_token))
            if mcp_result['success']:
                mcp_token = mcp_result['token']
                session['mcp_token'] = mcp_token
                logger.info(f"🔧 Zero-trust: Obtained minimal MCP token on first chat use")
            else:
                error_msg = mcp_result.get('error', 'Unknown error')
                logger.error(f"❌ Failed to exchange for MCP token: {error_msg}")
                return jsonify({
                    'error': f'Failed to obtain MCP permissions: {error_msg}', 
                    'success': False
                }), 403
        
        # User message will be automatically saved by Llama Stack session
        
        if stream:
            # Stream the response, but include special markers for authorization errors
            try:
                auth_cookies = {'auth_session': request.cookies.get('auth_session')} if request.cookies.get('auth_session') else {}
                mcp_token = session.get('mcp_token')  # Get MCP token from session while in request context
                access_token = session.get('access_token')  # Get access token from session while in request context
                return Response(
                    stream_agent_response_with_auth_detection(
                        message, 
                        bearer_token,
                        session.get('user_email', ''),
                        message,
                        auth_cookies,
                        0,  # retry_count
                        mcp_token,  # Pass MCP token to avoid context issues
                        access_token  # Pass access token to avoid context issues
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
                    
                    # Check if this is a Llama Stack scope error
                    if error_details.get('error_type') == 'llama_insufficient_scope':
                        llama_scopes = error_details.get('llama_scopes', [required_scope])
                        logger.info(f"🔍 Llama Stack scope error in streaming: tool_name={tool_name}, required_scope={required_scope}, llama_scopes={llama_scopes}")
                        
                        # Try to exchange token for the required scopes
                        try:
                            from api.tokens import exchange_token_for_audience
                            import asyncio
                            
                            access_token = session.get('access_token')
                            if not access_token:
                                return jsonify({
                                    'response': "❌ Authentication error - please re-login",
                                    'user': session.get('user_name', 'User'),
                                    'success': False
                                }), 401
                            
                            # Start with basic OIDC scopes and add the required Llama Stack scopes
                            basic_scopes = ['email', 'profile']
                            for scope in llama_scopes:
                                if scope not in basic_scopes:
                                    basic_scopes.append(scope)
                            
                            logger.info(f"🔍 Requesting Llama Stack scopes: {basic_scopes}")
                            
                            # Exchange token for new scopes using Keycloak
                            OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "authentication-demo")
                            exchange_result = asyncio.run(exchange_token_for_audience(
                                access_token=access_token,
                                audience=OIDC_CLIENT_ID,  # Self-exchange
                                scopes=basic_scopes
                            ))
                            
                            if exchange_result.get('success'):
                                # Get the new Llama Stack token
                                new_llama_token = exchange_result['access_token']
                                
                                # Store the new token in session
                                session['llama_stack_token'] = new_llama_token
                                logger.info(f"✅ Successfully exchanged token for Llama Stack scopes: {llama_scopes}")
                                
                                # Return success response - the streaming will handle the retry
                                return jsonify({
                                    'response': f"🔄 **Acquired Llama Stack permissions for `{tool_name}` - retrying...**",
                                    'user': session.get('user_name', 'User'),
                                    'success': True,
                                    'retry_with_token': new_llama_token
                                })
                            else:
                                error_msg = exchange_result.get('error', 'Unknown error')
                                logger.error(f"❌ Keycloak token exchange failed for Llama Stack: {error_msg}")
                                return jsonify({
                                    'response': f"❌ Llama Stack permission denied for `{tool_name}`. {error_msg}",
                                    'user': session.get('user_name', 'User'),
                                    'success': False
                                })
                                
                        except Exception as e:
                            logger.error(f"❌ Exception during Llama Stack token exchange: {e}")
                            return jsonify({
                                'response': f"❌ Failed to acquire Llama Stack permission for `{tool_name}`: {str(e)}",
                                'user': session.get('user_name', 'User'),
                                'success': False
                            })
                    
                    # Handle MCP authorization errors
                    elif mcp_server_url:
                        # Store the pending message for retry
                        message_id = secrets.token_urlsafe(16)
                        pending_messages[message_id] = {
                            'message': message,
                            'user_email': session.get('user_email', ''),
                            'bearer_token': session.get('llama_stack_token', 'NO_TOKEN_YET'),
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
                        logger.error("❌ No MCP server URL found in error details - cannot process authorization error")
                        return jsonify({'error': 'Cannot determine MCP server URL from error'}), 400
                
                # For other errors, return generic error response
                return jsonify({
                    'response': f"❌ Error: {error_message}",
                    'user': session.get('user_name', 'User'),
                    'success': False
                })
        else:
            # Non-streaming response
            # Use the MCP token that was just created or retrieved from session
            result = send_message_to_llama_stack(message, bearer_token, session.get('user_email', ''), mcp_token)
            
            if result['success']:
                return jsonify({
                    'response': result['response'],
                    'user': session.get('user_name', 'User'),
                    'success': True
                })
            else:
                # Check if this is a Llama Stack authorization error that needs scope exchange
                if result.get('error_type') == 'llama_authorization_error':
                    error_details = result.get('error_details', {})
                    tool_name = error_details.get('tool_name', 'llama_stack_api')
                    required_scope = error_details.get('required_scope', 'llama:agent_create')
                    llama_scopes = error_details.get('llama_scopes', [required_scope])
                    
                    logger.info(f"🔍 Llama Stack scope error in non-streaming mode: tool_name={tool_name}, required_scope={required_scope}, llama_scopes={llama_scopes}")
                    
                    # Try to exchange token for the required scopes
                    try:
                        from api.tokens import exchange_token_for_audience
                        import asyncio
                        
                        access_token = session.get('access_token')
                        if not access_token:
                            return jsonify({
                                'response': "❌ Authentication error - please re-login",
                                'user': session.get('user_name', 'User'),
                                'success': False
                            }), 401
                        
                        # Start with basic OIDC scopes and add the required Llama Stack scopes
                        basic_scopes = ['email', 'profile']
                        for scope in llama_scopes:
                            if scope not in basic_scopes:
                                basic_scopes.append(scope)
                        
                        logger.info(f"🔍 Requesting Llama Stack scopes: {basic_scopes}")
                        
                        # Exchange token for new scopes using Keycloak
                        OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "authentication-demo")
                        exchange_result = asyncio.run(exchange_token_for_audience(
                            access_token=access_token,
                            audience=OIDC_CLIENT_ID,  # Self-exchange
                            scopes=basic_scopes
                        ))
                        
                        if exchange_result.get('success'):
                            # Get the new Llama Stack token
                            new_llama_token = exchange_result['access_token']
                            
                            # Store the new token in session
                            session['llama_stack_token'] = new_llama_token
                            logger.info(f"✅ Successfully exchanged token for Llama Stack scopes: {llama_scopes}")
                            
                            # Retry the original request with new token
                            retry_result = send_message_to_llama_stack(message, new_llama_token, session.get('user_email', ''), mcp_token)
                            
                            if retry_result['success']:
                                return jsonify({
                                    'response': f"🔄 **Acquired Llama Stack permissions for `{tool_name}` - retrying...**\n\n{retry_result['response']}",
                                    'user': session.get('user_name', 'User'),
                                    'success': True
                                })
                            else:
                                return jsonify({
                                    'response': f"❌ Llama Stack permission denied for `{tool_name}` after token exchange",
                                    'user': session.get('user_name', 'User'),
                                    'success': False
                                })
                        else:
                            error_msg = exchange_result.get('error', 'Unknown error')
                            logger.error(f"❌ Keycloak token exchange failed for Llama Stack: {error_msg}")
                            return jsonify({
                                'response': f"❌ Llama Stack permission denied for `{tool_name}`. {error_msg}",
                                'user': session.get('user_name', 'User'),
                                'success': False
                            })
                            
                    except Exception as e:
                        logger.error(f"❌ Exception during Llama Stack token exchange: {e}")
                        return jsonify({
                            'response': f"❌ Failed to acquire Llama Stack permission for `{tool_name}`: {str(e)}",
                            'user': session.get('user_name', 'User'),
                            'success': False
                        })
                
                # For other errors, return generic error response
                return jsonify({
                    'response': f"❌ {result.get('response', 'Unknown error')}",
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
            logger.warning("❌ Chat history request: Not authenticated")
            return jsonify({'error': 'Not authenticated'}), 401
        
        user_email = session.get('user_email')
        bearer_token = session.get('llama_stack_token')
        
        if not user_email:
            return jsonify({'error': 'User email not found in session'}), 400
        
        if not bearer_token:
            return jsonify({'error': 'Llama Stack token not found in session'}), 400
        
        logger.info(f"🔍 Chat history request for {user_email}")
        logger.info(f"🔍 Llama Stack token present: {bool(bearer_token)}")
        
        # Get agent and session ID (this will check cache first, then Flask session)
        logger.info(f"🔄 Getting agent and session for {user_email}")
        agent, session_id = get_or_create_session_for_user(user_email, bearer_token)
        
        logger.info(f"🔍 Agent created: {bool(agent)}")
        logger.info(f"🔍 Session ID returned: {session_id}")
        
        if not agent or not session_id:
            logger.warning(f"⚠️ Could not get agent/session for {user_email}")
            return jsonify({
                'status': 'success',
                'messages': [],
                'message': 'Session not available'
            })
        
        # Query Llama Stack's kvstore database directly for turn data
        try:
            logger.info(f"📚 Attempting to retrieve session messages from kvstore database")
            
            # Connect to Llama Stack's kvstore database
            db_path = KVSTORE_DB_PATH
            if not os.path.exists(db_path):
                logger.warning(f"⚠️ kvstore.db not found at {db_path}")
                return jsonify({
                    'status': 'success',
                    'messages': [],
                    'message': 'No chat history database found'
                })
            
            logger.info(f"🔍 Using kvstore database at: {db_path}")
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Find all turn keys for this session
            session_pattern = f"session:{agent.agent_id}:{session_id}:%"
            logger.info(f"🔍 Searching for session pattern: {session_pattern}")
            
            cursor.execute("""
                SELECT key, value FROM kvstore 
                WHERE key LIKE ? AND key NOT LIKE '%num_infer_iters_in_turn%'
            """, (session_pattern,))
            
            turn_data = cursor.fetchall()
            conn.close()
            
            logger.info(f"🔍 Found {len(turn_data)} turn records in database")
            
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
            
            logger.info(f"✅ Retrieved {len(messages)} messages from session {session_id}")
            return jsonify({
                'status': 'success',
                'messages': messages,
                'session_id': session_id
            })
                
        except Exception as db_error:
            logger.error(f"❌ Error querying kvstore database: {db_error}")
            import traceback
            traceback.print_exc()
            return jsonify({
                'status': 'success',
                'messages': [],
                'message': f'Could not retrieve session: {str(db_error)}'
            })
        
    except Exception as e:
        logger.error(f"❌ Error getting chat history: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/clear-chat-history', methods=['POST'])
def clear_chat_history():
    """Clear chat history for the current user"""
    try:
        # Check authentication
        if not session.get('authenticated'):
            return jsonify({'error': 'Not authenticated'}), 401
        
        user_email = session.get('user_email')
        bearer_token = session.get('llama_stack_token')
        
        if not user_email:
            return jsonify({'error': 'User email not found in session'}), 400
        
        if not bearer_token:
            return jsonify({'error': 'Llama Stack token not found in session'}), 400
        
        logger.info(f"🗑️ Clearing chat history for {user_email}")
        
        # Get current agent and session ID
        agent, session_id = get_or_create_session_for_user(user_email, bearer_token)
        
        if not agent or not session_id:
            logger.warning(f"⚠️ No active session found for {user_email}")
            return jsonify({
                'success': True,
                'message': 'No active session to clear'
            })
        
        try:
            # Connect to Llama Stack's kvstore database
            db_path = KVSTORE_DB_PATH
            if not os.path.exists(db_path):
                logger.warning(f"⚠️ kvstore.db not found at {db_path}")
                return jsonify({
                    'success': True,
                    'message': 'No chat history database found to clear'
                })
            
            logger.info(f"🔍 Clearing history from kvstore database at: {db_path}")
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Delete all turn data for this session
            session_pattern = f"session:{agent.agent_id}:{session_id}:%"
            logger.info(f"🗑️ Deleting records matching pattern: {session_pattern}")
            
            cursor.execute("""
                DELETE FROM kvstore 
                WHERE key LIKE ?
            """, (session_pattern,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            logger.info(f"✅ Deleted {deleted_count} records from kvstore database")
            
            # Clear the session from our cache and Flask session to force a new session
            from utils.llama_agents_utils import clear_user_session
            clear_user_session(user_email)
            
            return jsonify({
                'success': True,
                'message': f'Chat history cleared ({deleted_count} records deleted)',
                'deleted_count': deleted_count
            })
            
        except Exception as db_error:
            logger.error(f"❌ Error clearing chat history from database: {db_error}")
            import traceback
            traceback.print_exc()
            return jsonify({
                'success': False,
                'message': f'Failed to clear chat history: {str(db_error)}'
            }), 500
        
    except Exception as e:
        logger.error(f"❌ Error clearing chat history: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/consent-response', methods=['POST'])
def handle_consent_response():
    """Handle user consent response for scope upgrade"""
    try:
        data = request.get_json()
        consent_id = data.get('consent_id')
        approved = data.get('approved', False)
        
        logger.info(f"Consent response received: consent_id={consent_id}, approved={approved}")
        
        if not consent_id:
            return jsonify({'status': 'error', 'message': 'Missing consent_id'}), 400
        
        # Update consent response in auth server database
        try:
            import httpx
            import asyncio
            
            async def update_consent_response():
                async with httpx.AsyncClient() as client:
                    response = await client.put(
                        f'http://localhost:8002/api/consent-requests/{consent_id}',
                        json={
                            'status': 'completed' if approved else 'denied',
                            'response': approved
                        },
                        timeout=5.0
                    )
                    return response.status_code, response.json() if response.status_code == 200 else None
            
            status_code, result = asyncio.run(update_consent_response())
            
            if status_code == 200:
                logger.info(f"✅ Updated consent {consent_id} in auth server: {approved}")
                return jsonify({'status': 'success', 'message': 'Consent response recorded'})
            else:
                logger.error(f"❌ Failed to update consent in auth server: {status_code}")
                return jsonify({'status': 'error', 'message': 'Failed to update consent'}), 500
                
        except Exception as e:
            logger.error(f"❌ Error calling auth server: {e}")
            return jsonify({'status': 'error', 'message': 'Auth server error'}), 500
        
    except Exception as e:
        logger.error(f"Error handling consent response: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500 