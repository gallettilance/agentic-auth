"""
MCP token management utilities
Handles MCP token storage, retrieval, and scope upgrades for Keycloak.
"""

import httpx
import asyncio
import logging
import json
import os
import sys
from typing import Dict, Optional
from flask import session

logger = logging.getLogger(__name__)

def get_base_mcp_url(mcp_server_url: str) -> str:
    """Get base MCP URL by stripping /sse suffix if present"""
    if mcp_server_url.endswith('/sse'):
        return mcp_server_url[:-4]
    return mcp_server_url

def get_mcp_tokens_for_user_direct(user_email: str) -> dict:
    """Get MCP tokens for a user from Flask session (Keycloak edition)"""
    logger.info(f"🔍 === get_mcp_tokens_for_user_direct START for {user_email} ===")
    
    try:
        # Get MCP token from Flask session (exchanged during login)
        mcp_token = session.get('mcp_token')
        
        if mcp_token:
            # Return tokens for the configured MCP server
            tokens = {
                "http://localhost:8001": mcp_token  # Default MCP server
            }
            logger.info(f"🔐 Retrieved MCP token for {user_email} from session")
            logger.info(f"🔍 === get_mcp_tokens_for_user_direct END for {user_email} (success) ===")
            return tokens
        else:
            logger.warning(f"⚠️ No MCP token found in session for {user_email}")
            logger.info(f"🔍 === get_mcp_tokens_for_user_direct END for {user_email} (no token) ===")
            return {}
    
    except Exception as e:
        logger.error(f"❌ Error retrieving MCP tokens for {user_email}: {e}")
        import traceback
        logger.error(f"❌ Full traceback: {traceback.format_exc()}")
        logger.info(f"🔍 === get_mcp_tokens_for_user_direct END for {user_email} (exception) ===")
        return {}

def store_mcp_token_for_user_direct(user_email: str, server_url: str, token: str):
    """Store MCP token for user in Flask session (Keycloak edition)"""
    try:
        # Store in Flask session
        session['mcp_token'] = token
        logger.info(f"🔐 Stored MCP token for {user_email} in session")
        return True
    except Exception as e:
        logger.error(f"❌ Error storing MCP token for {user_email}: {e}")
        return False

def generate_initial_no_scope_token(user_email: str, bearer_token: str) -> bool:
    """
    Generate initial no-scope token for MCP server access
    
    DEPRECATED: This function is deprecated. MCP tokens are now generated
    via Keycloak token exchange during login.
    """
    logger.info(f"🎫 === generate_initial_no_scope_token START for {user_email} ===")
    logger.info(f"🎫 generate_initial_no_scope_token is deprecated - MCP tokens now generated via Keycloak")
    logger.info(f"🎫 === generate_initial_no_scope_token END for {user_email} (DEPRECATED) ===")
    
    # Return True to maintain compatibility with existing code
    return True

def prepare_mcp_headers_for_user(user_email: str, mcp_token: Optional[str] = None) -> dict:
    """
    Prepare MCP headers for a user by using the provided MCP token or getting it from Flask session
    """
    logger.info(f"🔍 === prepare_mcp_headers_for_user START for {user_email} ===")
    
    try:
        # Use provided token or try to get from Flask session
        if not mcp_token:
            try:
                mcp_token = session.get('mcp_token')
            except RuntimeError:
                # Outside request context - token must be provided
                logger.warning(f"⚠️ No MCP token provided and outside request context for {user_email}")
                logger.info(f"🔍 === prepare_mcp_headers_for_user END for {user_email} (no context) ===")
                return {}
        
        logger.info(f"🔍 DEBUG: Found MCP token: {bool(mcp_token)}")
        
        if mcp_token and mcp_token != "NO_TOKEN_YET":
            # Build headers for the MCP server
            mcp_server_url = "http://localhost:8001"
            mcp_endpoint_url = f"{mcp_server_url}/sse"
            
            mcp_headers = {
                mcp_endpoint_url: {
                    "Authorization": f"Bearer {mcp_token}"
                }
            }
            
            logger.info(f"🔐 Added MCP header for {mcp_endpoint_url}: Bearer {mcp_token[:20]}...")
            
            # Format headers for Llama Stack
            headers = {
                "X-LlamaStack-Provider-Data": json.dumps({
                    "mcp_headers": mcp_headers
                })
            }
            logger.info(f"🔐 Returning MCP headers for {user_email}")
            logger.info(f"🔍 === prepare_mcp_headers_for_user END for {user_email} (with headers) ===")
            return headers
        else:
            logger.info(f"🔐 No MCP token for {user_email} - agent will call MCP tools without auth")
            logger.info(f"🔍 === prepare_mcp_headers_for_user END for {user_email} (no headers) ===")
            return {}
    
    except Exception as e:
        logger.error(f"❌ Error preparing MCP headers for {user_email}: {e}")
        import traceback
        logger.error(f"❌ Full traceback: {traceback.format_exc()}")
        logger.info(f"🔍 === prepare_mcp_headers_for_user END for {user_email} (exception) ===")
        return {} 