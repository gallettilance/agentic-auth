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

# Global MCP token cache to track updated tokens
mcp_tokens = {}  # {user_email: current_token}

def update_mcp_token_cache(user_email: str, token: str):
    """Update the MCP token cache for a user"""
    global mcp_tokens
    old_token = mcp_tokens.get(user_email)
    mcp_tokens[user_email] = token
    
    # Log token change details
    if old_token != token:
        logger.info(f"🔄 MCP TOKEN UPDATED for {user_email}")
        logger.info(f"   Old token: {old_token[:20] + '...' if old_token else 'None'}")
        logger.info(f"   New token: {token[:20] + '...' if token else 'None'}")
        
        # Decode and log scope changes
        try:
            import jwt
            if old_token:
                old_decoded = jwt.decode(old_token, options={"verify_signature": False})
                old_scopes = old_decoded.get('scope', '').split()
                logger.info(f"   Old scopes: {old_scopes}")
            else:
                old_scopes = []
                logger.info(f"   Old scopes: None")
                
            if token:
                new_decoded = jwt.decode(token, options={"verify_signature": False})
                new_scopes = new_decoded.get('scope', '').split()
                logger.info(f"   New scopes: {new_scopes}")
                
                # Log scope changes
                added_scopes = [s for s in new_scopes if s not in old_scopes]
                removed_scopes = [s for s in old_scopes if s not in new_scopes]
                if added_scopes:
                    logger.info(f"   ➕ Added scopes: {added_scopes}")
                if removed_scopes:
                    logger.info(f"   ➖ Removed scopes: {removed_scopes}")
            else:
                logger.info(f"   New scopes: None")
        except Exception as e:
            logger.warning(f"   ⚠️ Could not decode token for scope comparison: {e}")
    else:
        logger.debug(f"🔄 MCP token cache updated (no change) for {user_email}")
    
    # Also try to update Flask session if in request context
    try:
        session['mcp_token'] = token
        logger.info(f"🔄 Updated Flask session with MCP token for {user_email}")
    except RuntimeError:
        # Not in request context, skip session update
        logger.info(f"🔄 MCP token updated (not in request context)")

def get_current_mcp_token(user_email: str) -> Optional[str]:
    """Get the current MCP token for a user"""
    global mcp_tokens
    token = mcp_tokens.get(user_email)
    
    logger.debug(f"🔍 get_current_mcp_token for {user_email}: type={type(token)}, value={token}")
    
    if token:
        logger.debug(f"🔍 Retrieved MCP token from cache for {user_email}: {token[:20]}...")
    else:
        logger.debug(f"🔍 No MCP token in cache for {user_email}")
    
    return token

def get_base_mcp_url(mcp_server_url: str) -> str:
    """Get base MCP URL by stripping /sse suffix if present"""
    if mcp_server_url.endswith('/sse'):
        return mcp_server_url[:-4]
    return mcp_server_url

def get_mcp_tokens_for_user_direct(user_email: str) -> dict:
    """Get MCP tokens for a user from Flask session (Keycloak edition)"""
    logger.info(f"🔍 === get_mcp_tokens_for_user_direct START for {user_email} ===")
    
    # Debug: Print stack trace to see where this is called from
    import traceback
    logger.info(f"🔍 DEBUG: get_mcp_tokens_for_user_direct called from:")
    for line in traceback.format_stack()[-3:-1]:  # Show last 2 stack frames (excluding current)
        logger.info(f"   {line.strip()}")
    
    try:
        # Get MCP token from Flask session (exchanged during login)
        try:
            mcp_token = session.get('mcp_token')
        except RuntimeError:
            # Outside request context - return empty tokens
            logger.warning(f"⚠️ Cannot access Flask session outside request context for {user_email}")
            logger.info(f"🔍 === get_mcp_tokens_for_user_direct END for {user_email} (no context) ===")
            return {}
        
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
    """Store MCP token for user in Flask session and cache (Keycloak edition)"""
    try:
        logger.info(f"🔐 STORING MCP TOKEN for {user_email}")
        logger.info(f"   Server URL: {server_url}")
        logger.info(f"   Token: {token[:20] + '...' if token else 'None'}")
        
        # Update the cache first
        update_mcp_token_cache(user_email, token)
        
        # Store in Flask session
        session['mcp_token'] = token
        logger.info(f"🔐 Stored MCP token for {user_email} in session and cache")
        
        # Log the final token state
        try:
            import jwt
            decoded = jwt.decode(token, options={"verify_signature": False})
            scopes = decoded.get('scope', '').split()
            logger.info(f"   Final token scopes: {scopes}")
        except Exception as e:
            logger.warning(f"   ⚠️ Could not decode token: {e}")
        
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
    
    # Debug: Print stack trace to see where this is called from
    import traceback
    logger.info(f"🔍 DEBUG: prepare_mcp_headers_for_user called from:")
    for line in traceback.format_stack()[-3:-1]:  # Show last 2 stack frames (excluding current)
        logger.info(f"   {line.strip()}")
    
    try:
        # Use provided token or try to get from Flask session
        if not mcp_token:
            try:
                mcp_token = session.get('mcp_token')
                logger.info(f"🔍 Retrieved MCP token from session for {user_email}")
            except RuntimeError:
                # Outside request context - token must be provided
                logger.warning(f"⚠️ No MCP token provided and outside request context for {user_email}")
                logger.info(f"🔍 === prepare_mcp_headers_for_user END for {user_email} (no context) ===")
                return {}
        else:
            logger.info(f"🔍 Using provided MCP token for {user_email}")
        
        logger.info(f"🔍 DEBUG: Found MCP token: {bool(mcp_token)}")
        
        if mcp_token and mcp_token != "NO_TOKEN_YET":
            # Log token details
            try:
                import jwt
                decoded = jwt.decode(mcp_token, options={"verify_signature": False})
                scopes = decoded.get('scope', '').split()
                logger.info(f"🔍 MCP token scopes for {user_email}: {scopes}")
            except Exception as e:
                logger.warning(f"⚠️ Could not decode MCP token: {e}")
            
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