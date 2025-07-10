"""
API routes for tools, tokens, approvals, etc.
"""

import logging
from fastapi import APIRouter, HTTPException, Request, Depends, Form
from fastapi.responses import JSONResponse
from auth.session_manager import verify_user_auth
from models.schemas import TokenPayload
from utils.mcp_utils import get_registered_tools, get_user_tool_access, validate_tool_access
from utils.approval_utils import (
    evaluate_approval_policy, create_approval_request, get_pending_approvals,
    approve_request, deny_request
)
from utils.jwt_utils import generate_token, build_jwt_io_url, get_public_key_pem
from database import auth_db
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/user-status")
async def get_user_status(user: TokenPayload = Depends(verify_user_auth)):
    """Get current user status"""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        # Get user from database
        db_user = auth_db.get_user(user.email)
        user_roles = db_user.roles if db_user else []
        is_admin = "admin" in user_roles
        
        # Get user's approved scopes from database (not just current token scopes)
        approved_scopes = auth_db.get_user_all_scopes(user.email)
        
        # Also get current token scopes for comparison
        current_token_scopes = user.scope.split() if user.scope else []
        
        return {
            "authenticated": True,
            "user": {
                "sub": user.sub,
                "email": user.email,
                "roles": user_roles,
                "is_admin": is_admin
            },
            "scopes": approved_scopes,  # Return approved scopes from database
            "current_token_scopes": current_token_scopes,  # Also include current token scopes
            "token_expires": user.exp
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to get user status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/tools")
async def get_user_tools(user: TokenPayload = Depends(verify_user_auth)):
    """Get available tools for the user"""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        # Get registered tools from database
        registered_tools = await get_registered_tools()
        
        # Get user scopes
        user_scopes = user.scope.split() if user.scope else []
        
        # Determine tool access
        tool_access = get_user_tool_access(user_scopes, registered_tools)
        
        # Generate current token if user has scopes
        current_token = None
        if user_scopes:
            current_token = generate_token(user, user_scopes)
        
        return {
            "tools": tool_access,
            "user_scopes": user_scopes,
            "current_token": current_token
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to get user tools: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/test-tool")
async def api_test_tool(
    request: Request,
    user: TokenPayload = Depends(verify_user_auth)
):
    """Validate user access to a tool"""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        data = await request.json()
        tool_name = data.get('tool_name')
        
        if not tool_name:
            raise HTTPException(status_code=400, detail="tool_name is required")
        
        # Get user scopes
        user_scopes = user.scope.split() if user.scope else []
        
        # Validate tool access
        result = await validate_tool_access(tool_name, user_scopes)
        
        return result
        
    except Exception as e:
        logger.error(f"❌ Tool validation failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/upgrade-scope")
async def upgrade_scope(
    request: Request,
    user: TokenPayload = Depends(verify_user_auth)
):
    """Request scope upgrade"""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        data = await request.json()
        scopes = data.get('scopes', [])
        justification = data.get('justification', 'User requested additional permissions')
        current_token = data.get('current_token')  # Current MCP token to upgrade
        resource_uri = data.get('resource')  # MCP server URI that needs the scope
        
        logger.info(f"🔄 Scope upgrade request from {user.email} for scopes: {scopes}, resource: {resource_uri}")
        
        if not scopes:
            raise HTTPException(status_code=400, detail="No scopes requested")
        
        # Evaluate approval policy
        policy_result = evaluate_approval_policy(user.email, scopes)
        
        auto_approved = policy_result['auto_approved']
        requires_approval = policy_result['requires_approval']
        
        logger.info(f"📋 Policy result: auto_approved={auto_approved}, requires_approval={requires_approval}")
        
        approval_request_ids = []
        
        # Create approval requests for scopes that require approval
        for scope in requires_approval:
            approval_request = create_approval_request(
                user_email=user.email,
                user_id=user.sub,
                tool_name=scope,  # Assuming scope name = tool name
                required_scope=scope,
                justification=justification,
                resource_uri=resource_uri  # Pass the MCP server URI
            )
            approval_request_ids.append(approval_request.request_id)
        
        # Get current scopes from the provided MCP token (if any)
        current_scopes = []
        if current_token:
            try:
                # Decode the current MCP token to get its scopes
                import jwt
                from utils.jwt_utils import get_jwt_key_for_verification, get_jwt_algorithm
                
                # Decode without verification first to get the payload
                unverified_payload = jwt.decode(current_token, options={"verify_signature": False})
                current_scope_str = unverified_payload.get('scope', '')
                current_scopes = current_scope_str.split() if current_scope_str else []
                logger.info(f"🔍 Extracted current scopes from MCP token: {current_scopes}")
                
            except Exception as e:
                logger.warning(f"⚠️ Failed to decode current MCP token: {e}")
                current_scopes = []
        else:
            # IMPORTANT: Use user's total approved scopes from database, not just session token scopes
            # This ensures all previously approved scopes are included in the new token
            current_scopes = auth_db.get_user_all_scopes(user.email)
            logger.info(f"🔍 Using user's approved scopes from database: {current_scopes}")
        
        # Combine current scopes with auto-approved scopes
        new_scopes = list(set(current_scopes + auto_approved))
        
        logger.info(f"🔍 DEBUG: current_scopes={current_scopes}, auto_approved={auto_approved}, new_scopes={new_scopes}")
        
        # Generate new token with updated scopes if any were auto-approved
        new_token = None
        if auto_approved:
            user.scope = ' '.join(new_scopes)
            # In production, you might want to update the database as well
        
            # Generate new token with updated scopes
            # Get the audience from the request data (for MCP tokens)
            audience = data.get('resource')  # Remove hardcoded fallback
            if audience:
                new_token = generate_token(user, new_scopes, audience)
                logger.info(f"✅ Generated new token for {user.email} with scopes: {new_scopes}, audience: {audience}")
                
                # CRITICAL FIX: Store the new token back in the database
                success = auth_db.store_mcp_token(user.email, audience, new_token)
                if success:
                    logger.info(f"🔐 Updated stored MCP token for {user.email} -> {audience}")
                else:
                    logger.error(f"❌ Failed to store updated MCP token for {user.email} -> {audience}")
            else:
                logger.warning("⚠️ No audience specified for token generation")
        
        return {
            "success": True,
            "auto_approved_scopes": auto_approved,
            "pending_approval_scopes": requires_approval,
            "approval_request_ids": approval_request_ids,
            "new_token": new_token,
            "message": f"Scope upgrade processed. {len(auto_approved)} scopes auto-approved, {len(requires_approval)} require manual approval."
        }
        
    except Exception as e:
        logger.error(f"❌ Scope upgrade failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/approve/{request_id}")
async def approve_approval_request(
    request_id: str,
    admin_email: str = Form(...),
    user: TokenPayload = Depends(verify_user_auth)
):
    """Approve a pending request"""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Check if user is admin
    db_user = auth_db.get_user(user.email)
    if not db_user or not db_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    try:
        success = approve_request(request_id, admin_email)
        
        if success:
            return {"message": "Request approved successfully"}
        else:
            raise HTTPException(status_code=404, detail="Request not found or already processed")
            
    except Exception as e:
        logger.error(f"❌ Approval failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/deny/{request_id}")
async def deny_approval_request(
    request_id: str,
    reason: str = Form(...),
    admin_email: str = Form(...),
    user: TokenPayload = Depends(verify_user_auth)
):
    """Deny a pending request"""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Check if user is admin
    db_user = auth_db.get_user(user.email)
    if not db_user or not db_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    try:
        success = deny_request(request_id, admin_email, reason)
        
        if success:
            return {"message": "Request denied successfully"}
        else:
            raise HTTPException(status_code=404, detail="Request not found or already processed")
            
    except Exception as e:
        logger.error(f"❌ Denial failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/admin/pending-approvals")
async def get_admin_pending_approvals(user: TokenPayload = Depends(verify_user_auth)):
    """Get pending approval requests for admin"""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Check if user is admin
    db_user = auth_db.get_user(user.email)
    if not db_user or not db_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    
    try:
        pending_approvals = get_pending_approvals()
        return {"approvals": pending_approvals}
        
    except Exception as e:
        logger.error(f"❌ Failed to get pending approvals: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/jwt-debug-url")
async def get_jwt_debug_url(user: TokenPayload = Depends(verify_user_auth)):
    """Get JWT.io debug URL for current token"""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        # Generate token with current scopes
        user_scopes = user.scope.split() if user.scope else []
        if not user_scopes:
            return {"debug_url": None, "message": "No scopes available"}
        
        token = generate_token(user, user_scopes)
        debug_url = build_jwt_io_url(token)
        
        return {"debug_url": debug_url, "token": token}
        
    except Exception as e:
        logger.error(f"❌ Failed to generate debug URL: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/public-key")
async def get_public_key_for_copy():
    """Get public key for copying"""
    try:
        public_key_pem = get_public_key_pem()
        if public_key_pem:
            return {"public_key": public_key_pem}
        else:
            raise HTTPException(status_code=500, detail="Public key not available")
    except Exception as e:
        logger.error(f"❌ Failed to get public key: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/initial-token")
async def get_initial_token(
    request: Request,
    user: TokenPayload = Depends(verify_user_auth)
):
    """Get initial token for MCP server access with proper approval checks"""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        data = await request.json()
        resource = data.get('resource')  # MCP server URI
        requested_scopes = data.get('scopes', [])  # Requested scopes
        
        if not resource:
            raise HTTPException(status_code=400, detail="Resource URI is required")
        
        logger.info(f"🎫 Initial token request from {user.email} for resource: {resource}, scopes: {requested_scopes}")
        
        # SECURITY FIX: Evaluate approval policy for requested scopes
        if requested_scopes:
            policy_result = evaluate_approval_policy(user.email, requested_scopes)
            auto_approved = policy_result['auto_approved']
            requires_approval = policy_result['requires_approval']
            
            logger.info(f"📋 Policy result: auto_approved={auto_approved}, requires_approval={requires_approval}")
            
            if requires_approval:
                # Cannot generate initial token with scopes that require approval
                logger.warning(f"⚠️ Initial token request denied - scopes require approval: {requires_approval}")
                raise HTTPException(
                    status_code=403, 
                    detail={
                        "error": "scope_approval_required",
                        "message": f"Scopes require admin approval: {', '.join(requires_approval)}",
                        "auto_approved_scopes": auto_approved,
                        "requires_approval_scopes": requires_approval,
                        "resource": resource
                    }
                )
            
            # Use only auto-approved scopes
            token_scopes = auto_approved
        else:
            # No scopes requested - generate empty token
            token_scopes = []
        
        # Generate token for the specific resource with only approved scopes
        logger.info(f"🎯 DEBUG: Token generation - resource: {resource}, audience: {resource}")
        token = generate_token(user, token_scopes, audience=resource)
        
        # Store the token in the database for future retrieval
        success = auth_db.store_mcp_token(user.email, resource, token)
        if success:
            logger.info(f"🔐 Stored initial MCP token for {user.email} -> {resource}")
        else:
            logger.warning(f"⚠️ Failed to store initial MCP token for {user.email} -> {resource}")
        
        logger.info(f"✅ Generated initial token for {user.email} with approved scopes: {token_scopes}")
        
        return {
            "success": True,
            "token": token,
            "scopes": token_scopes,
            "resource": resource,
            "message": f"Initial token generated with approved scopes: {', '.join(token_scopes) if token_scopes else 'none'}"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Initial token generation failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/check-token-update")
async def check_token_update(user: TokenPayload = Depends(verify_user_auth)):
    """Check if user's token needs to be updated"""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        # Check if user has pending token updates in database
        pending_update = auth_db.get_pending_token_update(user.email)
        
        if not pending_update:
            # No updates needed
            return {
                "update_needed": False,
                "has_updates": False,
                "current_scopes": user.scope.split() if user.scope else [],
                "message": "Token is up to date"
            }
        
        # User has pending updates - generate new token with updated scopes
        new_scopes = pending_update['new_scopes']
        approval_type = pending_update['approval_type']
        
        # IMPORTANT: Get user's total approved scopes from database, not just current token scopes
        # This ensures scopes are additive - new approvals add to existing ones
        current_scopes = auth_db.get_user_all_scopes(user.email)
        logger.info(f"🔍 User {user.email} current approved scopes from database: {current_scopes}")
        
        # Add the newly approved scopes to current scopes
        updated_scopes = current_scopes.copy()
        for scope in new_scopes:
            if scope not in updated_scopes:
                updated_scopes.append(scope)
        
        logger.info(f"🔍 Final updated scopes for {user.email}: current={current_scopes} + new={new_scopes} = total={updated_scopes}")
        
        # Generate new tokens with updated scopes
        from utils.jwt_utils import generate_token
        
        # IMPORTANT: Separate scopes by audience
        # Llama Stack tokens should only have general user permissions, not tool-specific scopes
        # MCP tokens should have the tool-specific scopes
        
        # Define what scopes are appropriate for Llama Stack vs MCP servers
        # Llama Stack scopes: general user permissions, admin, etc.
        # MCP scopes: tool names like execute_command, list_files, etc.
        
        # For now, assume tool-specific scopes (that match common tool names) are MCP scopes
        common_tool_scopes = {'execute_command', 'list_files', 'read_file', 'write_file', 'delete_file', 'search_files', 'get_system_info'}
        
        # Separate scopes
        llama_stack_scopes = [scope for scope in updated_scopes if scope not in common_tool_scopes]
        mcp_scopes = [scope for scope in updated_scopes if scope in common_tool_scopes]
        
        logger.info(f"🔍 Separated scopes - Llama Stack: {llama_stack_scopes}, MCP: {mcp_scopes}")
        
        # For token refresh, generate a Llama Stack token for the session with only appropriate scopes
        llama_stack_audience = "http://localhost:8321"
        session_token = generate_token(user, llama_stack_scopes, audience=llama_stack_audience)
        
        # Also generate MCP token for the requesting MCP server (if specified in approval)
        mcp_audience = pending_update.get('audience')
        mcp_token = None
        if mcp_audience and mcp_scopes:
            mcp_token = generate_token(user, mcp_scopes, audience=mcp_audience)
            logger.info(f"🎫 Generated MCP token for {user.email} with audience: {mcp_audience}")
        
        # Clear the pending update since we're generating the tokens
        auth_db.clear_pending_token_update(user.email)
        
        logger.info(f"🎫 Generated updated tokens for {user.email} with scopes: {updated_scopes}")
        
        response_data = {
            "update_needed": True,
            "has_updates": True,
            "new_scopes": new_scopes,
            "total_scopes": updated_scopes,
            "new_token": session_token,  # This is the Llama Stack session token
            "audience": llama_stack_audience,
            "approval_type": approval_type,
            "has_manual_approvals": approval_type == 'manual',
            "has_auto_approvals": approval_type == 'auto',
            "message": f"Token updated with new scopes: {', '.join(new_scopes)}"
        }
        
        # Add MCP token info if available
        if mcp_token and mcp_audience:
            response_data["mcp_token"] = mcp_token
            response_data["mcp_audience"] = mcp_audience
        
        return response_data
        
    except Exception as e:
        logger.error(f"❌ Failed to check token update: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/user-mcp-tokens")
async def get_user_mcp_tokens(user_email: str):
    """Get MCP tokens for a user"""
    try:
        # Get tokens from database
        tokens = auth_db.get_mcp_tokens(user_email)
        
        logger.info(f"🔐 Retrieved {len(tokens)} MCP tokens for {user_email}")
        
        return {
            "success": True,
            "tokens": tokens,
            "user_email": user_email
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to get MCP tokens for {user_email}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error") 