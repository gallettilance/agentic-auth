"""
API routes for tools, tokens, approvals, etc.
"""

import logging
from fastapi import APIRouter, HTTPException, Request, Depends, Form
from fastapi.responses import JSONResponse
from auth.session_manager import verify_user_auth
from models.schemas import TokenPayload
from utils.mcp_utils import fetch_mcp_tools, get_user_tool_access, test_mcp_tool
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
        
        return {
            "authenticated": True,
            "user": {
                "sub": user.sub,
                "email": user.email,
                "roles": user_roles,
                "is_admin": is_admin
            },
            "scopes": user.scope.split() if user.scope else [],
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
        # Fetch MCP tools
        mcp_tools = await fetch_mcp_tools(user)
        
        # Get user scopes
        user_scopes = user.scope.split() if user.scope else []
        
        # Determine tool access
        tool_access = get_user_tool_access(user_scopes, mcp_tools)
        
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
    """Test an MCP tool"""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        data = await request.json()
        tool_name = data.get('tool_name')
        
        if not tool_name:
            raise HTTPException(status_code=400, detail="tool_name is required")
        
        # Get user scopes
        user_scopes = user.scope.split() if user.scope else []
        
        # Test the tool
        result = await test_mcp_tool(tool_name, user_scopes)
        
        return result
        
    except Exception as e:
        logger.error(f"❌ Tool test failed: {e}")
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
        
        logger.info(f"🔄 Scope upgrade request from {user.email} for scopes: {scopes}")
        
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
                justification=justification
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
            # Fall back to auth session token scopes (usually empty)
            current_scopes = user.scope.split() if user.scope else []
            logger.info(f"🔍 Using auth session scopes: {current_scopes}")
        
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
            audience = data.get('resource', 'http://localhost:8001')
            new_token = generate_token(user, new_scopes, audience)
            logger.info(f"✅ Generated new token for {user.email} with scopes: {new_scopes}, audience: {audience}")
        
        response = {
            "status": "pending_admin_approval" if requires_approval else "approved",
            "auto_approved": auto_approved,
            "requires_approval": requires_approval,
            "approval_request_ids": approval_request_ids,
            "message": f"Approval requests created for scopes: {requires_approval}. Request IDs: {approval_request_ids}" if requires_approval else "All scopes auto-approved"
        }
        
        # Include new token in response if scopes were auto-approved
        if new_token:
            response["access_token"] = new_token
            response["token_type"] = "Bearer"
            response["expires_in"] = 3600
            response["scope"] = " ".join(new_scopes)
            logger.info(f"🎫 Returning new token with scopes: {new_scopes}")
        
        return response
        
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
    """Get initial token for user"""
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        data = await request.json()
        audience = data.get('audience', 'llama-stack')
        scopes = data.get('scopes', [])
        
        # Generate token with requested scopes
        token = generate_token(user, scopes, audience)
        
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": " ".join(scopes)
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to generate initial token: {e}")
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
                "current_scopes": user.scope.split() if user.scope else [],
                "message": "Token is up to date"
            }
        
        # User has pending updates - generate new token with updated scopes
        new_scopes = pending_update['new_scopes']
        approval_type = pending_update['approval_type']
        
        # Get user's current scopes from their existing token
        current_scopes = user.scope.split() if user.scope else []
        
        # Add the newly approved scopes to current scopes
        updated_scopes = current_scopes.copy()
        for scope in new_scopes:
            if scope not in updated_scopes:
                updated_scopes.append(scope)
        
        # Generate new token with updated scopes
        from utils.jwt_utils import generate_token
        new_token = generate_token(user, updated_scopes, audience="http://localhost:8001")
        
        # Clear the pending update since we're generating the token
        auth_db.clear_pending_token_update(user.email)
        
        logger.info(f"🎫 Generated updated token for {user.email} with scopes: {updated_scopes}")
        
        return {
            "update_needed": True,
            "has_updates": True,
            "new_scopes": new_scopes,
            "total_scopes": updated_scopes,
            "new_token": new_token,
            "audience": "http://localhost:8001",
            "approval_type": approval_type,
            "has_manual_approvals": approval_type == 'manual',
            "has_auto_approvals": approval_type == 'auto',
            "message": f"Token updated with new scopes: {', '.join(new_scopes)}"
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to check token update: {e}")
        raise HTTPException(status_code=500, detail="Internal server error") 