"""
Approval system utilities
"""

import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Set, Optional
from models.schemas import ApprovalRequest, ApprovalStatus, RiskLevel
from database import auth_db

logger = logging.getLogger(__name__)

# Global approval requests storage (in production, this should be in database)
approval_requests: Dict[str, ApprovalRequest] = {}

def evaluate_approval_policy(user_email: str, requested_scopes: List[str]) -> Dict[str, Any]:
    """Evaluate approval policy for requested scopes"""
    # Use the database's scope policy evaluation system
    result = auth_db.evaluate_scope_request(user_email, requested_scopes)
    
    # Handle errors
    if 'error' in result:
        logger.error(f"Error evaluating approval policy for {user_email}: {result['error']}")
        return {
            'auto_approved': [],
            'requires_approval': requested_scopes,  # Default to requiring approval on error
            'all_approved': False
        }
    
    # Convert denied scopes to requires_approval for backwards compatibility
    denied_scopes = [item['scope'] if isinstance(item, dict) else item for item in result.get('denied', [])]
    requires_approval = result.get('requires_approval', []) + denied_scopes
    
    return {
        'auto_approved': result.get('auto_approved', []),
        'requires_approval': requires_approval,
        'all_approved': len(requires_approval) == 0
    }

def check_existing_approvals(user_email: str, required_scopes: List[str]) -> List[str]:
    """Check for existing approvals for the user and scopes"""
    # This would check the database for existing approvals
    # For now, return empty list
    return []

def create_approval_request(
    user_email: str,
    user_id: str,
    tool_name: str,
    required_scope: str,
    justification: str,
    risk_level: str = "medium",
    resource_uri: Optional[str] = None
) -> ApprovalRequest:
    """Create a new approval request"""
    
    request_id = secrets.token_urlsafe(16)
    
    # Determine risk level
    risk_enum = RiskLevel.MEDIUM
    if risk_level.lower() == "low":
        risk_enum = RiskLevel.LOW
    elif risk_level.lower() == "high":
        risk_enum = RiskLevel.HIGH
    elif risk_level.lower() == "critical":
        risk_enum = RiskLevel.CRITICAL
    
    # Store resource URI in metadata for decoupled architecture
    metadata = {}
    if resource_uri:
        metadata['resource_uri'] = resource_uri
        logger.info(f"📝 Storing resource URI in approval request: {resource_uri}")
    
    # Create approval request
    import time
    now = time.time()
    approval_request = ApprovalRequest(
        request_id=request_id,
        user_email=user_email,
        user_id=user_id,
        tool_name=tool_name,
        required_scope=required_scope,
        risk_level=risk_enum,
        justification=justification,
        requested_at=datetime.fromtimestamp(now),
        expires_at=datetime.fromtimestamp(now + 24*3600),  # 24 hour expiry
        status=ApprovalStatus.PENDING,
        metadata=metadata if metadata else None
    )
    
    # Store in global dict (in production, store in database)
    approval_requests[request_id] = approval_request
    
    # Also store in database for persistence
    try:
        auth_db.create_approval_request(approval_request)
        logger.info(f"📝 Created approval request {request_id} for {user_email} requesting scope: {required_scope}")
    except Exception as e:
        logger.error(f"❌ Failed to store approval request in database: {e}")
    
    return approval_request

def get_pending_approvals() -> List[Dict[str, Any]]:
    """Get all pending approval requests"""
    try:
        # Get from database
        pending_requests = auth_db.get_pending_approval_requests()
        
        # Convert to dict format for API response
        pending_list = []
        for req in pending_requests:
            pending_list.append({
                'request_id': req.request_id,
                'user_email': req.user_email,
                'user_id': req.user_id,
                'tool_name': req.tool_name,
                'required_scope': req.required_scope,
                'risk_level': req.risk_level.value,
                'justification': req.justification,
                'requested_at': req.requested_at.strftime("%Y-%m-%d %H:%M:%S") if req.requested_at else None,
                'expires_at': req.expires_at.strftime("%Y-%m-%d %H:%M:%S") if req.expires_at else None,
                'status': req.status.value
            })
        
        return pending_list
        
    except Exception as e:
        logger.error(f"❌ Failed to get pending approvals: {e}")
        return []

def approve_request(request_id: str, admin_email: str) -> bool:
    """Approve a pending request"""
    try:
        # Get request from database
        request = auth_db.get_approval_request(request_id)
        if not request:
            logger.warning(f"⚠️ Approval request {request_id} not found")
            return False
        
        if request.status != ApprovalStatus.PENDING:
            logger.warning(f"⚠️ Approval request {request_id} is not pending (status: {request.status})")
            return False
        
        # Update request status
        import time
        request.status = ApprovalStatus.APPROVED
        request.approved_by = admin_email
        request.approved_at = datetime.fromtimestamp(time.time())
        
        # Update in database
        auth_db.update_approval_request(request)
        
        # Update in memory
        if request_id in approval_requests:
            approval_requests[request_id] = request
        
        # Add pending token update to database
        user_email = request.user_email
        new_scope = request.required_scope
        
        # Extract resource URI from approval request metadata
        resource_uri = None
        if request.metadata and 'resource_uri' in request.metadata:
            resource_uri = request.metadata['resource_uri']
            logger.info(f"🎫 Using resource URI from approval request: {resource_uri}")
        
        # Get existing pending update or create new one
        existing_update = auth_db.get_pending_token_update(user_email)
        if existing_update:
            # Add new scope to existing update
            new_scopes = existing_update['new_scopes']
            if new_scope not in new_scopes:
                new_scopes.append(new_scope)
        else:
            new_scopes = [new_scope]
        
        # Store the pending update in database with the resource URI
        auth_db.add_pending_token_update(user_email, new_scopes, 'manual', audience=resource_uri)
        
        logger.info(f"✅ Approved request {request_id} by {admin_email}")
        logger.info(f"🎫 Marked {user_email} for token update with scope: {new_scope}, resource: {resource_uri}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to approve request {request_id}: {e}")
        return False

def deny_request(request_id: str, admin_email: str, reason: str) -> bool:
    """Deny a pending request"""
    try:
        # Get request from database
        request = auth_db.get_approval_request(request_id)
        if not request:
            logger.warning(f"⚠️ Approval request {request_id} not found")
            return False
        
        if request.status != ApprovalStatus.PENDING:
            logger.warning(f"⚠️ Approval request {request_id} is not pending (status: {request.status})")
            return False
        
        # Update request status
        import time
        request.status = ApprovalStatus.DENIED
        request.denied_by = admin_email
        request.denied_at = datetime.fromtimestamp(time.time())
        request.denial_reason = reason
        
        # Update in database
        auth_db.update_approval_request(request)
        
        # Update in memory
        if request_id in approval_requests:
            approval_requests[request_id] = request
        
        logger.info(f"❌ Denied request {request_id} by {admin_email}: {reason}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to deny request {request_id}: {e}")
        return False 

 