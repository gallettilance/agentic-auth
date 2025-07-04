"""
Pydantic models and data structures for the auth server
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
from pydantic import BaseModel

# Enums
class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Data classes
@dataclass
class ApprovalRequest:
    """Approval request data structure"""
    request_id: str
    user_email: str
    user_id: str
    tool_name: str
    required_scope: str
    risk_level: RiskLevel
    justification: str
    requested_at: datetime
    expires_at: datetime
    status: ApprovalStatus
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    denied_by: Optional[str] = None
    denied_at: Optional[datetime] = None
    denial_reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

# Pydantic models
class TokenPayload(BaseModel):
    sub: str
    aud: str
    email: str
    scope: str
    exp: int
    iat: int
    iss: str

class ProtectedResourceMetadata(BaseModel):
    resource: str
    authorization_servers: List[str]
    scopes_supported: Optional[List[str]] = None
    bearer_methods_supported: Optional[List[str]] = None
    resource_documentation: Optional[str] = None

class GoogleDiscoveryDocument(BaseModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str

class ApprovalRequestModel(BaseModel):
    user_email: str
    user_id: str
    tool_name: str
    required_scope: str
    risk_level: str
    justification: str
    callback_url: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

# RFC 7591 Dynamic Client Registration Models
class ClientRegistrationRequest(BaseModel):
    """RFC 7591 Dynamic Client Registration Request"""
    client_name: Optional[str] = None
    client_uri: Optional[str] = None
    redirect_uris: List[str] = []
    grant_types: List[str] = ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"]
    response_types: List[str] = ["code"]
    scope: Optional[str] = None
    contacts: List[str] = []
    logo_uri: Optional[str] = None
    policy_uri: Optional[str] = None
    tos_uri: Optional[str] = None
    client_type: str = "confidential"  # confidential or public

class ClientRegistrationResponse(BaseModel):
    """RFC 7591 Dynamic Client Registration Response"""
    client_id: str
    client_secret: Optional[str] = None
    client_id_issued_at: int
    client_secret_expires_at: int
    client_name: Optional[str] = None
    client_uri: Optional[str] = None
    redirect_uris: List[str] = []
    grant_types: List[str] = []
    response_types: List[str] = []
    scope: Optional[str] = None
    # Additional metadata
    registration_access_token: Optional[str] = None
    registration_client_uri: Optional[str] = None 