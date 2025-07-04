# Auth Server Security & Usability Recommendations

**Component**: OAuth 2.1 Authorization Server  
**Role**: Core security infrastructure providing authentication and authorization services  
**Security Level**: **CRITICAL** - Foundation of entire system security

## 🛡️ **Security Recommendations**

### **1. OAuth 2.1 Compliance & Best Practices**

#### **PKCE (Proof Key for Code Exchange) - RFC 7636**
```python
# Mandatory for all OAuth flows, including confidential clients
import secrets
import hashlib
import base64

class PKCEManager:
    """
    PKCE implementation for OAuth 2.1 compliance.
    Required for all authorization code flows.
    """
    
    def generate_code_verifier(self) -> str:
        """Generate cryptographically secure code verifier"""
        # RFC 7636: 43-128 characters, URL-safe
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    def generate_code_challenge(self, verifier: str) -> str:
        """Generate SHA256 code challenge from verifier"""
        digest = hashlib.sha256(verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
    
    def verify_code_challenge(self, verifier: str, challenge: str) -> bool:
        """Verify code verifier matches stored challenge"""
        expected_challenge = self.generate_code_challenge(verifier)
        return secrets.compare_digest(expected_challenge, challenge)
```

#### **Secure Token Generation**
```python
# Cryptographically secure token generation
import jwt
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

class SecureTokenGenerator:
    """
    Secure JWT token generation with proper key management.
    Implements OAuth 2.1 security requirements.
    """
    
    def __init__(self, private_key_path: str, public_key_path: str):
        self.private_key = self.load_private_key(private_key_path)
        self.public_key = self.load_public_key(public_key_path)
        self.algorithm = "RS256"  # Asymmetric signing required
    
    def generate_access_token(
        self, 
        user_id: str, 
        client_id: str, 
        scopes: list, 
        audience: str,
        expires_in: int = 3600
    ) -> str:
        """Generate secure access token with proper claims"""
        now = int(time.time())
        
        payload = {
            # Standard claims (RFC 7519)
            'iss': self.issuer_uri,          # Issuer
            'sub': user_id,                  # Subject (user)
            'aud': audience,                 # Audience (resource server)
            'exp': now + expires_in,         # Expiration time
            'iat': now,                      # Issued at
            'jti': self.generate_jti(),      # JWT ID (unique)
            
            # OAuth-specific claims
            'client_id': client_id,
            'scope': ' '.join(scopes),
            'token_type': 'Bearer',
            
            # Security claims
            'auth_time': now,
            'token_use': 'access'
        }
        
        return jwt.encode(payload, self.private_key, algorithm=self.algorithm)
    
    def generate_refresh_token(self, user_id: str, client_id: str) -> str:
        """Generate secure refresh token"""
        # Refresh tokens should be opaque, not JWT
        return secrets.token_urlsafe(64)
```

#### **Client Authentication Methods**
```python
# Support multiple client authentication methods per OAuth 2.1
class ClientAuthenticator:
    """
    OAuth 2.1 client authentication methods.
    Supports multiple authentication methods for different client types.
    """
    
    def __init__(self):
        self.supported_methods = [
            'client_secret_basic',    # HTTP Basic auth
            'client_secret_post',     # POST body
            'client_secret_jwt',      # JWT with shared secret
            'private_key_jwt',        # JWT with private key
            'none'                    # Public clients with PKCE
        ]
    
    def authenticate_client(self, request_data: dict, headers: dict) -> dict:
        """
        Authenticate client using appropriate method.
        Returns client info or raises AuthenticationError.
        """
        # Try client_secret_basic first (Authorization header)
        if 'Authorization' in headers:
            return self.authenticate_basic(headers['Authorization'])
        
        # Try client_secret_post (request body)
        if 'client_secret' in request_data:
            return self.authenticate_post(request_data)
        
        # Try JWT authentication methods
        if 'client_assertion' in request_data:
            return self.authenticate_jwt(request_data)
        
        # Public client (must have PKCE)
        if 'code_verifier' in request_data:
            return self.authenticate_public(request_data)
        
        raise AuthenticationError("No valid client authentication method found")
    
    def authenticate_basic(self, auth_header: str) -> dict:
        """HTTP Basic authentication"""
        try:
            encoded = auth_header.split(' ')[1]
            decoded = base64.b64decode(encoded).decode('utf-8')
            client_id, client_secret = decoded.split(':', 1)
            
            # Verify client credentials
            client = self.get_client_by_id(client_id)
            if not client or not secrets.compare_digest(client['secret'], client_secret):
                raise AuthenticationError("Invalid client credentials")
            
            return client
            
        except Exception as e:
            raise AuthenticationError(f"Basic authentication failed: {e}")
```

### **2. Scope Management & Authorization**

#### **Dynamic Scope Validation**
```python
class ScopeManager:
    """
    Dynamic scope management with hierarchical permissions.
    Supports scope inheritance and validation.
    """
    
    def __init__(self):
        # Define scope hierarchy and relationships
        self.scope_hierarchy = {
            'read': ['read_basic'],
            'write': ['read', 'write_basic'],
            'admin': ['read', 'write', 'admin_basic'],
            'system': ['read', 'write', 'admin', 'system_basic']
        }
        
        # Define resource-specific scopes
        self.resource_scopes = {
            'user_profile': ['read', 'write'],
            'financial_data': ['read', 'write', 'admin'],
            'system_config': ['admin', 'system'],
            'audit_logs': ['admin', 'system']
        }
    
    def validate_requested_scopes(
        self, 
        requested_scopes: list, 
        client_id: str, 
        user_id: str = None
    ) -> list:
        """
        Validate and filter requested scopes based on client and user permissions.
        
        Args:
            requested_scopes: Scopes requested by client
            client_id: Client making the request
            user_id: User granting consent (if applicable)
            
        Returns:
            list: Validated scopes that can be granted
        """
        client = self.get_client_by_id(client_id)
        client_allowed_scopes = client.get('allowed_scopes', [])
        
        # Filter scopes based on client permissions
        valid_scopes = []
        for scope in requested_scopes:
            if self.is_scope_allowed_for_client(scope, client_allowed_scopes):
                # Check if user has permission for this scope (if user context)
                if user_id is None or self.is_scope_allowed_for_user(scope, user_id):
                    valid_scopes.append(scope)
        
        return valid_scopes
    
    def is_scope_allowed_for_client(self, scope: str, client_scopes: list) -> bool:
        """Check if scope is allowed for client"""
        # Direct match
        if scope in client_scopes:
            return True
        
        # Check hierarchical permissions
        for client_scope in client_scopes:
            if self.scope_implies(client_scope, scope):
                return True
        
        return False
    
    def scope_implies(self, parent_scope: str, child_scope: str) -> bool:
        """Check if parent scope implies child scope"""
        implied_scopes = self.scope_hierarchy.get(parent_scope, [])
        return child_scope in implied_scopes
```

#### **Consent Management**
```python
class ConsentManager:
    """
    User consent management for OAuth authorization.
    Handles consent storage, retrieval, and revocation.
    """
    
    def __init__(self, storage_backend):
        self.storage = storage_backend
    
    def get_user_consent(self, user_id: str, client_id: str, scopes: list) -> dict:
        """
        Get existing user consent for client and scopes.
        
        Returns:
            dict: Consent status and details
        """
        existing_consent = self.storage.get_consent(user_id, client_id)
        
        if not existing_consent:
            return {
                'status': 'required',
                'consented_scopes': [],
                'new_scopes': scopes
            }
        
        consented_scopes = existing_consent.get('scopes', [])
        new_scopes = [scope for scope in scopes if scope not in consented_scopes]
        
        if new_scopes:
            return {
                'status': 'partial',
                'consented_scopes': consented_scopes,
                'new_scopes': new_scopes
            }
        
        return {
            'status': 'granted',
            'consented_scopes': consented_scopes,
            'new_scopes': []
        }
    
    def store_user_consent(
        self, 
        user_id: str, 
        client_id: str, 
        scopes: list,
        consent_metadata: dict = None
    ):
        """Store user consent decision"""
        consent_record = {
            'user_id': user_id,
            'client_id': client_id,
            'scopes': scopes,
            'granted_at': int(time.time()),
            'metadata': consent_metadata or {}
        }
        
        self.storage.store_consent(consent_record)
    
    def revoke_consent(self, user_id: str, client_id: str, scopes: list = None):
        """Revoke user consent for specific scopes or all scopes"""
        if scopes is None:
            # Revoke all consent for this client
            self.storage.delete_consent(user_id, client_id)
        else:
            # Revoke specific scopes
            existing_consent = self.storage.get_consent(user_id, client_id)
            if existing_consent:
                remaining_scopes = [
                    scope for scope in existing_consent['scopes'] 
                    if scope not in scopes
                ]
                if remaining_scopes:
                    existing_consent['scopes'] = remaining_scopes
                    self.storage.update_consent(existing_consent)
                else:
                    self.storage.delete_consent(user_id, client_id)
```

### **3. Token Introspection & Validation**

#### **RFC 7662 Token Introspection**
```python
class TokenIntrospectionService:
    """
    OAuth 2.0 Token Introspection (RFC 7662) implementation.
    Allows resource servers to validate tokens.
    """
    
    def __init__(self, token_storage, client_authenticator):
        self.token_storage = token_storage
        self.client_authenticator = client_authenticator
    
    def introspect_token(self, token: str, client_info: dict) -> dict:
        """
        Introspect token and return metadata.
        
        Args:
            token: Token to introspect
            client_info: Authenticated client information
            
        Returns:
            dict: Token introspection response per RFC 7662
        """
        try:
            # Validate token format and signature
            if self.is_jwt_token(token):
                token_data = self.validate_jwt_token(token)
            else:
                token_data = self.validate_opaque_token(token)
            
            if not token_data:
                return {'active': False}
            
            # Check if client is authorized to introspect this token
            if not self.can_client_introspect_token(client_info, token_data):
                return {'active': False}
            
            # Build introspection response
            response = {
                'active': True,
                'client_id': token_data.get('client_id'),
                'username': token_data.get('username'),
                'scope': token_data.get('scope'),
                'token_type': 'Bearer',
                'exp': token_data.get('exp'),
                'iat': token_data.get('iat'),
                'sub': token_data.get('sub'),
                'aud': token_data.get('aud'),
                'iss': token_data.get('iss')
            }
            
            return response
            
        except Exception as e:
            # Log error but don't expose details
            self.logger.error(f"Token introspection error: {e}")
            return {'active': False}
    
    def can_client_introspect_token(self, client_info: dict, token_data: dict) -> bool:
        """Check if client can introspect this token"""
        # Only allow introspection of tokens issued to the same client
        # or if client has introspection permission
        return (
            client_info['client_id'] == token_data.get('client_id') or
            'token_introspection' in client_info.get('permissions', [])
        )
```

### **4. Security Monitoring & Threat Detection**

#### **Anomaly Detection**
```python
class SecurityMonitor:
    """
    Security monitoring and threat detection for OAuth flows.
    Detects suspicious patterns and potential attacks.
    """
    
    def __init__(self, alert_manager):
        self.alert_manager = alert_manager
        self.suspicious_patterns = {
            'rapid_token_requests': {'threshold': 100, 'window': 60},
            'failed_authentications': {'threshold': 10, 'window': 300},
            'unusual_scope_requests': {'threshold': 5, 'window': 3600},
            'geographic_anomalies': {'enabled': True},
            'device_fingerprint_changes': {'enabled': True}
        }
    
    def analyze_authorization_request(self, request_data: dict, client_info: dict) -> dict:
        """
        Analyze authorization request for security threats.
        
        Returns:
            dict: Security analysis results
        """
        analysis = {
            'risk_score': 0,
            'threats_detected': [],
            'recommendations': []
        }
        
        # Check for suspicious redirect URIs
        if self.is_suspicious_redirect_uri(request_data.get('redirect_uri')):
            analysis['risk_score'] += 30
            analysis['threats_detected'].append('suspicious_redirect_uri')
        
        # Check for scope escalation attempts
        if self.is_scope_escalation_attempt(request_data.get('scope'), client_info):
            analysis['risk_score'] += 40
            analysis['threats_detected'].append('scope_escalation')
        
        # Check for rapid successive requests
        if self.is_rapid_request_pattern(client_info['client_id']):
            analysis['risk_score'] += 20
            analysis['threats_detected'].append('rapid_requests')
        
        # Geographic anomaly detection
        if self.is_geographic_anomaly(request_data.get('ip_address'), client_info):
            analysis['risk_score'] += 25
            analysis['threats_detected'].append('geographic_anomaly')
        
        # Generate recommendations based on risk score
        if analysis['risk_score'] > 70:
            analysis['recommendations'].append('require_additional_authentication')
        elif analysis['risk_score'] > 40:
            analysis['recommendations'].append('enhanced_monitoring')
        
        return analysis
    
    def is_suspicious_redirect_uri(self, redirect_uri: str) -> bool:
        """Check if redirect URI is suspicious"""
        if not redirect_uri:
            return False
        
        suspicious_patterns = [
            'localhost',
            '127.0.0.1',
            'data:',
            'javascript:',
            'file://',
            # Add more patterns based on your security policy
        ]
        
        return any(pattern in redirect_uri.lower() for pattern in suspicious_patterns)
    
    def is_scope_escalation_attempt(self, requested_scopes: str, client_info: dict) -> bool:
        """Detect scope escalation attempts"""
        if not requested_scopes:
            return False
        
        scopes = requested_scopes.split()
        client_allowed_scopes = client_info.get('allowed_scopes', [])
        
        # Check if client is requesting scopes beyond their allowed set
        for scope in scopes:
            if scope not in client_allowed_scopes:
                return True
        
        return False
```

### **5. Audit Logging & Compliance**

#### **Comprehensive Audit Trail**
```python
class OAuthAuditLogger:
    """
    Comprehensive audit logging for OAuth operations.
    Supports compliance requirements and security monitoring.
    """
    
    def __init__(self, storage_backend, encryption_key=None):
        self.storage = storage_backend
        self.encryption_key = encryption_key
        self.logger = logging.getLogger('oauth.audit')
    
    def log_authorization_request(
        self, 
        client_id: str, 
        user_id: str, 
        scopes: list,
        request_metadata: dict
    ):
        """Log authorization request"""
        event = {
            'event_type': 'authorization_request',
            'client_id': client_id,
            'user_id': user_id,
            'requested_scopes': scopes,
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': request_metadata.get('ip_address'),
            'user_agent': request_metadata.get('user_agent'),
            'session_id': request_metadata.get('session_id')
        }
        
        self._store_audit_event(event)
    
    def log_token_issued(
        self, 
        client_id: str, 
        user_id: str, 
        token_type: str,
        scopes: list,
        expires_in: int
    ):
        """Log token issuance"""
        event = {
            'event_type': 'token_issued',
            'client_id': client_id,
            'user_id': user_id,
            'token_type': token_type,
            'granted_scopes': scopes,
            'expires_in': expires_in,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self._store_audit_event(event)
    
    def log_security_event(
        self, 
        event_type: str, 
        client_id: str, 
        details: dict,
        severity: str = 'medium'
    ):
        """Log security events"""
        event = {
            'event_type': f'security_{event_type}',
            'client_id': client_id,
            'severity': severity,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self._store_audit_event(event)
        
        # Send alerts for high-severity events
        if severity == 'high':
            self.alert_manager.send_security_alert(event)
    
    def _store_audit_event(self, event: dict):
        """Store audit event with optional encryption"""
        if self.encryption_key:
            event = self._encrypt_sensitive_data(event)
        
        self.storage.store_audit_event(event)
        self.logger.info(f"AUDIT: {json.dumps(event)}")
```

## 🚀 **Usability Recommendations**

### **1. Developer Experience**

#### **Comprehensive Error Responses**
```python
class OAuthErrorHandler:
    """
    OAuth 2.1 compliant error handling with developer-friendly messages.
    Provides clear guidance for resolving issues.
    """
    
    def __init__(self):
        self.error_descriptions = {
            'invalid_request': 'The request is missing a required parameter, includes an invalid parameter value, or is otherwise malformed.',
            'unauthorized_client': 'The client is not authorized to request an authorization code using this method.',
            'access_denied': 'The resource owner or authorization server denied the request.',
            'unsupported_response_type': 'The authorization server does not support obtaining an authorization code using this method.',
            'invalid_scope': 'The requested scope is invalid, unknown, or malformed.',
            'server_error': 'The authorization server encountered an unexpected condition.',
            'temporarily_unavailable': 'The authorization server is currently unable to handle the request.'
        }
    
    def create_error_response(
        self, 
        error_code: str, 
        description: str = None,
        help_info: dict = None
    ) -> dict:
        """Create OAuth 2.1 compliant error response"""
        response = {
            'error': error_code,
            'error_description': description or self.error_descriptions.get(error_code, 'Unknown error')
        }
        
        # Add helpful debugging information
        if help_info:
            response['help'] = help_info
        
        # Add documentation links
        response['documentation_url'] = f"https://docs.example.com/oauth/errors/{error_code}"
        
        return response
    
    def handle_invalid_scope_error(self, requested_scopes: list, allowed_scopes: list) -> dict:
        """Handle invalid scope errors with helpful guidance"""
        invalid_scopes = [scope for scope in requested_scopes if scope not in allowed_scopes]
        
        return self.create_error_response(
            'invalid_scope',
            f"The following scopes are not allowed: {', '.join(invalid_scopes)}",
            help_info={
                'invalid_scopes': invalid_scopes,
                'allowed_scopes': allowed_scopes,
                'scope_documentation': 'https://docs.example.com/oauth/scopes'
            }
        )
```

#### **OAuth Discovery & Metadata**
```python
class OAuthDiscoveryService:
    """
    OAuth 2.0 Authorization Server Metadata (RFC 8414) implementation.
    Provides discoverable configuration for clients.
    """
    
    def __init__(self, config: dict):
        self.config = config
    
    def get_authorization_server_metadata(self) -> dict:
        """Return OAuth 2.0 authorization server metadata"""
        return {
            # Required metadata
            'issuer': self.config['issuer'],
            'authorization_endpoint': f"{self.config['base_url']}/oauth/authorize",
            'token_endpoint': f"{self.config['base_url']}/oauth/token",
            'jwks_uri': f"{self.config['base_url']}/.well-known/jwks.json",
            'response_types_supported': ['code'],
            'subject_types_supported': ['public'],
            'id_token_signing_alg_values_supported': ['RS256'],
            
            # Optional but recommended
            'scopes_supported': self.config.get('supported_scopes', []),
            'token_endpoint_auth_methods_supported': [
                'client_secret_basic',
                'client_secret_post',
                'private_key_jwt',
                'none'
            ],
            'grant_types_supported': [
                'authorization_code',
                'refresh_token',
                'client_credentials'
            ],
            'code_challenge_methods_supported': ['S256'],
            'introspection_endpoint': f"{self.config['base_url']}/oauth/introspect",
            'revocation_endpoint': f"{self.config['base_url']}/oauth/revoke",
            
            # Security features
            'require_pushed_authorization_requests': self.config.get('require_par', False),
            'pushed_authorization_request_endpoint': f"{self.config['base_url']}/oauth/par",
            'tls_client_certificate_bound_access_tokens': True,
            'dpop_signing_alg_values_supported': ['RS256', 'ES256'],
            
            # Custom extensions
            'custom_scope_documentation': 'https://docs.example.com/oauth/scopes',
            'client_registration_endpoint': f"{self.config['base_url']}/oauth/register"
        }
```

### **2. Client Management**

#### **Dynamic Client Registration (RFC 7591)**
```python
class DynamicClientRegistration:
    """
    OAuth 2.0 Dynamic Client Registration (RFC 7591) implementation.
    Allows clients to register programmatically.
    """
    
    def __init__(self, storage_backend, security_policy):
        self.storage = storage_backend
        self.security_policy = security_policy
    
    def register_client(self, registration_request: dict) -> dict:
        """
        Register new OAuth client dynamically.
        
        Args:
            registration_request: Client registration request per RFC 7591
            
        Returns:
            dict: Client registration response
        """
        # Validate registration request
        validation_result = self.validate_registration_request(registration_request)
        if not validation_result['valid']:
            raise ValidationError(validation_result['errors'])
        
        # Generate client credentials
        client_id = self.generate_client_id()
        client_secret = self.generate_client_secret() if self.requires_secret(registration_request) else None
        
        # Create client record
        client_record = {
            'client_id': client_id,
            'client_secret': client_secret,
            'client_name': registration_request.get('client_name'),
            'redirect_uris': registration_request.get('redirect_uris', []),
            'grant_types': registration_request.get('grant_types', ['authorization_code']),
            'response_types': registration_request.get('response_types', ['code']),
            'scope': registration_request.get('scope', ''),
            'token_endpoint_auth_method': registration_request.get('token_endpoint_auth_method', 'client_secret_basic'),
            'created_at': int(time.time()),
            'status': 'active'
        }
        
        # Store client
        self.storage.store_client(client_record)
        
        # Return registration response
        response = {
            'client_id': client_id,
            'client_id_issued_at': client_record['created_at'],
            'client_name': client_record['client_name'],
            'redirect_uris': client_record['redirect_uris'],
            'grant_types': client_record['grant_types'],
            'response_types': client_record['response_types'],
            'scope': client_record['scope'],
            'token_endpoint_auth_method': client_record['token_endpoint_auth_method']
        }
        
        if client_secret:
            response['client_secret'] = client_secret
            response['client_secret_expires_at'] = 0  # Never expires
        
        return response
    
    def validate_registration_request(self, request: dict) -> dict:
        """Validate client registration request"""
        errors = []
        
        # Required fields validation
        if not request.get('redirect_uris'):
            errors.append('redirect_uris is required')
        
        # Validate redirect URIs
        for uri in request.get('redirect_uris', []):
            if not self.is_valid_redirect_uri(uri):
                errors.append(f'Invalid redirect URI: {uri}')
        
        # Validate grant types
        supported_grant_types = ['authorization_code', 'refresh_token', 'client_credentials']
        for grant_type in request.get('grant_types', []):
            if grant_type not in supported_grant_types:
                errors.append(f'Unsupported grant type: {grant_type}')
        
        return {
            'valid': len(errors) == 0,
            'errors': errors
        }
```

### **3. Token Management**

#### **Token Lifecycle Management**
```python
class TokenLifecycleManager:
    """
    Comprehensive token lifecycle management.
    Handles token creation, refresh, revocation, and cleanup.
    """
    
    def __init__(self, storage_backend, crypto_service):
        self.storage = storage_backend
        self.crypto = crypto_service
    
    def refresh_access_token(self, refresh_token: str, client_info: dict) -> dict:
        """
        Refresh access token using refresh token.
        
        Args:
            refresh_token: Valid refresh token
            client_info: Authenticated client information
            
        Returns:
            dict: New token response
        """
        # Validate refresh token
        token_data = self.storage.get_refresh_token(refresh_token)
        if not token_data or token_data['client_id'] != client_info['client_id']:
            raise InvalidTokenError('Invalid refresh token')
        
        # Check if refresh token is expired
        if token_data['expires_at'] < int(time.time()):
            raise InvalidTokenError('Refresh token expired')
        
        # Generate new access token
        new_access_token = self.crypto.generate_access_token(
            user_id=token_data['user_id'],
            client_id=token_data['client_id'],
            scopes=token_data['scopes'].split(),
            audience=token_data['audience']
        )
        
        # Optionally rotate refresh token
        new_refresh_token = None
        if self.should_rotate_refresh_token(token_data):
            new_refresh_token = self.crypto.generate_refresh_token(
                token_data['user_id'], 
                token_data['client_id']
            )
            # Invalidate old refresh token
            self.storage.revoke_refresh_token(refresh_token)
        
        # Store new tokens
        self.storage.store_access_token(new_access_token, token_data)
        if new_refresh_token:
            self.storage.store_refresh_token(new_refresh_token, token_data)
        
        response = {
            'access_token': new_access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'scope': token_data['scopes']
        }
        
        if new_refresh_token:
            response['refresh_token'] = new_refresh_token
        
        return response
    
    def revoke_token(self, token: str, token_type_hint: str = None) -> bool:
        """
        Revoke access or refresh token (RFC 7009).
        
        Args:
            token: Token to revoke
            token_type_hint: Hint about token type
            
        Returns:
            bool: True if revocation successful
        """
        try:
            # Try to revoke as access token first
            if token_type_hint == 'access_token' or token_type_hint is None:
                if self.storage.revoke_access_token(token):
                    return True
            
            # Try to revoke as refresh token
            if token_type_hint == 'refresh_token' or token_type_hint is None:
                if self.storage.revoke_refresh_token(token):
                    # Also revoke associated access tokens
                    self.storage.revoke_tokens_by_refresh_token(token)
                    return True
            
            return False
            
        except Exception as e:
            # Log error but don't expose details
            self.logger.error(f"Token revocation error: {e}")
            return False
```

## 🔧 **Implementation Checklist**

### **OAuth 2.1 Compliance**
- [ ] Implement PKCE for all authorization code flows
- [ ] Support multiple client authentication methods
- [ ] Implement secure token generation with asymmetric signing
- [ ] Add comprehensive scope validation and management
- [ ] Implement proper consent management
- [ ] Add token introspection endpoint (RFC 7662)
- [ ] Implement token revocation endpoint (RFC 7009)
- [ ] Add OAuth discovery metadata endpoint (RFC 8414)

### **Security Features**
- [ ] Implement security monitoring and threat detection
- [ ] Add comprehensive audit logging
- [ ] Implement rate limiting and abuse prevention
- [ ] Add geographic anomaly detection
- [ ] Implement client reputation scoring
- [ ] Add automated security alerting
- [ ] Implement token binding and DPoP support
- [ ] Add pushed authorization requests (PAR) support

### **Developer Experience**
- [ ] Create comprehensive error responses with guidance
- [ ] Implement dynamic client registration
- [ ] Add OAuth discovery and metadata endpoints
- [ ] Create developer documentation and examples
- [ ] Implement client management dashboard
- [ ] Add token lifecycle management tools
- [ ] Create debugging and troubleshooting utilities
- [ ] Implement automated testing framework

### **Operational Excellence**
- [ ] Add health check and monitoring endpoints
- [ ] Implement configuration management
- [ ] Add backup and disaster recovery procedures
- [ ] Create deployment automation
- [ ] Implement log aggregation and analysis
- [ ] Add performance monitoring and optimization
- [ ] Create capacity planning tools
- [ ] Implement automated security scanning

## 🎯 **Success Metrics**

### **Security Metrics**
- **Token Security**: 0 token compromise incidents
- [ ] **Authentication Success Rate**: >99.95%
- [ ] **Threat Detection Accuracy**: >95% true positive rate
- [ ] **Security Response Time**: <15 minutes for high-severity alerts
- [ ] **Compliance Score**: 100% OAuth 2.1 compliance

### **Performance Metrics**
- [ ] **Authorization Response Time**: <200ms average
- [ ] **Token Endpoint Response Time**: <100ms average
- [ ] **System Uptime**: >99.99%
- [ ] **Throughput**: >10,000 requests/minute
- [ ] **Error Rate**: <0.1% of requests

### **Developer Experience Metrics**
- [ ] **Integration Time**: <4 hours for new clients
- [ ] **Documentation Completeness**: 100% API coverage
- [ ] **Error Resolution Time**: <30 minutes average
- [ ] **Developer Satisfaction**: >95% positive feedback
- [ ] **API Adoption Rate**: >80% of eligible clients using OAuth 