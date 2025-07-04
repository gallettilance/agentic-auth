# MCP Server Security & Usability Recommendations

**Component**: MCP Server (OAuth Resource Server)  
**Role**: Protected resource that validates tokens and executes tools  
**Security Level**: **CRITICAL** - Direct tool execution and system access

## 🛡️ **Security Recommendations**

### **1. MCP Specification Compliance**

#### **OAuth 2.1 Resource Server Implementation**
```python
# REQUIRED by MCP Spec: Token validation for all tool requests
def verify_token_from_context(ctx: Context) -> dict:
    """
    Extract and validate Bearer token from MCP request context.
    Must be implemented by all MCP servers per specification.
    """
    auth_header = ctx.meta.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise AuthenticationError("Missing or invalid Authorization header")
    
    token = auth_header[7:]  # Remove "Bearer " prefix
    
    # Validate token (JWT or introspection)
    return validate_jwt_token(token)  # Implementation specific

# REQUIRED by MCP Spec: HTTP error responses
def handle_auth_error(error_type: str) -> dict:
    """Return proper HTTP status codes and WWW-Authenticate headers"""
    if error_type == "missing_token":
        return {
            "status": 401,
            "headers": {"WWW-Authenticate": "Bearer"},
            "error": "authentication_required"
        }
    elif error_type == "insufficient_scope":
        return {
            "status": 403,
            "error": "insufficient_scope",
            "error_description": "Token lacks required scope for this tool"
        }
```

#### **Protected Resource Metadata (RFC 9728)**
```python
# REQUIRED by MCP Spec: Discovery endpoint
@app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata():
    """
    OAuth Protected Resource Metadata as required by MCP specification.
    Must be implemented by all MCP servers.
    """
    return {
        # Required fields per RFC 9728
        "resource": SERVER_URI,
        "authorization_servers": [AUTH_SERVER_URI],
        
        # MCP-specific extensions
        "mcp_version": "2024-11-05",
        "scopes_supported": get_supported_scopes(),
        "tools_supported": get_available_tools(),
        
        # Security policy information
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "introspection_endpoint": f"{AUTH_SERVER_URI}/introspect"
    }

def get_supported_scopes() -> list:
    """Return list of OAuth scopes supported by this MCP server"""
    # Implementation should return actual scopes for your tools
    # Example: ["read_files", "write_files", "execute_commands", "manage_database"]
    pass

def get_available_tools() -> list:
    """Return list of tools available on this MCP server"""
    # Implementation should return actual tool names
    # Example: ["list_files", "create_file", "run_query", "backup_data"]
    pass
```

### **2. Asymmetric JWT Verification (Recommended)**

#### **JWKS-Based Token Validation**
```python
import jwt
from jwt import PyJWKClient

class MCPTokenValidator:
    """
    Asymmetric JWT validator for MCP servers.
    Eliminates need for shared secrets between auth server and MCP servers.
    """
    
    def __init__(self, auth_server_uri: str, server_uri: str):
        self.jwks_client = PyJWKClient(f"{auth_server_uri}/.well-known/jwks.json")
        self.auth_server_uri = auth_server_uri
        self.server_uri = server_uri
        
    def validate_token(self, token: str) -> dict:
        """
        Validate JWT token using public key from JWKS endpoint.
        
        Returns:
            dict: Token payload with user info and scopes
            
        Raises:
            AuthenticationError: If token is invalid
        """
        try:
            # Get signing key from JWKS
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            
            # Verify token signature and claims
            payload = jwt.decode(
                token, 
                signing_key.key, 
                algorithms=["RS256"],
                issuer=self.auth_server_uri,
                options={"verify_aud": False}  # We'll verify manually
            )
            
            # CRITICAL: Verify audience matches this server
            if payload.get("aud") != self.server_uri:
                raise jwt.InvalidAudienceError("Token not intended for this server")
            
            return payload
            
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {e}")
```

### **3. Tool-Scope Authorization Pattern**

#### **Recommended: Tool Name as Scope**
```python
class MCPAuthorizationHandler:
    """
    Implements tool-scope authorization for MCP servers.
    Recommended pattern: tool_name == required_scope
    """
    
    def __init__(self):
        # Map each tool to its required scope
        # Recommendation: Use 1:1 mapping for maximum granularity
        self.tool_scope_mapping = self.build_tool_scope_mapping()
    
    def build_tool_scope_mapping(self) -> dict:
        """
        Build mapping of tools to required scopes.
        Override this method to define your tool permissions.
        """
        # Example implementation - customize for your tools
        return {
            "read_operation_tool": "read_data",
            "write_operation_tool": "write_data", 
            "admin_operation_tool": "admin_access",
            "dangerous_operation_tool": "high_privilege"
        }
    
    def check_tool_authorization(self, tool_name: str, token_scopes: list) -> bool:
        """
        Check if token has required scope for tool execution.
        
        Args:
            tool_name: Name of the tool being requested
            token_scopes: List of scopes from validated token
            
        Returns:
            bool: True if authorized, False otherwise
        """
        required_scope = self.tool_scope_mapping.get(tool_name)
        
        if not required_scope:
            # Tool not found - deny by default
            return False
        
        return required_scope in token_scopes
    
    def get_required_scope(self, tool_name: str) -> str:
        """Get the scope required for a specific tool"""
        return self.tool_scope_mapping.get(tool_name)
```

### **4. Input Validation & Security**

#### **Generic Input Sanitization**
```python
class MCPInputValidator:
    """
    Generic input validation for MCP tool parameters.
    Customize validation rules based on your tool requirements.
    """
    
    def __init__(self):
        self.max_string_length = 10000
        self.max_array_length = 1000
        self.dangerous_patterns = [
            # Common injection patterns
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'on\w+\s*=',
            # Command injection patterns  
            r'[;&|`$]',
            r'\$\(',
            r'`[^`]*`'
        ]
    
    def validate_tool_parameters(self, tool_name: str, parameters: dict) -> dict:
        """
        Validate and sanitize tool parameters.
        Override this method to add tool-specific validation.
        """
        sanitized = {}
        
        for key, value in parameters.items():
            # Basic type and length validation
            if isinstance(value, str):
                if len(value) > self.max_string_length:
                    raise ValueError(f"Parameter {key} exceeds maximum length")
                sanitized[key] = self.sanitize_string(value)
            
            elif isinstance(value, list):
                if len(value) > self.max_array_length:
                    raise ValueError(f"Parameter {key} array too large")
                sanitized[key] = [self.sanitize_string(str(item)) for item in value]
            
            else:
                sanitized[key] = value
        
        return sanitized
    
    def sanitize_string(self, value: str) -> str:
        """Remove potentially dangerous patterns from strings"""
        import re
        
        for pattern in self.dangerous_patterns:
            value = re.sub(pattern, '', value, flags=re.IGNORECASE)
        
        return value.strip()
```

### **5. Rate Limiting & Abuse Prevention**

#### **Per-User, Per-Tool Rate Limiting**
```python
from collections import defaultdict
import time

class MCPRateLimiter:
    """
    Rate limiting for MCP tool execution.
    Prevents abuse and ensures fair resource usage.
    """
    
    def __init__(self):
        self.requests = defaultdict(list)
        # Configure limits based on tool risk level
        self.default_limits = {
            'low_risk': (100, 60),     # 100 requests per minute
            'medium_risk': (50, 60),   # 50 requests per minute  
            'high_risk': (10, 60),     # 10 requests per minute
            'admin_only': (5, 60)      # 5 requests per minute
        }
    
    def check_rate_limit(self, user_id: str, tool_name: str, risk_level: str = 'medium_risk') -> bool:
        """
        Check if user has exceeded rate limit for tool category.
        
        Args:
            user_id: Unique identifier for user
            tool_name: Name of tool being executed
            risk_level: Risk category of the tool
            
        Returns:
            bool: True if within limits, False if exceeded
        """
        max_requests, window_seconds = self.default_limits.get(risk_level, (50, 60))
        now = time.time()
        
        # Clean old requests outside window
        rate_key = f"{user_id}:{tool_name}"
        self.requests[rate_key] = [
            req_time for req_time in self.requests[rate_key] 
            if now - req_time < window_seconds
        ]
        
        # Check if limit exceeded
        if len(self.requests[rate_key]) >= max_requests:
            return False
        
        # Record this request
        self.requests[rate_key].append(now)
        return True
```

## 🚀 **FastMCP Integration Recommendations**

### **1. Authentication Middleware for FastMCP**

#### **Drop-in Authentication Decorator**
```python
from fastmcp import FastMCP
from functools import wraps

class FastMCPAuth:
    """
    Authentication middleware for FastMCP framework.
    Provides easy integration of OAuth authentication.
    """
    
    def __init__(self, auth_server_uri: str, server_uri: str):
        self.validator = MCPTokenValidator(auth_server_uri, server_uri)
        self.authorizer = MCPAuthorizationHandler()
        self.rate_limiter = MCPRateLimiter()
    
    def require_scope(self, required_scope: str, risk_level: str = 'medium_risk'):
        """
        Decorator to require specific scope for FastMCP tools.
        
        Usage:
            @mcp.tool()
            @auth.require_scope("read_files")
            def list_files(path: str) -> list:
                return os.listdir(path)
        """
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract context from FastMCP
                ctx = kwargs.get('ctx') or args[0] if args else None
                if not ctx:
                    raise ValueError("No MCP context available")
                
                # Validate token
                try:
                    token_payload = self.validator.validate_token_from_context(ctx)
                except AuthenticationError as e:
                    raise MCPError(f"Authentication failed: {e}")
                
                # Check authorization
                user_scopes = token_payload.get('scope', '').split()
                if required_scope not in user_scopes:
                    raise MCPError(f"Insufficient scope. Required: {required_scope}")
                
                # Check rate limits
                user_id = token_payload.get('sub')
                tool_name = func.__name__
                
                if not self.rate_limiter.check_rate_limit(user_id, tool_name, risk_level):
                    raise MCPError("Rate limit exceeded")
                
                # Execute tool
                return await func(*args, **kwargs)
            
            return wrapper
        return decorator

# Usage example
mcp = FastMCP("Secure MCP Server")
auth = FastMCPAuth(
    auth_server_uri="https://auth.example.com",
    server_uri="https://mcp.example.com"
)

@mcp.tool()
@auth.require_scope("read_data", risk_level="low_risk")
def safe_read_operation(ctx, path: str) -> str:
    """Safe read operation with authentication"""
    return perform_read(path)

@mcp.tool() 
@auth.require_scope("admin_access", risk_level="high_risk")
def dangerous_admin_operation(ctx, command: str) -> str:
    """Dangerous operation requiring admin privileges"""
    return perform_admin_command(command)
```

### **2. Configuration-Driven Security**

#### **Security Configuration for FastMCP**
```python
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class MCPSecurityConfig:
    """Configuration class for MCP server security settings"""
    
    # Authentication
    auth_server_uri: str
    server_uri: str
    token_validation_method: str = "jwt_asymmetric"  # or "jwt_symmetric", "introspection"
    
    # Authorization  
    default_scope_mapping: Dict[str, str] = None
    require_scope_for_all_tools: bool = True
    
    # Rate limiting
    enable_rate_limiting: bool = True
    default_rate_limits: Dict[str, tuple] = None
    
    # Input validation
    max_parameter_length: int = 10000
    enable_input_sanitization: bool = True
    
    def __post_init__(self):
        if self.default_scope_mapping is None:
            # Default to tool_name == scope_name pattern
            self.default_scope_mapping = {}
        
        if self.default_rate_limits is None:
            self.default_rate_limits = {
                'low_risk': (100, 60),
                'medium_risk': (50, 60), 
                'high_risk': (10, 60)
            }

# Usage
config = MCPSecurityConfig(
    auth_server_uri="https://auth.example.com",
    server_uri="https://mcp.example.com",
    default_scope_mapping={
        "read_files": "file_read",
        "write_files": "file_write",
        "execute_command": "system_admin"
    }
)

mcp = FastMCP("My Secure Server", security_config=config)
```

## 🔧 **Implementation Checklist**

### **MCP Specification Compliance**
- [ ] Implement token validation in `verify_token_from_context()`
- [ ] Add proper HTTP error responses (401/403 with WWW-Authenticate)
- [ ] Create OAuth protected resource metadata endpoint
- [ ] Implement scope-based tool authorization
- [ ] Add comprehensive audit logging

### **FastMCP Integration**
- [ ] Create authentication middleware/decorator
- [ ] Implement configuration-driven security
- [ ] Add automatic scope mapping for tools
- [ ] Integrate rate limiting with FastMCP
- [ ] Create security-aware error handling

### **Security Hardening**
- [ ] Implement asymmetric JWT verification
- [ ] Add input validation and sanitization
- [ ] Implement per-tool rate limiting
- [ ] Add security monitoring and alerting
- [ ] Create comprehensive logging

### **Developer Experience**
- [ ] Create easy-to-use authentication decorators
- [ ] Add clear error messages with remediation steps
- [ ] Implement automatic security configuration
- [ ] Add debugging and troubleshooting tools
- [ ] Create comprehensive documentation

## 🎯 **Success Metrics**

### **Security Metrics**
- **Authentication Success Rate**: >99.9%
- **Authorization Violations**: <0.1% of requests
- **Security Incidents**: 0 per month
- **Token Validation Time**: <50ms average

### **Developer Experience Metrics**
- **Integration Time**: <30 minutes for new MCP server
- **Error Resolution Time**: <5 minutes average
- **Documentation Completeness**: 100% of security features documented
- **Developer Satisfaction**: >95% positive feedback

### **Performance Metrics**
- **Tool Execution Time**: <200ms average overhead
- **Rate Limiting Accuracy**: >99% correct decisions
- **Memory Usage**: <10MB additional overhead
- **Uptime**: >99.95% 