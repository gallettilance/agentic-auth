# Llama Stack Security & Usability Recommendations

**Component**: Llama Stack (OAuth Resource Server)  
**Role**: Protected AI/ML resource that validates tokens and provides model access  
**Security Level**: **HIGH** - AI model access, data processing, and inference capabilities

## 🛡️ **Security Recommendations**

### **1. OAuth 2.1 Resource Server Integration**

#### **Token Validation Middleware (Required Changes)**
```python
# FILE: llama_stack/providers/adapters/inference/common/auth_middleware.py
from typing import Dict, Optional
import jwt
from jwt import PyJWKClient

class LlamaStackAuthMiddleware:
    """
    OAuth authentication middleware for Llama Stack.
    Add this to the inference provider chain.
    """
    
    def __init__(self, auth_server_uri: str, stack_uri: str):
        self.jwks_client = PyJWKClient(f"{auth_server_uri}/.well-known/jwks.json")
        self.auth_server_uri = auth_server_uri
        self.stack_uri = stack_uri
    
    async def authenticate_request(self, request_headers: Dict[str, str]) -> Dict[str, any]:
        """
        Validate Bearer token from inference request headers.
        
        Args:
            request_headers: HTTP headers from inference request
            
        Returns:
            dict: Token payload with user info and scopes
            
        Raises:
            AuthenticationError: If token is invalid or missing
        """
        auth_header = request_headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise AuthenticationError("Missing or invalid Authorization header")
        
        token = auth_header[7:]  # Remove "Bearer " prefix
        
        try:
            # Get signing key from JWKS
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            
            # Verify token signature and claims
            payload = jwt.decode(
                token, 
                signing_key.key, 
                algorithms=["RS256"],
                issuer=self.auth_server_uri,
                audience=self.stack_uri
            )
            
            return payload
            
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {e}")
```

#### **Inference Provider Authorization (Required Changes)**
```python
# FILE: llama_stack/providers/adapters/inference/meta_reference/meta_reference.py
# MODIFY: Add authorization checks to inference methods

class MetaReferenceInferenceAdapter:
    def __init__(self, config: MetaReferenceImplConfig):
        # ... existing initialization ...
        
        # ADD: Initialize auth middleware
        self.auth_middleware = LlamaStackAuthMiddleware(
            auth_server_uri=config.auth_server_uri,
            stack_uri=config.stack_uri
        )
        
        # ADD: Define model-scope mapping
        self.model_scope_mapping = {
            "llama-3.1-8b": "model_llama_3_1_8b",
            "llama-3.1-70b": "model_llama_3_1_70b", 
            "llama-3.2-1b": "model_llama_3_2_1b",
            "llama-3.2-3b": "model_llama_3_2_3b",
            "code-llama": "model_code_llama",
            # Add all supported models
        }
    
    async def chat_completion(
        self, 
        model_id: str,
        messages: List[Message],
        request_headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> ChatCompletionResponse:
        """
        MODIFY: Add authentication and authorization to chat completion.
        """
        # ADD: Authenticate request
        if not request_headers:
            raise AuthenticationError("No authentication headers provided")
        
        token_payload = await self.auth_middleware.authenticate_request(request_headers)
        
        # ADD: Check model authorization
        required_scope = self.model_scope_mapping.get(model_id)
        if not required_scope:
            raise AuthorizationError(f"Model {model_id} not supported")
        
        user_scopes = token_payload.get('scope', '').split()
        if required_scope not in user_scopes:
            raise AuthorizationError(f"Insufficient scope. Required: {required_scope}")
        
        # ADD: Log inference request
        self.log_inference_request(token_payload.get('sub'), model_id, len(messages))
        
        # EXISTING: Continue with original inference logic
        return await self._perform_chat_completion(model_id, messages, **kwargs)
```

#### **Safety and Content Filtering (Required Changes)**
```python
# FILE: llama_stack/providers/adapters/safety/common/content_safety.py
# ADD: New content safety provider with OAuth integration

class OAuthContentSafetyAdapter:
    """
    Content safety provider that enforces different safety levels
    based on user authorization scopes.
    """
    
    def __init__(self, config: ContentSafetyConfig):
        self.safety_levels = {
            "basic_user": {
                "max_violence_score": 0.3,
                "max_hate_score": 0.2,
                "max_sexual_score": 0.2,
                "blocked_categories": ["illegal", "harmful"]
            },
            "premium_user": {
                "max_violence_score": 0.5,
                "max_hate_score": 0.4,
                "max_sexual_score": 0.4,
                "blocked_categories": ["illegal"]
            },
            "research_user": {
                "max_violence_score": 0.8,
                "max_hate_score": 0.7,
                "max_sexual_score": 0.7,
                "blocked_categories": []
            }
        }
    
    async def check_content_safety(
        self, 
        content: str, 
        user_scopes: List[str]
    ) -> ContentSafetyResult:
        """
        Apply content safety checks based on user authorization level.
        
        Args:
            content: Text content to check
            user_scopes: OAuth scopes from validated token
            
        Returns:
            ContentSafetyResult: Safety assessment with user-specific thresholds
        """
        # Determine user safety level from scopes
        safety_level = self.get_safety_level_from_scopes(user_scopes)
        safety_config = self.safety_levels[safety_level]
        
        # Run content analysis
        safety_scores = await self.analyze_content(content)
        
        # Apply user-specific thresholds
        violations = []
        if safety_scores.violence > safety_config["max_violence_score"]:
            violations.append("violence")
        if safety_scores.hate > safety_config["max_hate_score"]:
            violations.append("hate")
        if safety_scores.sexual > safety_config["max_sexual_score"]:
            violations.append("sexual")
        
        # Check blocked categories
        for category in safety_config["blocked_categories"]:
            if category in safety_scores.categories:
                violations.append(category)
        
        return ContentSafetyResult(
            safe=len(violations) == 0,
            violations=violations,
            safety_level=safety_level
        )
    
    def get_safety_level_from_scopes(self, scopes: List[str]) -> str:
        """Determine safety level based on OAuth scopes"""
        if "research_access" in scopes:
            return "research_user"
        elif "premium_access" in scopes:
            return "premium_user"
        else:
            return "basic_user"
```

### **2. Model Access Control (Required Changes)**

#### **Model Permission Matrix**
```python
# FILE: llama_stack/providers/adapters/inference/common/model_permissions.py
# ADD: New model permission system

class ModelPermissionManager:
    """
    Manages model access permissions based on OAuth scopes.
    Integrates with existing Llama Stack model registry.
    """
    
    def __init__(self):
        # Define model categories and required scopes
        self.model_permissions = {
            # General purpose models
            "llama-3.1-8b": {
                "required_scope": "model_llama_3_1_8b",
                "category": "general",
                "risk_level": "low"
            },
            "llama-3.1-70b": {
                "required_scope": "model_llama_3_1_70b", 
                "category": "general",
                "risk_level": "medium"
            },
            
            # Code generation models
            "code-llama": {
                "required_scope": "model_code_llama",
                "category": "code",
                "risk_level": "high"
            },
            
            # Specialized models
            "llama-guard": {
                "required_scope": "model_safety",
                "category": "safety",
                "risk_level": "low"
            },
            
            # Research models (restricted)
            "experimental-model": {
                "required_scope": "model_experimental",
                "category": "research",
                "risk_level": "critical"
            }
        }
    
    def check_model_access(self, model_id: str, user_scopes: List[str]) -> bool:
        """
        Check if user has permission to access specific model.
        
        Args:
            model_id: Identifier of the model being requested
            user_scopes: List of OAuth scopes from validated token
            
        Returns:
            bool: True if access granted, False otherwise
        """
        model_info = self.model_permissions.get(model_id)
        if not model_info:
            return False  # Model not found - deny by default
        
        required_scope = model_info["required_scope"]
        return required_scope in user_scopes
    
    def get_accessible_models(self, user_scopes: List[str]) -> List[str]:
        """Return list of models accessible to user based on scopes"""
        accessible = []
        for model_id, model_info in self.model_permissions.items():
            if model_info["required_scope"] in user_scopes:
                accessible.append(model_id)
        return accessible
```

### **3. Rate Limiting and Resource Management (Required Changes)**

#### **User-Based Rate Limiting**
```python
# FILE: llama_stack/providers/adapters/inference/common/rate_limiter.py
# ADD: New rate limiting system for inference requests

from collections import defaultdict
import time
from typing import Dict, Tuple

class InferenceRateLimiter:
    """
    Rate limiting for AI inference requests based on user tiers.
    Prevents abuse and ensures fair resource allocation.
    """
    
    def __init__(self):
        self.request_history = defaultdict(list)
        
        # Rate limits by user tier (requests per minute, tokens per minute)
        self.tier_limits = {
            "free": (10, 1000),        # 10 requests, 1K tokens per minute
            "basic": (50, 10000),      # 50 requests, 10K tokens per minute  
            "premium": (200, 50000),   # 200 requests, 50K tokens per minute
            "enterprise": (1000, 500000)  # 1K requests, 500K tokens per minute
        }
    
    def check_rate_limit(
        self, 
        user_id: str, 
        user_scopes: List[str],
        estimated_tokens: int = 100
    ) -> Tuple[bool, str]:
        """
        Check if user has exceeded rate limits for inference.
        
        Args:
            user_id: Unique identifier for user
            user_scopes: OAuth scopes to determine user tier
            estimated_tokens: Estimated tokens for this request
            
        Returns:
            Tuple[bool, str]: (allowed, reason_if_denied)
        """
        user_tier = self.get_user_tier_from_scopes(user_scopes)
        max_requests, max_tokens = self.tier_limits[user_tier]
        
        now = time.time()
        minute_ago = now - 60
        
        # Clean old requests
        user_requests = self.request_history[user_id]
        recent_requests = [
            (req_time, tokens) for req_time, tokens in user_requests
            if req_time > minute_ago
        ]
        self.request_history[user_id] = recent_requests
        
        # Check request count limit
        if len(recent_requests) >= max_requests:
            return False, f"Request limit exceeded ({max_requests}/minute for {user_tier})"
        
        # Check token limit
        total_tokens = sum(tokens for _, tokens in recent_requests) + estimated_tokens
        if total_tokens > max_tokens:
            return False, f"Token limit exceeded ({max_tokens}/minute for {user_tier})"
        
        # Record this request
        self.request_history[user_id].append((now, estimated_tokens))
        return True, ""
    
    def get_user_tier_from_scopes(self, scopes: List[str]) -> str:
        """Determine user tier based on OAuth scopes"""
        if "enterprise_access" in scopes:
            return "enterprise"
        elif "premium_access" in scopes:
            return "premium"
        elif "basic_access" in scopes:
            return "basic"
        else:
            return "free"
```

### **4. Audit Logging and Monitoring (Required Changes)**

#### **Inference Audit Logger**
```python
# FILE: llama_stack/providers/adapters/inference/common/audit_logger.py
# ADD: Comprehensive audit logging for AI inference

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

class InferenceAuditLogger:
    """
    Audit logging for AI inference requests and responses.
    Tracks usage patterns and security events.
    """
    
    def __init__(self, log_level: str = "INFO"):
        self.logger = logging.getLogger("llama_stack.inference.audit")
        self.logger.setLevel(getattr(logging, log_level))
        
        # Create structured log formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Add file handler for audit logs
        file_handler = logging.FileHandler("inference_audit.log")
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    
    def log_inference_request(
        self,
        user_id: str,
        model_id: str,
        request_type: str,
        token_info: Dict,
        request_metadata: Dict = None
    ):
        """Log inference request details"""
        event = {
            "event_type": "inference_request",
            "user_id": user_id,
            "model_id": model_id,
            "request_type": request_type,
            "scopes": token_info.get('scope', '').split(),
            "token_issuer": token_info.get('iss'),
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": request_metadata or {}
        }
        
        self.logger.info(f"INFERENCE_REQUEST: {json.dumps(event)}")
    
    def log_inference_response(
        self,
        user_id: str,
        model_id: str,
        success: bool,
        response_metadata: Dict = None,
        error_details: str = None
    ):
        """Log inference response details"""
        event = {
            "event_type": "inference_response",
            "user_id": user_id,
            "model_id": model_id,
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": response_metadata or {}
        }
        
        if error_details:
            event["error"] = error_details
        
        if success:
            self.logger.info(f"INFERENCE_SUCCESS: {json.dumps(event)}")
        else:
            self.logger.warning(f"INFERENCE_FAILURE: {json.dumps(event)}")
    
    def log_security_event(
        self,
        event_type: str,
        user_id: str,
        details: Dict,
        severity: str = "WARNING"
    ):
        """Log security-related events"""
        event = {
            "event_type": f"security_{event_type}",
            "user_id": user_id,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details
        }
        
        log_level = getattr(self.logger, severity.lower())
        log_level(f"SECURITY_EVENT: {json.dumps(event)}")
```

### **5. Configuration Integration (Required Changes)**

#### **OAuth Configuration for Llama Stack**
```python
# FILE: llama_stack/distribution/stack_config.py
# MODIFY: Add OAuth configuration to stack configuration

from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class OAuthConfig:
    """OAuth configuration for Llama Stack"""
    
    # Authentication server settings
    auth_server_uri: str
    stack_uri: str
    
    # Token validation settings
    token_validation_method: str = "jwt_asymmetric"  # or "introspection"
    jwks_cache_ttl: int = 300  # 5 minutes
    
    # Authorization settings
    enforce_model_permissions: bool = True
    enforce_content_safety: bool = True
    default_safety_level: str = "basic_user"
    
    # Rate limiting settings
    enable_rate_limiting: bool = True
    default_user_tier: str = "free"
    
    # Audit logging settings
    enable_audit_logging: bool = True
    audit_log_level: str = "INFO"
    
    # Model permission overrides
    model_scope_overrides: Optional[Dict[str, str]] = None

# MODIFY: Add OAuth config to main stack configuration
@dataclass
class StackConfig:
    # ... existing fields ...
    
    # ADD: OAuth configuration
    oauth_config: Optional[OAuthConfig] = None
    
    def __post_init__(self):
        # ... existing validation ...
        
        # ADD: Validate OAuth config if provided
        if self.oauth_config:
            self.validate_oauth_config()
    
    def validate_oauth_config(self):
        """Validate OAuth configuration"""
        if not self.oauth_config.auth_server_uri:
            raise ValueError("auth_server_uri is required for OAuth")
        if not self.oauth_config.stack_uri:
            raise ValueError("stack_uri is required for OAuth")
```

## 🚀 **Integration Instructions**

### **1. Modify Existing Llama Stack Files**

#### **Required File Changes:**
```bash
# Core inference adapters (ADD authentication)
llama_stack/providers/adapters/inference/meta_reference/meta_reference.py
llama_stack/providers/adapters/inference/together/together.py
llama_stack/providers/adapters/inference/fireworks/fireworks.py

# Safety providers (ADD scope-based safety)
llama_stack/providers/adapters/safety/llama_guard/llama_guard.py

# Distribution configuration (ADD OAuth config)
llama_stack/distribution/stack_config.py
llama_stack/distribution/server/server.py

# API endpoints (ADD auth middleware)
llama_stack/apis/inference/inference.py
llama_stack/apis/safety/safety.py
```

#### **New Files to Create:**
```bash
# Authentication middleware
llama_stack/providers/adapters/inference/common/auth_middleware.py

# Model permissions
llama_stack/providers/adapters/inference/common/model_permissions.py

# Rate limiting
llama_stack/providers/adapters/inference/common/rate_limiter.py

# Audit logging
llama_stack/providers/adapters/inference/common/audit_logger.py

# Content safety with OAuth
llama_stack/providers/adapters/safety/common/content_safety.py
```

### **2. Configuration Changes**

#### **Stack Configuration File (stack_config.yaml)**
```yaml
# ADD: OAuth configuration section
oauth_config:
  auth_server_uri: "https://auth.example.com"
  stack_uri: "https://llama-stack.example.com"
  token_validation_method: "jwt_asymmetric"
  enforce_model_permissions: true
  enforce_content_safety: true
  enable_rate_limiting: true
  enable_audit_logging: true
  
  # Model-specific scope requirements
  model_scope_overrides:
    "llama-3.1-8b": "model_llama_3_1_8b"
    "llama-3.1-70b": "model_llama_3_1_70b"
    "code-llama": "model_code_llama"
```

#### **Environment Variables**
```bash
# ADD: OAuth environment variables
export LLAMA_STACK_OAUTH_AUTH_SERVER_URI="https://auth.example.com"
export LLAMA_STACK_OAUTH_STACK_URI="https://llama-stack.example.com"
export LLAMA_STACK_OAUTH_ENABLE_AUTH="true"
export LLAMA_STACK_OAUTH_ENABLE_RATE_LIMITING="true"
```

### **3. API Endpoint Changes**

#### **Inference API Modifications**
```python
# FILE: llama_stack/apis/inference/inference.py
# MODIFY: Add authentication to inference endpoints

class InferenceAPI:
    def __init__(self, config: StackConfig):
        # ... existing initialization ...
        
        # ADD: Initialize OAuth components if configured
        if config.oauth_config:
            self.auth_middleware = LlamaStackAuthMiddleware(
                config.oauth_config.auth_server_uri,
                config.oauth_config.stack_uri
            )
            self.model_permissions = ModelPermissionManager()
            self.rate_limiter = InferenceRateLimiter()
            self.audit_logger = InferenceAuditLogger()
            self.oauth_enabled = True
        else:
            self.oauth_enabled = False
    
    async def chat_completion(self, request: ChatCompletionRequest) -> ChatCompletionResponse:
        """MODIFY: Add OAuth authentication to chat completion endpoint"""
        
        # ADD: OAuth authentication if enabled
        if self.oauth_enabled:
            # Extract token from request headers
            auth_header = request.headers.get("Authorization")
            if not auth_header:
                raise AuthenticationError("Missing Authorization header")
            
            # Validate token
            token_payload = await self.auth_middleware.authenticate_request(request.headers)
            
            # Check model permissions
            user_scopes = token_payload.get('scope', '').split()
            if not self.model_permissions.check_model_access(request.model_id, user_scopes):
                raise AuthorizationError(f"Access denied to model {request.model_id}")
            
            # Check rate limits
            user_id = token_payload.get('sub')
            allowed, reason = self.rate_limiter.check_rate_limit(
                user_id, user_scopes, estimated_tokens=len(str(request.messages))
            )
            if not allowed:
                raise RateLimitError(reason)
            
            # Log request
            self.audit_logger.log_inference_request(
                user_id, request.model_id, "chat_completion", token_payload
            )
        
        # EXISTING: Continue with original inference logic
        try:
            response = await self._perform_chat_completion(request)
            
            # ADD: Log successful response
            if self.oauth_enabled:
                self.audit_logger.log_inference_response(
                    user_id, request.model_id, True, 
                    {"response_length": len(response.content)}
                )
            
            return response
            
        except Exception as e:
            # ADD: Log failed response
            if self.oauth_enabled:
                self.audit_logger.log_inference_response(
                    user_id, request.model_id, False, error_details=str(e)
                )
            raise
```

## 🔧 **Implementation Checklist**

### **Core Integration**
- [ ] Add OAuth configuration to `StackConfig`
- [ ] Create authentication middleware for inference providers
- [ ] Implement model permission system
- [ ] Add rate limiting based on user tiers
- [ ] Create comprehensive audit logging

### **Provider Modifications**
- [ ] Update Meta Reference adapter with OAuth support
- [ ] Update Together adapter with OAuth support
- [ ] Update Fireworks adapter with OAuth support
- [ ] Update safety providers with scope-based filtering
- [ ] Add OAuth support to all inference providers

### **API Endpoint Updates**
- [ ] Add authentication to inference API endpoints
- [ ] Add authentication to safety API endpoints
- [ ] Implement proper error handling for auth failures
- [ ] Add OAuth metadata endpoints
- [ ] Create user-accessible model listing endpoint

### **Configuration and Deployment**
- [ ] Update stack configuration schema
- [ ] Add OAuth environment variable support
- [ ] Create deployment documentation
- [ ] Add OAuth troubleshooting guide
- [ ] Create migration guide for existing deployments

## 🎯 **Success Metrics**

### **Security Metrics**
- **Authentication Success Rate**: >99.9%
- **Unauthorized Access Attempts**: <0.1% of requests
- **Model Access Violations**: 0 per month
- **Token Validation Time**: <100ms average

### **Performance Metrics**
- **Inference Response Time**: <500ms additional overhead
- **Rate Limiting Accuracy**: >99% correct decisions
- **Memory Usage**: <50MB additional overhead
- **Uptime**: >99.9%

### **User Experience Metrics**
- **Integration Time**: <2 hours for existing deployments
- **Error Resolution Time**: <10 minutes average
- **Documentation Completeness**: 100% of OAuth features documented
- **User Satisfaction**: >90% positive feedback 