# LlamaStackClient Token Exchange with Keycloak Guide

This guide explains how to modify a `LlamaStackClient` to perform token exchange with Keycloak using RFC 8693 (Token Exchange V2) and environment variables for secure configuration.

## Overview

The implementation allows LlamaStackClient to:
- Start with minimal scope tokens (basic OIDC scopes only)
- Exchange tokens on-demand for additional scopes when needed
- Use environment variables for secure configuration
- Follow zero-trust principles with granular scope acquisition

## Security Best Practices

✅ **No hardcoded secrets** in source code
✅ **Environment-specific configuration** (dev/staging/prod)
✅ **Docker/Kubernetes secret management** compatible
✅ **CI/CD pipeline friendly** (set env vars in pipeline)
✅ **Compliance friendly** (easier to audit)
✅ **Version control safe** (no secrets in git)

## Environment Variable Configuration

### Required Environment Variables

```bash
# .env file or environment variables
KEYCLOAK_SERVER_URL=http://localhost:8002
KEYCLOAK_REALM=authentication-demo
KEYCLOAK_CLIENT_ID=authentication-demo
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_AUDIENCE=authentication-demo
```

### Environment Variable Setup Options

#### Option A: .env file
```bash
# .env file
KEYCLOAK_SERVER_URL=http://localhost:8002
KEYCLOAK_REALM=authentication-demo
KEYCLOAK_CLIENT_ID=authentication-demo
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_AUDIENCE=authentication-demo
```

#### Option B: Export environment variables
```bash
export KEYCLOAK_SERVER_URL=http://localhost:8002
export KEYCLOAK_REALM=authentication-demo
export KEYCLOAK_CLIENT_ID=authentication-demo
export KEYCLOAK_CLIENT_SECRET=your-client-secret
export KEYCLOAK_AUDIENCE=authentication-demo
```

#### Option C: Docker/Kubernetes secrets
```yaml
# docker-compose.yml
environment:
  - KEYCLOAK_SERVER_URL=http://localhost:8002
  - KEYCLOAK_REALM=authentication-demo
  - KEYCLOAK_CLIENT_ID=authentication-demo
  - KEYCLOAK_CLIENT_SECRET=${KEYCLOAK_CLIENT_SECRET}
  - KEYCLOAK_AUDIENCE=authentication-demo
```

## Implementation

### 1. OAuth2Config Class

```python
import os
from typing import Optional

class OAuth2Config:
    def __init__(self, 
                 token_endpoint: str = None,
                 client_id: str = None, 
                 client_secret: str = None,
                 realm: str = None,
                 audience: str = None):
        
        # Use environment variables with fallbacks
        self.token_endpoint = token_endpoint or os.getenv('KEYCLOAK_SERVER_URL')
        self.client_id = client_id or os.getenv('KEYCLOAK_CLIENT_ID')
        self.client_secret = client_secret or os.getenv('KEYCLOAK_CLIENT_SECRET')
        self.realm = realm or os.getenv('KEYCLOAK_REALM')
        self.audience = audience or os.getenv('KEYCLOAK_AUDIENCE')
        
        # Validate required configuration
        if not all([self.token_endpoint, self.client_id, self.client_secret, self.realm]):
            raise ValueError(
                "Missing required OAuth2 configuration. Set environment variables:\n"
                "KEYCLOAK_SERVER_URL, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET, KEYCLOAK_REALM"
            )
        
        # Construct full token exchange URL
        self.token_exchange_url = f"{self.token_endpoint}/realms/{self.realm}/protocol/openid-connect/token"
```

### 2. LlamaStackClient Implementation

```python
import os
import base64
import requests
from typing import Optional, List
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class LlamaStackClient:
    def __init__(self, api_key: str, oauth2_config: Optional[OAuth2Config] = None):
        self.api_key = api_key
        self.oauth2_config = oauth2_config or OAuth2Config()  # Auto-configure from env vars
        self.user_scopes = self._extract_scopes_from_token(api_key)
    
    def _validate_oauth2_config(self):
        """Validate OAuth2 configuration is complete"""
        required_vars = [
            'KEYCLOAK_SERVER_URL',
            'KEYCLOAK_CLIENT_ID', 
            'KEYCLOAK_CLIENT_SECRET',
            'KEYCLOAK_REALM'
        ]
        
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        
        if missing_vars:
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing_vars)}\n"
                "Please set these environment variables or provide OAuth2Config explicitly."
            )
    
    def _exchange_token_for_scopes(self, required_scopes: List[str], audience: str = None) -> str:
        """
        Exchange current token for one with additional scopes using Keycloak RFC 8693
        
        Args:
            required_scopes: List of scopes to request (e.g., ['llama:agent_create', 'mcp:list_files'])
            audience: Target audience for the new token (defaults to configured audience)
            
        Returns:
            New access token with requested scopes
        """
        if not self.oauth2_config:
            raise Exception("OAuth2 configuration required for token exchange")
        
        # Use configured audience or default
        target_audience = audience or self.oauth2_config.audience
        
        # Prepare Basic Auth header
        credentials = f"{self.oauth2_config.client_id}:{self.oauth2_config.client_secret}"
        basic_auth = base64.b64encode(credentials.encode()).decode()
        
        # Prepare form data for RFC 8693 token exchange
        form_data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token': self.api_key,
            'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'scope': ' '.join(required_scopes),
            'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token'
        }
        
        # Add audience if specified
        if target_audience:
            form_data['audience'] = target_audience
        
        # Make token exchange request
        response = requests.post(
            self.oauth2_config.token_exchange_url,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': f'Basic {basic_auth}'
            },
            data=form_data
        )
        
        if response.status_code != 200:
            raise Exception(f"Token exchange failed: {response.status_code} - {response.text}")
        
        token_data = response.json()
        return token_data['access_token']
    
    def _extract_scopes_from_token(self, token: str) -> List[str]:
        """Extract scopes from JWT token (simplified implementation)"""
        # This is a simplified implementation
        # In production, you'd want to properly decode and verify the JWT
        try:
            import jwt
            decoded = jwt.decode(token, options={"verify_signature": False})
            return decoded.get('scope', '').split()
        except:
            return []
    
    def ensure_scope(self, required_scope: str) -> str:
        """
        Ensure the client has the required scope, exchanging token if necessary
        
        Args:
            required_scope: The scope that needs to be available
            
        Returns:
            Access token with the required scope
        """
        if required_scope in self.user_scopes:
            return self.api_key
        
        # Exchange token for additional scope
        new_token = self._exchange_token_for_scopes([required_scope])
        self.api_key = new_token
        self.user_scopes = self._extract_scopes_from_token(new_token)
        return new_token
```

### 3. Usage Examples

#### Basic Usage (Auto-configured from environment)
```python
# No need to pass sensitive data in code
client = LlamaStackClient(
    api_key="initial_token_with_basic_scopes"
    # oauth2_config will be auto-configured from environment variables
)

# Ensure specific scope is available
token_with_scope = client.ensure_scope("llama:agent_create")
```

#### Explicit Configuration (for testing)
```python
# For testing or when you need explicit configuration
oauth2_config = OAuth2Config(
    token_endpoint="http://localhost:8002",
    client_id="authentication-demo",
    client_secret="your-client-secret",
    realm="authentication-demo",
    audience="authentication-demo"
)

client = LlamaStackClient(
    api_key="initial_token",
    oauth2_config=oauth2_config
)
```

#### Zero-Trust Scope Acquisition
```python
# Start with minimal scope token
client = LlamaStackClient(api_key="token_with_only_email_profile")

# Acquire scopes on-demand
try:
    # Try to create an agent
    agent = client.create_agent(...)
except AuthorizationError as e:
    # Parse error to get required scope
    required_scope = parse_authorization_error(e)
    # Exchange token for required scope
    new_token = client.ensure_scope(required_scope)
    # Retry with new token
    agent = client.create_agent(...)
```

## Keycloak Configuration Requirements

### 1. Enable Token Exchange
In Keycloak Admin Console:
1. Go to **Clients** → **authentication-demo**
2. Go to **Settings** tab
3. Enable **Token Exchange** permission

### 2. Client Configuration
The client must be configured as a **confidential client** with:
- **Client ID**: `authentication-demo`
- **Client Secret**: Your configured secret
- **Access Type**: `confidential`
- **Token Exchange**: Enabled

### 3. Scopes and Policies
Ensure your Keycloak realm has the required scopes defined:
- `llama:agent_create`
- `llama:agent_session_create`
- `llama:inference_chat_completion`
- `mcp:list_files`
- `mcp:get_server_info`
- `mcp:health_check`

## Error Handling

### Common Error Scenarios

#### 1. Missing Environment Variables
```python
# Error: Missing required environment variables: KEYCLOAK_CLIENT_SECRET
# Solution: Set all required environment variables
```

#### 2. Invalid Token Exchange
```python
# Error: Token exchange failed: 400 - Invalid scopes
# Solution: Ensure requested scopes are defined in Keycloak
```

#### 3. Authentication Failure
```python
# Error: Token exchange failed: 401 - Unauthorized
# Solution: Verify client_id and client_secret are correct
```

## Integration with Llama Stack

### 1. Agent Creation Flow
```python
# 1. Start with minimal scope token
client = LlamaStackClient(api_key="token_with_basic_scopes")

# 2. Try to create agent
try:
    agent = client.create_agent(name="my-agent")
except AuthorizationError as e:
    # 3. Exchange for required scope
    new_token = client.ensure_scope("llama:agent_create")
    # 4. Retry with new token
    agent = client.create_agent(name="my-agent")
```

### 2. Tool Usage Flow
```python
# 1. Try to use MCP tool
try:
    files = client.list_files(directory=".")
except AuthorizationError as e:
    # 2. Exchange for MCP scope
    new_token = client.ensure_scope("mcp:list_files")
    # 3. Retry with new token
    files = client.list_files(directory=".")
```

## Security Considerations

### 1. Token Storage
- Store tokens securely (encrypted at rest)
- Use short-lived tokens
- Implement token refresh logic

### 2. Scope Validation
- Always validate scopes before use
- Implement scope-based access control
- Log scope usage for audit trails

### 3. Error Handling
- Don't expose sensitive information in error messages
- Implement proper logging for debugging
- Handle network failures gracefully

### 4. Environment Management
- Use different configurations for dev/staging/prod
- Rotate secrets regularly
- Use secret management services in production

## Testing

### 1. Unit Tests
```python
import unittest
from unittest.mock import patch, MagicMock

class TestLlamaStackClient(unittest.TestCase):
    
    @patch.dict(os.environ, {
        'KEYCLOAK_SERVER_URL': 'http://localhost:8002',
        'KEYCLOAK_CLIENT_ID': 'test-client',
        'KEYCLOAK_CLIENT_SECRET': 'test-secret',
        'KEYCLOAK_REALM': 'test-realm'
    })
    def test_oauth2_config_from_env(self):
        config = OAuth2Config()
        self.assertEqual(config.client_id, 'test-client')
    
    @patch('requests.post')
    def test_token_exchange(self, mock_post):
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'access_token': 'new-token'}
        mock_post.return_value = mock_response
        
        client = LlamaStackClient(api_key="old-token")
        new_token = client._exchange_token_for_scopes(['llama:agent_create'])
        
        self.assertEqual(new_token, 'new-token')
```

### 2. Integration Tests
```python
def test_end_to_end_token_exchange():
    """Test complete token exchange flow with real Keycloak"""
    # Set up test environment
    os.environ['KEYCLOAK_SERVER_URL'] = 'http://localhost:8002'
    os.environ['KEYCLOAK_CLIENT_ID'] = 'authentication-demo'
    os.environ['KEYCLOAK_CLIENT_SECRET'] = 'your-secret'
    os.environ['KEYCLOAK_REALM'] = 'authentication-demo'
    
    # Test token exchange
    client = LlamaStackClient(api_key="initial-token")
    new_token = client.ensure_scope("llama:agent_create")
    
    # Verify new token has required scope
    scopes = client._extract_scopes_from_token(new_token)
    assert "llama:agent_create" in scopes
```

## Troubleshooting

### Common Issues

1. **"Missing required environment variables"**
   - Check all required environment variables are set
   - Verify `.env` file is loaded correctly

2. **"Token exchange failed: 400"**
   - Verify scopes are defined in Keycloak
   - Check token exchange is enabled for the client

3. **"Token exchange failed: 401"**
   - Verify client_id and client_secret are correct
   - Check client is configured as confidential

4. **"Token exchange failed: 403"**
   - Verify token exchange permission is enabled
   - Check user has required roles for requested scopes

### Debug Mode
```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# This will show detailed request/response information
client = LlamaStackClient(api_key="test-token")
```

## Conclusion

This implementation provides a secure, zero-trust approach to token management with LlamaStackClient. By using environment variables for configuration and implementing on-demand scope acquisition, it follows security best practices while maintaining flexibility for different deployment scenarios.

The key benefits are:
- **Security**: No hardcoded secrets
- **Flexibility**: Environment-specific configuration
- **Zero-trust**: Minimal initial scopes with on-demand acquisition
- **Standards compliance**: Uses RFC 8693 token exchange
- **Production ready**: Includes proper error handling and validation 