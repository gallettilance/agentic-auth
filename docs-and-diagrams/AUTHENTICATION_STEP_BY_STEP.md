# Authentication and Authorization: Step-by-Step Process

## Overview
This document provides a detailed, step-by-step walkthrough of how authentication and authorization work in the Authentication Demo repository. Each step includes the specific code paths, API calls, and security considerations.

## Prerequisites
- Keycloak server running on `http://localhost:8002`
- Llama Stack server running on `http://localhost:8321`
- MCP server running on `http://localhost:8001`
- Chat UI running on `http://localhost:5001`

## Step 1: Initial Setup and Configuration

### 1.1 Keycloak Configuration
**File**: `setup_keycloak_v2.py`

**Process**:
1. Create realm `authentication-demo`
2. Create confidential client `authentication-demo`
3. Enable Token Exchange V2 feature
4. Define scopes and roles:
   - **MCP Scopes**: `mcp:list_files`, `mcp:health_check`, etc.
   - **Llama Stack Scopes**: `llama:inference`, `llama:models:read`, etc.
   - **Roles**: `user` (most scopes), `admin` (all scopes)
5. Create authorization policies
6. Create users with assigned roles

**Key Configuration**:
```python
SCOPE_DEFINITIONS = {
    "mcp:list_files": {"description": "List files via MCP", "risk_level": "low", "min_role": "user"},
    "llama:inference": {"description": "Inference via Llama Stack", "risk_level": "medium", "min_role": "user"},
    # ... more scopes
}

ROLE_DEFINITIONS = {
    "user": {
        "scopes": ["mcp:list_files", "llama:inference", "llama:models:read", ...]
    },
    "admin": {
        "scopes": list(SCOPE_DEFINITIONS.keys())  # All scopes
    }
}
```

### 1.2 Environment Configuration
**File**: `env.example` → `env`

**Required Variables**:
```bash
OIDC_ISSUER_URL=http://localhost:8002/realms/authentication-demo
OIDC_CLIENT_ID=authentication-demo
OIDC_CLIENT_SECRET=demo-client-secret-change-in-production
LLAMA_STACK_URL=http://localhost:8321
MCP_SERVER_URL=http://localhost:8001
```

## Step 2: User Authentication Flow

### 2.1 User Visits Chat UI
**File**: `frontends/chat-ui/app.py` - `@app.route('/')`

**Process**:
1. User visits `http://localhost:5001`
2. Flask checks session for `authenticated` flag
3. If not authenticated → redirect to `/login`
4. If authenticated → show chat interface

**Code Path**:
```python
@app.route('/')
def index():
    if 'authenticated' not in session:
        return redirect('/login')
    return render_template('chat.html')
```

### 2.2 OAuth2 Authorization Request
**File**: `frontends/chat-ui/app.py` - `@app.route('/login')`

**Process**:
1. Generate PKCE code verifier and challenge
2. Store state and code verifier in session
3. Redirect to Keycloak authorization endpoint

**Code Path**:
```python
@app.route('/login')
def login():
    # Generate PKCE parameters
    code_verifier = secrets.token_urlsafe(32)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip('=')
    
    # Store in session
    session['code_verifier'] = code_verifier
    session['oauth_state'] = state
    
    # Redirect to Keycloak
    auth_url = f"{OIDC_ISSUER_URL}/protocol/openid-connect/auth"
    params = {
        'response_type': 'code',
        'client_id': OIDC_CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'openid profile email',  # Basic OIDC scopes only
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    return redirect(f"{auth_url}?{urllib.parse.urlencode(params)}")
```

### 2.3 Keycloak Authentication
**Process**:
1. User enters credentials in Keycloak login form
2. Keycloak validates credentials against user database
3. Keycloak checks user roles and permissions
4. Keycloak generates authorization code
5. Redirect back to Chat UI with code

**Keycloak Actions**:
- Validate user credentials
- Check user roles (`user` or `admin`)
- Generate authorization code
- Include user info in token claims

### 2.4 Token Exchange
**File**: `frontends/chat-ui/app.py` - `@app.route('/callback')`

**Process**:
1. Receive authorization code from Keycloak
2. Exchange code for access token using PKCE
3. Store access token in session
4. Set user as authenticated

**Code Path**:
```python
@app.route('/callback')
def callback():
    code = request.args.get('code')
    state = request.args.get('state')
    
    # Verify state parameter
    if state != session.get('oauth_state'):
        return redirect('/')
    
    # Exchange code for token
    result = asyncio.run(exchange_code_for_token(code, state, session['code_verifier']))
    
    if result['success']:
        # Store tokens in session
        session['authenticated'] = True
        session['user_email'] = result['user_info']['email']
        session['access_token'] = result['access_token']
        
        # 🔒 ZERO-TRUST: No service tokens yet
        logger.info("🔒 Zero-trust login: User has only basic OIDC scopes initially")
```

**Token Exchange Details**:
```python
async def exchange_code_for_token(code: str, state: str, code_verifier: str) -> dict:
    token_endpoint = f"{OIDC_ISSUER_URL}/protocol/openid-connect/token"
    
    data = {
        'grant_type': 'authorization_code',
        'client_id': OIDC_CLIENT_ID,
        'client_secret': OIDC_CLIENT_SECRET,
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'code_verifier': code_verifier
    }
    
    response = await client.post(token_endpoint, data=data)
    return response.json()
```

## Step 3: Zero Trust Initial State

### 3.1 Initial Token State
**Result**: User has access token with basic OIDC scopes only
- **Scopes**: `openid`, `profile`, `email`
- **No Service Scopes**: No `llama:` or `mcp:` scopes
- **Audience**: `authentication-demo` (client ID)
- **Purpose**: Identity verification only

**Token Structure**:
```json
{
  "sub": "user-uuid",
  "aud": "authentication-demo",
  "scope": "openid profile email",
  "realm_access": {
    "roles": ["user"]
  },
  "email": "user@example.com"
}
```

### 3.2 Token Dashboard Initial State
**File**: `frontends/chat-ui/api/tokens.py` - `@tokens_bp.route('/token-info')`

**Display**:
- ✅ Access Token: Available (basic OIDC scopes)
- 🔒 Llama Stack Token: Not exchanged yet
- 🔒 MCP Token: Not exchanged yet
- **Message**: "Zero-trust: Service tokens will be exchanged when first needed"

## Step 4: Service Access and Token Exchange

### 4.1 Llama Stack Token Exchange

#### 4.1.1 User Starts Chat
**File**: `frontends/chat-ui/api/chat.py` - `@chat_bp.route('/chat')`

**Process**:
1. User sends message to chat
2. Chat UI creates LlamaStackClient
3. Client configured with OAuth2Config
4. Client performs API call

**Code Path**:
```python
@chat_bp.route('/chat', methods=['POST'])
def chat():
    user_email = session.get('user_email')
    access_token = session.get('access_token')
    
    # Create LlamaStackClient with OAuth2Config
    llama_client = LlamaStackClient(
        base_url=LLAMA_STACK_URL,
        api_key=access_token,  # Initial token
        oauth2_config=oauth2_config
    )
```

#### 4.1.2 Automatic Token Exchange
**File**: `frontends/chat-ui/utils/llama_agents_utils.py`

**Process**:
1. LlamaStackClient makes API call (e.g., `models.list()`)
2. Llama Stack returns 401 with required scopes
3. LlamaStackClient automatically exchanges token
4. New token includes required scopes
5. API call retried with new token

**OAuth2Config Setup**:
```python
oauth2_config = OAuth2Config(
    token_endpoint=f"{OIDC_ISSUER_URL}/protocol/openid-connect/token",
    client_id=OIDC_CLIENT_ID,
    client_secret=OIDC_CLIENT_SECRET,
    realm="authentication-demo"
)
```

#### 4.1.3 Token Exchange V2 Request
**Process**:
1. LlamaStackClient calls Keycloak token endpoint
2. Uses self-exchange pattern (audience = client_id)
3. Requests specific scopes (e.g., `llama:models:read`)
4. Keycloak validates user permissions
5. Returns new token with scopes

**Request Details**:
```http
POST /realms/authentication-demo/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<current_access_token>
audience=authentication-demo
requested_token_type=urn:ietf:params:oauth:token-type:jwt
scope=llama:models:read
```

**Response**:
```json
{
  "access_token": "new_jwt_with_scopes",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "openid profile email llama:models:read"
}
```

### 4.2 MCP Token Exchange

#### 4.2.1 MCP Tool Call
**File**: `frontends/chat-ui/utils/streaming_utils.py`

**Process**:
1. User requests MCP tool (e.g., list files)
2. MCP server validates token
3. If insufficient scopes → returns `InsufficientScopeError`
4. Chat UI parses error for required scopes

**Error Handling**:
```python
def handle_mcp_error(error_response: dict) -> dict:
    if "InsufficientScopeError" in str(error_response):
        # Parse required scopes from error
        required_scopes = parse_required_scopes(error_response)
        return exchange_mcp_token_for_scopes(required_scopes)
```

#### 4.2.2 Manual Token Exchange
**File**: `frontends/chat-ui/api/tokens.py` - `@tokens_bp.route('/exchange-mcp-token-scope')`

**Process**:
1. Parse required scopes from error
2. Call Keycloak token exchange endpoint
3. Request specific MCP scopes
4. Store new token in session
5. Retry MCP tool call

**Code Path**:
```python
@tokens_bp.route('/exchange-mcp-token-scope', methods=['POST'])
def exchange_mcp_token_scope():
    data = request.get_json()
    required_scope = data.get('required_scope')
    
    # Exchange token for specific scope
    result = asyncio.run(exchange_token_for_audience(
        session['access_token'],
        'authentication-demo',
        [required_scope]
    ))
    
    if result['success']:
        session['mcp_token'] = result['access_token']
        return jsonify({'success': True})
```

## Step 5: Token Dashboard Updates

### 5.1 Real-time Token Status
**File**: `frontends/chat-ui/api/tokens.py` - `@tokens_bp.route('/llama-stack-token-info')`

**Process**:
1. Query LlamaStackClient for current token
2. Fall back to session token if needed
3. Display token information and scopes
4. Show token source (client vs session)

**Code Path**:
```python
@tokens_bp.route('/llama-stack-token-info')
def get_llama_stack_token_info():
    user_email = session.get('user_email')
    
    # Try to get current token from LlamaStackClient
    if user_email in user_agents:
        llama_client = user_agents[user_email]['client']
        if hasattr(llama_client, 'get_current_token'):
            current_token = llama_client.get_current_token()
            client_message = "Token from LlamaStackClient"
    
    # Fallback to session token
    if not current_token:
        current_token = session.get('llama_stack_token')
        client_message = "Token from session (fallback)"
```

### 5.2 Scope Tracking
**Display**:
- **Current Scopes**: Shows all scopes in current token
- **Token Source**: Indicates where token came from
- **Exchange History**: Tracks scope acquisitions
- **Error Information**: Shows recent errors

## Step 6: Continuous Operation

### 6.1 Additional Scope Requests
**Process**:
1. Service requires new scope
2. Automatic token exchange triggered
3. New token with additional scopes
4. Service call proceeds
5. Token dashboard updated

### 6.2 Token Refresh
**Process**:
1. Token expires
2. OAuth2Config handles refresh automatically
3. New token obtained transparently
4. Service continues without interruption

### 6.3 Error Recovery
**Scenarios**:
1. **Network Issues**: Retry with exponential backoff
2. **Key Rotation**: JWKS cache refresh
3. **Authorization Denied**: User-friendly error messages
4. **Session Expired**: Redirect to login

## Step 7: Logout and Cleanup

### 7.1 User Logout
**File**: `frontends/chat-ui/app.py` - `@app.route('/logout')`

**Process**:
1. Clear Flask session
2. Clear token cache
3. Redirect to Keycloak logout
4. Clear browser cookies

**Code Path**:
```python
@app.route('/logout')
def logout():
    # Clear token cache
    user_email = session.get('user_email')
    if user_email in token_cache:
        del token_cache[user_email]
    
    # Clear session
    session.clear()
    
    # Redirect to Keycloak logout
    logout_url = f"{OIDC_ISSUER_URL}/protocol/openid-connect/logout"
    params = {
        'post_logout_redirect_uri': 'http://localhost:5001',
        'client_id': OIDC_CLIENT_ID
    }
    return redirect(f"{logout_url}?{urllib.parse.urlencode(params)}")
```

### 7.2 Session Cleanup
**Process**:
1. Remove user from `user_agents` cache
2. Clear MCP token from session
3. Clear Llama Stack token from session
4. Clear access token from session

## Security Considerations

### 1. Zero Trust Principles
- **Initial State**: No service-specific scopes
- **On-Demand Escalation**: Scopes acquired only when needed
- **Granular Permissions**: Each scope has specific purpose
- **Audit Trail**: All scope requests logged

### 2. Token Security
- **JWT Validation**: All tokens verified by services
- **Audience Validation**: Ensures tokens for correct services
- **Scope Validation**: Services check required permissions
- **Key Rotation**: Handled via JWKS endpoints

### 3. Session Security
- **Secure Cookies**: HTTP-only, secure flags
- **CSRF Protection**: State parameter validation
- **Session Timeout**: Configurable session lifetime
- **Secure Logout**: Proper cleanup and Keycloak logout

### 4. Error Handling
- **Graceful Degradation**: Services continue with available scopes
- **User-Friendly Messages**: Clear error explanations
- **Automatic Recovery**: Retry mechanisms for transient errors
- **Security Logging**: All authorization events tracked

## Monitoring and Debugging

### 1. Token Dashboard
- **Real-time Status**: Current token information
- **Scope Display**: Shows all active scopes
- **Source Tracking**: Indicates token origin
- **Error History**: Recent errors and resolutions

### 2. Debug Endpoints
- `/debug/token`: Current token details
- `/debug/session`: Session state
- `/api/tokens/token-info`: Comprehensive token analysis
- `/api/tokens/llama-stack-token-info`: Llama Stack specific info

### 3. Logging
- **Authentication Events**: Login, logout, token exchange
- **Authorization Events**: Scope requests, denials
- **Error Events**: Network issues, validation failures
- **Performance Metrics**: Response times, cache hits

## Best Practices

### 1. Security
- **Principle of Least Privilege**: Request minimal scopes
- **Token Rotation**: Regular token refresh
- **Audit Logging**: Track all authorization events
- **Secure Configuration**: Environment variables for secrets

### 2. Performance
- **Token Caching**: Cache tokens appropriately
- **Connection Pooling**: Reuse HTTP connections
- **Error Handling**: Graceful degradation
- **Monitoring**: Real-time status tracking

### 3. User Experience
- **Seamless Authentication**: Single sign-on
- **Transparent Escalation**: Automatic scope acquisition
- **Clear Feedback**: Token dashboard visibility
- **Error Recovery**: Automatic retry mechanisms

This step-by-step process ensures a secure, scalable, and user-friendly authentication and authorization system that follows zero trust principles while providing seamless access to services. 