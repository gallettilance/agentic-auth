# Complete Authentication Flow Documentation

This document provides a detailed walkthrough of the entire authentication and authorization flow, showing exactly which component is responsible for each step and the code that implements it.

## System Components

- **🔍 Google OAuth**: External identity provider
- **🔐 Auth Server** (Port 8002): OAuth authorization server with RFC 8693 token exchange and JWT key management
- **💬 Chat App** (Port 5001): Frontend application with session management  
- **🛠️ MCP Server** (Port 8001): Protected resource with scope-based authorization
- **🔑 JWT Key Management**: RSA key pair generation and JWKS endpoint for asymmetric signing

## JWT Modes

The system supports both symmetric and asymmetric JWT signing:

### **Asymmetric Mode (RS256) - Default**
- **Auto-generated RSA key pairs** on startup
- **Public key distribution** via JWKS endpoint
- **Enhanced security** with public/private key separation
- **Production-ready** with industry standards

### **Symmetric Mode (HS256)**
- **Shared secret** for development environments
- **Simpler deployment** for testing scenarios

## Step-by-Step Flow with Component Responsibility

## **Step 0: JWT Key Setup (Asymmetric Mode)**
**Component: 🔐 Auth Server**

Auth server generates RSA key pairs and sets up JWKS endpoint for public key distribution.

```python
# auth-server/unified_auth_server.py
def auto_generate_keys():
    """Auto-generate RSA key pairs for JWT signing"""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import json
    import hashlib
    
    # Generate 2048-bit RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Extract public key
    public_key = private_key.public_key()
    
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Generate key ID from public key hash
    key_id = hashlib.sha256(public_pem).hexdigest()[:16]
    
    # Create JWKS (JSON Web Key Set)
    jwks = {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": key_id,
            "alg": "RS256",
            "n": "...",  # RSA modulus (base64url encoded)
            "e": "AQAB"  # RSA exponent (base64url encoded)
        }]
    }
    
    # Save keys to files
    os.makedirs("keys", exist_ok=True)
    with open("keys/private_key.pem", "wb") as f:
        f.write(private_pem)
    with open("keys/public_key.pem", "wb") as f:
        f.write(public_pem)
    with open("keys/jwks.json", "w") as f:
        json.dump(jwks, f, indent=2)
    with open("keys/kid.txt", "w") as f:
        f.write(key_id)

@app.get("/.well-known/jwks.json")
async def jwks_endpoint():
    """JWKS endpoint for public key distribution"""
    if JWT_MODE == "asymmetric" and jwks_data:
        return jwks_data
    else:
        raise HTTPException(status_code=404, detail="JWKS not available in symmetric mode")
```

## **Step 1: User Login Request**
**Component: 🌐 Browser → 💬 Chat App**

User navigates to the chat application. Chat app detects no session and redirects to login.

```python
# frontend/chat_app.py
@app.route('/')
def home():
    session_cookie = request.cookies.get(COOKIE_NAME)
    if not session_cookie:
        return redirect('/auth/login')
    
    # Verify session with auth server
    user = verify_session_with_auth_server(session_cookie)
    if not user:
        return redirect('/auth/login')
    
    return render_template('chat.html', user=user)
```

## **Step 2: OAuth Flow Initiation**
**Component: 💬 Chat App → 🔐 Auth Server → 🔍 Google**

Auth server initiates OAuth flow, redirecting user to Google for consent.

```python
# auth-server/unified_auth_server.py
@app.get("/auth/login")
async def login():
    state = secrets.token_urlsafe(32)
    
    google_auth_url = (
        f"{google_config.authorization_endpoint}"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope=openid email profile"
        f"&response_type=code"
        f"&state={state}"
    )
    
    return RedirectResponse(url=google_auth_url)
```

## **Step 3: Authorization Code Return**
**Component: 🔍 Google → 🔐 Auth Server**

Google returns authorization code after user consent.

```python
# auth-server/unified_auth_server.py
@app.get("/auth/callback")
async def oauth_callback(code: str, state: str):
    # Exchange authorization code for tokens
    async with httpx.AsyncClient() as client:
        response = await client.post(
            google_config.token_endpoint,
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": REDIRECT_URI
            }
        )
    
    tokens = response.json()
    access_token = tokens["access_token"]
    id_token = tokens["id_token"]
```

## **Step 4: JWT Creation and Session Setup**
**Component: 🔐 Auth Server**

Auth server validates Google tokens, creates internal JWT with asymmetric signing, and establishes session.

```python
# auth-server/unified_auth_server.py
def generate_token(user: TokenPayload, scopes: List[str], audience: Optional[str] = None) -> str:
    """Generate JWT token with asymmetric or symmetric signing"""
    now = datetime.utcnow()
    
    payload = {
        "sub": user.sub,
        "aud": audience or MCP_SERVER_URI,
        "email": user.email,
        "scope": " ".join(scopes),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
        "iss": SERVER_URI
    }
    
    # Choose signing method based on JWT mode
    if JWT_MODE == "asymmetric":
        # Use RSA private key for signing
        headers = {"kid": KID} if KID else {}
        return jwt.encode(
            payload,
            get_jwt_key_for_signing(),  # RSA private key
            algorithm="RS256",
            headers=headers
        )
    else:
        # Use shared secret for signing
        return jwt.encode(
            payload,
            JWT_SECRET,
            algorithm="HS256"
        )

async def oauth_callback(code: str, state: str):
    # ... token exchange with Google ...
    
    # Decode and validate Google ID token
    id_payload = jwt.decode(
        id_token, 
        options={"verify_signature": False}  # Google's signature
    )
    
    user_email = id_payload["email"]
    
    # Create internal JWT with zero-trust model (empty scope)
    internal_payload = TokenPayload(
        sub=id_payload["sub"],
        aud="http://localhost:8001",  # MCP Server audience
        email=user_email,
        scope="",  # Start with no permissions (RFC 8693 compliance)
        exp=int((datetime.now() + timedelta(hours=1)).timestamp()),
        iat=int(datetime.now().timestamp()),
        iss="http://localhost:8002"
    )
    
    # Generate JWT token (asymmetric or symmetric)
    jwt_token = generate_token(internal_payload, [])
    
    # Create session
    session_id = create_session(internal_payload)
    
    # Set secure cookie and redirect
    response = RedirectResponse(url="http://localhost:5001")
    response.set_cookie(
        key=COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=3600
    )
    return response
```

## **Step 5: Chat Message Handling**
**Component: 💬 Chat App**

User sends chat message, chat app forwards to Llama Stack with JWT token.

```python
# frontend/chat_app.py
@app.route('/api/chat', methods=['POST'])
def chat():
    user = verify_session()  # Get user from session
    message = request.json['message']
    
    # Get JWT token for this user
    jwt_token = get_jwt_token_for_user(user['email'])
    
    # Forward to Llama Stack with authorization
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = requests.post(
        'http://localhost:8321/chat',
        json={'message': message},
        headers=headers
    )
    
    return response.json()
```

## **Step 6: Tool Call with JWT**
**Component: 💬 Chat App → 🛠️ MCP Server**

Chat app calls MCP server tool with JWT token in Authorization header.

```python
# Chat app forwards request to MCP server
headers = {
    "Authorization": f"Bearer {jwt_token}",
    "Content-Type": "application/json"
}

mcp_response = requests.post(
    'http://localhost:8001/sse',
    json={
        "method": "tools/call",
        "params": {
            "name": "list_files",
            "arguments": {"directory": "/tmp"}
        }
    },
    headers=headers
)
```

## **Step 7a: JWT Verification with JWKS**
**Component: 🛠️ MCP Server**

MCP server verifies JWT using JWKS endpoint for asymmetric tokens or shared secret for symmetric tokens.

```python
# mcp/mcp_server.py
def verify_token_from_context(ctx: Context) -> dict:
    """Extract and verify JWT token from MCP context"""
    try:
        auth_header = ctx.request_context.request.headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise Exception("Missing or invalid Authorization header")
        
        token = auth_header.split(" ")[1]
        
        # Choose verification method based on JWT mode
        if JWT_MODE == "asymmetric":
            # Use JWKS for asymmetric verification
            try:
                from jwt import PyJWKClient
                jwks_client = PyJWKClient(f"{AUTH_SERVER_URI}/.well-known/jwks.json")
                signing_key = jwks_client.get_signing_key_from_jwt(token)
                
                payload = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["RS256"],
                    options={"verify_aud": False},
                    leeway=21600  # 6 hours leeway for clock skew
                )
                logger.info(f"✅ Verified RS256 token using JWKS")
            except Exception as jwks_error:
                logger.error(f"❌ JWKS verification failed: {jwks_error}")
                # Fallback to symmetric verification
                payload = jwt.decode(
                    token, 
                    JWT_SECRET, 
                    algorithms=["HS256"],
                    options={"verify_aud": False},
                    leeway=21600
                )
        else:
            # Use shared secret for symmetric verification
            payload = jwt.decode(
                token, 
                JWT_SECRET, 
                algorithms=["HS256"],
                options={"verify_aud": False},
                leeway=21600
            )
        
        # Validate audience and issuer
        if payload.get("aud") != SERVER_URI:
            raise Exception(f"Invalid audience: expected {SERVER_URI}, got {payload.get('aud')}")
        if payload.get("iss") != AUTH_SERVER_URI:
            raise Exception(f"Invalid issuer: expected {AUTH_SERVER_URI}, got {payload.get('iss')}")
        
        return payload
        
    except jwt.ExpiredSignatureError:
        raise Exception("Token expired")
    except jwt.InvalidTokenError as e:
        raise Exception("Invalid token")

@mcp.tool()
async def list_files(ctx: Context, directory: str = ".") -> Dict[str, Any]:
    try:
        # Verify authentication and scope
        user = check_scope(ctx, "read:files")
        
        # Execute tool
        files = []
        for item in os.listdir(directory):
            # ... file listing logic ...
        
        return {
            "success": True,
            "files": files,
            "user": user.get('email')
        }
    except Exception as e:
        return await handle_scope_error(ctx, str(e))
```

## **Step 7b: Insufficient Scope Error**
**Component: 🛠️ MCP Server → 💬 Chat App**

MCP server detects missing scope and returns upgrade information.

```python
# mcp/mcp_server.py
def check_scope(ctx: Context, required_scope: str) -> dict:
    """Check if user has required scope, return upgrade info if insufficient"""
    user = verify_token_from_context(ctx)
    user_scopes = user.get("scope", "").split()
    
    if required_scope not in user_scopes:
        error_info = {
            "error_type": "insufficient_scope",
            "error": f"Insufficient scope. Required: {required_scope}",
            "required_scope": required_scope,
            "user_scopes": user_scopes,
            "scope_upgrade_endpoint": f"{AUTH_SERVER_URI}/api/upgrade-scope",
            "scope_description": get_scope_description(required_scope),
            "upgrade_instructions": "Use the scope_upgrade_endpoint to request additional permissions"
        }
        raise Exception(json.dumps(error_info))
    
    return user

async def handle_scope_error(ctx: Context, error_msg: str) -> Dict[str, Any]:
    try:
        error_data = json.loads(error_msg)
        if error_data.get("error_type") == "insufficient_scope":
            return {
                "success": False,
                "error_type": "insufficient_scope",
                "required_scope": error_data["required_scope"],
                "user_scopes": error_data["user_scopes"],
                "scope_upgrade_endpoint": error_data["scope_upgrade_endpoint"],
                "upgrade_instructions": error_data["upgrade_instructions"]
            }
    except (json.JSONDecodeError, KeyError):
        pass
    
    return {"success": False, "error": error_msg}
```

## **Step 8: Token Exchange Request**
**Component: 💬 Chat App → 🔐 Auth Server**

Chat app requests token exchange using RFC 8693 to get required scope.

```python
# frontend/chat_app.py
async def request_scope_upgrade(current_token, required_scope):
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": current_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "client_id": "chat-app",
        "client_secret": "chat-app-secret",
        "scope": required_scope,
        "audience": "http://localhost:8001"
    }
    
    response = requests.post(
        'http://localhost:8002/oauth/token',
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    
    return response.json()
```

## **Step 9: New JWT Issuance with Asymmetric Signing**
**Component: 🔐 Auth Server**

Auth server evaluates approval policy and issues new JWT with required scope using asymmetric signing.

```python
# auth-server/unified_auth_server.py
@app.post("/oauth/token")
async def oauth_token_endpoint(
    grant_type: str = Form(...),
    subject_token: str = Form(...),
    scope: str = Form(...),
    # ... other parameters
):
    # Validate subject token (supports both asymmetric and symmetric)
    try:
        if JWT_MODE == "asymmetric":
            # Verify with RSA public key
            subject_payload = jwt.decode(
                subject_token, 
                get_jwt_key_for_verification(),  # RSA public key
                algorithms=["RS256"]
            )
        else:
            # Verify with shared secret
            subject_payload = jwt.decode(
                subject_token, 
                JWT_SECRET, 
                algorithms=["HS256"]
            )
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid subject token")
    
    user_email = subject_payload.get("email")
    
    # Evaluate approval policy
    requested_scopes = scope.split()
    policy_result = evaluate_approval_policy(user_email, requested_scopes)
    
    if policy_result.get("requires_approval"):
        # Create approval request and return authorization_pending
        return JSONResponse(
            status_code=400,
            content={
                "error": "authorization_pending",
                "error_description": "Admin approval required",
                "interval": 5,
                "expires_in": 600
            }
        )
    
    # Auto-approve: create new token with additional scopes
    current_scopes = subject_payload.get("scope", "").split()
    auto_approved = policy_result.get("auto_approved", [])
    new_scopes = list(set(current_scopes + auto_approved))
    
    # Generate new JWT with asymmetric signing
    new_token = generate_token(
        TokenPayload(**subject_payload),
        new_scopes,
        audience="http://localhost:8001"
    )
    
    return {
        "access_token": new_token,
        "token_type": "Bearer",
        "scope": " ".join(new_scopes),
        "expires_in": 3600
    }
```

## **Step 10: Retry Tool Call**
**Component: 💬 Chat App → 🛠️ MCP Server**

Chat app retries the original tool call with the upgraded JWT token.

```python
# frontend/chat_app.py
async def retry_with_upgraded_token(tool_name, arguments, new_token):
    headers = {"Authorization": f"Bearer {new_token}"}
    
    response = requests.post(
        'http://localhost:8001/sse',
        json={
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        },
        headers=headers
    )
    
    return response.json()
```

## **Step 11: Successful Execution**
**Component: 🛠️ MCP Server → 💬 Chat App**

MCP server validates the upgraded token using JWKS and successfully executes the tool.

---

## **Enhanced Security Features**

### **Asymmetric JWT Token Structure (RS256)**
```json
{
  "header": {
    "alg": "RS256", 
    "typ": "JWT",
    "kid": "a1b2c3d4e5f6"
  },
  "payload": {
    "sub": "user-123",
    "email": "user@example.com", 
    "aud": "http://localhost:8001",
    "iss": "http://localhost:8002",
    "scope": "read:files execute:commands",
    "exp": 1640995200,
    "iat": 1640991600
  }
}
```

### **JWKS Endpoint Response**
```json
{
  "keys": [{
    "kty": "RSA",
    "use": "sig",
    "kid": "a1b2c3d4e5f6",
    "alg": "RS256",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e": "AQAB"
  }]
}
```

### **JWT Debugging Features**
```python
# auth-server/unified_auth_server.py
@app.get("/api/jwt-debug-url")
async def get_jwt_debug_url(user: TokenPayload = Depends(verify_user_auth)):
    """Get JWT.io debug URL with token and public key"""
    jwt_token = generate_token(user, user.scope.split() if user.scope else [])
    
    # Build JWT.io URL with token and public key for immediate verification
    jwt_io_url = build_jwt_io_url(jwt_token)
    
    return {
        "jwt_io_url": jwt_io_url,
        "jwt_token": jwt_token,
        "jwt_mode": JWT_MODE,
        "algorithm": get_jwt_algorithm(),
        "has_public_key": JWT_MODE == "asymmetric"
    }

@app.get("/api/public-key")
async def get_public_key_for_copy():
    """Get the public key in PEM format for easy copying"""
    if JWT_MODE == "asymmetric":
        public_key_pem = get_public_key_pem()
        return {
            "public_key": public_key_pem,
            "algorithm": get_jwt_algorithm(),
            "key_id": KID,
            "instructions": "Copy this public key and paste it into the 'Verify Signature' section of JWT.io"
        }
    else:
        raise HTTPException(status_code=400, detail="Public key only available in asymmetric mode")

def build_jwt_io_url(jwt_token: str) -> str:
    """Build JWT.io URL with token and public key for immediate verification"""
    import urllib.parse
    
    base_url = "https://jwt.io/#debugger-io"
    params = {"token": jwt_token}
    
    # Add public key for asymmetric mode
    if JWT_MODE == "asymmetric":
        public_key_pem = get_public_key_pem()
        if public_key_pem:
            params["publicKey"] = public_key_pem
    
    return f"{base_url}?{urllib.parse.urlencode(params)}"
```

### **Secure Cookie Configuration**
```javascript
Set-Cookie: auth_session=<session_id>; 
            HttpOnly; Secure; SameSite=Strict; 
            Max-Age=3600; Path=/; Domain=localhost
```

### **Component Responsibilities Summary**

| Component | Responsibilities |
|-----------|-----------------|
| **🔐 Auth Server** | OAuth flow, RSA key generation, JWT creation/validation (RS256/HS256), RFC 8693 token exchange, JWKS endpoint, approval workflows |
| **💬 Chat App** | Session management, UI, token exchange requests, tool call coordination |
| **🛠️ MCP Server** | JWT validation via JWKS/shared secret, scope checking, tool execution, scope upgrade guidance |
| **🔍 Google OAuth** | User authentication, identity verification |
| **🔑 JWKS Endpoint** | Public key distribution for JWT verification |

### **Enhanced Token Flow Summary**

1. **Startup**: RSA key generation → JWKS endpoint setup
2. **Login**: OAuth → JWT creation (RS256/HS256) → Secure session
3. **Tool Call**: JWT validation via JWKS/secret → Scope check → Execute or upgrade
4. **Token Exchange**: RFC 8693 → Policy evaluation → New JWT (RS256/HS256)
5. **Retry**: Upgraded token → JWKS verification → Successful execution
6. **Debug**: JWT.io integration with public key → Token inspection

## **Admin Approval Flow (When Required)**

When a scope requires admin approval, the flow extends with enhanced JWT verification:

**Step 9b: Authorization Pending Response**
```json
{
  "error": "authorization_pending", 
  "error_description": "Admin approval required for execute:commands scope",
  "interval": 5,
  "expires_in": 600
}
```

**Step 10b: Admin Dashboard with JWT Debugging**
```python
# auth-server/unified_auth_server.py
@app.get("/dashboard")
async def dashboard(user: TokenPayload = Depends(verify_user_auth)):
    """Admin dashboard with JWT debugging tools"""
    jwt_token = generate_token(user, user.scope.split() if user.scope else [])
    
    return HTMLResponse(f"""
    <div class="jwt-debug">
        <h3>JWT Token Debugging</h3>
        <p>JWT Mode: <strong>{JWT_MODE.upper()} ({get_jwt_algorithm()})</strong></p>
        <p>
            <a href="{build_jwt_io_url(jwt_token)}" target="_blank">Debug Token on JWT.io</a>
            {'''<button onclick="copyPublicKey(this)">📋 Copy Public Key</button>''' if JWT_MODE == 'asymmetric' else ''}
        </p>
    </div>
    """)

@app.post("/api/approve/{request_id}")
async def approve_request(request_id: str, admin_email: str = Form(...)):
    approval_request = approval_requests.get(request_id)
    
    if not approval_request:
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    # Update approval status
    approval_request.status = ApprovalStatus.APPROVED
    approval_request.approved_by = admin_email
    approval_request.approved_at = datetime.now()
    
    return {"message": "Request approved successfully"}
```

**Step 11b: Polling Resolution with Enhanced JWT**
Chat app polls until approval is granted, then receives the upgraded token with proper asymmetric signing.

---

## **Key Security Enhancements**

### **1. Asymmetric JWT Benefits**
- **Enhanced Security**: Private key never leaves auth server
- **Scalability**: Public key can be distributed to multiple services
- **Non-repudiation**: Cryptographic proof of token authenticity
- **Industry Standard**: Follows OAuth 2.0 and OIDC best practices

### **2. JWKS Integration**
- **Automatic Key Discovery**: Services fetch public keys automatically
- **Key Rotation Support**: Multiple keys can be supported simultaneously
- **Standards Compliance**: RFC 7517 JSON Web Key (JWK) specification

### **3. Enhanced Debugging**
- **JWT.io Integration**: One-click token debugging with public key
- **Public Key Copying**: Easy verification in external tools
- **Real-time Validation**: Immediate feedback on token structure

This enhanced flow demonstrates **production-grade JWT security** with asymmetric signing, automatic key management, and comprehensive debugging tools, while maintaining backward compatibility with symmetric JWT for development environments. 