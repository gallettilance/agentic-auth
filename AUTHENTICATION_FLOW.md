# Complete Authentication Flow Documentation

This document provides a detailed walkthrough of the entire authentication and authorization flow, showing exactly which component is responsible for each step and the code that implements it.

## System Components

- **🔍 Google OAuth**: External identity provider
- **🔐 Auth Server** (Port 8002): OAuth authorization server with RFC 8693 token exchange
- **💬 Chat App** (Port 5001): Frontend application with session management  
- **🛠️ MCP Server** (Port 8001): Protected resource with scope-based authorization

## Step-by-Step Flow with Component Responsibility

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

Auth server validates Google tokens, creates internal JWT, and establishes session.

```python
# auth-server/unified_auth_server.py
async def oauth_callback(code: str, state: str):
    # ... token exchange with Google ...
    
    # Decode and validate Google ID token
    id_payload = jwt.decode(
        id_token, 
        options={"verify_signature": False}  # Google's signature
    )
    
    user_email = id_payload["email"]
    user_roles = get_user_roles(user_email)
    
    # Create internal JWT
    internal_payload = TokenPayload(
        sub=id_payload["sub"],
        aud="http://localhost:8001",  # MCP Server audience
        email=user_email,
        scope="read:files",  # Initial scope based on role
        exp=int((datetime.now() + timedelta(hours=1)).timestamp()),
        iat=int(datetime.now().timestamp()),
        iss="http://localhost:8002"
    )
    
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

## **Step 7a: Successful Tool Execution**
**Component: 🛠️ MCP Server**

MCP server validates JWT and executes tool if user has required scope.

```python
# mcp/mcp_server.py
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

def check_scope(ctx: Context, required_scope: str) -> dict:
    user = verify_token_from_context(ctx)
    user_scopes = user.get("scope", "").split()
    
    if required_scope not in user_scopes:
        error_info = {
            "error_type": "insufficient_scope",
            "required_scope": required_scope,
            "user_scopes": user_scopes,
            "scope_upgrade_endpoint": f"{AUTH_SERVER_URI}/oauth/token"
        }
        raise Exception(json.dumps(error_info))
    
    return user
```

## **Step 7b: Insufficient Scope Error**
**Component: 🛠️ MCP Server → 💬 Chat App**

MCP server detects missing scope and returns upgrade information.

```python
# mcp/mcp_server.py
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
                "upgrade_instructions": "Use the scope_upgrade_endpoint to request additional permissions"
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

## **Step 9: New JWT Issuance**
**Component: 🔐 Auth Server**

Auth server evaluates approval policy and issues new JWT with required scope.

```python
# auth-server/unified_auth_server.py
@app.post("/oauth/token")
async def oauth_token_endpoint(
    grant_type: str = Form(...),
    subject_token: str = Form(...),
    scope: str = Form(...),
    # ... other parameters
):
    # Validate subject token
    subject_payload = jwt.decode(subject_token, JWT_SECRET, algorithms=["HS256"])
    user_email = subject_payload.get("email")
    
    # Evaluate approval policy
    requested_scopes = scope.split()
    policy_result = evaluate_approval_policy(user_email, requested_scopes)
    
    if policy_result["requires_admin_approval"]:
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
    new_scopes = list(set(current_scopes + policy_result["auto_approved"]))
    
    new_token = generate_token(
        subject_payload,
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

MCP server validates the upgraded token and successfully executes the tool.

```python
# mcp/mcp_server.py - Same validation logic as Step 7a
# Now the token contains the required scope, so execution succeeds

def verify_token_from_context(ctx: Context) -> dict:
    auth_header = ctx.request_context.request.headers.get("authorization")
    token = auth_header.split(" ")[1]
    
    payload = jwt.decode(
        token, 
        JWT_SECRET, 
        algorithms=["HS256"]
    )
    
    # Validate audience, issuer, expiration
    if payload.get("aud") != SERVER_URI:
        raise Exception("Invalid audience")
    if payload.get("iss") != AUTH_SERVER_URI:
        raise Exception("Invalid issuer")
    
    return payload
```

---

## **Key Security Features**

### **JWT Token Structure**
```json
{
  "header": {"alg": "HS256", "typ": "JWT"},
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

### **Secure Cookie Configuration**
```javascript
Set-Cookie: auth_session=<session_id>; 
            HttpOnly; Secure; SameSite=Strict; 
            Max-Age=3600; Path=/
```

### **Component Responsibilities Summary**

| Component | Responsibilities |
|-----------|-----------------|
| **🔐 Auth Server** | OAuth flow, JWT creation/validation, RFC 8693 token exchange, approval workflows |
| **💬 Chat App** | Session management, UI, token exchange requests, tool call coordination |
| **🛠️ MCP Server** | JWT validation, scope checking, tool execution, scope upgrade guidance |
| **🔍 Google OAuth** | User authentication, identity verification |

### **Token Flow Summary**

1. **Login**: OAuth → JWT creation → Secure session
2. **Tool Call**: JWT validation → Scope check → Execute or upgrade
3. **Token Exchange**: RFC 8693 → Policy evaluation → New JWT
4. **Retry**: Upgraded token → Successful execution

## **Admin Approval Flow (When Required)**

When a scope requires admin approval, the flow extends:

**Step 9b: Authorization Pending Response**
```json
{
  "error": "authorization_pending", 
  "error_description": "Admin approval required for execute:commands scope",
  "interval": 5,
  "expires_in": 600
}
```

**Step 10b: Admin Dashboard Approval**
```python
# auth-server/unified_auth_server.py
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

**Step 11b: Polling Resolution**
Chat app polls until approval is granted, then receives the upgraded token.

---

This flow demonstrates **complete token negotiation** from OAuth login through secure tool execution, with clear component responsibilities and RFC 8693 compliant token exchange. 