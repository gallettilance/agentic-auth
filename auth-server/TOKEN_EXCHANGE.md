# Token Exchange Implementation Guide

This document provides a complete guide to the **RFC 8693 Token Exchange** implementation with transparent approval handling for MCP servers.

## 🎯 **Overview**

The system implements **RFC 8693 Token Exchange** with transparent approval workflows, allowing MCP servers to be deployed independently while maintaining security and admin oversight.

### **Key Benefits**
- ✅ **Standards Compliant** - RFC 8693 token exchange protocol
- ✅ **Independent Deployment** - MCP servers work with any compliant auth server
- ✅ **Transparent Approval** - Auth server handles approval internally
- ✅ **No Custom APIs** - Standard OAuth2 error responses and polling

## 🏗️ **Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   MCP Server    │    │   Auth Server   │    │  Admin Portal   │
│                 │    │                 │    │                 │
│ 1. Token        │───▶│ 2. Validate     │    │                 │
│    Exchange     │    │    Request      │    │                 │
│    Request      │    │                 │    │                 │
│                 │    │ 3. Check        │    │                 │
│                 │    │    Approval     │    │                 │
│                 │    │    Policy       │    │                 │
│                 │    │                 │    │                 │
│ 6. Poll for     │◀───│ 4. Create       │───▶│ 5. Admin        │
│    Approval     │    │    Approval     │    │    Reviews      │
│                 │    │    Request      │    │                 │
│                 │    │                 │    │                 │
│ 7. Success!     │◀───│ 8. Return       │◀───│ 9. Approval     │
│    New Token    │    │    New Token    │    │    Granted      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🌐 **API Endpoints**

### **Token Exchange Endpoint**

**`POST /oauth/token`** - RFC 8693 compliant token exchange

**Request:**
```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=ACCESS_TOKEN_HERE
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&client_id=mcp-server
&client_secret=mcp-server-secret
&audience=file-service
&scope=execute:commands
```

**Success Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "execute:commands"
}
```

**Approval Required Response (400):**
```json
{
  "error": "authorization_pending",
  "error_description": "Administrator approval required for requested scopes",
  "interval": 5,
  "expires_in": 600
}
```

### **Authorization Server Metadata**

**`GET /.well-known/oauth-authorization-server`** - RFC 8414 metadata

**Response:**
```json
{
  "issuer": "http://localhost:8002",
  "token_endpoint": "http://localhost:8002/oauth/token",
  "grant_types_supported": [
    "authorization_code",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "token_exchange_grant_type_supported": true,
  "token_types_supported": [
    "urn:ietf:params:oauth:token-type:access_token"
  ],
  "subject_token_types_supported": [
    "urn:ietf:params:oauth:token-type:access_token"
  ]
}
```

## 🔧 **Client Configuration**

### **Registered Clients**
```python
CLIENTS = {
    "mcp-server": {
        "client_secret": "mcp-server-secret",
        "client_type": "confidential",
        "token_exchange_enabled": True,
        "allowed_audiences": ["file-service", "command-executor", "mcp-tools"]
    },
    "chat-app": {
        "client_secret": "chat-app-secret", 
        "client_type": "confidential",
        "token_exchange_enabled": True,
        "allowed_audiences": ["mcp-server"]
    }
}
```

## 💻 **Usage Examples**

### **Python MCP Server Implementation**

```python
from token_exchange_example import TokenExchangeClient

# Initialize client
client = TokenExchangeClient(
    auth_server_url="http://localhost:8002",
    client_id="mcp-server",
    client_secret="mcp-server-secret"
)

# Exchange token with automatic approval polling
result = await client.exchange_with_polling(
    subject_token=user_token,
    required_scopes=["execute:commands"],
    audience="command-executor",
    max_wait_time=300  # 5 minutes
)

if result["success"]:
    # Use the new token for tool calls
    new_token = result["access_token"]
    approved_scopes = result["scopes"]
else:
    # Handle error
    error = result["error"]
    description = result["description"]
```

### **Manual Token Exchange**

```bash
# Auto-approved scope (immediate success)
curl -X POST http://localhost:8002/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=YOUR_ACCESS_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "client_id=mcp-server" \
  -d "client_secret=mcp-server-secret" \
  -d "scope=read:files" \
  -d "audience=file-service"

# Admin-required scope (approval needed)
curl -X POST http://localhost:8002/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=YOUR_ACCESS_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "client_id=mcp-server" \
  -d "client_secret=mcp-server-secret" \
  -d "scope=execute:commands" \
  -d "audience=command-executor"
```

## 🔄 **Approval Flow**

### **1. Auto-Approved Scopes**
Scopes that match the user's role are automatically approved:

```python
SCOPES = {
    "read:files": {
        "auto_approve_roles": ["user", "developer", "manager", "admin"]
    }
}
```

### **2. Admin-Required Scopes**
High-risk scopes require admin approval:

```python
SCOPES = {
    "execute:commands": {
        "risk_level": "critical",
        "requires_admin": True,
        "auto_approve_roles": ["admin"]  # Only admins auto-approved
    }
}
```

### **3. Approval Process**

1. **Request Received** → Auth server validates token exchange request
2. **Policy Evaluation** → Check if scopes can be auto-approved
3. **Approval Creation** → Create approval request for missing scopes
4. **Standard Response** → Return `authorization_pending` error
5. **Admin Review** → Admin sees request in dashboard at `/dashboard`
6. **Polling** → MCP server polls every 5 seconds
7. **Success** → Return new token with approved scopes

## 🚨 **Error Handling**

### **Standard RFC 8693 Errors**

| Error Code | Description | Action |
|------------|-------------|---------|
| `invalid_request` | Missing required parameters | Fix request format |
| `invalid_client` | Client authentication failed | Check credentials |
| `invalid_grant` | Invalid/expired subject token | Get new token |
| `unsupported_grant_type` | Not token exchange | Use correct grant type |
| `authorization_pending` | Approval required | Poll for approval |

### **Custom Errors**

| Error Code | Description | Action |
|------------|-------------|---------|
| `approval_timeout` | No approval within timeout | Retry later |
| `request_failed` | Network/connection error | Check connectivity |

## ⚙️ **Configuration**

### **Environment Variables**

```bash
# Auth server configuration
AUTH_SERVER_URL=http://localhost:8002
CLIENT_ID=mcp-server
CLIENT_SECRET=mcp-server-secret

# Polling configuration
APPROVAL_POLL_INTERVAL=5        # seconds
APPROVAL_MAX_WAIT_TIME=300      # seconds (5 minutes)
```

### **MCP Server Integration**

Add to your MCP server's configuration:

```python
# config.py
TOKEN_EXCHANGE_CONFIG = {
    "auth_server_url": os.getenv("AUTH_SERVER_URL", "http://localhost:8002"),
    "client_id": os.getenv("CLIENT_ID", "mcp-server"),
    "client_secret": os.getenv("CLIENT_SECRET", "mcp-server-secret"),
    "poll_interval": int(os.getenv("APPROVAL_POLL_INTERVAL", "5")),
    "max_wait_time": int(os.getenv("APPROVAL_MAX_WAIT_TIME", "300"))
}
```

## 🧪 **Testing**

### **Test the Implementation**

```bash
# 1. Start the auth server
cd auth-server
python unified_auth_server.py

# 2. Run the token exchange examples
python token_exchange_example.py

# 3. Run the test suite
python test_token_exchange.py
```

### **Expected Test Results**

```
🧪 RFC 8693 Token Exchange Implementation Test
============================================================

🔄 Test 1: Admin user requesting auto-approved scope
✅ Success: Token generated with scopes 'read:files'

🔄 Test 2: Admin user requesting admin-required scope  
✅ Success: Token generated with scopes 'execute:commands'

🔄 Test 3: Regular user requesting auto-approved scope
✅ Success: Token generated with scopes 'read:files'

🔄 Test 4: Regular user requesting admin-required scope
✅ Expected error: authorization_pending
   Missing scopes: ['execute:commands']
   User roles: ['user']

🔄 Test 5: Invalid client credentials
✅ Expected error: invalid_client

🔄 Test 6: Multiple scopes with mixed approval
✅ Expected error: authorization_pending
   Missing scopes: ['execute:commands']
   User roles: ['user']

============================================================
✅ Token Exchange Implementation Tests Completed
```

## 🔄 **Migration Guide**

### **From Custom Scope Upgrade**

If you're currently using the custom `/api/upgrade-scope` endpoint:

**Before:**
```python
# Custom API call
response = await client.post("/api/upgrade-scope", json={
    "required_scope": "execute:commands",
    "justification": "Need to run system commands"
})
```

**After:**
```python
# Standard RFC 8693 token exchange
client = TokenExchangeClient()
result = await client.exchange_with_polling(
    subject_token=current_token,
    required_scopes=["execute:commands"]
)
```

### **Benefits of Migration**

1. **Standards Compliance** → Works with any OAuth2/RFC 8693 server
2. **Better Error Handling** → Standard error codes and descriptions  
3. **Automatic Polling** → No manual approval status checking
4. **Audience Support** → Target specific services with tokens
5. **Independent Deployment** → MCP servers don't need custom auth logic

## 🎯 **Implementation Status**

### **✅ Completed Features**
- RFC 8693 Token Exchange endpoint
- Client authentication and validation
- Automatic approval for user roles
- Transparent admin approval workflow
- Standard OAuth2 error responses
- Audience validation and targeting
- Comprehensive test suite
- Example client implementation

### **📁 Files**
- `unified_auth_server.py` - Main auth server with token exchange
- `token_exchange_example.py` - MCP client implementation
- `test_token_exchange.py` - Test suite

## 🔗 **Related Documentation**

- **[README.md](README.md)** - Main auth server documentation
- **[APPROVAL_WORKFLOWS.md](APPROVAL_WORKFLOWS.md)** - Approval and scope upgrade flows

## 🎉 **Conclusion**

The RFC 8693 Token Exchange implementation provides a **standards-compliant**, **independently deployable** solution for MCP server authentication with transparent approval handling. MCP servers can be deployed across different systems without requiring knowledge of custom approval workflows, while maintaining the security and admin oversight of the original system. 