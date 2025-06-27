# Unified Authentication Server

This directory contains the **Unified Authentication Server** and related components that provide OAuth2, JWT, and RFC 8693 Token Exchange capabilities for the MCP (Model Context Protocol) system.

## 🏗️ **Architecture**

The auth server provides centralized authentication and authorization for:
- **MCP Servers** - Tool execution with scope-based authorization
- **Chat Applications** - Web interfaces with user authentication  
- **Admin Dashboards** - Approval workflows and user management
- **Llama Stack Agents** - AI agents with authenticated tool access

## 📁 **Directory Contents**

### **Core Server**
- `unified_auth_server.py` - Main authentication server with OAuth2, JWT, and RFC 8693 support

### **RFC 8693 Token Exchange**
- `token_exchange_example.py` - MCP client implementation for token exchange
- `test_token_exchange.py` - Test suite for token exchange functionality
- `RFC8693_TOKEN_EXCHANGE.md` - Comprehensive token exchange documentation

### **Documentation**
- `APPROVAL_FLOWS.md` - Admin approval workflow documentation
- `SCOPE_UPGRADE_FLOW.md` - Dynamic scope escalation flow documentation  
- `IMPLEMENTATION_SUMMARY.md` - Complete implementation summary
- `README.md` - This file

## 🚀 **Quick Start**

### **1. Start the Auth Server**
```bash
cd auth-server
python unified_auth_server.py
```

The server will start on `http://localhost:8002`

### **2. Access the Dashboard**
Visit `http://localhost:8002/dashboard` to:
- View user authentication status
- Manage approval requests (admin users)
- See available MCP tools and permissions
- Monitor system activity

### **3. Test Token Exchange**
```bash
# Test the RFC 8693 implementation
python test_token_exchange.py

# Run example token exchange client
python token_exchange_example.py
```

## 🔐 **Authentication Methods**

### **Demo Login**
- Visit `http://localhost:8002/auth/demo-login`
- Use predefined demo credentials
- Good for development and testing

### **Google OAuth**
- Visit `http://localhost:8002/auth/login`
- Authenticate with Google account
- Production-ready OAuth2 flow

## 👥 **User Roles & Permissions**

### **Admin Users**
- `gallettilance@gmail.com` - Pre-configured admin account (set via `ADMIN_EMAIL` environment variable)
- Can approve scope upgrade requests
- Auto-approved for all scopes

### **Auto-Created Users**  
- **Any Google account** - Automatically assigned `user` role on first login
- Auto-approved for `read:files`
- Requires approval for `execute:commands`

### **Role Assignment Logic**
Users are automatically created with roles based on:
- Default role: `user` (for all new users)
- Admin role: Pre-configured via environment variable
- Custom logic: Can be implemented based on email domain or other criteria

## 🔧 **API Endpoints**

### **Authentication**
- `GET /auth/login` - Google OAuth login
- `GET /auth/demo-login` - Demo login page
- `POST /auth/demo-login` - Demo login submission
- `GET /auth/callback` - OAuth callback
- `GET /auth/logout` - Logout

### **Authorization**
- `POST /api/upgrade-scope` - Request scope upgrade (legacy)
- `POST /oauth/token` - RFC 8693 Token Exchange
- `POST /api/request-approval` - Submit approval request
- `GET /api/status/{request_id}` - Check approval status

### **Admin Functions**
- `GET /dashboard` - Admin dashboard
- `POST /api/approve/{request_id}` - Approve request
- `POST /api/deny/{request_id}` - Deny request
- `GET /api/user-status` - Get user status
- `GET /api/tools` - Get user's tool access

### **Metadata**
- `GET /.well-known/oauth-authorization-server` - RFC 8414 metadata

## 🎯 **Scopes & Risk Levels**

| Scope | Risk Level | Description | Auto-Approve Roles |
|-------|------------|-------------|-------------------|
| `read:files` | Low | Read file system information | `user`, `developer`, `admin` |
| `execute:commands` | Critical | Execute system commands | `admin` only |
| `admin:users` | Critical | Manage user accounts | None (always requires approval) |

## 🔄 **Approval Workflows**

### **Auto-Approval**
- Immediate access for trusted user roles
- Based on scope risk level and user permissions
- All auto-approvals are logged

### **Admin Approval**
- Required for high-risk scopes
- Real-time dashboard notifications
- Approval request expires after 10 minutes

## 🧪 **Testing**

### **Unit Tests**
```bash
python test_token_exchange.py
```

### **Integration Tests**
1. Start the auth server: `cd auth-server && python unified_auth_server.py`
2. Start the MCP server: `cd mcp && python mcp_server.py` 
3. Start the chat app: `cd frontend && python chat_app.py`
4. Test the complete flow through the web interface

### **Manual API Testing**
```bash
# Test token exchange
curl -X POST http://localhost:8002/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=YOUR_TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "client_id=mcp-server" \
  -d "client_secret=mcp-server-secret" \
  -d "scope=read:files"
```

## 🔧 **Configuration**

### **Environment Variables**
```bash
# Server configuration
AUTH_SERVER_HOST=localhost
AUTH_SERVER_PORT=8002
JWT_SECRET=your-secret-key-here

# OAuth configuration  
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# MCP integration
MCP_SERVER_URI=http://localhost:8001
```

### **Client Registration**
Add new OAuth2 clients in `unified_auth_server.py`:
```python
CLIENTS = {
    "your-client-id": {
        "client_secret": "your-client-secret",
        "client_type": "confidential", 
        "token_exchange_enabled": True,
        "allowed_audiences": ["your-service"]
    }
}
```

## 🛡️ **Security Features**

### **✅ Standards Compliance**
- **RFC 8693** Token Exchange
- **RFC 8414** Authorization Server Metadata
- **OAuth 2.0** and **OpenID Connect** flows

### **✅ Token Security**
- JWT tokens with configurable expiration
- HMAC-SHA256 signing
- Audience validation
- Scope-based authorization

### **✅ Session Management**
- Secure HTTP-only cookies
- Session expiration and cleanup
- Cross-site request forgery protection

### **✅ Audit Trail**
- All authentication events logged
- Approval decisions tracked
- Token exchanges monitored

## 🚀 **Production Deployment**

### **Security Checklist**
- [ ] Change default JWT secret
- [ ] Configure proper Google OAuth credentials
- [ ] Enable HTTPS/TLS
- [ ] Set secure cookie flags
- [ ] Configure rate limiting
- [ ] Set up log monitoring

### **Scaling**
- Use Redis for session storage
- Database for approval requests
- Load balancer for multiple instances
- Separate admin and user interfaces

## 📚 **Documentation**

- **[TOKEN_EXCHANGE.md](TOKEN_EXCHANGE.md)** - Complete RFC 8693 token exchange implementation guide
- **[APPROVAL_WORKFLOWS.md](APPROVAL_WORKFLOWS.md)** - Approval flows and dynamic scope escalation guide

## 🤝 **Integration**

### **With MCP Servers**
```python
from token_exchange_example import TokenExchangeClient

client = TokenExchangeClient(
    auth_server_url="http://localhost:8002",
    client_id="mcp-server",
    client_secret="mcp-server-secret"
)

result = await client.exchange_with_polling(
    subject_token=user_token,
    required_scopes=["execute:commands"]
)
```

### **With Chat Applications**
- Include JWT tokens in MCP requests
- Handle authorization errors gracefully
- Implement approval UI components
- Poll for approval status updates

### **With Admin Dashboards**
- Embed approval queue widgets
- Real-time notification system
- User management interfaces
- Audit log viewers

## 📞 **Support**

For questions about the authentication server:
1. Check the documentation files in this directory
2. Review the test files for usage examples
3. Examine the server logs for debugging information
4. Test with the provided example clients 