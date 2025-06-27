# 🚀 Unified Authentication & Authorization Demo

This demo showcases a **unified authentication and authorization system** with dynamic scope-based permissions, approval workflows, and role-based access control for MCP (Model Context Protocol) tools.

## 🏗️ **Architecture Overview**

The system consists of four main components:

- **🔐 Auth Server** (Port 8002) - OAuth, JWT, scopes, approvals, admin dashboard, RFC 8693 token exchange
- **📡 MCP Server** (Port 8001) - Tool execution with scope-based authorization  
- **🦙 Llama Stack** (Port 8321) - AI agent runtime with auth-agent integration and session management
- **🌐 Chat App** (Port 5001) - Web interface with streaming responses, approval UI, and persistent chat history

## 👥 **User Management**

The system uses **automatic user creation** with role-based access:

| User Type | Email | Auto-Created Role | Auto-Approved Scopes |
|-----------|-------|-------------------|---------------------|
| **Admin** | `gallettilance@gmail.com` | admin | All scopes (pre-configured) |
| **Regular Users** | Any Google account | user | `read:files` only |

- **Admin user** is pre-configured during demo setup
- **All other users** are automatically created with `user` role on first login
- **No passwords needed** - uses Google OAuth for authentication

## 🛠️ **Quick Start**

### **1. Environment Setup (Optional)**
```bash
# Copy environment template
cp env.example .env

# Edit with your Google OAuth credentials (optional)
nano .env
```

### **2. Start All Services**
```bash
# Start the complete demo environment
./start_demo.sh
```

### **3. Access the Demo**
- **Chat Interface:** http://localhost:5001
- **Auth Dashboard:** http://localhost:8002/dashboard

## 🎬 **Demo Walkthrough**

### **Phase 1: User Login & Auto-Creation**

1. **Open Chat Interface**
   ```
   🌐 http://localhost:5001
   ```

2. **Login with Google Account**
   - Click "Login" button
   - Authenticate with any Google account
   - **User is automatically created** with `user` role on first login
   - Redirected back to chat interface

3. **Try Basic Commands** ✅
   ```
   💬 "What server information is available?"
   💬 "Check the health status"
   ```
   These work immediately (no scopes required).

### **Phase 2: File Access (Auto-Approved)**

4. **Try File Operations** ✅
   ```
   💬 "List files in the current directory"
   ```
   - New user has `user` role → auto-approved for `read:files` scope
   - Command executes immediately
   - Shows: "✅ Auto-approved! Retry your request."

### **Phase 3: Command Execution (Admin Approval Required)**

5. **Try System Commands** ⚠️
   ```
   💬 "Execute the command 'ps aux | head -5'"
   ```
   - Requires `execute:commands` scope (admin approval needed)
   - Shows authorization error with approval UI:
     - **🔓 Request Approval** button
     - **📋 Check Status** button  
     - **🔄 Retry Message** button (disabled)

6. **Request Approval**
   - Click "🔓 Request Approval"
   - Status shows: "📋 Approval request submitted"
   - Approval request appears in admin dashboard

### **Phase 4: Admin Approval Process**

7. **Open Admin Dashboard** (New Tab)
   ```
   🌐 http://localhost:8002/dashboard
   ```

8. **Login as Admin**
   - Use the pre-configured admin account: `gallettilance@gmail.com`
   - Authenticate with Google OAuth

9. **Review & Approve Request**
   - See pending request from the regular user
   - Tool: `execute_command`
   - Required scope: `execute:commands`
   - Risk level: **CRITICAL**
   - Click "✅ Approve"

### **Phase 5: Successful Execution**

10. **Return to User's Chat**
    - Status automatically updates to "✅ Approved"
    - "🔄 Retry Message" button becomes enabled
    - Click "🔄 Retry Message"
    - Command executes successfully with upgraded token!

### **Phase 6: Chat History Persistence**

11. **Test Session Persistence**
    - Navigate to dashboard and back to chat
    - Chat history is preserved across navigation
    - Previous messages and approvals remain visible
    - Welcome message displays on first visit

## 🔍 **Key Features Demonstrated**

### **🔒 Zero-Trust Security**
- Users start with minimal permissions (`user` role, `read:files` scope only)
- Scope escalation requires explicit approval
- No standing privileges for high-risk operations

### **👤 Automatic User Onboarding**
- **No manual user creation** required
- **Google OAuth integration** for seamless authentication
- **Auto-assigned roles** based on email domain or default policies
- **Admin pre-configuration** during demo setup

### **📊 Role-Based Auto-Approval**
```python
SCOPES = {
    "read:files": {
        "auto_approve_roles": ["user", "developer", "admin"]  # ✅ Auto-approved
    },
    "execute:commands": {
        "auto_approve_roles": ["admin"]  # ⚠️ Admin approval required for others
    }
}
```

### **🎯 Dynamic Permission Escalation**
- Real-time scope upgrades during conversations
- Seamless token refresh and retry
- Persistent approval UI in chat history

### **🌊 Streaming Response Integration**
- Authorization errors handled mid-stream
- UI updates without interrupting conversation flow
- Auto-scrolling and visual feedback

### **🛡️ Admin Dashboard**
- Real-time approval queue
- User context and justification
- One-click approve/deny actions
- Tool access visualization

### **💾 Persistent Chat History**
- Chat history stored in Llama Stack's native database
- Sessions persist across browser navigation
- Welcome messages and conversation context maintained
- Direct database access for optimal performance

## 🎯 **Architecture Highlights**

### **Unified Auth Server Benefits**
- **Single source of truth** for authentication and authorization
- **Integrated approval workflows** - no separate approval service needed
- **Built-in admin dashboard** with real-time updates
- **Google OAuth integration** for production-ready authentication
- **RFC 8693 token exchange** for standards-compliant MCP integration
- **Automatic user provisioning** with role-based defaults

### **Scope-Based Authorization**
```python
# Example: Tool requires execute:commands scope
user_scopes = ["read:files"]  # User's current scopes
required_scope = "execute:commands"  # Tool requirement

if required_scope not in user_scopes:
    # Trigger approval workflow
    return authorization_error_with_upgrade_info()
```

### **Smart Approval Logic**
```python
def evaluate_approval_policy(user_email, requested_scopes):
    user_roles = get_user_roles(user_email)
    auto_approved = []
    admin_approval_required = []
    
    for scope in requested_scopes:
        config = SCOPES[scope]
        if any(role in config["auto_approve_roles"] for role in user_roles):
            auto_approved.append(scope)
        else:
            admin_approval_required.append(scope)
    
    return {
        "auto_approved": auto_approved,
        "requires_admin_approval": admin_approval_required
    }
```

### **Automatic User Creation**
```python
# OAuth callback handler
@app.get("/auth/callback")
async def oauth_callback(code: str, state: str):
    # ... token exchange ...
    
    # Create or get user from database
    db_user = auth_db.get_user(user_email)
    if not db_user:
        # Auto-create new user with default role
        auth_db.create_user(user_email, ["user"])
        db_user = auth_db.get_user(user_email)
```

### **Chat History Integration**
- **Llama Stack Native Storage** - Uses Llama Stack's built-in session management
- **Direct Database Access** - Queries `kvstore.db` for optimal performance
- **Session Isolation** - Per-user agent instances with isolated chat history
- **Timestamp Ordering** - Chronological message ordering with proper sorting

## 🔧 **Customization Points**

### **1. Admin User Configuration**
Edit the admin email in `start_demo.sh`:
```bash
# Set admin email for the demo
export ADMIN_EMAIL="your-admin@company.com"
```

### **2. User Role Assignment**
Modify auto-role assignment logic in `auth-server/unified_auth_server_v2.py`:
```python
# Example: Assign roles based on email domain
def determine_user_role(email: str) -> List[str]:
    if email.endswith("@company.com"):
        return ["developer"]
    elif email.endswith("@admin.company.com"):
        return ["admin"]
    else:
        return ["user"]  # Default role
```

### **3. Scope Configuration**
Modify `SCOPES` to add new permissions:
```python
SCOPES = {
    "read:database": {
        "description": "Access database information",
        "risk_level": "medium",
        "requires_admin": False,
        "auto_approve_roles": ["developer", "admin"]
    }
}
```

### **4. OAuth Integration**
Set environment variables for Google OAuth:
```bash
export GOOGLE_CLIENT_ID=your_client_id
export GOOGLE_CLIENT_SECRET=your_client_secret
```

### **5. Token Exchange Configuration**
Configure MCP clients in `auth-server/unified_auth_server_v2.py`:
```python
CLIENTS = {
    "mcp-server": {
        "client_secret": "mcp-server-secret",
        "client_type": "confidential",
        "token_exchange_enabled": True,
        "allowed_audiences": ["file-service", "command-executor"]
    }
}
```

## 🛑 **Stopping the Demo**

```bash
# Stop all services
./stop_demo.sh
```

## 📊 **Service Health Check**

```bash
# Check if all services are running
curl http://localhost:8002  # Unified Auth Server
curl http://localhost:8001  # MCP Server  
curl http://localhost:5001  # Chat App
curl http://localhost:8321  # Llama Stack
```

## 🐛 **Troubleshooting**

### **Services Won't Start**
```bash
# Check for port conflicts
lsof -i :8002 -i :8001 -i :5001 -i :8321

# Kill existing processes
./stop_demo.sh
```

### **Authorization Not Working**
```bash
# Check auth server logs
tail -f logs/unified_auth_server.log

# Verify MCP server connection
curl http://localhost:8001/sse
```

### **Chat App Issues**
```bash
# Check chat app logs
tail -f logs/chat_app.log

# Verify Llama Stack connection
curl http://localhost:8321

# Check chat history database
ls -la ~/.llama/sessions/
```

### **Google OAuth Issues**
```bash
# Verify OAuth configuration
echo $GOOGLE_CLIENT_ID
echo $GOOGLE_CLIENT_SECRET

# Check redirect URI in Google Console:
# http://localhost:8002/auth/callback
```

### **User Creation Issues**
```bash
# Check if users are being created
sqlite3 auth-server/auth.db "SELECT email, roles FROM users;"

# Verify admin user exists
sqlite3 auth-server/auth.db "SELECT email, is_admin FROM users WHERE is_admin = 1;"
```

### **Chat History Not Persisting**
```bash
# Verify Llama Stack database
sqlite3 ~/.llama/sessions/kvstore.db ".tables"

# Check session data
sqlite3 ~/.llama/sessions/kvstore.db "SELECT key FROM kvstore WHERE key LIKE 'session:%' LIMIT 5;"
```

## 📚 **Additional Documentation**

### **Core Documentation**
- **[Auth Server README](auth-server/README.md)** - Authentication server implementation
- **[MCP Server README](mcp/README.md)** - MCP server implementation guide

### **Auth Server Detailed Guides**
- **[Token Exchange Guide](auth-server/TOKEN_EXCHANGE.md)** - RFC 8693 token exchange implementation
- **[Approval Workflows](auth-server/APPROVAL_WORKFLOWS.md)** - Approval and scope upgrade flows

### **Frontend Documentation**
- **[Auth Agent README](frontend/auth-agent/README.md)** - Agent integration documentation

---

This unified demo showcases a production-ready authentication and authorization system with **automatic user onboarding** that scales from development to enterprise environments while maintaining security, usability, and transparency with persistent chat history and standards-compliant token exchange. 