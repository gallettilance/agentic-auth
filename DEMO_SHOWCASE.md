# 🚀 Unified Authentication & Authorization Demo

This demo showcases a **unified authentication and authorization system** with dynamic scope-based permissions, approval workflows, and role-based access control for MCP (Model Context Protocol) tools.

## 🏗️ **Architecture Overview**

The system consists of four main components:

- **🔐 Unified Auth Server** (Port 8002) - OAuth, JWT, scopes, approvals, admin dashboard
- **📡 MCP Server** (Port 8001) - Tool execution with scope-based authorization  
- **🦙 Llama Stack** (Port 8321) - AI agent runtime with auth-agent integration
- **🌐 Chat App** (Port 5001) - Web interface with streaming responses and approval UI

## 👥 **Demo User Accounts**

| User | Email | Roles | Auto-Approved Scopes |
|------|-------|-------|---------------------|
| **Admin** | `gallettilance@gmail.com` | admin, developer | All scopes |
| **Developer** | `demo@example.com` | developer | `read:files` |
| **User** | `lgallett@redhat.com` | user | `read:files` |

**Demo Password:** `demo` (for all accounts)

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
- **Demo Login:** http://localhost:8002/auth/demo-login

## 🎬 **Demo Walkthrough**

### **Phase 1: Basic Access (No Scopes Required)**

1. **Open Chat Interface**
   ```
   🌐 http://localhost:5001
   ```

2. **Login as Regular User**
   - Click "Login with Demo Account"
   - Email: `lgallett@redhat.com`
   - Password: `demo`

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
   - User has `user` role → auto-approved for `read:files` scope
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
   - Email: `gallettilance@gmail.com` 
   - Password: `demo`

9. **Review & Approve Request**
   - See pending request from `lgallett@redhat.com`
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

## 🔍 **Key Features Demonstrated**

### **🔒 Zero-Trust Security**
- Users start with minimal permissions
- Scope escalation requires explicit approval
- No standing privileges for high-risk operations

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

## 🎯 **Architecture Highlights**

### **Unified Auth Server Benefits**
- **Single source of truth** for authentication and authorization
- **Integrated approval workflows** - no separate approval service needed
- **Built-in admin dashboard** with real-time updates
- **OAuth + Demo login** support for flexible authentication

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

## 🔧 **Customization Points**

### **1. User Roles & Permissions**
Edit `USER_ROLES` in `mcp/unified_auth_server.py`:
```python
USER_ROLES = {
    "your-email@company.com": ["admin", "developer"],
    "user@company.com": ["user"],
    # Add more users...
}
```

### **2. Scope Configuration**
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

### **3. OAuth Integration**
Set environment variables for Google OAuth:
```bash
export GOOGLE_CLIENT_ID=your_client_id
export GOOGLE_CLIENT_SECRET=your_client_secret
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
```

## 📚 **Additional Documentation**

- **[Approval Flows](mcp/APPROVAL_FLOWS.md)** - Detailed approval workflow documentation
- **[Scope Upgrade Flow](mcp/SCOPE_UPGRADE_FLOW.md)** - Technical implementation details
- **[Auth Agent README](frontend/auth-agent/README.md)** - Agent integration documentation

---

This unified demo showcases a production-ready authentication and authorization system that scales from development to enterprise environments while maintaining security, usability, and transparency. 