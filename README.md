# 🔐 Unified Authentication & Authorization System

A production-ready authentication and authorization system for MCP (Model Context Protocol) tools with dynamic scope-based permissions, role-based access control, and integrated approval workflows.



## 🌟 **Key Features**

- **🔒 Zero-Trust Security** - Users start with minimal permissions, request additional scopes on-demand
- **👥 Role-Based Access Control** - Admin, developer, and user roles with different permission levels
- **⚡ Dynamic Scope Escalation** - Real-time permission upgrades during conversations
- **🛡️ Approval Workflows** - Auto-approval for trusted users, admin approval for high-risk operations
- **🌐 Modern Web Interface** - Dark theme chat app with streaming responses and approval UI
- **📊 Admin Dashboard** - Real-time approval queue and user access visualization
- **🔄 Seamless Integration** - Works with Llama Stack agents and MCP tools

## 🎥 **Demo Video**

[![Authentication System Demo](https://img.youtube.com/vi/xwLiawE0xQc/0.jpg)](https://youtu.be/xwLiawE0xQc)

*Click the image above to watch a full demonstration of the authentication system in action.*

## 🏗️ **Architecture**

```
┌─────────────────┐    ┌────────────────────────-─┐    ┌─────────────────┐
│   Chat App      │    │  Auth Server & Dashbaord │    │   MCP Server    │
│   (Port 5001)   │◄──►│        (Port 8002)       │◄──►│   (Port 8001)   │
│                 │    │                          │    │                 │
│ • Web Interface │    │     • OAuth & JWT        │    │ • Tool Execution│
│ • Streaming UI  │    │     • Scope Management   │    │ • Authorization │
│ • Approval UI   │    │     • Admin Dashboard    │    │ • File/Command  │
└─────────────────┘    │     • Approval Queue     │    │   Operations    │
          │            └──────────────────────────┘    └─────────────────┘
          │                        │                       │
          └────────────────────────┼───────────────────────┘
                                   │
                            ┌──────▼──────┐
                            │ Llama Stack │
                            │ (Port 8321) │
                            │             │
                            │ • AI Agent  │
                            │ • Auth Agent│
                            │ • Tool Calls│
                            └─────────────┘
```

### **Components**

| Component | Port | Purpose | Key Features |
|-----------|------|---------|--------------|
| **Unified Auth Server** | 8002 | Authentication & Authorization | OAuth, JWT, scopes, approvals, admin dashboard |
| **MCP Server** | 8001 | Tool Execution | File operations, command execution, scope validation |
| **Llama Stack** | 8321 | AI Agent Runtime | Auth-agent integration, tool orchestration |
| **Chat App** | 5001 | Web Interface | Streaming responses, approval UI, session management |

## 🚀 **Quick Start**

### **1. Clone & Setup**
```bash
git clone <repository-url>
cd Authentication

# Optional: Set up Google OAuth
cp env.example .env
# Edit .env with your OAuth credentials
```

### **2. Start Demo Environment**
```bash
# Start all services with one command
./start_demo.sh
```

### **3. Access the System**
- **💬 Chat Interface:** http://localhost:5001
- **🔑 Demo Login:** http://localhost:8002/auth/demo-login  
- **📊 Admin Dashboard:** http://localhost:8002/dashboard

### **4. Demo Users**
| User | Email | Password | Roles | Auto-Approved Scopes |
|------|-------|----------|-------|---------------------|
| **Admin** | `gallettilance@gmail.com` | `demo` | admin, developer | All scopes |
| **Developer** | `demo@example.com` | `demo` | developer | `read:files` |
| **User** | `lgallett@redhat.com` | `demo` | user | `read:files` |

## 🎯 **Usage Examples**

### **Auto-Approved Operations** ✅
```bash
# Login as any user
💬 "List files in the current directory"
💬 "What's the server status?"
```
→ Executes immediately (read:files auto-approved for all users)

### **Admin Approval Required** ⚠️
```bash
# Login as regular user
💬 "Execute the command 'ps aux | head -5'"
```
→ Shows approval UI → Admin approves → Command executes

### **Admin Dashboard Workflow**
1. Open http://localhost:8002/dashboard as admin
2. See pending approval requests
3. Review user context and justification
4. One-click approve/deny actions

## 🔐 **Security Model**

### **Scope-Based Authorization**
| Scope | Description | Risk Level | Auto-Approve Roles |
|-------|-------------|------------|-------------------|
| `none` | Basic server info | None | All users |
| `read:files` | File system read access | Low | user, developer, admin |
| `execute:commands` | System command execution | **Critical** | admin only |
| `admin:users` | User management | **Critical** | None (always requires approval) |

### **Approval Flows**
1. **🚀 Auto-Approval** - Immediate access for trusted user/scope combinations
2. **🛡️ Admin Approval** - Human oversight for high-risk operations
3. **⏱️ Time-Limited** - Approval requests expire in 10 minutes

### **Zero-Trust Principles**
- **Minimal initial permissions** - Users start with role-based auto-approved scopes only
- **Dynamic escalation** - Additional permissions requested on-demand
- **Audit trail** - All requests, approvals, and tool executions logged
- **Session-based** - Permissions tied to authenticated sessions

## 📊 **Monitoring & Observability**

### **Logs**
```bash
# View all service logs
tail -f logs/*.log

# Specific services
tail -f logs/unified_auth_server.log  # Auth events
tail -f logs/mcp_server.log           # Tool executions  
tail -f logs/chat_app.log             # User interactions
tail -f logs/llama_stack.log          # Agent operations
```

### **Health Checks**
```bash
# Check all services
curl http://localhost:8002  # Auth Server
curl http://localhost:8001  # MCP Server
curl http://localhost:5001  # Chat App
curl http://localhost:8321  # Llama Stack
```

## 🔧 **Configuration**

### **User Roles**
Edit `mcp/unified_auth_server.py`:
```python
USER_ROLES = {
    "your-admin@company.com": ["admin", "developer"],
    "developer@company.com": ["developer"], 
    "user@company.com": ["user"]
}
```

### **Scope Policies**
```python
SCOPES = {
    "custom:scope": {
        "description": "Custom operation",
        "risk_level": "medium",
        "requires_admin": False,
        "auto_approve_roles": ["developer", "admin"]
    }
}
```

### **OAuth Integration**
```bash
export GOOGLE_CLIENT_ID=your_client_id
export GOOGLE_CLIENT_SECRET=your_client_secret
```

## 🛑 **Stop Services**

```bash
# Stop all services
./stop_demo.sh
```

## 🐛 **Troubleshooting**

### **Common Issues**

**Services won't start:**
```bash
# Check for port conflicts
lsof -i :8002 -i :8001 -i :5001 -i :8321

# Kill existing processes
./stop_demo.sh
```

**Authorization not working:**
```bash
# Check auth server logs
tail -f logs/unified_auth_server.log

# Verify MCP connection
curl http://localhost:8001/sse
```

**Chat app issues:**
```bash
# Check chat logs
tail -f logs/chat_app.log

# Verify session
# Clear browser cookies and re-login
```

## 📚 **Documentation**

- **[Demo Showcase](DEMO_SHOWCASE.md)** - Complete walkthrough with examples
- **[Approval Flows](mcp/APPROVAL_FLOWS.md)** - Detailed approval workflow documentation  
- **[Scope Upgrade Flow](mcp/SCOPE_UPGRADE_FLOW.md)** - Technical implementation details
- **[Auth Agent README](frontend/auth-agent/README.md)** - Agent integration guide

## 🚀 **Production Deployment**

### **Security Hardening**
- Use HTTPS for all endpoints
- Implement proper JWT secret rotation
- Add rate limiting for approval requests
- Monitor for suspicious scope escalation patterns
- Integrate with enterprise identity providers (LDAP/SAML)

### **Scaling Considerations**
- Replace in-memory storage with Redis/database
- Implement horizontal scaling for auth server
- Add load balancing for high availability
- Consider CDN for static assets

### **Enterprise Integration**
- LDAP/Active Directory for user roles
- SAML/OIDC for enterprise SSO
- Webhook notifications for approval requests
- SIEM integration for audit logging

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with the demo environment
5. Submit a pull request

## 📄 **License**

[Add your license information here]

---

**🌟 This unified authentication and authorization system provides enterprise-grade security with a consumer-grade user experience, scaling from development environments to production deployments.** 