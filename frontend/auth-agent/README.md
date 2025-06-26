# Auth Agent for Llama Stack

A unified authorization agent provider for Llama Stack that integrates with the unified authentication and authorization system to provide dynamic scope-based permissions and approval workflows for MCP tools.

## 🏗️ **Architecture Integration**

The Auth Agent seamlessly integrates with:
- **🔐 Unified Auth Server** (Port 8002) - Handles OAuth, JWT, scopes, and approvals
- **📡 MCP Server** (Port 8001) - Executes tools with scope-based authorization
- **🌐 Chat App** (Port 5001) - Provides approval UI and token management

## ✨ **Features**

### **🔒 Dynamic Authorization**
- **Scope-based permissions** - Tools require specific scopes (e.g., `read:files`, `execute:commands`)
- **Role-based auto-approval** - Admin users get immediate access, regular users require approval
- **Real-time scope escalation** - Request additional permissions during conversations

### **🎯 Intelligent Error Handling**
- **Authorization error detection** - Automatically detects insufficient scope errors
- **Structured error responses** - Provides clear upgrade paths and user context
- **Graceful degradation** - Falls back to error messages when approval systems unavailable

### **🔄 Seamless Approval Integration**
- **Unified approval workflow** - Integrates with chat app approval UI
- **Token management** - Handles JWT token upgrades automatically
- **Session persistence** - Maintains approved scopes across conversations

## 🛠️ **Configuration**

### **Agent Configuration**
```python
from auth_agent import AuthAgentsImplConfig

config = AuthAgentsImplConfig(
    auth_endpoint="http://localhost:8002"  # Unified Auth Server
)
```

### **Llama Stack Integration**
The agent is configured via `frontend/stack/run.yml`:
```yaml
agents:
  - provider_id: auth-agent
    provider_type: inline
    config:
      auth_endpoint: http://localhost:8002
```

## 🔐 **Authorization Flow**

### **1. Tool Execution Attempt**
```python
# User requests tool execution through chat
response = agent.create_turn(
    agent_id="auth-agent",
    messages=[{"role": "user", "content": "List files in /tmp"}]
)
```

### **2. Scope Validation**
```python
# Auth agent calls MCP server
mcp_response = await mcp_client.call_tool("list_files", {"path": "/tmp"})

# MCP server validates JWT token scopes
if "read:files" not in token_scopes:
    return insufficient_scope_error(required_scope="read:files")
```

### **3. Authorization Error Handling**
```python
# Auth agent detects authorization error
if is_authorization_error(mcp_response):
    error_details = extract_authorization_error_details(mcp_response)
    
    # Return structured error for chat app to handle
    return ToolInvocationResult(
        error_message=f"🔐 Authorization required for {error_details['tool_name']}",
        error_type="authorization_error",
        **error_details
    )
```

### **4. Scope Upgrade Request**
```python
# Chat app handles authorization error
if response.error_type == "authorization_error":
    # Show approval UI
    # User clicks "Request Approval"
    approval_response = await auth_server.upgrade_scope(
        required_scope=error_details["required_scope"],
        user_email=error_details["user_email"]
    )
```

## 🎯 **Scope-Based Tool Authorization**

### **Available Scopes**
| Scope | Description | Risk Level | Auto-Approve Roles |
|-------|-------------|------------|-------------------|
| `none` | No special permissions | None | All users |
| `read:files` | File system read access | Low | `user`, `developer`, `admin` |
| `execute:commands` | System command execution | Critical | `admin` only |
| `admin:users` | User management | Critical | None (always requires approval) |

### **Tool Scope Requirements**
```python
# MCP tools specify required scopes in their implementation
TOOL_SCOPES = {
    "get_server_info": "none",
    "health_check": "none", 
    "list_files": "read:files",
    "execute_command": "execute:commands"
}
```

## 🚨 **Error Types & Handling**

### **Authorization Errors**
```python
{
    "error_type": "authorization_error",
    "tool_name": "execute_command",
    "required_scope": "execute:commands",
    "current_scopes": ["read:files"],
    "approval_type": "admin_required",
    "user_email": "lgallett@redhat.com"
}
```

### **Insufficient Scope Errors**
```python
class InsufficientScopeError(Exception):
    def __init__(self, tool_name: str, required_scope: str, current_scopes: List[str]):
        self.tool_name = tool_name
        self.required_scope = required_scope
        self.current_scopes = current_scopes
```

## 🔧 **Development & Testing**

### **Local Development Setup**
```bash
# Install dependencies
cd frontend/auth-agent
pip install -e .

# Start unified demo environment
cd ../..
./start_demo.sh
```

### **Testing Authorization Flows**
```bash
# Test auto-approval (user requesting read:files)
curl -X POST http://localhost:5001/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "List files in current directory"}'

# Test admin approval (user requesting execute:commands)  
curl -X POST http://localhost:5001/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Execute command: ps aux | head -5"}'
```

## 📊 **Integration Points**

### **With Unified Auth Server**
- **Token validation** - Validates JWT tokens for each tool call
- **Scope upgrade** - Requests additional permissions when needed
- **Session management** - Maintains user sessions and approved scopes

### **With Chat App**
- **Error propagation** - Returns structured authorization errors
- **Approval UI** - Triggers approval interface in chat
- **Token updates** - Receives upgraded tokens after approval

### **With MCP Server**
- **Tool execution** - Calls MCP tools with proper authorization
- **Scope enforcement** - Validates required scopes before execution
- **Error handling** - Processes insufficient scope responses

## 🛡️ **Security Features**

### **Zero-Trust Authorization**
- **Minimal initial permissions** - Users start with role-based auto-approved scopes
- **Dynamic escalation** - Additional permissions requested on-demand
- **Scope validation** - Every tool call validates current permissions

### **Audit & Compliance**
- **Request logging** - All authorization requests are logged
- **Approval tracking** - Complete audit trail of approvals and denials
- **Session monitoring** - Track scope usage across conversations

### **Token Security**
- **JWT validation** - Cryptographic validation of all tokens
- **Scope enforcement** - Server-side validation of token scopes
- **Session binding** - Tokens bound to specific user sessions

## 🚀 **Production Deployment**

### **Environment Variables**
```bash
# Auth server endpoint
export AUTH_ENDPOINT=https://auth.your-domain.com

# JWT validation settings
export JWT_SECRET=your-secret-key
export JWT_ALGORITHM=HS256
```

### **Security Hardening**
- Use HTTPS for all auth server communication
- Implement proper JWT secret rotation
- Add rate limiting for approval requests
- Monitor for suspicious scope escalation patterns

### **Scaling Considerations**
- Auth agent is stateless and scales horizontally
- Session state managed by unified auth server
- Consider Redis for distributed session storage

## 📚 **Additional Documentation**

- **[Demo Showcase](../../DEMO_SHOWCASE.md)** - Complete demo walkthrough
- **[Approval Flows](../../mcp/APPROVAL_FLOWS.md)** - Detailed approval workflow documentation
- **[Scope Upgrade Flow](../../mcp/SCOPE_UPGRADE_FLOW.md)** - Technical implementation details

---

The Auth Agent provides a secure, user-friendly way to handle dynamic permission escalation in MCP environments while maintaining the principle of least privilege and enterprise-grade security controls.
