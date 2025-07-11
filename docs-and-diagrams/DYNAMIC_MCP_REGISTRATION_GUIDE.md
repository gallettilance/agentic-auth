# Dynamic MCP Server Registration: Complete Guide

## Table of Contents
1. [Problem Statement](#problem-statement)
2. [Current Architecture Limitations](#current-architecture-limitations)
3. [Security Evolution](#security-evolution)
4. [Zero Trust Solution](#zero-trust-solution)
5. [Implementation Details](#implementation-details)
6. [Admin Experience](#admin-experience)
7. [User Experience](#user-experience)
8. [Benefits and Tradeoffs](#benefits-and-tradeoffs)

## Problem Statement

The current authentication system requires **pre-configuration** of all MCP servers, their tools, scopes, and policies before the system can start. This creates a fundamental scalability problem:

### Current Static Requirements
- ❌ **Pre-configure MCP servers** as OAuth clients in database
- ❌ **Pre-define all tool scopes** in permissions table
- ❌ **Pre-configure scope policies** for each tool
- ❌ **Pre-set role mappings** for permissions
- ❌ **Hardcode auth server URLs** in MCP servers

### The Manual Process Today
```bash
# To add a new MCP server, you must:
1. Stop the auth server
2. Manually add all tools to permissions table
3. Create scope policies for each tool
4. Add MCP server as OAuth client
5. Configure allowed audiences
6. Set up role-permission mappings
7. Restart auth server
8. Hope it works
```

## Current Architecture Limitations

### Hardcoded Configuration Examples

**Database Initialization (auth-server/database.py)**:
```python
# These are hardcoded for current MCP server only!
default_permissions = [
    ("list_files", "List files in a directory", "low", False),
    ("execute_command", "Execute system commands", "critical", True),
    ("get_server_info", "Get server information", "low", False),
    # ... all tools must be known in advance
]

# MCP servers must be pre-registered!
default_clients = [
    ("mcp-server", "MCP Server for tool execution", "confidential", True, 
     ["file-service", "command-executor", "mcp-tools"]),
    ("chat-app", "Chat application frontend", "confidential", True, ["mcp-server"])
]

# Every tool needs a pre-configured approval policy!
default_scope_policies = [
    ("list_files", "auto_approve", ["user", "admin"], {...}),
    ("execute_command", "role_required", ["admin"], {...}),
    # ... every tool must have a policy defined
]
```

### The Chicken-and-Egg Problem
- **Single-Tenant Only**: System only works with one known MCP server
- **Manual Setup**: Adding new MCP servers requires database changes and restarts
- **Brittle**: Cannot handle dynamic environments or third-party MCP servers
- **Not Scalable**: Doesn't work for multi-tenant or SaaS deployments

## Security Evolution

### Initial Approach: Trust MCP Server Self-Assessment ❌
```python
# DANGEROUS - trusting MCP server's self-assessment
tool = {
    "name": "delete_all_files",
    "risk_level": "low"  # ← Malicious server lies about risk!
}
```

**Why this fails**: A malicious MCP server could claim its most dangerous tools are "low risk."

### Balanced Approach: Risk-Based Defaults ⚠️
```python
# Semi-automatic based on server-provided risk levels
if tool['risk_level'] == 'low':
    auto_approve_for_users()
elif tool['risk_level'] == 'medium':
    admin_approval_required()
```

**Why this fails**: We cannot trust the MCP server to accurately assess its own tools' risk levels.

### Final Approach: Zero Trust ✅
```python
# ALL tools blocked until admin manually reviews them
for tool in discovered_tools:
    await auth_db.add_discovered_tool(
        tool_name=tool['name'],
        status='pending_admin_review',  # ← Blocked by default
        # NO automatic risk assessment
    )
```

**Why this works**: Admin makes all security decisions about unknown tools.

## Zero Trust Solution

### Core Security Principle
**ALL tools are blocked until admin manually reviews them**

### What We Can Trust from MCP Servers
- ✅ **Tool names**: `execute_command`, `list_files`
- ✅ **Descriptions**: "Execute system commands"
- ⚠️ **Metadata**: Treat as informational only, don't trust

### What We CANNOT Trust
- ❌ **Risk assessments**: "This tool is safe"
- ❌ **Recommended permissions**: "Give this to all users"
- ❌ **Security claims**: "This tool is sandboxed"

## Implementation Details

### 1. Dynamic Discovery & Registration

**When**: During OAuth callback - right after user login

```python
@app.route('/oauth/callback')
async def oauth_callback():
    # ... handle OAuth token ...
    
    # After successful login, discover MCP servers
    await discover_and_auto_register_mcp_servers()

async def discover_and_auto_register_mcp_servers():
    """
    Called after OAuth login - discovery happens once per session
    """
    try:
        # Get toolgroups from Llama Stack
        toolgroups = await get_llama_stack_toolgroups()
        
        for toolgroup in toolgroups.get('data', []):
            if toolgroup.get('identifier', '').startswith('mcp::'):
                mcp_server_url = toolgroup['mcp_endpoint']['uri']
                base_url = get_base_mcp_url(mcp_server_url)
                
                # Check if already registered
                existing = await auth_db.get_mcp_server_by_url(base_url)
                if not existing:
                    # Auto-register (safe operations only)
                    await auto_register_discovered_mcp_server(base_url)
```

### 2. Zero Trust Registration Process

```python
async def auto_register_discovered_mcp_server(mcp_server_url: str):
    """
    Zero Trust Registration: Block everything by default
    """
    capabilities = await fetch_mcp_capabilities(mcp_server_url)
    
    # 1. Register as OAuth client (this is safe)
    client_id = f"mcp-{hash(mcp_server_url)}"
    await auth_db.create_client(
        client_id=client_id,
        client_secret=generate_secret(),
        description=f"Auto-discovered MCP server: {mcp_server_url}",
        trust_level="untrusted"
    )
    
    # 2. Discover ALL tools but grant NO access
    for tool in capabilities.get('tools', []):
        await auth_db.add_discovered_tool(
            mcp_server_url=mcp_server_url,
            tool_name=tool['name'],
            description=tool.get('description', 'No description provided'),
            # NO risk_level - we don't trust the server's assessment
            status='pending_admin_review',
            auto_discovered=True
        )
    
    # 3. Queue EVERYTHING for admin review
    await auth_db.create_admin_review_request(
        mcp_server_url=mcp_server_url,
        tools=capabilities.get('tools', []),
        status='pending_review',
        message=f"New MCP server discovered with {len(capabilities.get('tools', []))} tools. ALL tools blocked pending review."
    )
    
    # 4. Notify admin
    await notify_admin_new_mcp_server(
        mcp_server_url=mcp_server_url,
        tool_count=len(capabilities.get('tools', [])),
        auto_enabled_count=0,  # Zero tools auto-enabled
        pending_review_count=len(capabilities.get('tools', []))
    )
```

### 3. MCP Server Capability Advertisement

MCP servers expose their capabilities via well-known endpoint:

```python
@mcp.custom_route("/.well-known/mcp-capabilities", methods=["GET"])
async def mcp_capabilities(request):
    """
    Advertise MCP server capabilities for dynamic discovery
    """
    return {
        "server_info": {
            "name": "My Custom MCP Server",
            "version": "1.0.0",
            "description": "Provides database and email tools",
            "uri": "https://my-mcp-server.example.com"
        },
        "tools": [
            {
                "name": "read_database",
                "description": "Read from database",
                "required_scope": "read_database"
                # NOTE: No risk_level - auth server doesn't trust this
            },
            {
                "name": "send_email",
                "description": "Send emails to users",
                "required_scope": "send_email"
            }
        ],
        "auth_requirements": {
            "authorization_server": "https://auth.example.com",
            "token_endpoint": "https://auth.example.com/oauth/token"
        }
    }
```

### 4. Database Schema Changes

```sql
-- Discovered tools table (before approval)
CREATE TABLE IF NOT EXISTS discovered_tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mcp_server_url TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    description TEXT,
    server_provided_metadata TEXT, -- JSON - don't trust this for security decisions
    status TEXT NOT NULL CHECK (status IN ('pending_admin_review', 'approved', 'blocked', 'needs_more_info')),
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed_by TEXT,
    reviewed_at TIMESTAMP,
    admin_notes TEXT,
    UNIQUE (mcp_server_url, tool_name)
);

-- Admin review requests
CREATE TABLE IF NOT EXISTS admin_review_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mcp_server_url TEXT NOT NULL,
    tool_count INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending_review', 'in_progress', 'completed')),
    assigned_to TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    priority TEXT DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'urgent'))
);

-- MCP servers table for dynamic registration
CREATE TABLE IF NOT EXISTS mcp_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_url TEXT UNIQUE NOT NULL,
    server_name TEXT NOT NULL,
    server_version TEXT,
    description TEXT,
    capabilities TEXT, -- JSON of server capabilities
    registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    trust_level TEXT DEFAULT 'untrusted' CHECK (trust_level IN ('trusted', 'untrusted', 'blocked'))
);
```

## Admin Experience

### 1. Admin Review Process

```python
@app.route('/admin/mcp-servers/<server_id>/review-tools', methods=['POST'])
async def admin_review_tools(server_id):
    """
    Admin manually reviews and approves each tool
    """
    data = await request.get_json()
    
    for tool_decision in data.get('tool_decisions', []):
        tool_name = tool_decision['tool_name']
        admin_decision = tool_decision['decision']  # 'approve', 'deny', 'needs_more_info'
        
        if admin_decision == 'approve':
            # Admin manually sets risk level and permissions
            risk_level = tool_decision['admin_risk_assessment']  # 'low', 'medium', 'high', 'critical'
            allowed_roles = tool_decision['allowed_roles']  # ['user'], ['admin'], etc.
            approval_policy = tool_decision['approval_policy']  # 'auto', 'admin_required', etc.
            
            # Add to permissions (with admin's risk assessment)
            await auth_db.add_permission(
                scope=tool_name,
                description=tool_decision.get('description', ''),
                risk_level=risk_level,  # Admin's assessment, not server's
                requires_admin=(risk_level == 'critical'),
                admin_approved=True,
                approved_by=get_current_admin_user(),
                approval_notes=tool_decision.get('notes', '')
            )
            
            # Create policy based on admin decision
            await auth_db.add_scope_policy(
                scope=tool_name,
                policy_type=approval_policy,
                target_roles=allowed_roles,
                admin_approved=True
            )
            
            # Update tool status
            await auth_db.update_tool_status(
                mcp_server_url=server_id,
                tool_name=tool_name,
                status='approved'
            )
```

### 2. Admin Review UI Example

```
New MCP Server: http://localhost:8003
Tools discovered: 5

═══════════════════════════════════════════════════════════════

Tool: health_check
Description: "Check server health"
Admin Assessment: 
  [ ] Low Risk - Auto-approve for all users
  [ ] Medium Risk - Require approval
  [ ] High Risk - Admin only
  [ ] Critical Risk - Block completely
  [x] Needs more information

═══════════════════════════════════════════════════════════════

Tool: execute_command  
Description: "Execute system commands"
Admin Assessment:
  [ ] Low Risk - Auto-approve for all users
  [ ] Medium Risk - Require approval
  [ ] High Risk - Admin only
  [x] Critical Risk - Block completely
Notes: "This can run arbitrary commands - too dangerous for this server"

═══════════════════════════════════════════════════════════════

Tool: list_files
Description: "List files in directory"
Admin Assessment:
  [x] Low Risk - Auto-approve for all users
  [ ] Medium Risk - Require approval
  [ ] High Risk - Admin only
  [ ] Critical Risk - Block completely
Assign to roles: [user, admin]

═══════════════════════════════════════════════════════════════

Tool: read_database
Description: "Read from internal database"
Admin Assessment:
  [ ] Low Risk - Auto-approve for all users
  [x] Medium Risk - Require approval
  [ ] High Risk - Admin only
  [ ] Critical Risk - Block completely
Assign to roles: [admin]
Notes: "Contains sensitive data - admin approval required"

═══════════════════════════════════════════════════════════════

Tool: send_email
Description: "Send emails to users"
Admin Assessment:
  [ ] Low Risk - Auto-approve for all users
  [ ] Medium Risk - Require approval
  [x] High Risk - Admin only
  [ ] Critical Risk - Block completely
Assign to roles: [admin]
Notes: "Email sending should be restricted to admins"
```

### 3. Admin Notification System

```python
async def notify_admin_new_mcp_server(mcp_server_url: str, tool_count: int, auto_enabled_count: int, pending_review_count: int):
    """
    Notify admin about new MCP server discovery
    """
    message = f"""
    🔍 New MCP Server Discovered: {mcp_server_url}
    
    📊 Summary:
    - Total tools: {tool_count}
    - Auto-enabled: {auto_enabled_count} (none - zero trust policy)
    - Pending review: {pending_review_count}
    
    🔒 Security Status: ALL TOOLS BLOCKED pending your review
    
    📋 Action Required: Please review at /admin/mcp-servers/review
    """
    
    # Send notification (email, Slack, dashboard alert, etc.)
    await send_admin_notification(message)
    
    # Create dashboard task
    await auth_db.create_admin_task(
        task_type='mcp_server_review',
        description=f'Review new MCP server: {mcp_server_url}',
        priority='medium',
        data={
            'mcp_server_url': mcp_server_url,
            'tool_count': tool_count,
            'pending_review_count': pending_review_count
        }
    )
```

## User Experience

### Before Admin Review
```
User: "Let me use this new MCP server"
System: "❌ No tools available - pending admin review"
System: "📞 Contact your admin to enable tools from this server"
System: "🔍 Server: http://localhost:8003 (5 tools discovered)"
```

### After Admin Review
```
User: "Let me use this new MCP server"
System: "✅ Available tools:"
System: "  - health_check (auto-approved)"
System: "  - list_files (auto-approved)"
System: "  - read_database (requires approval)"
System: "⚠️ Blocked tools:"
System: "  - execute_command (admin decision: too dangerous)"
System: "  - send_email (admin-only)"
```

### Runtime Access Control

```python
async def check_user_tool_access(user_email: str, tool_name: str, mcp_server_url: str):
    """
    Runtime access control with zero trust
    """
    # Check if MCP server is trusted
    server_info = await auth_db.get_mcp_server_by_url(mcp_server_url)
    
    if server_info['trust_level'] == 'blocked':
        raise AccessDenied("MCP server is blocked by admin")
    
    # Check if tool is approved
    tool_info = await auth_db.get_discovered_tool(mcp_server_url, tool_name)
    
    if tool_info['status'] == 'pending_admin_review':
        raise AccessDenied("Tool requires admin approval - not yet reviewed")
    
    if tool_info['status'] == 'blocked':
        raise AccessDenied("Tool blocked by admin")
    
    if tool_info['status'] == 'approved':
        # Check user roles and permissions
        user_roles = await auth_db.get_user_roles(user_email)
        tool_policy = await auth_db.get_scope_policy(tool_name)
        
        return evaluate_access_policy(user_roles, tool_policy)
    
    # Default deny
    raise AccessDenied("Tool access denied")
```

## Benefits and Tradeoffs

### ✅ Benefits

#### For MCP Server Operators
- **Zero Configuration**: Just deploy and advertise capabilities
- **Standards-Based**: Uses well-known endpoints for discovery
- **Automatic Discovery**: No manual auth server registration needed
- **Clear Process**: Straightforward path to getting tools approved

#### For Users
- **Transparent**: Clear visibility into available vs. blocked tools
- **Consistent**: Same approval process for all MCP servers
- **Secure**: Protection against malicious or poorly configured servers
- **Informative**: Clear messages about why tools are blocked

#### For System Administrators
- **Complete Control**: Admin makes all security decisions
- **Audit Trail**: Full history of what was approved/denied and why
- **Scalable**: One-time review per tool, not per user
- **Secure by Default**: Zero trust approach eliminates accidental permissions

### ⚠️ Tradeoffs

#### Manual Review Required
- **Admin Workload**: Every new MCP server requires admin review
- **Delay**: Tools not immediately available to users
- **Scaling**: Admin becomes bottleneck for new MCP servers

#### No Automation
- **No Smart Defaults**: Cannot auto-approve even "obviously safe" tools
- **Conservative**: May block tools that could be safely auto-approved
- **Process Heavy**: Requires formal review process

#### Limited Trust
- **No Server Reputation**: Cannot build trust over time
- **No Risk Learning**: System doesn't learn from admin decisions
- **Static Assessment**: Risk levels don't adapt to usage patterns

## Implementation Phases

### Phase 1: Foundation
1. **Add dynamic tables** to database schema
2. **Create MCP capabilities endpoint** specification
3. **Implement basic discovery** service
4. **Add admin notification** system

### Phase 2: Core Registration
1. **Add registration endpoints** to auth server
2. **Update chat app** to auto-discover servers
3. **Create admin review UI** for tool approval
4. **Implement zero trust** access control

### Phase 3: User Experience
1. **Add user-facing** tool status display
2. **Create clear error messages** for blocked tools
3. **Implement approval request** workflows
4. **Add audit logging** for all decisions

### Phase 4: Operations
1. **Add monitoring** for discovery failures
2. **Create admin tools** for server management
3. **Implement bulk operations** for tool reviews
4. **Add performance optimization** for large numbers of servers

## Conclusion

This zero trust approach to dynamic MCP server registration provides:

1. **Automatic Discovery**: MCP servers are found and registered automatically
2. **Complete Security**: All tools blocked until admin review
3. **Clear Process**: Straightforward workflow for admins and users
4. **Audit Trail**: Full accountability for all security decisions
5. **Scalability**: Supports unlimited MCP servers with controlled security

The key insight is that **dynamic discovery is possible, but dynamic permission assignment is not**. The human admin remains the only entity capable of making security decisions about unknown tools from untrusted sources.

This approach transforms the authentication system from static configuration to dynamic discovery while maintaining the highest security standards through zero trust principles. 