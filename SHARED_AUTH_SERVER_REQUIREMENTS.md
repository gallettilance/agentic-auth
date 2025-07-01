# Shared Auth Server Architecture Requirements

## Current State vs. Required State

### ✅ Already Implemented
- Separate auth server and MCP server processes
- Database-backed user/role/permission management
- OAuth 2.1 endpoints (authorization, token, metadata)
- JWT token generation with asymmetric/symmetric modes
- Client credential validation
- Scope-based authorization

### ❌ Missing for True Shared Auth Server

#### 1. **Remove MCP Server Coupling**

**Problem**: Auth server is hardcoded to specific MCP server
```python
# auth-server/unified_auth_server.py:46
MCP_SERVER_URI = os.getenv("MCP_SERVER_URI", "http://localhost:8001")
```

**Solution**: Remove this dependency. Auth server should not know about specific MCP servers.

#### 2. **Implement RFC 8707 Resource Parameter**

**Problem**: Token endpoint missing `resource` parameter
```python
# Current - Missing resource parameter
@app.post("/oauth/token")
async def oauth_token_endpoint(
    audience: Optional[str] = Form(default=None),
    scope: Optional[str] = Form(default=None)
):
```

**Solution**: Add resource parameter and validate against registered MCP servers
```python
@app.post("/oauth/token")
async def oauth_token_endpoint(
    audience: Optional[str] = Form(default=None),
    resource: Optional[str] = Form(default=None),  # RFC 8707
    scope: Optional[str] = Form(default=None)
):
    # Validate resource parameter against registered MCP servers
    if resource and not is_valid_mcp_server(resource):
        raise HTTPException(status_code=400, detail="invalid_target")
    
    # Use resource as audience if provided
    token_audience = resource or audience
```

#### 3. **Remove Hardcoded Tool Knowledge**

**Problem**: Auth server has hardcoded MCP tool definitions
```python
# auth-server/unified_auth_server.py:420-460
async def fetch_mcp_tools(user: TokenPayload) -> Dict[str, Any]:
    tools_info = [
        {"name": "list_files", "required_scope": "read:files"},
        # ... hardcoded tools
    ]
```

**Solution**: Remove this function entirely. Auth server should only manage scopes, not tools.

#### 4. **Add MCP Server Registration**

**Problem**: No way to register multiple MCP servers

**Solution**: Add MCP server registration endpoint
```python
@app.post("/api/admin/mcp-servers")
async def register_mcp_server(
    request: Request,
    admin: TokenPayload = Depends(verify_admin_auth)
):
    data = await request.json()
    server_uri = data["server_uri"]
    supported_scopes = data["supported_scopes"]
    
    # Store in database
    auth_db.register_mcp_server(server_uri, supported_scopes)
```

#### 5. **Add Protected Resource Metadata for MCP Servers**

**Problem**: No discovery mechanism for MCP servers

**Solution**: Add Protected Resource Metadata endpoint for each registered MCP server
```python
# MCP Server should expose this, not auth server
@mcp_app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata():
    return {
        "resource": SERVER_URI,
        "authorization_servers": [AUTH_SERVER_URI],
        "scopes_supported": ["list_files", "execute_command"],
        "bearer_methods_supported": ["header"]
    }
```

#### 6. **Database Schema Updates**

**Problem**: Database doesn't support multiple MCP servers

**Solution**: Add MCP server registration table
```sql
CREATE TABLE mcp_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_uri TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    supported_scopes TEXT, -- JSON array
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### 7. **Client-Server Mapping**

**Problem**: No way to map OAuth clients to allowed MCP servers

**Solution**: Update client registration to include allowed resources
```sql
-- Add to oauth_clients table
ALTER TABLE oauth_clients ADD COLUMN allowed_resources TEXT; -- JSON array of MCP server URIs
```

#### 8. **Scope Validation Against MCP Servers**

**Problem**: Auth server validates scopes without knowing which MCP server supports them

**Solution**: Validate requested scopes against target MCP server's capabilities
```python
def validate_scopes_for_resource(scopes: List[str], resource_uri: str) -> bool:
    """Validate that requested scopes are supported by target MCP server"""
    mcp_server = auth_db.get_mcp_server(resource_uri)
    if not mcp_server:
        return False
    
    supported_scopes = json.loads(mcp_server.supported_scopes)
    return all(scope in supported_scopes for scope in scopes)
```

## Implementation Priority

### Phase 1: Core Separation
1. Remove `MCP_SERVER_URI` from auth server
2. Remove `fetch_mcp_tools()` function
3. Add `resource` parameter to token endpoint

### Phase 2: Multi-Server Support
1. Add MCP server registration database table
2. Add MCP server registration API endpoints
3. Update client registration to include allowed resources

### Phase 3: Discovery & Validation
1. Implement scope validation against registered MCP servers
2. Add Protected Resource Metadata to MCP servers
3. Update token validation to check resource parameter

## Example Multi-Server Scenario

With these changes, you could have:

```
Auth Server (localhost:8002)
├── MCP Server 1 (localhost:8001) - File operations
├── MCP Server 2 (localhost:8003) - Database operations  
├── MCP Server 3 (localhost:8004) - Email operations
└── Chat Client - Can access all three with appropriate tokens
```

Each MCP server would:
1. Register with auth server on startup
2. Expose Protected Resource Metadata
3. Validate tokens with `aud` claim matching their URI
4. Return 403 for insufficient scopes (using tool name as scope)

The auth server would:
1. Issue tokens with `aud` claim set to requested `resource`
2. Validate scopes against target MCP server capabilities
3. Not know anything about specific tools, only scopes 