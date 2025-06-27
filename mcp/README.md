# MCP Server

This directory contains the **Model Context Protocol (MCP) Server** implementation for the authentication system. The MCP server provides secure, scope-based access to system resources and commands through JWT token authentication.

## Overview

The MCP server acts as a **protected resource** in the OAuth 2.0 architecture. It validates JWT tokens locally (without contacting the auth server) and provides tools based on user permissions. It implements scope-based authorization to control access to different functionalities.

## Architecture

```
┌─────────────────┐    JWT Token    ┌─────────────────┐
│   Chat Client   │────────────────▶│   MCP Server    │
│   (Port 5001)   │                 │   (Port 8001)   │
└─────────────────┘                 └─────────────────┘
         │                                   │
         │ Token Exchange                    │ Local JWT
         │ (when scope insufficient)         │ Validation
         ▼                                   ▼
┌─────────────────┐                 ┌─────────────────┐
│   Auth Server   │                 │  System Tools   │
│   (Port 8002)   │                 │ (Files, Commands)│
└─────────────────┘                 └─────────────────┘
```

**Key Points:**
- **Chat Client** ↔ **MCP Server**: Direct communication with JWT tokens
- **Chat Client** ↔ **Auth Server**: Token exchange when scope upgrade needed
- **MCP Server** ↔ **Auth Server**: **NO direct communication** - only shared JWT secret

## Authentication Flow

1. **JWT Validation (Local)**: MCP server validates tokens using shared `JWT_SECRET`
2. **Scope Checking**: Verifies user has required permissions for each tool
3. **Scope Upgrade Info**: Returns auth server endpoint when permissions insufficient
4. **No Network Calls**: MCP server never makes HTTP requests to auth server

## Features

### 🔐 JWT Token Authentication
- Validates JWT tokens **locally** using shared secret
- Verifies token audience, issuer, and expiration
- Extracts user information and scopes from tokens
- **No communication with auth server** for validation

### 🎯 Scope-Based Authorization
- **`read:files`** - Read file system information and list directory contents
- **`execute:commands`** - Execute system commands with safety restrictions
- **No scope required** - Basic server information and health checks

### 🛠️ Available Tools

| Tool | Required Scope | Description |
|------|----------------|-------------|
| `list_files` | `read:files` | List files and directories with metadata |
| `execute_command` | `execute:commands` | Execute safe system commands |
| `get_server_info` | None | Get server and authentication information |
| `get_oauth_metadata` | None | Get OAuth 2.0 resource metadata |
| `health_check` | None | Verify server health status |
| `list_tool_scopes` | None | List all tools and their scope requirements |

### 🔒 Security Features
- Command validation to block dangerous operations (`rm`, `del`, `format`, etc.)
- Command timeout protection (30 seconds)
- Comprehensive error handling and logging
- Scope upgrade guidance for insufficient permissions

## Configuration

The server uses the following configuration:

```python
SERVER_HOST = "localhost"
SERVER_PORT = 8001
SERVER_URI = "http://localhost:8001"
AUTH_SERVER_URI = "http://localhost:8002"  # Referenced in tokens and error messages
JWT_SECRET = os.getenv("JWT_SECRET", "demo-secret-key-change-in-production")
```

**Note**: `AUTH_SERVER_URI` is used for:
- JWT issuer validation (checking `iss` claim)
- Scope upgrade endpoint references in error messages
- **NOT for making HTTP requests** to the auth server

## Usage

### Starting the Server

```bash
cd mcp
python mcp_server.py
```

The server will start on `http://localhost:8001` and begin accepting MCP connections.

### Authentication

All tool calls require a valid JWT token in the Authorization header:

```
Authorization: Bearer <jwt_token>
```

The token must:
- Be issued by the configured authentication server (`iss` claim)
- Have the correct audience (`aud` claim = `http://localhost:8001`)
- Not be expired (`exp` claim)
- Contain appropriate scopes for the requested tool (`scope` claim)

### JWT Token Structure

The MCP server expects JWT tokens with these claims:
```json
{
  "iss": "http://localhost:8002",           // Auth server (issuer)
  "aud": "http://localhost:8001",           // MCP server (audience)
  "sub": "user@example.com",                // User identifier
  "email": "user@example.com",              // User email
  "scope": "read:files execute:commands",   // Space-separated scopes
  "exp": 1234567890,                        // Expiration timestamp
  "iat": 1234567800                         // Issued at timestamp
}
```

### Example Tool Usage

#### List Files (requires `read:files` scope)
```python
result = await mcp_client.call_tool("list_files", {"directory": "/home/user"})
```

#### Execute Command (requires `execute:commands` scope)
```python
result = await mcp_client.call_tool("execute_command", {"command": "ls -la"})
```

#### Get Server Info (no scope required)
```python
result = await mcp_client.call_tool("get_server_info", {})
```

## Error Handling

### Insufficient Scope
When a user lacks the required scope, the server returns detailed upgrade information:

```json
{
  "success": false,
  "error_type": "insufficient_scope",
  "required_scope": "read:files",
  "user_scopes": ["basic"],
  "scope_upgrade_endpoint": "http://localhost:8002/api/upgrade-scope",
  "upgrade_instructions": "Use the scope_upgrade_endpoint to request additional permissions"
}
```

**Important**: The MCP server provides this information but does **not** make the upgrade request itself. The chat client handles scope upgrade requests.

### Invalid Token
- `Token expired` - JWT token has expired
- `Invalid token` - JWT signature validation failed
- `Missing or invalid Authorization header` - No Bearer token provided
- `Invalid audience` - Token not intended for this server
- `Invalid issuer` - Token not issued by expected auth server

## OAuth 2.0 Protected Resource Pattern

The MCP server follows the **OAuth 2.0 Protected Resource** pattern:

1. **Token Validation**: Validates JWT tokens locally using shared secret
2. **Scope Enforcement**: Checks token scopes against required permissions
3. **Resource Access**: Provides access to tools based on validated scopes
4. **Error Responses**: Returns standard OAuth 2.0 error responses

This pattern eliminates the need for the MCP server to contact the authorization server for each request, improving performance and reducing dependencies.

## Files

- **`mcp_server.py`** - Main MCP server implementation with all tools and authentication
- **`access_token.txt`** - Token storage file (automatically managed)

## Dependencies

The MCP server requires:
- `fastmcp` - MCP server framework
- `PyJWT` - JWT token validation
- `python-dotenv` - Environment configuration

## Integration

The MCP server integrates with:
- **Authentication Server** (`../auth-server/`) - Shares JWT secret for token validation
- **Chat Application** (`../frontend/chat_app.py`) - As the primary client
- **Llama Stack** - Through the chat application for AI agent interactions

## Security Considerations

1. **JWT Secret Management** - Use strong secrets in production, shared with auth server
2. **Command Filtering** - Dangerous commands are blocked by default
3. **Timeout Protection** - Commands are limited to 30 seconds execution time
4. **Scope Validation** - All operations require appropriate permissions
5. **Logging** - Comprehensive audit trail of all operations
6. **No Network Dependencies** - Local token validation reduces attack surface

## Development

To extend the MCP server:

1. Add new tools using the `@mcp.tool()` decorator
2. Implement scope checking with `check_scope(ctx, "required:scope")`
3. Handle errors with `handle_scope_error(ctx, error_message)`
4. Update the scope descriptions in `get_scope_description()`
5. Document new scopes in `list_tool_scopes()`

## Monitoring

The server provides comprehensive logging for:
- Authentication attempts and results
- Scope validation checks
- Tool execution and results
- Error conditions and security violations

Monitor the logs for security events and performance metrics. 