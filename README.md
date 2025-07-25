# Authentication Demo - Keycloak Token Exchange V2

A demonstration of **Keycloak-based authentication and authorization** using RFC 8693 Token Exchange for dynamic scope management. Shows how users can authenticate once and exchange tokens for specific service access (MCP tools, Llama Stack agents) based on their roles.

## What This Demo Shows

- **Keycloak** as the authorization server (replaces custom auth server code)
- **Zero-trust authentication**: Users start with minimal permissions
- **Dynamic scope exchange**: Request specific service permissions when needed
- **Role-based access**: Regular users vs admin users get different scopes
- **Standards compliance**: RFC 8693 OAuth 2.0 Token Exchange

**Services in the demo:**
- Chat UI frontend with Keycloak authentication
- MCP Server for file operations (with scope-based permissions)
- Llama Stack for AI agents (with scope-based permissions)

## Prerequisites

- **Docker** (for Keycloak)
- **Python 3.8+**
- **pip**

## Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt  # If requirements.txt exists
# OR install manually:
pip install requests flask authlib httpx fastmcp llama-stack-client
```

## Run the Demo

```bash
# Start everything (Keycloak + all services)
./start_demo.sh
```

**What this does:**
1. Starts Keycloak authorization server
2. Configures realm, client, scopes, roles, and users automatically  
3. Starts chat frontend, MCP server, and Llama Stack
4. Sets up environment variables

**Access the demo:**
- **Chat Frontend**: http://localhost:5001
- **Login credentials**: 
  - Regular user: `lance` / `password`
  - Admin user: `admin-user` / `password`

**Try it out:**
1. Login to the chat UI
2. Send messages to see AI agent responses
3. Try file operations (uses MCP with dynamic token exchange)
4. Notice how admin users can access additional commands

## Cleanup

```bash
# Stop all services
./stop_demo.sh

# Complete cleanup (removes Docker containers)
./cleanup_demo.sh
```

## Key Files

- `setup_keycloak_v2.py` - Configures Keycloak automatically
- `start_demo.sh` - One-command demo startup
- `frontends/chat-ui/` - Chat interface with Keycloak auth
- `mcp/mcp_server.py` - MCP server with token validation
- `auth-server/` - ❌ Old custom auth server (no longer used)

---

**🎯 Quick Start**: Run `./start_demo.sh` and visit http://localhost:5001 
