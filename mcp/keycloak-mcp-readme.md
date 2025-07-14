# MCP Keycloak OIDC Kubernetes Integration

This integration allows MCP tools to authenticate with Keycloak and use those credentials to interact with Kubernetes resources through the MCP protocol.

## Architecture

```
 1. OIDC Auth 
┌─────────────────┐        ┌────────────┐
│ MCP Client      │──────▶ │ Keycloak   │
│ (Demo Script) │ │        | (OIDC IdP) │
└─────────────────┘        └────────────┘
  │
  │ 2. Access Token
  ▼
3. Token Exchange
┌─────────────────┐
│  │ Auth Server │
          └─────────────▶│ (Token Bridge) │
└─────────────────┘
│
│ 4. Internal JWT
▼
┌─────────────────┐
│ MCP Server │
│ (kubectl tools) │
└─────────────────┘
│
│ 5. K8s API (NOT IMPLEMENTED)
▼
┌─────────────────┐
│ Kubernetes │ ❌ STUB ONLY
│ API Server │
└─────────────────┘

✅ WORKING: Steps 1-4 (Authentication chain)
❌ NOT IMPLEMENTED: Step 5 (Actual K8s API calls)
```


## Prerequisites

- Docker or Podman for running Keycloak container
- Kubernetes API server configured with OIDC flags (optional for demo)
- Python 3.12+ with required packages (see requirements.txt)

## Keycloak Setup

### 1. Start Keycloak Container

```bash
# Start Keycloak with development settings
podman run -d \
  --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest \
  start-dev
```

Wait for Keycloak to start (check logs with `podman logs keycloak`), then access the admin console at http://localhost:8080

### 2. Configure Keycloak Client

1. **Login to Admin Console**:
   - URL: http://localhost:8080
   - Username: `admin`
   - Password: `admin`

2. **Create/Select Realm**:
   - Use `master` realm for demo, or create a new realm
   - Navigate to the realm settings

3. **Create OIDC Client**:
   - Go to **Clients** → **Create client**
   - **Client type**: OpenID Connect
   - **Client ID**: `kubernetes`
   - **Name**: `Kubernetes MCP Client`
   - Click **Next**

4. **Configure Client Settings**:
   - **Client authentication**: OFF (public client)
   - **Authorization**: OFF
   - **Standard flow**: ON (Authorization Code Flow)
   - **Direct access grants**: OFF
   - **Implicit flow**: OFF
   - **Service accounts roles**: OFF
   - Click **Next**, then **Save**

5. **Configure Client Details**:
   - **Root URL**: `http://localhost:8081`
   - **Valid redirect URIs**: `http://localhost:8081/callback`
   - **Web origins**: `http://localhost:8081`
   - **Admin URL**: (leave empty)
   - Click **Save**

6. **Configure Advanced Settings**:
   - Go to **Advanced** tab
   - **Proof Key for Code Exchange Code Challenge Method**: `S256`
   - **Access Token Lifespan**: `15 minutes` (adjust as needed)
   - Click **Save**

### 3. Create Test User (Optional)

1. **Create User**:
   - Go to **Users** → **Create new user**
   - **Username**: `testuser`
   - **Email**: `test@example.com`
   - **First name**: `Test`
   - **Last name**: `User`
   - **Email verified**: ON
   - Click **Create**

2. **Set Password**:
   - Go to **Credentials** tab
   - Click **Set password**
   - **Password**: `password`
   - **Temporary**: OFF
   - Click **Save**

## Application Setup

1. **Install dependencies**:
   ```bash
   pip install -r mcp/requirements.txt
   ```

2. **Configure environment**:
   ```bash
   # For local development with Docker Keycloak
   export KEYCLOAK_HOST=http://localhost:8080
   export KEYCLOAK_REALM=master
   export CLIENT_ID=kubernetes
   export KUBE_API_SERVER=https://localhost:6443  # Optional for demo
   export AUTH_SERVER=http://localhost:8002
   export MCP_SERVER=http://localhost:8001
   ```

3. **Start services**:
   ```bash
   ./start_demo.sh
   ```

4. **Run demo**:
   ```bash
   # Test the complete authentication flow
   python scripts/mcp_k8s_real_tool_demo.py
   ```

## Quick Start (All-in-One)

```bash
# 1. Start Keycloak
podman run -d --name keycloak -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev

# 2. Wait for Keycloak to start (30-60 seconds)
podman logs -f keycloak

# 3. Configure client (manual step in web UI - see above)
Visit http://localhost:8080 and follow "Configure Keycloak Client" steps

# 4. Set environment and start services
export KEYCLOAK_HOST=http://localhost:8080
export KEYCLOAK_REALM=master
export CLIENT_ID=kubernetes
./start_demo.sh

# 5. Run the demo
python scripts/mcp_k8s_real_tool_demo.py
```

## Available MCP Tools

- `kubectl_get_pods` - List pods in a namespace (requires `kubectl:read`)
- `kubectl_get_services` - List services in a namespace (requires `kubectl:read`)
- `kubectl_apply_yaml` - Apply YAML configuration (requires `kubectl:write`)

## Scope Mapping

Keycloak roles are mapped to internal scopes:
- `admin` role → `kubectl:admin` scope
- `developer` role → `kubectl:read`, `kubectl:write` scopes
- `viewer` role → `kubectl:read` scope

## References

- [Kubernetes OIDC Auth](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens)
- [Keycloak OIDC Docs](https://www.keycloak.org/docs/latest/server_admin/#oidc)
- [MCP Protocol](https://modelcontextprotocol.io/)
