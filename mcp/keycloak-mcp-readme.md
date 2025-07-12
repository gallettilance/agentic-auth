# MCP Keycloak OIDC Kubernetes Integration

This integration allows MCP tools to authenticate with Keycloak and use those credentials to interact with Kubernetes resources through the MCP protocol.

## Architecture

```
┌─────────────────┐ 1. Auth ┌─────────────────┐
│ MCP Client │───────────────▶│ Keycloak │
│ │ │ (OIDC IdP) │
└─────────────────┘ └─────────────────┘
│
│ 2. Exchange Token
▼
┌─────────────────┐ 3. JWT ┌─────────────────┐
│ Auth Server │───────────────▶│ MCP Server │
│ (Token Bridge)│ │ (kubectl tools)│
└─────────────────┘ └─────────────────┘
│
│ 4. K8s API
▼
┌─────────────────┐
│ Kubernetes │
│ API Server │
└─────────────────┘
```


## Prerequisites

- Keycloak server with realm and OIDC client configured
- Kubernetes API server configured with OIDC flags
- Python 3.12+ with required packages (see requirements.txt)

## Setup

1. **Install dependencies**:
   ```sh
   pip install -r mcp/requirements.txt
   ```

2. **Configure environment**:
   ```sh
   export KEYCLOAK_HOST=https://your-keycloak.example.com
   export KEYCLOAK_REALM=yourrealm
   export CLIENT_ID=kubernetes
   export KUBE_API_SERVER=https://your-k8s-api.example.com:6443
   export AUTH_SERVER=http://localhost:8002
   ```

3. **Start services**:
   ```sh
   # Start auth server
   python auth-server/main.py
   
   # Start MCP server
   python mcp/mcp_server.py
   ```

4. **Run demo**:
   ```sh
   python scripts/mcp_k8s_oidc_demo.py
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
