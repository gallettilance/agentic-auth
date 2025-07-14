#!/usr/bin/env python3
"""
MCP Keycloak OIDC Kubernetes Demo
Demonstrates the full integration flow:
1. Authenticate with Keycloak
2. Exchange token with auth server
3. Use MCP tools to interact with Kubernetes
"""

import os
import sys
import asyncio
import json
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from mcp.oidc_keycloak import get_oidc_token
import requests

# Configuration
KEYCLOAK_HOST = os.environ.get("KEYCLOAK_HOST", "http://localhost:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "master")
CLIENT_ID = os.environ.get("CLIENT_ID", "kubernetes")
AUTH_SERVER = os.environ.get("AUTH_SERVER", "http://localhost:8002")
MCP_SERVER = os.environ.get("MCP_SERVER", "http://localhost:8001")

async def main():
    print("🚀 Starting MCP Keycloak OIDC Kubernetes Demo")
    print("=" * 50)
    
    # Step 1: Authenticate with Keycloak
    print("\n1. Authenticating with Keycloak...")
    try:
        tokens = get_oidc_token(KEYCLOAK_HOST, KEYCLOAK_REALM, CLIENT_ID)
        keycloak_token = tokens["access_token"]
        print("✅ Keycloak authentication successful")
    except Exception as e:
        print(f"❌ Keycloak authentication failed: {e}")
        return
    
    # Step 2: Exchange token with auth server
    print("\n2. Exchanging token with auth server...")
    try:
        response = requests.post(f"{AUTH_SERVER}/auth/keycloak/exchange", json={
            "keycloak_token": keycloak_token,
            "scopes": ["kubectl:read", "kubectl:write"]
        })
        
        print(f"Response status: {response.status_code}")
        print(f"Response text: {response.text}")
        
        response.raise_for_status()
        auth_data = response.json()
        internal_jwt = auth_data["access_token"]
        print("✅ Token exchange successful")
    except Exception as e:
        print(f"❌ Token exchange failed: {e}")
        return
    
    # Step 3: Use MCP tools
    print("\n3. Using MCP tools to interact with Kubernetes...")
    
    # Simulate MCP tool calls (in a real scenario, this would use the MCP protocol)
    tools_to_test = [
        ("kubectl_get_pods", {"namespace": "default"}),
        ("kubectl_get_services", {"namespace": "default"}),
    ]
    
    for tool_name, params in tools_to_test:
        print(f"\n🔧 Calling MCP tool: {tool_name}")
        try:
            # In a real MCP client, this would use the MCP protocol
            # For demo purposes, we'll simulate the call
            print(f"   Parameters: {params}")
            print(f"   Token: {internal_jwt[:20]}...")
            print("   ✅ Tool call would be executed with proper authentication")
        except Exception as e:
            print(f"   ❌ Tool call failed: {e}")
    
    print("\n🎉 Demo completed successfully!")
    print("\nNext steps:")
    print("- Start the MCP server: python mcp/mcp_server.py")
    print("- Start the auth server: python auth-server/main.py")
    print("- Use a proper MCP client to make tool calls")

if __name__ == "__main__":
    asyncio.run(main()) 