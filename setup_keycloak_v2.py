#!/usr/bin/env python3
"""
Keycloak Token Exchange V2 - Complete Programmatic Setup
Configures realm, client, scopes, roles, authorization policies, and users
"""

import requests
import time
import json
import os
import base64
from typing import List, Dict, Optional
import sys

# Configuration
KEYCLOAK_URL = os.getenv("KEYCLOAK_ENV", "http://localhost:8002")
KEYCLOAK_REALM_NAME = os.getenv("KEYCLOAK_REALM_NAME", "authentication-demo")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "authentication-demo")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "demo-client-secret-change-in-production")

# Scopes configuration with role requirements
SCOPE_DEFINITIONS = {
    # MCP Scopes
    "mcp:list_files": {"description": "List files via MCP", "risk_level": "low", "min_role": "user"},
    "mcp:health_check": {"description": "Health check via MCP", "risk_level": "low", "min_role": "user"},
    "mcp:get_server_info": {"description": "Get server info via MCP", "risk_level": "low", "min_role": "user"},
    "mcp:list_tool_scopes": {"description": "List tool scopes via MCP", "risk_level": "low", "min_role": "user"},
    "mcp:execute_command": {"description": "Execute commands via MCP (admin only)", "risk_level": "critical", "min_role": "admin"},
    
    # Llama Stack Scopes (Official scopes only)
    "llama:inference": {"description": "Inference via Llama Stack", "risk_level": "medium", "min_role": "user"},
    "llama:models:read": {"description": "Read models via Llama Stack", "risk_level": "low", "min_role": "user"},
    "llama:models:write": {"description": "Write models via Llama Stack", "risk_level": "medium", "min_role": "user"},
    "llama:agents:read": {"description": "Read agents via Llama Stack", "risk_level": "low", "min_role": "user"},
    "llama:agents:write": {"description": "Write agents via Llama Stack", "risk_level": "medium", "min_role": "user"},
    "llama:tools": {"description": "Use tools via Llama Stack", "risk_level": "medium", "min_role": "user"},
    "llama:toolgroups:read": {"description": "Read tool groups via Llama Stack", "risk_level": "low", "min_role": "user"},
    "llama:toolgroups:write": {"description": "Write tool groups via Llama Stack", "risk_level": "medium", "min_role": "user"},
    "llama:vector_dbs:read": {"description": "Read vector databases via Llama Stack", "risk_level": "low", "min_role": "user"},
    "llama:vector_dbs:write": {"description": "Write vector databases via Llama Stack", "risk_level": "medium", "min_role": "user"},
    "llama:safety": {"description": "Safety features via Llama Stack", "risk_level": "medium", "min_role": "user"},
    "llama:eval": {"description": "Evaluation features via Llama Stack", "risk_level": "medium", "min_role": "user"},
    "llama:admin": {"description": "Admin access via Llama Stack", "risk_level": "critical", "min_role": "admin"},
}

# Role definitions
ROLE_DEFINITIONS = {
    "user": {
        "description": "Standard user with basic operational permissions",
        "scopes": [
            "mcp:list_files", "mcp:health_check", "mcp:get_server_info", "mcp:list_tool_scopes",
            "llama:inference", "llama:models:read", "llama:models:write", "llama:agents:read", 
            "llama:agents:write", "llama:tools", "llama:toolgroups:read", "llama:toolgroups:write",
            "llama:vector_dbs:read", "llama:vector_dbs:write", "llama:safety", "llama:eval"
        ]
    },
    "admin": {
        "description": "System administrator with full system access",
        "scopes": list(SCOPE_DEFINITIONS.keys())  # All scopes including llama:admin
    }
}

# User definitions
USER_DEFINITIONS = [
    {
        "username": "lance",
        "email": "lance@example.com",
        "first_name": "Lance",
        "last_name": "User",
        "password": "password",
        "roles": ["user"]
    },
    {
        "username": "admin-user",
        "email": "admin@example.com", 
        "first_name": "Admin",
        "last_name": "User",
        "password": "password",
        "roles": ["admin"]
    }
]

class KeycloakV2Setup:
    """Keycloak Token Exchange V2 Setup Manager"""
    
    def __init__(self):
        self.admin_token = None
        self.headers = {}
        self.client_uuid = None
        
    def wait_for_keycloak(self) -> bool:
        """Wait for Keycloak to be ready"""
        print("🔄 Waiting for Keycloak to be ready...")
        max_attempts = 30
        
        for attempt in range(max_attempts):
            try:
                response = requests.get(f"{KEYCLOAK_URL}/realms/master", timeout=5)
                if response.status_code == 200:
                    print("✅ Keycloak is ready!")
                    return True
            except requests.exceptions.RequestException:
                pass
            
            if attempt < max_attempts - 1:
                time.sleep(2)
        
        print("❌ Keycloak did not become ready in time")
        return False

    def get_admin_token(self) -> bool:
        """Get admin access token"""
        try:
            response = requests.post(
                f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
                data={
                    'grant_type': 'password',
                    'client_id': 'admin-cli',
                    'username': 'admin',
                    'password': 'admin123'
                }
            )
            
            if response.status_code == 200:
                self.admin_token = response.json()['access_token']
                self.headers = {
                    'Authorization': f'Bearer {self.admin_token}',
                    'Content-Type': 'application/json'
                }
                print("✅ Admin authentication successful")
                return True
            else:
                print(f"❌ Failed to get admin token: {response.status_code}")
                print(f"   Error: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error getting admin token: {e}")
            return False

    def create_realm(self) -> bool:
        """Create the authentication realm with Token Exchange V2 settings"""
        realm_config = {
            "realm": KEYCLOAK_REALM_NAME,
            "displayName": "Token Exchange V2 Demo Realm",
            "enabled": True,
            "registrationAllowed": False,
            "loginWithEmailAllowed": True,
            "duplicateEmailsAllowed": False,
            "resetPasswordAllowed": True,
            "editUsernameAllowed": False,
            "bruteForceProtected": True,
            "accessTokenLifespan": 1800,  # 30 minutes
            "ssoSessionIdleTimeout": 1800,
            "ssoSessionMaxLifespan": 36000,
            # Token Exchange V2 is enabled by default - no special realm settings needed
        }
        
        # Check if realm exists
        response = requests.get(f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}", headers=self.headers)
        if response.status_code == 200:
            print(f"✅ Realm {KEYCLOAK_REALM_NAME} already exists")
            return True
        
        # Create realm
        response = requests.post(f"{KEYCLOAK_URL}/admin/realms", headers=self.headers, json=realm_config)
        
        if response.status_code == 201:
            print(f"✅ Created realm: {KEYCLOAK_REALM_NAME}")
            return True
        elif response.status_code == 409:
            print(f"✅ Realm {KEYCLOAK_REALM_NAME} already exists")
            return True
        else:
            print(f"❌ Failed to create realm: {response.status_code}")
            if response.content:
                print(f"   Error: {response.text}")
            return False

    def create_client(self) -> bool:
        """Create confidential client with Token Exchange V2 enabled"""
        client_config = {
            "clientId": KEYCLOAK_CLIENT_ID,
            "name": "Token Exchange V2 Client",
            "description": "Single confidential client for Token Exchange V2 self-exchange",
            "enabled": True,
            "clientAuthenticatorType": "client-secret",  # Required: V2 only supports confidential clients
            "secret": KEYCLOAK_CLIENT_SECRET,
            "redirectUris": [
                "http://localhost:3000/*",
                "http://localhost:5000/*",
                "http://localhost:5001/*",
                "http://localhost:8000/*",
                "http://localhost:8080/*"
            ],
            "webOrigins": [
                "http://localhost:3000",
                "http://localhost:5000",
                "http://localhost:5001", 
                "http://localhost:8000",
                "http://localhost:8080"
            ],
            "protocol": "openid-connect",
            "publicClient": False,  # Required: V2 requires confidential clients
            "bearerOnly": False,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": True,
            "authorizationServicesEnabled": True,  # Required for fine-grained permissions
            "authorizationSettings": {
                "allowRemoteResourceManagement": True,
                "policyEnforcementMode": "ENFORCING",  # Critical: Enable policy enforcement
                "decisionStrategy": "UNANIMOUS"
            },
            "attributes": {
                "post.logout.redirect.uris": "+",
                "oauth2.device.authorization.grant.enabled": "false",
                "oidc.ciba.grant.enabled": "false",
                "standard.token.exchange.enabled": "true"
            },
            "defaultClientScopes": ["openid", "profile", "email"],  # Minimal initial scopes
            # CRITICAL: For self-exchange, the client must be able to issue tokens to itself
            "optionalClientScopes": [],  # Will be populated with custom scopes
            # Ensure self-audience capability
            "fullScopeAllowed": False  # Important for scope-based access control
        }
        
        # Check if client exists
        response = requests.get(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients",
            params={"clientId": KEYCLOAK_CLIENT_ID},
            headers=self.headers
        )
        
        if response.status_code == 200 and response.json():
            self.client_uuid = response.json()[0]['id']
            print(f"✅ Client {KEYCLOAK_CLIENT_ID} already exists (UUID: {self.client_uuid})")
            
            # Update existing client with token exchange configuration
            print(f"🔄 Updating client with Token Exchange V2 settings...")
            update_response = requests.put(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}",
                headers=self.headers,
                json=client_config
            )
            
            if update_response.status_code == 204:
                print(f"✅ Updated client with Token Exchange V2 configuration")
                # Verify token exchange is enabled
                self._verify_token_exchange_enabled()
                return True
            else:
                print(f"❌ Failed to update client: {update_response.status_code}")
                if update_response.content:
                    print(f"   Error: {update_response.text}")
                return False
        
        # Create client
        response = requests.post(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients",
            headers=self.headers,
            json=client_config
        )
        
        if response.status_code == 201:
            # Get the created client UUID
            response = requests.get(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients",
                params={"clientId": KEYCLOAK_CLIENT_ID},
                headers=self.headers
            )
            self.client_uuid = response.json()[0]['id']
            print(f"✅ Created client: {KEYCLOAK_CLIENT_ID} (UUID: {self.client_uuid})")
            # Verify token exchange is enabled
            self._verify_token_exchange_enabled()
            return True
        else:
            print(f"❌ Failed to create client: {response.status_code}")
            if response.content:
                print(f"   Error: {response.text}")
            return False

    def _verify_token_exchange_enabled(self) -> bool:
        """Verify that Token Exchange V2 is properly enabled for the client"""
        try:
            # Get client configuration
            response = requests.get(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}",
                headers=self.headers
            )
            
            if response.status_code == 200:
                client_config = response.json()
                
                # Check if token exchange is enabled
                attributes = client_config.get('attributes', {})
                token_exchange_enabled = attributes.get('token-exchange.grant.enabled', 'false')
                
                if token_exchange_enabled.lower() == 'true':
                    print(f"   ✅ Token Exchange V2 verified: attribute 'token-exchange.grant.enabled' = {token_exchange_enabled}")
                    print(f"   📋 Client is properly configured for RFC 8693 Standard Token Exchange")
                    return True
                else:
                    print(f"   ❌ Token Exchange V2 not enabled: attribute 'token-exchange.grant.enabled' = {token_exchange_enabled}")
                    print(f"   ⚠️  This client will NOT be able to perform token exchange")
                    return False
            else:
                print(f"   ⚠️ Could not verify token exchange status: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"   ⚠️ Error verifying token exchange: {e}")
            return False

    def create_client_scopes(self) -> bool:
        """Create custom client scopes for Token Exchange V2"""
        success = True
        
        # First create a special token-exchange scope (may be required for V2 in some cases)
        print("🔧 Creating token-exchange client scope...")
        token_exchange_scope = {
            "name": "token-exchange",
            "description": "Allows token exchange operations",
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": "true",
                "display.on.consent.screen": "true"
            }
        }
        
        response = requests.get(f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/client-scopes", headers=self.headers)
        existing_scopes = {scope['name'] for scope in response.json()}
        
        if "token-exchange" not in existing_scopes:
            response = requests.post(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/client-scopes",
                headers=self.headers,
                json=token_exchange_scope
            )
            
            if response.status_code == 201:
                print(f"✅ Created token-exchange client scope")
            else:
                print(f"❌ Failed to create token-exchange scope: {response.status_code}")
                if response.content:
                    print(f"   Error: {response.text}")
                success = False
        else:
            print(f"✅ Token-exchange client scope already exists")
        
        # Create application-specific scopes
        for scope_name, scope_config in SCOPE_DEFINITIONS.items():
            scope_payload = {
                "name": scope_name,
                "description": scope_config["description"],
                "protocol": "openid-connect",
                "attributes": {
                    "risk_level": scope_config["risk_level"],
                    "min_role": scope_config["min_role"]
                },
                "protocolMappers": []
            }
            
            # Check if scope exists
            response = requests.get(f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/client-scopes", headers=self.headers)
            existing_scopes = {scope['name'] for scope in response.json()}
            
            if scope_name in existing_scopes:
                print(f"✅ Client scope already exists: {scope_name}")
                continue
            
            # Create scope
            response = requests.post(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/client-scopes",
                headers=self.headers,
                json=scope_payload
            )
            
            if response.status_code == 201:
                print(f"✅ Created client scope: {scope_name}")
            else:
                print(f"❌ Failed to create client scope {scope_name}: {response.status_code}")
                if response.content:
                    print(f"   Error: {response.text}")
                success = False
        
        return success

    def assign_scopes_to_client(self) -> bool:
        """Assign all custom scopes as optional scopes to the client"""
        success = True
        
        # Get all client scopes
        response = requests.get(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/client-scopes",
            headers=self.headers
        )
        
        if response.status_code != 200:
            print(f"❌ Failed to get client scopes: {response.status_code}")
            return False
        
        all_scopes = response.json()
        scope_map = {scope['name']: scope['id'] for scope in all_scopes}
        
        # Assign token-exchange scope as optional (critical for V2)
        if "token-exchange" in scope_map:
            scope_uuid = scope_map["token-exchange"]
            response = requests.put(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/optional-client-scopes/{scope_uuid}",
                headers=self.headers
            )
            
            if response.status_code == 204:
                print(f"✅ Assigned token-exchange scope to client")
            else:
                print(f"❌ Failed to assign token-exchange scope: {response.status_code}")
                success = False
        
        # Assign application-specific scopes
        for scope_name in SCOPE_DEFINITIONS.keys():
            if scope_name not in scope_map:
                print(f"❌ Scope not found: {scope_name}")
                success = False
                continue
            
            scope_uuid = scope_map[scope_name]
            
            # Assign as optional scope (users can request via token exchange)
            response = requests.put(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/optional-client-scopes/{scope_uuid}",
                headers=self.headers
            )
            
            if response.status_code == 204:
                print(f"✅ Assigned optional scope to client: {scope_name}")
            else:
                print(f"❌ Failed to assign scope {scope_name}: {response.status_code}")
                success = False
        
        return success
    
    def assign_client_roles_to_scopes(self) -> bool:
        """Assign roles to client scopes"""
        success = True

        # Get all client scopes
        response = requests.get(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/client-scopes",
            headers=self.headers
        )
        
        if response.status_code != 200:
            print(f"❌ Failed to get client scopes: {response.status_code}")
            return False
        
        all_scopes = response.json()
        scope_map = {scope['name']: scope['id'] for scope in all_scopes}

        for scope_name, scope_config in SCOPE_DEFINITIONS.items():
        
            if scope_name not in scope_map:
                print(f"❌ Scope not found: {scope_name}")
                success = False
                continue
        
            scope_uuid = scope_map[scope_name]

            for role_name, role_config in ROLE_DEFINITIONS.items():
                if scope_name in role_config['scopes']:
                    print(f"🔗 Assigning role '{role_name}' to scope '{scope_name}'")

                    # Get the actual role ID
                    role_id = self.get_client_role_id(role_name)
                    if not role_id:
                        print(f"❌ Could not find role ID for {role_name}")
                        success = False
                        continue

                    role_payload = [{
                        "id": role_id,
                        "name": role_name
                    }]

                    # Assign role to client scope
                    response = requests.post(
                        f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/client-scopes/{scope_uuid}/scope-mappings/clients/{self.client_uuid}",
                        headers=self.headers,
                        json=role_payload
                    )
                
                    if response.status_code == 204:
                        print(f"✅ Assigned role to {role_name} to client scope {scope_name}")
                    else:
                        print(f"❌ Failed to assign role to {role_name} to client scope {scope_name}: {response.status_code}")
                        success = False

        return success

    def add_self_audience_mapper(self) -> bool:
        """Add audience protocol mapper to ensure client appears in its own token aud claim"""
        print("🎯 Adding self-audience and sub claim protocol mappers...")
        
        # This mapper ensures that tokens issued to this client include the client itself in the aud claim
        # This is CRITICAL for Token Exchange V2 to work
        audience_mapper = {
            "name": "self-audience-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "consentRequired": False,
            "config": {
                "included.client.audience": KEYCLOAK_CLIENT_ID,  # Include this client in aud claim
                "id.token.claim": "false",
                "access.token.claim": "true"  # Add to access token aud claim
            }
        }
        
        # Add sub claim mapper to include 'sub' claim (standard JWT)
        sub_claim_mapper = {
            "name": "sub-claim-mapper",
            "protocol": "openid-connect", 
            "protocolMapper": "oidc-usermodel-property-mapper",
            "consentRequired": False,
            "config": {
                "userinfo.token.claim": "true",
                "user.attribute": "username",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "claim.name": "sub",
                "jsonType.label": "String"
            }
        }
        
        # Check if mappers already exist
        response = requests.get(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/protocol-mappers/models",
            headers=self.headers
        )
        
        existing_mappers = set()
        if response.status_code == 200:
            existing_mappers = {mapper['name'] for mapper in response.json()}
        
        success = True
        
        # Create audience mapper
        if "self-audience-mapper" not in existing_mappers:
            response = requests.post(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/protocol-mappers/models",
                headers=self.headers,
                json=audience_mapper
            )
            
            if response.status_code == 201:
                print(f"✅ Added self-audience protocol mapper")
            else:
                print(f"❌ Failed to add self-audience mapper: {response.status_code}")
                if response.content:
                    print(f"   Error: {response.text}")
                success = False
        else:
            print(f"✅ Self-audience mapper already exists")
        
        # Create sub claim mapper
        if "sub-claim-mapper" not in existing_mappers:
            response = requests.post(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/protocol-mappers/models",
                headers=self.headers,
                json=sub_claim_mapper
            )
            
            if response.status_code == 201:
                print(f"✅ Added sub claim protocol mapper")
                print(f"   This ensures tokens include 'sub' claim for standard JWT compliance")
            else:
                print(f"❌ Failed to add sub claim mapper: {response.status_code}")
                if response.content:
                    print(f"   Error: {response.text}")
                success = False
        else:
            print(f"✅ Sub claim mapper already exists")
        
        if success:
            print(f"✅ Protocol mappers configured for Token Exchange V2 compliance")
            
        return success

    def create_client_roles(self) -> bool:
        """Create client roles for role-based access control"""
        success = True
        
        for role_name, role_config in ROLE_DEFINITIONS.items():
            role_payload = {
                "name": role_name,
                "description": role_config["description"],
                "attributes": {
                    "available_scopes": role_config["scopes"]
                }
            }
            
            # Check if role exists
            response = requests.get(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/roles/{role_name}",
                headers=self.headers
            )
            
            if response.status_code == 200:
                print(f"✅ Client role already exists: {role_name}")
                continue
            
            # Create role
            response = requests.post(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/roles",
                headers=self.headers,
                json=role_payload
            )
            
            if response.status_code == 201:
                print(f"✅ Created client role: {role_name}")
            else:
                print(f"❌ Failed to create client role {role_name}: {response.status_code}")
                if response.content:
                    print(f"   Error: {response.text}")
                success = False
        
        return success

    def cleanup_old_scopes(self) -> bool:
        """Clean up old scopes that are no longer needed"""
        print("🧹 Cleaning up old scopes...")
        
        old_scopes_to_remove = [
            "llama:agent_create",
            "llama:agent_session_create", 
            "llama:inference_chat_completion"
        ]
        
        for scope_name in old_scopes_to_remove:
            # Remove from client scopes
            try:
                response = requests.delete(
                    f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/client-scopes/{scope_name}",
                    headers=self.headers
                )
                if response.status_code == 204:
                    print(f"✅ Removed client scope: {scope_name}")
                elif response.status_code == 404:
                    print(f"⚠️ Client scope not found: {scope_name}")
                else:
                    print(f"⚠️ Failed to remove client scope {scope_name}: {response.status_code}")
            except Exception as e:
                print(f"⚠️ Error removing client scope {scope_name}: {e}")
            
            # Remove from authorization scopes
            try:
                response = requests.delete(
                    f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/scope/{scope_name}",
                    headers=self.headers
                )
                if response.status_code == 204:
                    print(f"✅ Removed authorization scope: {scope_name}")
                elif response.status_code == 404:
                    print(f"⚠️ Authorization scope not found: {scope_name}")
                else:
                    print(f"⚠️ Failed to remove authorization scope {scope_name}: {response.status_code}")
            except Exception as e:
                print(f"⚠️ Error removing authorization scope {scope_name}: {e}")
        
        print("✅ Old scopes cleanup completed")
        return True

    def create_authorization_scopes(self) -> bool:
        """Create authorization scopes for fine-grained access control"""
        success = True
        
        for scope_name, scope_config in SCOPE_DEFINITIONS.items():
            auth_scope_config = {
                "name": scope_name,
                "displayName": f"{scope_name} Authorization Scope",
                "iconUri": ""
            }
            
            # Check if authorization scope exists
            response = requests.get(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/scope",
                headers=self.headers
            )
            
            if response.status_code == 200:
                existing_auth_scopes = {scope['name'] for scope in response.json()}
                if scope_name in existing_auth_scopes:
                    print(f"✅ Authorization scope already exists: {scope_name}")
                    continue
            
            # Create authorization scope
            response = requests.post(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/scope",
                headers=self.headers,
                json=auth_scope_config
            )
            
            if response.status_code in [201, 409]:
                print(f"✅ Authorization scope created: {scope_name}")
            else:
                print(f"❌ Failed to create authorization scope {scope_name}: {response.status_code}")
                if response.content:
                    print(f"   Error: {response.text}")
                success = False
        
        return success

    def create_authorization_resources(self) -> bool:
        """Create authorization resources for fine-grained access control"""
        success = True
        
        # Create a single resource that represents all scopes
        resource_config = {
            "name": "Application Resource",
            "displayName": "Application Resource",
            "type": "urn:application:resources:default",
            "scopes": list(SCOPE_DEFINITIONS.keys()),
            "attributes": {},
            "uris": ["/api/*"]
        }
        
        # Check if resource exists
        response = requests.get(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/resource",
            headers=self.headers
        )
        
        if response.status_code == 200:
            existing_resources = {res['name'] for res in response.json()}
            if "Application Resource" in existing_resources:
                print(f"✅ Authorization resource already exists: Application Resource")
                return success
        
        # Create the resource
        response = requests.post(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/resource",
            headers=self.headers,
            json=resource_config
        )
        
        if response.status_code in [201, 409]:
            print(f"✅ Authorization resource created: Application Resource")
        else:
            print(f"❌ Failed to create authorization resource: {response.status_code}")
            if response.content:
                print(f"   Error: {response.text}")
            success = False
        
        return success

    def get_client_role_id(self, role_name: str) -> Optional[str]:
        """Get the ID of a client role by name"""
        response = requests.get(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/roles/{role_name}",
            headers=self.headers
        )
        
        if response.status_code == 200:
            role_data = response.json()
            return role_data.get('id')
        else:
            print(f"❌ Failed to get role ID for {role_name}: {response.status_code}")
            return None

    def create_authorization_policies(self) -> bool:
        """Create role-based authorization policies"""
        success = True
        
        for role_name in ROLE_DEFINITIONS.keys():
            # Get the actual role ID
            role_id = self.get_client_role_id(role_name)
            if not role_id:
                print(f"❌ Could not find role ID for {role_name}")
                success = False
                continue
            
            # Create role-based policy
            policy_config = {
                "name": f"{role_name}_policy",
                "description": f"Policy for {role_name} role",
                "type": "role",
                "logic": "POSITIVE",
                "decisionStrategy": "UNANIMOUS",
                "roles": [
                    {
                        "id": role_id,  # Use actual role ID instead of role name
                        "required": False
                    }
                ]
            }
            
            # Check if policy exists
            response = requests.get(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/policy",
                headers=self.headers
            )
            
            if response.status_code == 200:
                existing_policies = {policy['name'] for policy in response.json()}
                if policy_config['name'] in existing_policies:
                    print(f"✅ Authorization policy already exists: {policy_config['name']}")
                    continue
            
            # Create policy
            response = requests.post(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/policy/role",
                headers=self.headers,
                json=policy_config
            )
            
            if response.status_code in [201, 409]:
                print(f"✅ Authorization policy created: {policy_config['name']} (assigned to role ID: {role_id})")
            else:
                print(f"❌ Failed to create authorization policy {policy_config['name']}: {response.status_code}")
                if response.content:
                    print(f"   Error: {response.text}")
                success = False
        
        return success

    def create_scope_permissions(self) -> bool:
        """Create scope-based permissions linking roles to scopes"""
        success = True
        
        # Get all authorization scopes
        scopes_response = requests.get(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/scope",
            headers=self.headers
        )
        
        if scopes_response.status_code != 200:
            print(f"❌ Failed to get authorization scopes: {scopes_response.status_code}")
            return False
        
        auth_scopes = {scope['name']: scope['id'] for scope in scopes_response.json()}
        
        # Get all policies
        policies_response = requests.get(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/policy",
            headers=self.headers
        )
        
        if policies_response.status_code != 200:
            print(f"❌ Failed to get authorization policies: {policies_response.status_code}")
            return False
        
        policies = {policy['name']: policy['id'] for policy in policies_response.json()}
        
        # Create permissions for each scope based on role requirements
        for scope_name, scope_config in SCOPE_DEFINITIONS.items():
            min_role = scope_config["min_role"]
            
            # Determine which policies should apply to this scope
            applicable_policies = []
            if min_role == "user":
                # Both user and admin can access
                applicable_policies = [policies.get("user_policy"), policies.get("admin_policy")]
                print(f"🔍 Scope {scope_name} (min_role: {min_role}) -> allowing user_policy + admin_policy")
            elif min_role == "admin":
                # Only admin can access
                applicable_policies = [policies.get("admin_policy")]
                print(f"🔍 Scope {scope_name} (min_role: {min_role}) -> allowing admin_policy ONLY")
            
            # Filter out None values
            applicable_policies = [p for p in applicable_policies if p is not None]
            
            if not applicable_policies:
                print(f"❌ No applicable policies found for scope: {scope_name}")
                success = False
                continue
            
            print(f"   📋 Policies assigned to {scope_name}: {applicable_policies}")
            
            # Get the application resource ID
            resource_response = requests.get(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/resource",
                headers=self.headers
            )
            
            resource_id = None
            if resource_response.status_code == 200:
                resources = resource_response.json()
                for resource in resources:
                    if resource['name'] == 'Application Resource':
                        resource_id = resource['_id']
                        break
            
            if not resource_id:
                print(f"❌ Could not find Application Resource for scope: {scope_name}")
                success = False
                continue

            permission_config = {
                "name": f"{scope_name}_permission",
                "description": f"Permission for {scope_name} scope (min_role: {min_role})",
                "type": "scope",
                "logic": "POSITIVE",
                "decisionStrategy": "AFFIRMATIVE",
                "resources": [resource_id],  # Link to the resource
                "scopes": [auth_scopes[scope_name]],
                "policies": applicable_policies
            }
            
            # Check if permission exists and potentially update it
            permissions_response = requests.get(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/permission",
                headers=self.headers
            )
            
            existing_permission = None
            if permissions_response.status_code == 200:
                for perm in permissions_response.json():
                    if perm['name'] == permission_config['name']:
                        existing_permission = perm
                        break
            
            if existing_permission:
                # Update existing permission to ensure correct policies
                print(f"🔄 Updating existing permission: {permission_config['name']}")
                response = requests.put(
                    f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/permission/scope/{existing_permission['id']}",
                    headers=self.headers,
                    json=permission_config
                )
                
                if response.status_code in [200, 201, 204]:
                    print(f"✅ Scope permission updated: {permission_config['name']}")
                else:
                    print(f"❌ Failed to update permission {permission_config['name']}: {response.status_code}")
                    if response.content:
                        print(f"   Error: {response.text}")
                    success = False
            else:
                # Create new permission
                response = requests.post(
                    f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/permission/scope",
                    headers=self.headers,
                    json=permission_config
                )
                
                if response.status_code in [201, 409]:
                    print(f"✅ Scope permission created: {permission_config['name']}")
                else:
                    print(f"❌ Failed to create scope permission {permission_config['name']}: {response.status_code}")
                    if response.content:
                        print(f"   Error: {response.text}")
                    success = False
        
        return success

    def create_users(self) -> bool:
        """Create users with proper role assignments"""
        success = True
        
        for user_def in USER_DEFINITIONS:
            # Create user
            user_config = {
                "username": user_def["username"],
                "email": user_def["email"],
                "firstName": user_def["first_name"],
                "lastName": user_def["last_name"],
                "enabled": True,
                "emailVerified": True,
                "attributes": {}
            }
            
            # Check if user exists
            response = requests.get(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/users",
                params={"username": user_def["username"]},
                headers=self.headers
            )
            
            if response.status_code == 200 and response.json():
                user_uuid = response.json()[0]['id']
                print(f"✅ User {user_def['username']} already exists")
            else:
                # Create user
                response = requests.post(
                    f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/users",
                    headers=self.headers,
                    json=user_config
                )
                
                if response.status_code != 201:
                    print(f"❌ Failed to create user {user_def['username']}: {response.status_code}")
                    if response.content:
                        print(f"   Error: {response.text}")
                    success = False
                    continue
                
                print(f"✅ Created user: {user_def['username']}")
                
                # Get user UUID
                response = requests.get(
                    f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/users",
                    params={"username": user_def["username"]},
                    headers=self.headers
                )
                
                if response.status_code != 200 or not response.json():
                    print(f"❌ Failed to get user {user_def['username']} after creation")
                    success = False
                    continue
                
                user_uuid = response.json()[0]['id']
            
            # Set password
            password_config = {
                "type": "password",
                "value": user_def["password"],
                "temporary": False
            }
            
            response = requests.put(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/users/{user_uuid}/reset-password",
                headers=self.headers,
                json=password_config
            )
            
            if response.status_code == 204:
                print(f"✅ Set password for {user_def['username']}")
            else:
                print(f"❌ Failed to set password for {user_def['username']}: {response.status_code}")
                success = False
            
            # Assign client roles
            if not self.assign_client_roles_to_user(user_def["username"], user_uuid, user_def["roles"]):
                success = False
        
        return success

    def assign_client_roles_to_user(self, username: str, user_uuid: str, role_names: List[str]) -> bool:
        """Assign client roles to a user"""
        success = True
        
        # Get client roles
        roles_resp = requests.get(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/roles",
            headers=self.headers
        )
        
        if roles_resp.status_code != 200:
            print(f"❌ Failed to get client roles: {roles_resp.status_code}")
            return False

        role_map = {role['name']: role for role in roles_resp.json()}
        
        roles_to_assign = []
        for role_name in role_names:
            if role_name in role_map:
                roles_to_assign.append(role_map[role_name])
            else:
                print(f"❌ Role not found: {role_name}")
                success = False
        
        if roles_to_assign:
            response = requests.post(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/users/{user_uuid}/role-mappings/clients/{self.client_uuid}",
                headers=self.headers,
                json=roles_to_assign
            )
            
            if response.status_code == 204:
                print(f"✅ Assigned roles to {username}: {[r['name'] for r in roles_to_assign]}")
            else:
                print(f"❌ Failed to assign roles to {username}: {response.status_code}")
                success = False
        
        return success

    def wait_for_manual_token_exchange_setup(self) -> bool:
        """Wait for user to manually enable Token Exchange V2 in Keycloak Admin UI"""
        print("\n⏸️  Manual Token Exchange Setup Required")
        print("=" * 50)
        print("🔧 Please enable Standard Token Exchange manually in Keycloak Admin UI:")
        print()
        print("1. Open Keycloak Admin Console: ${KEYCLOAK_URL}/admin")
        print("2. Login with admin credentials")
        print("3. Navigate to: Clients → authentication-demo → Settings")
        print("4. Scroll down to 'Capability config' section")
        print("5. Enable 'Standard token exchange' (toggle switch)")
        print("6. Click 'Save'")
        print()
        print("📋 Quick Navigation:")
        print(f"   • Realm: {KEYCLOAK_REALM_NAME}")
        print(f"   • Client ID: {KEYCLOAK_CLIENT_ID}")
        print("   • Setting: Standard token exchange (Capability config)")
        print()
        print("💡 This step is required because enabling token exchange via REST API")
        print("   can be unreliable in some Keycloak versions.")
        print()
        
        while True:
            user_input = input("✅ Press ENTER when you've enabled Standard Token Exchange (or 'q' to quit): ").strip().lower()
            
            if user_input == 'q':
                print("❌ Setup cancelled by user")
                return False
            elif user_input == '':
                 # Skip attribute verification since it's unreliable
                 # The real test will be in the actual token exchange step
                 print("✅ Proceeding to token exchange test...")
                 print("   (We'll verify token exchange works in the next step)")
                 return True
            else:
                print("❌ Invalid input. Press ENTER to continue or 'q' to quit.")

    def test_token_exchange_setup(self) -> bool:
        """Test the Token Exchange V2 setup with actual token exchange"""
        print("\n🧪 Testing Token Exchange V2 Setup...")
        print("   This test validates that Standard Token Exchange (RFC 8693) is working")
        
        # Test user authentication
        try:
            auth_response = requests.post(
                f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM_NAME}/protocol/openid-connect/token",
                data={
                    'grant_type': 'password',
                    'client_id': KEYCLOAK_CLIENT_ID,
                    'client_secret': KEYCLOAK_CLIENT_SECRET,
                    'username': 'lance',
                    'password': 'password',
                    'scope': 'openid profile email'
                }
            )
            
            if auth_response.status_code == 200:
                user_token = auth_response.json()['access_token']
                print("✅ User authentication successful")
                
                # Test token exchange for MCP scopes (Token Exchange V2 self-exchange pattern)
                print("   🔄 Testing token exchange: basic token -> scoped token")
                exchange_response = requests.post(
                    f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM_NAME}/protocol/openid-connect/token",
                    data={
                        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                        'subject_token': user_token,
                        'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
                        'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token',
                        'audience': KEYCLOAK_CLIENT_ID,
                        'scope': 'mcp:list_files mcp:health_check'
                    },
                    headers={
                        'Authorization': f'Basic {base64.b64encode(f"{KEYCLOAK_CLIENT_ID}:{KEYCLOAK_CLIENT_SECRET}".encode()).decode()}',
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                )
                
                if exchange_response.status_code == 200:
                    print("✅ Token exchange successful")
                    exchange_result = exchange_response.json()
                    print(f"   Granted scopes: {exchange_result.get('scope', 'N/A')}")
                    return True
                else:
                    print(f"❌ Token exchange failed: {exchange_response.status_code}")
                    try:
                        error_details = exchange_response.json()
                        print(f"   Error Type: {error_details.get('error', 'unknown')}")
                        print(f"   Description: {error_details.get('error_description', 'No description')}")
                        
                        # Common Token Exchange V2 issues
                        if 'audience not available' in exchange_response.text.lower():
                            print("   💡 SOLUTION: Client needs to be able to request itself as audience")
                            print("      Check if self-audience mapper is configured correctly")
                        elif 'not enabled for the requested client' in exchange_response.text.lower():
                            print("   💡 SOLUTION: Enable 'Standard token exchange' in client settings")
                            print("      Client attribute: token-exchange.grant.enabled = true")
                        elif 'invalid scopes' in exchange_response.text.lower():
                            print("   💡 INFO: This may be expected if testing invalid scope rejection")
                        
                    except:
                        print(f"   Raw Error: {exchange_response.text}")
                    return False
            else:
                print(f"❌ User authentication failed: {auth_response.status_code}")
                print(f"   Error: {auth_response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            return False

    def debug_user_roles_and_permissions(self) -> bool:
        """Debug function to check user role assignments and scope permissions"""
        print("\n🔍 DEBUG: User Roles and Permission Analysis")
        print("=" * 60)
        
        # Check each user's role assignments
        for user_def in USER_DEFINITIONS:
            username = user_def["username"]
            expected_roles = user_def["roles"]
            
            print(f"\n👤 User: {username}")
            print(f"   Expected roles: {expected_roles}")
            
            # Get user ID
            user_response = requests.get(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/users",
                headers=self.headers,
                params={"username": username}
            )
            
            if user_response.status_code != 200 or not user_response.json():
                print(f"   ❌ User not found")
                continue
                
            user_id = user_response.json()[0]['id']
            
            # Get actual client role assignments
            roles_response = requests.get(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/users/{user_id}/role-mappings/clients/{self.client_uuid}",
                headers=self.headers
            )
            
            if roles_response.status_code == 200:
                actual_roles = [role['name'] for role in roles_response.json()]
                print(f"   Actual roles: {actual_roles}")
                
                # Check if roles match expectations
                if set(actual_roles) == set(expected_roles):
                    print(f"   ✅ Role assignment correct")
                else:
                    print(f"   ❌ Role mismatch!")
                    print(f"      Missing: {set(expected_roles) - set(actual_roles)}")
                    print(f"      Extra: {set(actual_roles) - set(expected_roles)}")
            else:
                print(f"   ❌ Could not get roles: {roles_response.status_code}")
        
        # Check permission configurations for admin-only scopes
        print(f"\n🔒 Admin-Only Scope Permission Analysis")
        print("-" * 40)
        
        admin_only_scopes = [name for name, config in SCOPE_DEFINITIONS.items() 
                           if config.get("min_role") == "admin"]
        
        if not admin_only_scopes:
            print("   No admin-only scopes found")
            return True
            
        # Get all permissions
        permissions_response = requests.get(
            f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/permission",
            headers=self.headers
        )
        
        if permissions_response.status_code != 200:
            print("   ❌ Could not get permissions")
            return False
        
        permissions = permissions_response.json()
        
        for scope_name in admin_only_scopes:
            permission_name = f"{scope_name}_permission"
            permission = next((p for p in permissions if p['name'] == permission_name), None)
            
            if not permission:
                print(f"   ❌ Permission not found: {permission_name}")
                continue
                
            print(f"   🔍 {scope_name}:")
            print(f"      Permission ID: {permission['id']}")
            print(f"      Policies: {permission.get('policies', [])}")
            
            # Get detailed permission info
            detail_response = requests.get(
                f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/permission/scope/{permission['id']}",
                headers=self.headers
            )
            
            if detail_response.status_code == 200:
                detail = detail_response.json()
                policy_ids = detail.get('policies', [])
                print(f"      Policy IDs: {policy_ids}")
                
                # Expected: should only have admin_policy for admin-only scopes
                expected_policies = ["admin_policy"]
                print(f"      Expected policies: {expected_policies}")
                
                # Get policy names for these IDs
                policies_response = requests.get(
                    f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM_NAME}/clients/{self.client_uuid}/authz/resource-server/policy",
                    headers=self.headers
                )
                
                if policies_response.status_code == 200:
                    all_policies = {p['id']: p['name'] for p in policies_response.json()}
                    actual_policy_names = [all_policies.get(pid, f"Unknown({pid})") for pid in policy_ids]
                    print(f"      Actual policy names: {actual_policy_names}")
                    
                    if set(actual_policy_names) == set(expected_policies):
                        print(f"      ✅ Correct policies assigned")
                    else:
                        print(f"      ❌ INCORRECT policies! Should only have admin_policy")
            else:
                print(f"      ❌ Could not get permission details")
        
        return True

    def run_complete_setup(self) -> bool:
        """Run the complete Token Exchange V2 setup"""
        print("🚀 Keycloak Token Exchange V2 - Complete Setup")
        print("=" * 60)
        
        steps = [
            ("🔄 Wait for Keycloak", self.wait_for_keycloak),
            ("🔑 Get admin token", self.get_admin_token),
            ("📋 Create realm", self.create_realm),
            ("🏢 Create client", self.create_client),
            ("🎯 Add self-audience mapper", self.add_self_audience_mapper),
            ("👥 Create client roles", self.create_client_roles),
            ("🧹 Clean up old scopes", self.cleanup_old_scopes),
            ("🎯 Create client scopes", self.create_client_scopes),
            ("👥 Assign client roles to scopes", self.assign_client_roles_to_scopes),
            ("🔗 Assign scopes to client", self.assign_scopes_to_client),
            ("🔐 Create authorization scopes", self.create_authorization_scopes),
            ("📦 Create authorization resources", self.create_authorization_resources),
            ("📜 Create authorization policies", self.create_authorization_policies),
            ("🛡️ Create scope permissions", self.create_scope_permissions),
            ("👤 Create users", self.create_users),
            ("🔍 Debug roles and permissions", self.debug_user_roles_and_permissions),
            # ("⏸️ Manual token exchange setup", self.wait_for_manual_token_exchange_setup),
            ("🧪 Test setup", self.test_token_exchange_setup)
        ]
        
        for step_name, step_func in steps:
            print(f"\n{step_name}")
            print("-" * 40)
            if not step_func():
                print(f"❌ Failed at step: {step_name}")
                return False
        
        print(f"\n🎉 Token Exchange V2 Setup Complete!")
        print("=" * 60)
        print("✅ Realm configured with Token Exchange V2")
        print("✅ Confidential client created with authorization services")
        print("✅ Custom scopes created with proper prefixes")
        print("✅ Role-based authorization policies configured")
        print("✅ Scope permissions created for fine-grained access")
        print("✅ Users created with appropriate role assignments")
        print("✅ Token exchange functionality tested successfully")
        print()
        print("📝 Configuration Summary:")
        print(f"   • Realm: {KEYCLOAK_REALM_NAME}")
        print(f"   • Client: {KEYCLOAK_CLIENT_ID}")
        print(f"   • Scopes: {len(SCOPE_DEFINITIONS)} custom scopes")
        print(f"   • Roles: {len(ROLE_DEFINITIONS)} client roles")
        print(f"   • Users: {len(USER_DEFINITIONS)} test users")
        print()
        print("🔄 Token Exchange V2 Flow:")
        print("   1. User authenticates → minimal token (openid, profile, email)")
        print("   2. Service access needed → token exchange request")
        print("   3. Keycloak validates role → grants appropriate scopes")
        print("   4. Service validates token → access granted/denied")
        print()
        print("🧪 Test your setup:")
        print("   python scripts/test_keycloak_config.py")
        
        # Print configuration for environment variables
        print()
        print("🔧 Environment Configuration")
        print("=" * 60)
        print("Copy these values to your .env files:")
        print()
        print("Frontend (.env or config file):")
        print(f"OIDC_ISSUER_URL={KEYCLOAK_URL}/realms/{KEYCLOAK_REALM_NAME}")
        print(f"OIDC_CLIENT_ID={KEYCLOAK_CLIENT_ID}")
        print(f"OIDC_CLIENT_SECRET={KEYCLOAK_CLIENT_SECRET}")
        print()
        print("Chat UI specific:")
        print("CHAT_UI_PORT=5001")
        print("CHAT_UI_HOST=0.0.0.0")
        print("LLAMA_STACK_URL=http://localhost:8321")
        print()
        print("Flask:")
        print("FLASK_SECRET_KEY=your-secret-key-here")
        print("FLASK_ENV=development")
        print()
        print("⚠️  SECURITY NOTE:")
        print(f"   Client secret '{KEYCLOAK_CLIENT_SECRET}' is for demo only!")
        print("   Change this in production environments.")
        
        return True

def main():
    """Main setup function"""
    setup = KeycloakV2Setup()
    success = setup.run_complete_setup()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 