import jwt
import requests
import os
from datetime import datetime, timedelta

# Get configuration from environment or use defaults
KEYCLOAK_HOST = os.getenv("KEYCLOAK_HOST", "http://localhost:8080")  # Default to HTTP
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "master")
JWT_SECRET = os.getenv("JWT_SECRET", "demo-secret-key-change-in-production")

def create_jwt_token(payload, expires_in=3600):
    """Create JWT token with the given payload"""
    now = datetime.utcnow()
    
    # Standard JWT claims
    jwt_payload = {
        "iss": "http://localhost:8002",  # Auth server as issuer
        "aud": "http://localhost:8001",  # MCP server as audience
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
        **payload  # Add the custom payload
    }
    
    # Create and return the JWT token
    token = jwt.encode(jwt_payload, JWT_SECRET, algorithm="HS256")
    return token

def verify_keycloak_token(keycloak_token):
    """Verify Keycloak OIDC token and extract user info"""
    try:
        # Get Keycloak's public keys - use HTTP and disable SSL verification
        jwks_url = f"{KEYCLOAK_HOST}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
        print(f"Fetching JWKS from: {jwks_url}")  # Debug output
        
        response = requests.get(jwks_url, verify=False, timeout=10)
        response.raise_for_status()
        jwks = response.json()
        
        # Decode token (simplified - in production, properly verify with JWKS)
        unverified_payload = jwt.decode(keycloak_token, options={"verify_signature": False})
        
        # Extract user information
        user_info = {
            "sub": unverified_payload.get("sub"),
            "email": unverified_payload.get("email"),
            "preferred_username": unverified_payload.get("preferred_username"),
            "groups": unverified_payload.get("groups", []),
            "realm_access": unverified_payload.get("realm_access", {})
        }
        
        return user_info
    except Exception as e:
        raise Exception(f"Invalid Keycloak token: {str(e)}")

def convert_keycloak_to_jwt(keycloak_token, requested_scopes=None):
    """Convert Keycloak token to internal JWT with appropriate scopes"""
    user_info = verify_keycloak_token(keycloak_token)
    
    # Map Keycloak roles/groups to internal scopes
    scopes = map_keycloak_roles_to_scopes(user_info, requested_scopes)
    
    # Create internal JWT token
    payload = {
        "sub": user_info["email"],
        "email": user_info["email"],
        "scope": " ".join(scopes),
        "keycloak_user": user_info["preferred_username"],
        "groups": user_info["groups"]
    }
    
    return create_jwt_token(payload)

def map_keycloak_roles_to_scopes(user_info, requested_scopes=None):
    """Map Keycloak roles to internal scopes"""
    scopes = ["basic"]  # Default scope
    
    realm_roles = user_info.get("realm_access", {}).get("roles", [])
    groups = user_info.get("groups", [])
    
    # Map roles to scopes
    if "admin" in realm_roles or "admin" in groups:
        scopes.extend(["read:files", "execute:commands", "kubectl:read", "kubectl:write", "kubectl:admin"])
    elif "developer" in realm_roles or "developers" in groups:
        scopes.extend(["read:files", "execute:commands", "kubectl:read", "kubectl:write"])
    elif "viewer" in realm_roles or "viewers" in groups:
        scopes.extend(["read:files", "kubectl:read"])
    
    # Filter by requested scopes if provided
    if requested_scopes:
        scopes = [s for s in scopes if s in requested_scopes]
    
    return scopes 