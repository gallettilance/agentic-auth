"""
Configuration settings for the auth server
"""

import os
from urllib.parse import urljoin

# Server Configuration
SERVER_NAME = "unified-auth-server"
SERVER_VERSION = "3.0.0"
SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8002"))
SERVER_URI = f"http://{SERVER_HOST}:{SERVER_PORT}"

# OIDC Configuration
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "your-oidc-client-id")
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "your-oidc-client-secret")
OIDC_ISSUER_URL = os.getenv("OIDC_ISSUER_URL", "your-oidc-issuer-url")
OIDC_DISCOVERY_URL = f"{OIDC_ISSUER_URL}/.well-known/openid-configuration"
REDIRECT_URI = f"{SERVER_URI}/auth/callback"

# Session management
COOKIE_NAME = "auth_session"
COOKIE_MAX_AGE = 3600  # 1 hour

# JWT Configuration - asymmetric only for security
PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "keys/private_key.pem")
JWKS_PATH = os.getenv("JWKS_PATH", "keys/jwks.json")
KID = None  # Key ID for asymmetric mode - loaded from keys/kid.txt

# Database path
DB_PATH = os.getenv("AUTH_DB_PATH", "auth.db") 