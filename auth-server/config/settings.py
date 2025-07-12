"""
Configuration settings for the auth server
"""

import os

# Server Configuration
SERVER_NAME = "unified-auth-server"
SERVER_VERSION = "3.0.0"
SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8002"))
SERVER_URI = f"http://{SERVER_HOST}:{SERVER_PORT}"

# Google OAuth 2.0 Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "your-google-client-id")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "your-google-client-secret")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
GOOGLE_ISSUER = "https://accounts.google.com"
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

# Keycloak Configuration
KEYCLOAK_HOST = os.getenv("KEYCLOAK_HOST", "https://localhost:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "master")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "kubernetes")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "")

# Kubernetes Configuration
KUBE_API_SERVER = os.getenv("KUBE_API_SERVER", "https://localhost:6443")
KUBE_CA_CERT = os.getenv("KUBE_CA_CERT", "") 

JWT_SECRET = os.getenv("JWT_SECRET", "demo-secret-key-change-in-production") 