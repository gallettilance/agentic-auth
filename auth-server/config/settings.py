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