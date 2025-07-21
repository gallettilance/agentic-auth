#!/usr/bin/env python3
"""
Refactored Production-Grade Unified Authentication & Authorization Server
Modular architecture with separated concerns
"""

import logging
import signal
import atexit
import sys
import uvicorn
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

# Import configuration
from config.settings import SERVER_NAME, SERVER_VERSION, SERVER_HOST, SERVER_PORT, DB_PATH

# Import utilities
from utils import jwt_utils
from auth.oauth_utils import load_oidc_config
from database import auth_db

# Import route modules
from api.auth_routes import router as auth_router
from api.api_routes import router as api_router

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(title=SERVER_NAME, version=SERVER_VERSION)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handling
class AuthorizationError(Exception):
    def __init__(self, status_code: int, detail: str, headers: Optional[dict] = None):
        self.status_code = status_code
        self.detail = detail
        self.headers = headers or {}

@app.exception_handler(AuthorizationError)
async def authorization_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers
    )

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize the server on startup"""
    logger.info(f"🚀 Starting {SERVER_NAME} v{SERVER_VERSION}")
    
    # Initialize database
    logger.info("📊 Initializing database...")
    auth_db.db_path = DB_PATH
    auth_db.init_database()
    
    # Load or generate JWT keys
    logger.info("🔑 Loading JWT keys...")
    if not jwt_utils.auto_generate_keys():
        logger.error("❌ Failed to load JWT keys")
        sys.exit(1)
    
    # Load OIDC configuration
    logger.info("🔐 Loading OIDC configuration...")
    if not await load_oidc_config():
        logger.error("❌ Failed to load OIDC configuration")
        sys.exit(1)
    
    # Initialize admin user if configured
    import os
    admin_email = os.getenv("ADMIN_EMAIL")
    
    if admin_email:
        logger.info(f"🔧 ADMIN_EMAIL environment variable found: {admin_email}")
        logger.info(f"🔄 Ensuring admin user exists: {admin_email}")
        
        # Check if user already exists
        existing_user = auth_db.get_user(admin_email)
        if existing_user:
            if existing_user.is_admin:
                logger.info(f"✅ Admin user {admin_email} already exists with admin privileges")
            else:
                logger.info(f"🔄 User {admin_email} exists but is not admin - upgrading to admin")
                if auth_db.create_admin_user(admin_email, "startup_upgrade"):
                    logger.info(f"✅ Successfully upgraded {admin_email} to admin")
                else:
                    logger.error(f"❌ Failed to upgrade {admin_email} to admin")
        else:
            logger.info(f"👤 Creating new admin user: {admin_email}")
            if auth_db.create_admin_user(admin_email, "startup"):
                logger.info(f"✅ Successfully created admin user: {admin_email}")
                
                # Show helpful information for first-time setup
                logger.info("=" * 60)
                logger.info("🎉 ADMIN USER SETUP COMPLETE")
                logger.info("=" * 60)
                logger.info(f"👤 Admin Email: {admin_email}")
                logger.info(f"🌐 Admin Dashboard: http://{SERVER_HOST}:{SERVER_PORT}/dashboard")
                logger.info(f"🔐 Login URL: http://{SERVER_HOST}:{SERVER_PORT}/auth/login")
                logger.info("")
                logger.info("📋 Next Steps:")
                logger.info("1. Visit the login URL above")
                logger.info(f"2. Sign in with OIDC using: {admin_email}")
                logger.info("3. Access the admin dashboard to manage permissions")
                logger.info("=" * 60)
            else:
                logger.error(f"❌ Failed to create admin user: {admin_email}")
    else:
        logger.warning("⚠️  ADMIN_EMAIL environment variable not set")
        logger.warning("   No admin user will be created automatically")
        logger.warning("   Set ADMIN_EMAIL=your-email@gmail.com to configure an admin")
        logger.warning("   Or run: python init_admin.py --email your-email@gmail.com")
    
    logger.info("✅ Server initialization complete")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("🛑 Shutting down server...")

# Root endpoint
@app.get("/")
async def home():
    """Root endpoint - redirect to dashboard"""
    return RedirectResponse(url="/dashboard")

# Dashboard endpoint - redirect to admin dashboard frontend
@app.get("/dashboard")
async def dashboard():
    """Dashboard endpoint - redirect to admin dashboard frontend"""
    return RedirectResponse(url="http://localhost:8003/dashboard")

# Well-known endpoints
@app.get("/.well-known/jwks.json")
async def get_jwks():
    """Get JSON Web Key Set for token verification"""
    try:
        if jwt_utils.jwks_data:
            return jwt_utils.jwks_data
        else:
            raise HTTPException(status_code=500, detail="JWKS not available")
    except Exception as e:
        logger.error(f"❌ JWKS endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/.well-known/openid-configuration")
async def get_openid_configuration():
    """Get OpenID Connect Discovery information"""
    try:
        base_url = "http://localhost:8002"  # Should be configurable in production
        return {
            "issuer": base_url,
            "authorization_endpoint": f"{base_url}/auth/authorize",
            "token_endpoint": f"{base_url}/auth/token",
            "userinfo_endpoint": f"{base_url}/api/user-status",
            "jwks_uri": f"{base_url}/.well-known/jwks.json",
            "scopes_supported": ["openid", "profile", "email", "llama_stack", "admin"],
            "response_types_supported": ["code", "token", "id_token"],
            "grant_types_supported": ["authorization_code", "implicit"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"]
        }
    except Exception as e:
        logger.error(f"❌ OpenID configuration endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/.well-known/oauth-authorization-server")
async def oauth_server_metadata():
    """OAuth 2.0 Authorization Server Metadata"""
    from config.settings import SERVER_URI
    
    return {
        "issuer": SERVER_URI,
        "authorization_endpoint": f"{SERVER_URI}/auth/authorize",
        "token_endpoint": f"{SERVER_URI}/auth/token",
        "jwks_uri": f"{SERVER_URI}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ],
        "scopes_supported": [
            "list_files",
            "execute_command",
            "get_server_info",
            "health_check",
            "read_file",
            "write_file",
            "delete_file"
        ],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "code_challenge_methods_supported": ["S256"]
    }

# Include route modules
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])
app.include_router(api_router, prefix="/api", tags=["API"])

# Signal handlers for graceful shutdown
def signal_handler(signum, frame):
    logger.info(f"🛑 Received signal {signum}, shutting down...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Cleanup on exit
def cleanup():
    logger.info("🧹 Cleanup completed")

atexit.register(cleanup)

if __name__ == "__main__":
    logger.info(f"🚀 Starting {SERVER_NAME} on {SERVER_HOST}:{SERVER_PORT}")
    uvicorn.run(
        "main:app",
        host=SERVER_HOST,
        port=SERVER_PORT,
        reload=True,
        log_level="info"
    ) 