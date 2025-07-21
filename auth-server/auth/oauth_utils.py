"""
OAuth 2.0 utilities for OIDC authentication
"""

import logging
import httpx
from typing import Optional
from models.schemas import OIDCDiscoveryDocument
from config.settings import (
    OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, 
    OIDC_DISCOVERY_URL, REDIRECT_URI
)

logger = logging.getLogger(__name__)

# Global variable for OIDC configuration
oidc_config: Optional[OIDCDiscoveryDocument] = None

async def load_oidc_config():
    """Load OIDC configuration"""
    global oidc_config
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(OIDC_DISCOVERY_URL)
            if response.status_code == 200:
                config_data = response.json()
                oidc_config = OIDCDiscoveryDocument(**config_data)
                logger.info("✅ Loaded OpenID Connect (OIDC) configuration")
                return True
            else:
                logger.error(f"❌ Failed to load OIDC config: {response.status_code}")
                return False
    except Exception as e:
        logger.error(f"❌ Error loading OIDC config: {e}")
        return False

def get_oauth_url(state: str = "") -> str:
    """Generate OAuth authorization URL"""
    if not oidc_config:
        raise ValueError("OIDC configuration not loaded")
    
    params = {
        'client_id': OIDC_CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state
    }
    
    param_string = '&'.join([f"{k}={v}" for k, v in params.items()])
    return f"{oidc_config.authorization_endpoint}?{param_string}"

async def exchange_code_for_token(code: str) -> dict:
    """Exchange authorization code for access token"""
    if not oidc_config:
        raise ValueError("OIDC configuration not loaded")
    
    token_data = {
        'client_id': OIDC_CLIENT_ID,
        'client_secret': OIDC_CLIENT_SECRET,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': REDIRECT_URI
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            oidc_config.token_endpoint,
            data=token_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"❌ Token exchange failed: {response.status_code} - {response.text}")
            raise Exception(f"Token exchange failed: {response.status_code}")

async def get_user_info(access_token: str) -> dict:
    """Get user information from OIDC"""
    if not oidc_config:
        raise ValueError("OIDC configuration not loaded")
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            oidc_config.userinfo_endpoint,
            headers={'Authorization': f'Bearer {access_token}'}
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"❌ Failed to get user info: {response.status_code} - {response.text}")
            raise Exception(f"Failed to get user info: {response.status_code}") 