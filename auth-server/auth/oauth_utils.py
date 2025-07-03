"""
OAuth 2.0 utilities for Google authentication
"""

import logging
import httpx
from typing import Optional
from models.schemas import GoogleDiscoveryDocument
from config.settings import (
    GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_DISCOVERY_URL, 
    GOOGLE_ISSUER, REDIRECT_URI
)

logger = logging.getLogger(__name__)

# Global variable for Google configuration
google_config: Optional[GoogleDiscoveryDocument] = None

async def load_google_config():
    """Load Google OAuth 2.0 configuration"""
    global google_config
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(GOOGLE_DISCOVERY_URL)
            if response.status_code == 200:
                config_data = response.json()
                google_config = GoogleDiscoveryDocument(**config_data)
                logger.info("✅ Loaded Google OAuth 2.0 configuration")
                return True
            else:
                logger.error(f"❌ Failed to load Google config: {response.status_code}")
                return False
    except Exception as e:
        logger.error(f"❌ Error loading Google config: {e}")
        return False

def get_oauth_url(state: str = "") -> str:
    """Generate OAuth authorization URL"""
    if not google_config:
        raise ValueError("Google configuration not loaded")
    
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state
    }
    
    param_string = '&'.join([f"{k}={v}" for k, v in params.items()])
    return f"{google_config.authorization_endpoint}?{param_string}"

async def exchange_code_for_token(code: str) -> dict:
    """Exchange authorization code for access token"""
    if not google_config:
        raise ValueError("Google configuration not loaded")
    
    token_data = {
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': REDIRECT_URI
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            google_config.token_endpoint,
            data=token_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"❌ Token exchange failed: {response.status_code} - {response.text}")
            raise Exception(f"Token exchange failed: {response.status_code}")

async def get_user_info(access_token: str) -> dict:
    """Get user information from Google"""
    if not google_config:
        raise ValueError("Google configuration not loaded")
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            google_config.userinfo_endpoint,
            headers={'Authorization': f'Bearer {access_token}'}
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"❌ Failed to get user info: {response.status_code} - {response.text}")
            raise Exception(f"Failed to get user info: {response.status_code}") 