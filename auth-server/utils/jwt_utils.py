"""
JWT utilities for token generation and verification
"""

import os
import json
import logging
from typing import Optional, List
import jwt
from cryptography.hazmat.primitives import serialization
from models.schemas import TokenPayload
from config.settings import PRIVATE_KEY_PATH, JWKS_PATH, SERVER_URI

logger = logging.getLogger(__name__)

# Global variables for key management
private_key = None
public_key = None
jwks_data = None
KID = None

def load_asymmetric_keys():
    """Load asymmetric keys for JWT signing and verification"""
    global private_key, public_key, jwks_data, KID
    
    try:
        # Load KID (Key ID) from file
        kid_file = "keys/kid.txt"
        if os.path.exists(kid_file):
            with open(kid_file, 'r') as f:
                KID = f.read().strip()
                logger.info(f"✅ Loaded KID: {KID}")
        else:
            logger.warning(f"⚠️ KID file not found: {kid_file}")
            KID = "default-key-id"
        
        # Load private key for signing
        if os.path.exists(PRIVATE_KEY_PATH):
            with open(PRIVATE_KEY_PATH, 'rb') as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
                logger.info(f"✅ Loaded private key from {PRIVATE_KEY_PATH}")
        else:
            logger.error(f"❌ Private key file not found: {PRIVATE_KEY_PATH}")
            return False
        
        # Load public key for verification
        public_key = private_key.public_key()
        logger.info("✅ Extracted public key from private key")
        
        # Load JWKS data
        if os.path.exists(JWKS_PATH):
            with open(JWKS_PATH, 'r') as f:
                jwks_data = json.load(f)
                logger.info(f"✅ Loaded JWKS from {JWKS_PATH}")
        else:
            logger.error(f"❌ JWKS file not found: {JWKS_PATH}")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to load asymmetric keys: {e}")
        return False

def auto_generate_keys():
    """Auto-generate keys if they don't exist"""
    if not os.path.exists("keys"):
        os.makedirs("keys")
        logger.info("📁 Created keys directory")
    
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(JWKS_PATH):
        logger.info("🔑 Auto-generating asymmetric keys...")
        
        try:
            # Import here to avoid circular imports
            import subprocess
            import sys
            
            # Run the key generation script in current directory
            result = subprocess.run([sys.executable, "generate_keys.py"], 
                                  capture_output=True, 
                                  text=True)
            
            if result.returncode == 0:
                logger.info("✅ Keys auto-generated successfully")
                return load_asymmetric_keys()
            else:
                logger.error(f"❌ Key generation failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Failed to auto-generate keys: {e}")
            return False
    
    return load_asymmetric_keys()

def get_jwt_algorithm() -> str:
    """Get JWT algorithm"""
    return "RS256"

def get_jwt_key_for_signing():
    """Get key for JWT signing"""
    return private_key

def get_jwt_key_for_verification():
    """Get key for JWT verification"""
    return public_key

def get_public_key_pem() -> Optional[str]:
    """Get public key in PEM format for external verification"""
    if public_key:
        try:
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to serialize public key: {e}")
            return None
    return None

def build_jwt_io_url(jwt_token: str) -> str:
    """Build JWT.io URL for token debugging"""
    return f"https://jwt.io/#debugger-io?token={jwt_token}"

def generate_token(user: TokenPayload, scopes: List[str], audience: Optional[str] = None) -> str:
    """Generate JWT token with given scopes and audience"""
    if not private_key:
        raise ValueError("Private key not loaded")
    
    # Use provided audience or default to server URI
    token_audience = audience or SERVER_URI
    
    # Create payload
    payload = {
        'sub': user.sub,
        'aud': token_audience,
        'email': user.email,
        'scope': ' '.join(scopes),
        'exp': user.exp,
        'iat': user.iat,
        'iss': user.iss
    }
    
    # Add KID to header if available
    headers = {}
    if KID:
        headers['kid'] = KID
    
    # Generate token
    token = jwt.encode(
        payload,
        private_key,
        algorithm=get_jwt_algorithm(),
        headers=headers
    )
    
    logger.info(f"🎫 Generated JWT token for {user.email} with scopes: {scopes}, audience: {token_audience}")
    return token 