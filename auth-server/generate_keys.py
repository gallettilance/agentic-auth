#!/usr/bin/env python3
"""
Simple RSA key pair generation for demo purposes.
In production, use proper key management (HSM, Key Vault, etc.)
"""

import os
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import json
import base64
import hashlib

def generate_rsa_keypair():
    """Generate RSA key pair for JWT signing"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    # Serialize private key (PEM format)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key (PEM format)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem, private_key, public_key

def create_jwk(private_key, kid=None):
    """Create JWK (JSON Web Key) from RSA private key"""
    # Get public key from private key
    public_key = private_key.public_key()
    
    # Get public key numbers
    public_numbers = public_key.public_numbers()
    
    # Convert to bytes and base64url encode
    def int_to_base64url(val):
        byte_length = (val.bit_length() + 7) // 8
        val_bytes = val.to_bytes(byte_length, 'big')
        return base64.urlsafe_b64encode(val_bytes).decode('ascii').rstrip('=')
    
    n = int_to_base64url(public_numbers.n)
    e = int_to_base64url(public_numbers.e)
    
    # Generate key ID if not provided
    if not kid:
        # Create a hash of the public key for the kid
        public_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        kid = hashlib.sha256(public_der).hexdigest()[:16]
    
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256", 
        "kid": kid,
        "n": n,
        "e": e
    }
    
    return jwk, kid

def save_keys(private_pem, public_pem, jwk, kid, keys_dir="keys"):
    """Save keys to files"""
    os.makedirs(keys_dir, exist_ok=True)
    
    # Save private key
    with open(f"{keys_dir}/private_key.pem", "wb") as f:
        f.write(private_pem)
    
    # Save public key
    with open(f"{keys_dir}/public_key.pem", "wb") as f:
        f.write(public_pem)
    
    # Save JWK
    with open(f"{keys_dir}/jwk.json", "w") as f:
        json.dump(jwk, f, indent=2)
    
    # Save JWKS (JSON Web Key Set)
    jwks = {
        "keys": [jwk]
    }
    with open(f"{keys_dir}/jwks.json", "w") as f:
        json.dump(jwks, f, indent=2)
    
    # Save key ID for reference
    with open(f"{keys_dir}/kid.txt", "w") as f:
        f.write(kid)
    
    print(f"✅ Keys generated and saved to {keys_dir}/")
    print(f"   - Private key: {keys_dir}/private_key.pem")
    print(f"   - Public key: {keys_dir}/public_key.pem") 
    print(f"   - JWK: {keys_dir}/jwk.json")
    print(f"   - JWKS: {keys_dir}/jwks.json")
    print(f"   - Key ID: {kid}")

def main():
    """Generate keys for demo"""
    print("🔑 Generating RSA key pair for JWT demo...")
    
    # Generate keys
    private_pem, public_pem, private_key, public_key = generate_rsa_keypair()
    
    # Create JWK
    jwk, kid = create_jwk(private_key)
    
    # Save everything
    save_keys(private_pem, public_pem, jwk, kid)
    
    print(f"\n📋 To use these keys:")
    print(f"   - Set PRIVATE_KEY_PATH=keys/private_key.pem")
    print(f"   - Set KID={kid}")
    print(f"   - JWKS endpoint will serve keys/jwks.json")

if __name__ == "__main__":
    main() 