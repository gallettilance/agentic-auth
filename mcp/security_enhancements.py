#!/usr/bin/env python3
"""
Security Enhancement Functions for MCP Server
Implements the security recommendations from our security guide.
"""

import re
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Security validation functions
def validate_callback_url(callback_url: str, client_type: str = "desktop") -> bool:
    """
    Validate callback URL according to security recommendations.
    
    Args:
        callback_url: The callback URL to validate
        client_type: Type of client ("desktop" or "web")
    
    Returns:
        True if callback URL is secure, False otherwise
    """
    if client_type == "desktop":
        # Desktop clients must use loopback addresses only
        allowed_patterns = [
            r"^http://127\.0\.0\.1:\d+/.*",  # Loopback IPv4
            r"^http://localhost:\d+/.*",     # Localhost
            r"^http://\[::1\]:\d+/.*"       # Loopback IPv6
        ]
        return any(re.match(pattern, callback_url) for pattern in allowed_patterns)
    
    elif client_type == "web":
        # Web clients should use HTTPS and registered domains
        parsed = urlparse(callback_url)
        return (
            parsed.scheme == "https" and
            bool(parsed.netloc) and
            not parsed.netloc.startswith("localhost") and
            not parsed.netloc.startswith("127.0.0.1")
        )
    
    return False

def validate_mcp_server_uri(server_uri: str) -> Dict[str, Any]:
    """
    Validate MCP server URI format and detect potential threats.
    
    Args:
        server_uri: The MCP server URI to validate
    
    Returns:
        Dictionary with validation results and security warnings
    """
    parsed = urlparse(server_uri)
    warnings = []
    
    # Check for suspicious domains (typosquatting)
    suspicious_patterns = [
        r".*paypaI\.com.*",      # Capital I instead of l
        r".*googIe\.com.*",      # Capital I instead of l
        r".*microsft\.com.*",    # Missing 'o'
        r".*githb\.com.*",       # Missing 'u'
    ]
    
    for pattern in suspicious_patterns:
        if re.match(pattern, parsed.netloc, re.IGNORECASE):
            warnings.append(f"Suspicious domain detected: {parsed.netloc} - possible typosquatting")
    
    # Check for non-standard ports (potential indicators of malicious servers)
    if parsed.port and parsed.port not in [80, 443, 8000, 8001, 8080, 8443]:
        warnings.append(f"Non-standard port detected: {parsed.port}")
    
    # Check for HTTPS requirement in production
    if parsed.scheme != "https" and not parsed.netloc.startswith(("localhost", "127.0.0.1")):
        warnings.append("Non-HTTPS URI detected for external server")
    
    return {
        "valid": len(warnings) == 0,
        "warnings": warnings,
        "parsed_uri": {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "port": parsed.port,
            "path": parsed.path
        }
    }

def verify_auth_server_consistency(mcp_server_metadata: Dict[str, Any], oauth_callback_issuer: str) -> bool:
    """
    Verify that the OAuth callback issuer matches the declared authorization server.
    
    Args:
        mcp_server_metadata: Protected Resource Metadata from MCP server
        oauth_callback_issuer: Issuer from OAuth callback
    
    Returns:
        True if consistent, False if potential spoofing detected
    """
    declared_auth_servers = mcp_server_metadata.get("authorization_servers", [])
    
    # Check exact match
    if oauth_callback_issuer in declared_auth_servers:
        return True
    
    # Check for domain consistency (handle trailing slashes, etc.)
    callback_domain = urlparse(oauth_callback_issuer).netloc
    for declared_server in declared_auth_servers:
        declared_domain = urlparse(declared_server).netloc
        if callback_domain == declared_domain:
            return True
    
    logger.warning(f"Auth server consistency check failed: declared={declared_auth_servers}, callback={oauth_callback_issuer}")
    return False

def generate_security_warning(server_uri: str, auth_server_uri: str) -> str:
    """
    Generate security warning message for user display.
    
    Args:
        server_uri: MCP server URI
        auth_server_uri: Authorization server URI
    
    Returns:
        Formatted security warning message
    """
    return f"""
    ⚠️  SECURITY WARNING ⚠️
    
    You are about to authorize access to:
    MCP Server: {server_uri}
    Auth Server: {auth_server_uri}
    
    Only proceed if you trust both services.
    Malicious servers can steal your OAuth tokens.
    
    Verify the URLs are correct and from trusted sources.
    """

def create_enhanced_metadata(server_uri: str, auth_server_uri: str, jwt_mode: str = "symmetric") -> Dict[str, Any]:
    """
    Create enhanced Protected Resource Metadata with security fields.
    
    Args:
        server_uri: This MCP server's URI
        auth_server_uri: Authorization server URI
        jwt_mode: JWT mode ("symmetric", "asymmetric", or "introspection")
    
    Returns:
        Enhanced metadata dictionary
    """
    metadata = {
        # REQUIRED by current MCP spec
        "resource": server_uri,
        "authorization_servers": [auth_server_uri],
        
        # RECOMMENDED security enhancements
        "scopes_supported": ["list_files", "execute_command", "get_server_info", "get_oauth_metadata", "health_check", "list_tool_scopes", "verify_domain"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{server_uri}/docs",
        
        # NEW SECURITY FIELDS (our recommendations)
        "token_validation_methods": ["jwt"] if jwt_mode != "introspection" else ["introspection"],
        "token_formats_supported": ["jwt"] if jwt_mode != "introspection" else ["opaque"],
        "security_contact": "security@example.com",
        "domain_verification_uri": f"{server_uri}/verify-domain",
        "threat_model_uri": f"{server_uri}/security/threat-model",
        "security_policy_uri": f"{server_uri}/security/policy",
        
        # MCP-specific security information
        "mcp_version": "1.0",
        "security_features": [
            "token_audience_validation",
            "tool_scope_authorization", 
            "enhanced_error_responses",
            "domain_verification_support"
        ],
        
        # Threat mitigation capabilities
        "threat_mitigations": {
            "malicious_server_protection": True,
            "oauth_server_spoofing_protection": True,
            "callback_url_validation": True,
            "token_audience_binding": True
        },
        
        # Security compliance status
        "security_compliance": {
            "current_mcp_spec_compliance": True,
            "enhanced_security_recommendations": True,
            "rfc_8707_resource_indicators": True,
            "rfc_9728_protected_resource_metadata": True,
            "threat_model_documented": True
        }
    }
    
    # Add JWT-specific fields
    if jwt_mode == "asymmetric":
        metadata["jwks_uri"] = f"{auth_server_uri}/.well-known/jwks.json"
    elif jwt_mode == "introspection":
        metadata["introspection_endpoint"] = f"{auth_server_uri}/oauth/introspect"
    
    return metadata

def create_domain_verification_response(domain: str, verification_token: str, user_email: str, server_uri: str) -> Dict[str, Any]:
    """
    Create domain verification response for demonstration.
    
    Args:
        domain: Domain to verify
        verification_token: Verification token
        user_email: User requesting verification
        server_uri: MCP server URI
    
    Returns:
        Domain verification response
    """
    return {
        "domain": domain,
        "verification_token": verification_token,
        "verification_status": "pending",
        "verification_method": "dns_txt_record",
        "verification_instructions": f"Add TXT record: _mcp-verification.{domain} = {verification_token}",
        "verification_uri": f"https://{domain}/.well-known/mcp-verification.txt",
        "expires_at": (datetime.now() + timedelta(hours=24)).isoformat(),
        "verified_by": user_email,
        "server_uri": server_uri,
        "message": "Domain verification initiated - follow instructions to complete"
    }

# Resource parameter validation for OAuth requests
def validate_resource_parameter(resource_uri: str, registered_servers: List[str]) -> bool:
    """
    Validate resource parameter against registered MCP servers.
    
    Args:
        resource_uri: Resource URI from OAuth request
        registered_servers: List of registered MCP server URIs
    
    Returns:
        True if resource is registered, False otherwise
    """
    return resource_uri in registered_servers

def create_oauth_request_with_resource(client_id: str, scopes: List[str], resource_uri: str, callback_url: str) -> Dict[str, str]:
    """
    Create OAuth request with resource parameter (RFC 8707).
    
    Args:
        client_id: OAuth client ID
        scopes: Requested scopes
        resource_uri: Target MCP server URI
        callback_url: OAuth callback URL
    
    Returns:
        OAuth request parameters
    """
    return {
        "response_type": "code",
        "client_id": client_id,
        "scope": " ".join(scopes),
        "resource": resource_uri,  # CRITICAL: RFC 8707 resource parameter
        "redirect_uri": callback_url,
        "state": f"mcp_auth_{datetime.now().timestamp()}"
    } 