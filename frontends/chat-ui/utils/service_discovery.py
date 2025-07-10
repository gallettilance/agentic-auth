"""
MCP Service Discovery Utility
Discovers auth configurations for MCP servers using RFC 9728 OAuth Protected Resource Discovery
"""

import httpx
import logging
from typing import Dict, Optional, List
from urllib.parse import urljoin
import asyncio
from datetime import datetime
import os

logger = logging.getLogger(__name__)

class MCPServiceDiscovery:
    """Service discovery specifically for MCP servers"""
    
    def __init__(self):
        self.discovered_configs = {}
        self.timeout = 10.0
    
    async def discover_mcp_auth(self, mcp_server_url: str) -> Optional[Dict]:
        """
        Discover MCP server auth configuration using RFC 9728 OAuth Protected Resource Discovery
        
        Args:
            mcp_server_url: Base URL of the MCP server
            
        Returns:
            Dictionary containing auth configuration or None if discovery fails
        """
        try:
            discovery_url = urljoin(mcp_server_url, "/.well-known/oauth-protected-resource")
            logger.info(f"🔍 Discovering MCP auth config: {discovery_url}")
            
            async with httpx.AsyncClient() as client:
                response = await client.get(discovery_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    config = response.json()
                    auth_server = config.get("authorization_server")
                    logger.info(f"✅ Discovered MCP auth server: {auth_server}")
                    
                    # Cache the discovery result
                    self.discovered_configs[mcp_server_url] = {
                        "mcp_server_url": mcp_server_url,
                        "authorization_server": auth_server,
                        "jwks_uri": config.get("jwks_uri"),
                        "scopes_supported": config.get("scopes_supported", []),
                        "bearer_methods_supported": config.get("bearer_methods_supported", ["header"]),
                        "resource_documentation": config.get("resource_documentation"),
                        "discovered_at": datetime.now().isoformat()
                    }
                    
                    return self.discovered_configs[mcp_server_url]
                else:
                    logger.warning(f"⚠️ MCP auth discovery failed for {mcp_server_url}: {response.status_code}")
                    return None
                    
        except Exception as e:
            logger.error(f"❌ Error discovering MCP auth for {mcp_server_url}: {e}")
            return None
    
    async def discover_all_mcp_servers(self, mcp_server_urls: List[str]) -> Dict[str, Dict]:
        """
        Discover auth configurations for all configured MCP servers
        
        Args:
            mcp_server_urls: List of MCP server URLs to discover
            
        Returns:
            Dictionary of mcp_server_url -> auth_config
        """
        logger.info(f"🔍 Discovering auth configs for {len(mcp_server_urls)} MCP servers")
        
        discovered_configs = {}
        
        for mcp_server_url in mcp_server_urls:
            try:
                config = await self.discover_mcp_auth(mcp_server_url)
                if config:
                    discovered_configs[mcp_server_url] = config
                    logger.info(f"✅ Discovered auth config for {mcp_server_url}")
                else:
                    logger.warning(f"⚠️ Failed to discover auth config for {mcp_server_url}")
                    
            except Exception as e:
                logger.error(f"❌ Error discovering {mcp_server_url}: {e}")
        
        logger.info(f"✅ Discovery complete: {len(discovered_configs)}/{len(mcp_server_urls)} MCP servers configured")
        return discovered_configs
    
    def get_auth_server_for_mcp(self, mcp_server_url: str) -> Optional[str]:
        """Get the auth server URL for a specific MCP server"""
        config = self.discovered_configs.get(mcp_server_url)
        if config:
            return config.get("authorization_server")
        return None
    
    def get_cached_config(self, mcp_server_url: str) -> Optional[Dict]:
        """Get cached discovery result for an MCP server"""
        return self.discovered_configs.get(mcp_server_url)
    
    def clear_cache(self):
        """Clear all cached discovery results"""
        self.discovered_configs.clear()
        logger.info("🔄 MCP service discovery cache cleared")


# Global instance
mcp_discovery = MCPServiceDiscovery()


def get_configured_mcp_servers() -> List[str]:
    """
    Get list of configured MCP server URLs from environment/settings
    
    Returns:
        List of MCP server URLs (empty list if no hardcoded servers)
    """
    mcp_servers = []
    
    # Only use explicitly configured additional MCP servers
    additional_mcp = os.getenv("ADDITIONAL_MCP_SERVERS", "")
    if additional_mcp:
        additional_servers = [url.strip() for url in additional_mcp.split(",") if url.strip()]
        mcp_servers.extend(additional_servers)
    
    logger.info(f"📋 Configured MCP servers: {mcp_servers}")
    return mcp_servers


async def discover_mcp_auth_configs() -> Dict[str, Dict]:
    """
    Discover auth configs for all configured MCP servers
    
    Returns:
        Dictionary of mcp_server_url -> auth_config
    """
    mcp_servers = get_configured_mcp_servers()
    return await mcp_discovery.discover_all_mcp_servers(mcp_servers)


async def get_auth_server_for_mcp_server(mcp_server_url: str) -> Optional[str]:
    """
    Get the auth server URL for a specific MCP server
    
    Args:
        mcp_server_url: URL of the MCP server
        
    Returns:
        Auth server URL or None if not found
    """
    # Check cache first
    cached_auth_server = mcp_discovery.get_auth_server_for_mcp(mcp_server_url)
    if cached_auth_server:
        return cached_auth_server
    
    # Discover if not cached
    config = await mcp_discovery.discover_mcp_auth(mcp_server_url)
    if config:
        return config.get("authorization_server")
    
    return None 