#!/usr/bin/env python3
"""
FastMCP Client for calling the health_check tool
Connects to http://localhost:8001 using FastMCP client library
"""

import asyncio
import json
from fastmcp import Client

async def main():
    """Main function to call the health_check tool"""
    print("🚀 FastMCP Client - Call Health Check Tool")
    print("="*40)
    
    # Create FastMCP client pointing to HTTP server
    client = Client("http://localhost:8001/sse")
    
    # Use async context manager for proper connection handling
    async with client:
        print("✅ Connected to MCP server")
        
        # Call the health_check tool
        print("\n🔍 Calling health_check tool...")
        result = await client.call_tool("health_check")
        
        # Pretty print the raw response
        print("\n" + "="*50)
        print("🔧 RAW HEALTH CHECK RESPONSE")
        print("="*50)
        print(json.dumps(result, indent=2, default=str))

if __name__ == "__main__":
    asyncio.run(main()) 