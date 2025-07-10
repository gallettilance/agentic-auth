#!/usr/bin/env python3
"""
FastMCP Client for listing tools from the MCP server
Connects to http://localhost:8001 using FastMCP client library
"""

import asyncio
import json
from fastmcp import Client

async def main():
    """Main function to demonstrate FastMCP client usage"""
    print("🚀 FastMCP Client - Raw Tool Listing")
    print("="*40)
    
    # Create FastMCP client pointing to HTTP server
    client = Client("http://localhost:8001/sse")
    
    # Use async context manager for proper connection handling
    async with client:
        print("✅ Connected to MCP server")
        
        # List available tools
        print("\n🔍 Listing available tools...")
        tools = await client.list_tools()
        
        # Pretty print the raw response
        print("\n" + "="*50)
        print("🔧 RAW TOOLS RESPONSE")
        print("="*50)
        print(json.dumps(tools, indent=2, default=str))

if __name__ == "__main__":
    asyncio.run(main()) 