#!/bin/bash

# Script to create a test agent in Llama Stack
# This creates an agent with MCP tools access

curl -X POST http://localhost:8321/agents \
  -H "Content-Type: application/json" \
  -d '{
    "agent_config": {
      "agent_id": "test-agent",
      "instructions": "You are an AI assistant with access to MCP tools.",
      "model": "gpt-4-turbo",
      "tools": ["mcp::mcp-auth"],
      "enable_session_persistence": true
    }
  }' 