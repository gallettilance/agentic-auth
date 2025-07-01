# Authentication Flow Diagrams

This directory contains visual diagrams showing the end-to-end authentication and tool execution flow in our MCP (Model Context Protocol) chat application.

## Diagrams Overview

### 1. E2E Flow Overview (`e2e-flow-overview.svg`)
**High-level process flow showing the complete user journey**

Shows the decision points and error handling paths from user prompt to final response, including:
- User authentication via Google OAuth
- Agent processing with GPT-4  
- MCP tool authorization and execution
- Automatic scope upgrade requests
- Admin approval workflows
- Error handling and retry mechanisms

### 2. Technical Architecture (`technical-architecture.svg`)
**Detailed component architecture and data flow**

Details the specific components and their interactions across three layers:
- **Frontend Layer**: Chat App (Flask), Llama Stack, Auth Agent
- **Authentication Layer**: Auth Server (FastAPI), Database, Google OAuth
- **MCP Layer**: MCP Server (FastMCP), File System Tools, Command Execution

Shows numbered flow steps and the relationships between all system components.

### 3. Sequence Diagram (`sequence-diagram.svg`)
**Detailed API call sequence and message flow**

Shows the exact API calls, HTTP requests, and message flow including:
- JWT token validation with audience and issuer checks
- Scope validation against tool requirements
- Error handling with `InsufficientScopeError`
- Automatic retry mechanisms after scope upgrades
- Admin approval workflows with polling

## Key Architecture Components

| Component | Technology | Port | Purpose |
|-----------|------------|------|---------|
| Chat App | Flask | 5001 | User interface, session management |
| Auth Server | FastAPI | 8002 | OAuth, JWT tokens, approval workflows |
| Llama Stack | Python | 8321 | AI agent orchestration |
| MCP Server | FastMCP | 8001 | Tool execution, authorization |
| Database | SQLite | - | Users, roles, permissions, approvals |

## Flow Summary

1. **User Input**: Message entered in chat interface
2. **Authentication**: JWT token validation with required scopes
3. **AI Processing**: GPT-4 determines if tools are needed
4. **Authorization**: MCP server validates token scopes against tool requirements
5. **Tool Execution**: If authorized, tools execute and return results
6. **Error Handling**: If insufficient scope, automatic upgrade request to auth server
7. **Approval Flow**: Auto-approve or admin approval based on policy
8. **Response**: Final answer incorporating tool results streamed back to user

## File Formats

- `.mmd` files: Source Mermaid diagram definitions
- `.svg` files: Rendered SVG images suitable for documentation

## Generating SVGs

To regenerate the SVG files from the Mermaid source:

```bash
# Install Mermaid CLI if not already installed
npm install -g @mermaid-js/mermaid-cli

# Generate SVGs
mmdc -i diagrams/e2e-flow-overview.mmd -o diagrams/e2e-flow-overview.svg
mmdc -i diagrams/technical-architecture.mmd -o diagrams/technical-architecture.svg
mmdc -i diagrams/sequence-diagram.mmd -o diagrams/sequence-diagram.svg
```

## Usage in Documentation

These diagrams can be embedded in Markdown documentation:

```markdown
![E2E Flow Overview](diagrams/e2e-flow-overview.svg)
![Technical Architecture](diagrams/technical-architecture.svg)
![Sequence Diagram](diagrams/sequence-diagram.svg)
```

Or viewed directly in GitHub, VS Code, or any SVG-compatible viewer. 