# MCP Memories Server

## Overview

This example demonstrates a full-featured MCP server built using the `@tylercoles/mcp-framework`. It provides persistent memory storage with NATS JetStream as the backend and OIDC for OAuth authentication.

This server showcases:
- Using the framework's HTTP transport with OAuth authentication
- Implementing multiple tools with context-aware user access
- Integration with external services (NATS for persistence)
- Custom routes alongside MCP endpoints
- Production-ready features like health checks and logging

## Setup Instructions

### 1. Prerequisites

- Node.js 18+ installed
- NATS server running with JetStream enabled
- OIDC instance configured with OAuth application

### 2. Installation

```bash
# From the root of the monorepo
npm install
npm run build

# Or just this example
cd examples/memory-server
npm install
npm run build
```

### Framework Usage

This server demonstrates how to use the `@tylercoles/mcp-framework`:

```typescript
// Core framework packages
import { MCPServer } from '@tylercoles/mcp-server';
import { HttpTransport } from '@tylercoles/mcp-transport-http';
import { Providers } from '@tylercoles/mcp-auth-oidc';

// Create server
const mcpServer = new MCPServer({
  name: 'mcp-memories',
  version: '1.0.0'
});

// Configure HTTP transport with OIDC auth
const transport = new HttpTransport({
  port: 3000,
  auth: Providers.Authentik('https://auth.example.com', 'claude-ai-mcp', 'claude-ai-mcp', undefined, {
    session: {
      secret: 'your-session-secret',
      callbackUrl: 'http://localhost:3000/auth/callback',
    },
  })
});

// Register tools (see tools/memory-tools.ts)
setupMemoryTools(mcpServer, memoryService);

// Start server
mcpServer.useTransport(transport);
await mcpServer.start();
```

### 3. Environment Configuration

Create a `.env` file with the following:

```env
# Server Configuration
PORT=3000
HOST=0.0.0.0

# Session Secret (generate a random string)
SESSION_SECRET=your-random-session-secret

# CORS Origins (adjust for your setup)
CORS_ORIGINS=http://localhost:*,https://claude.ai,https://*.claude.ai

# NATS Configuration
NATS_SERVERS=nats://localhost:4222
NATS_USER=your-nats-user
NATS_PASS=your-nats-password

# OIDC OAuth Configuration
OIDC_URL=https://auth.example.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=http://localhost:3000/auth/callback

# Enable REST API (optional)
ENABLE_API=true

# Logging
LOG_LEVEL=info
LOG_FORMAT=json
```

### 4. Running the Server

```bash
# Development mode
npm run dev

# Production mode
npm start
```

### 5. Claude.ai Configuration

To use this server with Claude.ai:

1. **Ensure the server is accessible from Claude.ai**
   - The server must be publicly accessible or use a tunnel service like ngrok
   - Example with ngrok: `ngrok http 3000`

2. **Configure Claude Desktop (if using desktop app)**
   
   Add to your Claude Desktop configuration file:
   ```json
   {
     "mcpServers": {
       "memories": {
         "url": "http://your-server-url:3000/mcp",
         "transport": "http"
       }
     }
   }
   ```

3. **Test the connection**
   - Visit `http://your-server-url:3000/mcp` in a browser
   - You should see the MCP discovery response with all available tools

## Available Tools

The server provides the following memory tools:

1. **store_memory** - Store a new memory with hierarchical organization
2. **retrieve_memories** - Search for memories with filtering
3. **search_by_tag** - Find memories by specific tags
4. **recall_memories** - Recall memories from a time period
5. **delete_memory** - Delete a specific memory
6. **get_memory_stats** - Get memory statistics
7. **list_projects** - List all memory projects
8. **list_topics** - List topics within a project
9. **list_types** - List memory types within a topic
10. **list_available_tools** - Get a list of all available tools (introspection)

## Authentication

**IMPORTANT: Authentication is required for all operations, including Claude.ai access.**

The server uses OAuth authentication via OIDC:

1. **Web Users** - Standard OAuth flow
   - Visit `/auth/login` to authenticate
   - Session-based authentication
   - Personal memory space per user

2. **Claude.ai Access** - Requires authentication
   - Must authenticate via OAuth first
   - Use authenticated session or API key
   - No default/bypass user - full security

## Endpoints

- `GET /` - Server info and status
- `GET /health` - Health check
- `GET /mcp` - MCP discovery (lists tools)
- `POST /mcp` - MCP JSON-RPC endpoint
- `GET /auth/login` - Start OAuth flow
- `GET /api/*` - REST API (if enabled)

## Troubleshooting

### Claude.ai doesn't show tools

1. **Ensure you are authenticated first** - Visit `/auth/login`
2. Check server is running: `curl http://localhost:3000/health`
3. Check MCP endpoint (requires auth): `curl -H "Cookie: <session-cookie>" http://localhost:3000/mcp`
4. Ensure CORS is properly configured
5. Check server logs for authentication errors

### Authentication issues

1. Verify OIDC configuration
2. Check redirect URI matches exactly
3. Ensure session secret is set
4. Check browser console for errors

### Memory storage issues

1. Verify NATS is running with JetStream
2. Check NATS credentials
3. Ensure NATS streams are created
4. Check server logs for NATS errors

## Development

```bash
# Run tests
npm test

# Lint code
npm run lint

# Format code
npm run format

# Type check
npm run type-check
```

## API Endpoints

The server exposes several REST API endpoints alongside the MCP protocol:

### Public Endpoints (No Auth Required)
- `GET /` - Server info and authentication status
- `GET /health` - Health check endpoint with service status

### Authenticated Endpoints
- `GET /api/tools` - List all available tools with their schemas
- `GET /api/tools/:name` - Get detailed information about a specific tool
- `GET /api/capabilities` - Get complete server capabilities (tools, resources, prompts)
- `POST /api/memories` - REST API for storing memories
- `GET /api/memories/search` - REST API for searching memories
- `GET /api/memories/stats` - Get memory statistics
- `DELETE /api/memories/:id` - Delete a specific memory

### MCP Protocol Endpoints
- `POST /mcp` - Main MCP protocol endpoint
- `GET /mcp` - SSE endpoint for server-to-client notifications
- `DELETE /mcp` - Session termination

### OAuth Discovery Endpoints
- `GET /.well-known/oauth-protected-resource` - OAuth resource metadata
- `GET /.well-known/oauth-authorization-server` - OAuth server metadata

## Architecture

```
Claude.ai <-> MCP Server <-> NATS JetStream
                  |
                  +-> OIDC OAuth
```

The server uses the official `@modelcontextprotocol/sdk` for MCP compliance and provides both HTTP/JSON-RPC transport for Claude.ai integration and OAuth-protected endpoints for web users.
