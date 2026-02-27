# MCP Framework Documentation

Welcome to the MCP Framework documentation. This comprehensive guide will help you build, deploy, and maintain MCP servers using our modular TypeScript framework.

## Table of Contents

### Getting Started
- [**Getting Started**](getting-started.md) - Installation, basic setup, and your first MCP server
- [**Quick Start Examples**](../examples/) - Ready-to-run example implementations

### Core Concepts
- [**Authentication Guide**](authentication.md) - Add OAuth 2.1 authentication with OIDC and Authentik providers
- [**Transport Guide**](transports.md) - Choose and configure transports (stdio, HTTP, WebSocket, SSE)
- [**Tool Development**](tool-development.md) - Advanced tool development patterns and best practices

### Deployment & Production
- [**Deployment Guide**](deployment.md) - Deploy to Docker, Kubernetes, and cloud platforms
- [**Security Guide**](../SECURITY.md) - Security best practices and considerations
- [**Contributing Guide**](../CONTRIBUTING.md) - How to contribute to the framework

## Quick Reference

### Installation
```bash
npm install @tylercoles/mcp-server @tylercoles/mcp-transport-stdio
```

### Basic Server Setup
```typescript
import { MCPServer } from '@tylercoles/mcp-server';
import { StdioTransport } from '@tylercoles/mcp-transport-stdio';

const server = new MCPServer({
  name: 'my-server',
  version: '1.0.0'
});

server.addTool({
  name: 'hello',
  description: 'Say hello',
  inputSchema: {
    type: 'object',
    properties: {
      name: { type: 'string' }
    },
    required: ['name']
  }
}, async (params) => {
  return { text: `Hello, ${params.name}!` };
});

server.useTransport(new StdioTransport());
await server.start();
```

## Framework Architecture

### Core Components
- **`@tylercoles/mcp-server`** - Core framework with plugin architecture
- **`@tylercoles/mcp-auth`** - Authentication abstractions and base implementations
- **Transport Packages** - Multiple transport implementations (stdio, HTTP, WebSocket, SSE)
- **Authentication Providers** - OAuth 2.1 providers (generic OIDC with pre-configured factories for Auth0, Okta, Keycloak, Google, Microsoft, Authentik)
- **Client Libraries** - Enhanced MCP clients with advanced features

### Key Features
- 🔌 **Transport Independence** - Run on multiple transports simultaneously
- 🏗️ **Plugin Architecture** - Modular design with pluggable components
- 🔐 **OAuth 2.1 Compliance** - Built-in authentication with PKCE
- 🚀 **Multi-Transport Support** - Single server, multiple transports
- 🎯 **Context Injection** - Rich context system for user info and metadata
- 🛡️ **Type Safety** - Full TypeScript support with comprehensive types
- ✅ **Testing Ready** - Comprehensive test coverage with Vitest

## Package Overview

| Package | Description | Use Case |
|---------|-------------|----------|
| `@tylercoles/mcp-server` | Core framework | All implementations |
| `@tylercoles/mcp-transport-stdio` | stdio transport | CLI tools, local development |
| `@tylercoles/mcp-transport-http` | HTTP transport | Web apps, REST APIs |
| `@tylercoles/mcp-transport-websocket` | WebSocket transport | Real-time applications |
| `@tylercoles/mcp-transport-sse` | SSE transport | Server-sent events |
| `@tylercoles/mcp-auth-oidc` | Generic OIDC auth | OAuth 2.1 authentication with optional session support |
| `@tylercoles/mcp-client` | Enhanced client | Advanced MCP client features |
| `@tylercoles/mcp-rate-limit` | Rate limiting | Request throttling |

## Common Use Cases

### Local Development
```typescript
// Use stdio transport for CLI tools
import { StdioTransport } from '@tylercoles/mcp-transport-stdio';
server.useTransport(new StdioTransport());
```

### Web Applications
```typescript
// Use HTTP transport with authentication
import { HttpTransport } from '@tylercoles/mcp-transport-http';
import { OIDCProvider } from '@tylercoles/mcp-auth-oidc';

const httpTransport = new HttpTransport({
  port: 3000,
  auth: new OIDCProvider({
    issuer: 'https://auth.example.com',
    clientId: 'your-client-id',
    clientSecret: 'your-client-secret'
  })
});
```

### Real-time Applications
```typescript
// Use WebSocket for real-time communication
import { WebSocketTransport } from '@tylercoles/mcp-transport-websocket';
server.useTransport(new WebSocketTransport({ port: 8080 }));
```

### Multi-Transport Server
```typescript
// Run on multiple transports simultaneously
server.useTransports([
  new StdioTransport(),
  new HttpTransport({ port: 3000 }),
  new WebSocketTransport({ port: 8080 })
]);
```

## Development Workflow

### 1. Setup Development Environment
```bash
git clone https://github.com/tylercoles-dev/mcp-framework.git
cd mcp-framework
npm install
npm run build
```

### 2. Run Tests
```bash
npm test                # Run all tests
npm run test:coverage   # Run with coverage
npm run test:ui         # Run with UI
```

### 3. Development Mode
```bash
npm run dev             # Watch all packages
npm run dev -w @tylercoles/mcp-server  # Watch specific package
```

### 4. Build and Verify
```bash
npm run build           # Build all packages
npm run typecheck       # Type checking
npm run lint            # Lint code
```

## Examples and Templates

### Complete Examples
- [**Echo Server**](../examples/echo-server/) - Basic MCP server with multiple transports
- [**Kanban Board**](../examples/kanban-board/) - Full-featured web application with Docker
- [**Memory Server**](../examples/memory-server/) - Distributed memory server with NATS
- [**Multi-Transport Server**](../examples/multi-transport-server/) - Server running on multiple transports

### Tool Examples
```typescript
// File operations tool
server.addTool({
  name: 'read_file',
  description: 'Read file contents',
  inputSchema: {
    type: 'object',
    properties: {
      path: { type: 'string' }
    },
    required: ['path']
  }
}, async (params) => {
  const content = await fs.readFile(params.path, 'utf8');
  return { text: content };
});

// Database query tool
server.addTool({
  name: 'query_users',
  description: 'Query user database',
  inputSchema: {
    type: 'object',
    properties: {
      filter: { type: 'string' }
    }
  }
}, async (params, context) => {
  // Check authentication
  if (!context.user) {
    throw new Error('Authentication required');
  }
  
  const users = await db.query('SELECT * FROM users WHERE name LIKE $1', [`%${params.filter}%`]);
  return {
    text: `Found ${users.length} users`,
    data: users
  };
});
```

## Troubleshooting

### Common Issues

**Port Already in Use**
```bash
# Find and kill process using port
lsof -ti:3000 | xargs kill -9
```

**TypeScript Compilation Errors**
```bash
# Clean build artifacts
npm run clean
npm run build
```

**Authentication Issues**
```typescript
// Enable debug logging
const oidcProvider = new OIDCProvider({
  // ... config
  debug: true
});
```

### Debug Mode
```bash
# Enable debug logging
DEBUG=mcp:* npm start
```

## Community and Support

### Getting Help
- [GitHub Issues](https://github.com/tylercoles-dev/mcp-framework/issues) - Bug reports and feature requests
- [GitHub Discussions](https://github.com/tylercoles-dev/mcp-framework/discussions) - Community Q&A
- [Documentation](https://github.com/tylercoles-dev/mcp-framework/tree/main/docs) - Comprehensive guides

### Contributing
- [Contributing Guide](../CONTRIBUTING.md) - How to contribute
- [Security Policy](../SECURITY.md) - Security guidelines
- [Code of Conduct](../CODE_OF_CONDUCT.md) - Community standards

### Resources
- [MCP Specification](../spec/) - Official MCP protocol specification
- [Examples](../examples/) - Working example implementations
- [Tools](../tools/) - Development and build tools

## License

This framework is released under the [MIT License](../LICENSE).

## Roadmap

### Current Version (0.2.x)
- ✅ Core framework with plugin architecture
- ✅ Multiple transport implementations
- ✅ OAuth 2.1 authentication providers
- ✅ Enhanced client libraries
- ✅ Comprehensive testing suite

### Future Releases
- 🔄 Additional transport implementations (gRPC, TCP)
- 🔄 More authentication providers (Auth0, Firebase Auth)
- 🔄 Plugin marketplace
- 🔄 Performance optimizations
- 🔄 Enhanced monitoring and metrics
- 🔄 GraphQL transport
- 🔄 Real-time collaboration features

---

**Get Started**: Begin with the [Getting Started Guide](getting-started.md) or explore our [Examples](../examples/) to see the framework in action.