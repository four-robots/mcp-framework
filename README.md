# MCP Framework

A modular TypeScript framework for building Model Context Protocol (MCP) servers with pluggable transports and authentication providers.

## Features

- **Transport Independence**: Run the same MCP server on multiple transports (stdio, HTTP, WebSocket, SSE)
- **Plugin Architecture**: Modular design with pluggable authentication providers
- **OAuth 2.1 Compliance**: Built-in support for OAuth 2.1 with PKCE and dynamic client registration
- **Multi-Transport Support**: Single server instance can run multiple transports simultaneously
- **Context Injection**: Rich context system for user info and request metadata
- **Type Safety**: Full TypeScript support with comprehensive type definitions
- **Testing Ready**: Comprehensive test coverage with Vitest

## Quick Start

### Installation

```bash
npm install @tylercoles/mcp-server @tylercoles/mcp-transport-stdio
```

### Basic Usage

```typescript
import { MCPServer } from '@tylercoles/mcp-server';
import { StdioTransport } from '@tylercoles/mcp-transport-stdio';

const server = new MCPServer({
  name: 'my-mcp-server',
  version: '1.0.0'
});

// Add a simple tool
server.addTool({
  name: 'echo',
  description: 'Echo back the input',
  inputSchema: {
    type: 'object',
    properties: {
      message: { type: 'string' }
    }
  }
}, async (params) => {
  return { text: params.message };
});

// Use stdio transport
server.useTransport(new StdioTransport());

// Start the server
await server.start();
```

### HTTP Transport with Authentication

```typescript
import { MCPServer } from '@tylercoles/mcp-server';
import { HttpTransport } from '@tylercoles/mcp-transport-http';
import { Providers } from '@tylercoles/mcp-auth-oidc';

const server = new MCPServer({
  name: 'my-http-server',
  version: '1.0.0'
});

// Configure HTTP transport with OIDC auth (Authentik example)
const httpTransport = new HttpTransport({
  port: 3000,
  auth: Providers.Authentik('https://auth.example.com', 'my-app', 'your-client-id', 'your-client-secret', {
    session: {
      secret: 'your-session-secret',
      callbackUrl: 'http://localhost:3000/auth/callback',
    },
  })
});

server.useTransport(httpTransport);
await server.start();
```

### Multi-Transport Server

```typescript
import { MCPServer } from '@tylercoles/mcp-server';
import { StdioTransport } from '@tylercoles/mcp-transport-stdio';
import { HttpTransport } from '@tylercoles/mcp-transport-http';

const server = new MCPServer({
  name: 'multi-transport-server',
  version: '1.0.0'
});

// Add your tools once
server.addTool(/* ... */);

// Run on multiple transports
server.useTransports([
  new StdioTransport(),
  new HttpTransport({ port: 3000 })
]);

await server.start();
```

## Architecture

### Core Components

- **`@tylercoles/mcp-server`**: Core framework with plugin architecture
- **`@tylercoles/mcp-auth`**: Authentication abstractions and base implementations
- **`@tylercoles/mcp-transport-stdio`**: stdio transport for local/CLI usage
- **`@tylercoles/mcp-transport-http`**: HTTP transport with session management
- **`@tylercoles/mcp-transport-sse`**: SSE transport for backwards compatibility
- **`@tylercoles/mcp-transport-websocket`**: WebSocket transport for real-time communication
- **`@tylercoles/mcp-auth-oidc`**: Generic OIDC authentication provider with session support
- **`@tylercoles/mcp-client`**: Enhanced MCP client with advanced features
- **`@tylercoles/mcp-rate-limit`**: Rate limiting middleware

### Package Structure

```
packages/
├── mcp-server/              # Core framework
├── mcp-auth/               # Authentication abstractions
├── mcp-auth-oidc/          # Generic OIDC provider with session support
├── mcp-transport-stdio/    # stdio transport
├── mcp-transport-http/     # HTTP transport
├── mcp-transport-sse/      # SSE transport
├── mcp-transport-websocket/ # WebSocket transport
├── mcp-client/             # Enhanced MCP client
├── mcp-client-http/        # HTTP client implementation
├── mcp-client-stdio/       # stdio client implementation
└── mcp-rate-limit/         # Rate limiting middleware
```

## Available Transports

| Transport | Use Case | Features |
|-----------|----------|----------|
| **stdio** | Local CLI usage, development | Process communication via stdin/stdout |
| **HTTP** | Production web usage | REST API, session management, OAuth |
| **WebSocket** | Real-time applications | Full-duplex communication |
| **SSE** | Backwards compatibility | Server-sent events |

## Authentication Providers

| Provider | Description | Features |
|----------|-------------|----------|
| **OIDC** | Generic OpenID Connect | Standards-compliant OIDC with optional session support, pre-configured factories for Auth0, Okta, Keycloak, Google, Microsoft, Authentik |

## Examples

Comprehensive examples are available in the `examples/` directory:

- **echo-server**: Basic MCP server with multiple transport examples
- **multi-transport-server**: Server running on multiple transports simultaneously
- **kanban-board**: Full-featured kanban board with Docker support
- **memory-server**: Distributed memory server with NATS integration
- **file-server**: File operations MCP server
- **ide-server**: IDE integration examples

## Development

### Prerequisites

- Node.js 18+
- npm 9+

### Setup

```bash
# Clone the repository
git clone https://github.com/tylercoles-dev/mcp-framework.git
cd mcp-framework

# Install dependencies
npm install

# Build all packages
npm run build

# Run tests
npm test

# Run in development mode
npm run dev
```

### Common Commands

```bash
# Build all packages
npm run build

# Build in dependency order (if build fails)
npm run build:order

# Run tests with coverage
npm run test:coverage

# Run tests with UI
npm run test:ui

# Type checking
npm run typecheck

# Lint all packages
npm run lint

# Clean build artifacts
npm run clean
```

### Working with Packages

```bash
# Install dependency in specific package
npm install express -w @tylercoles/mcp-transport-http

# Build specific package
npm run build -w @tylercoles/mcp-server

# Test specific package
npm test -w @tylercoles/mcp-server

# Run specific package in dev mode
npm run dev -w @tylercoles/mcp-server
```

## Security

This framework implements security best practices including:

- OAuth 2.1 with PKCE for secure authentication
- Dynamic client registration
- Session management with secure cookies
- CORS protection
- Rate limiting
- Input validation with Zod schemas
- Helmet.js security headers

See [SECURITY.md](SECURITY.md) for detailed security information.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- GitHub Issues: [Report bugs and request features](https://github.com/tylercoles-dev/mcp-framework/issues)
- Documentation: [Full documentation](docs/)
- Examples: [Example implementations](examples/)

## Roadmap

- [ ] Additional transport implementations (gRPC, TCP)
- [ ] More authentication providers (Auth0, Firebase Auth)
- [ ] Plugin marketplace
- [ ] Performance optimizations
- [ ] Enhanced monitoring and metrics