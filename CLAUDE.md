# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a modular framework for building Model Context Protocol (MCP) servers using npm workspaces. The framework provides a plugin architecture with pluggable transports and authentication providers.

## Common Development Commands

### Building
- `npm run build` - Build all packages in parallel
- `npm run build:order` - Build packages in dependency order (use when build dependencies fail)
- `npm run build -w @tylercoles/mcp-server` - Build specific package

### Testing
- `npm test` or `npm run test:all` - Run all tests using Vitest
- `npm run test:coverage` - Run tests with coverage
- `npm run test:ui` - Run tests with UI interface
- `npm test -w @tylercoles/mcp-server` - Test specific package
- `npm run test:watch` - Run tests in watch mode (in specific package directory)

### Development
- `npm run dev` - Run all packages in watch mode
- `npm run dev -w @tylercoles/mcp-server` - Watch specific package
- `npm run typecheck` - TypeScript type checking across all packages
- `npm run lint` - Lint all packages using ESLint

### Maintenance
- `npm run clean` - Clean all build artifacts and node_modules
- `npm run verify` - Verify workspace configuration
- `npm run security:audit` - Run security audit

### Workspace Management
- `npm install express -w @tylercoles/mcp-transport-http` - Install dependency in specific package
- `npm run ws:info` - List all workspace packages

## Architecture

### Core Package Structure
```
packages/
├── mcp-server/              # Core framework with plugin architecture
├── mcp-auth/                # Authentication abstractions and base implementations
├── mcp-auth-oidc/           # Generic OIDC provider with session support
├── mcp-transport-stdio/     # stdio transport for local/CLI usage
├── mcp-transport-http/      # HTTP transport with session management
├── mcp-transport-sse/       # SSE transport for backwards compatibility
├── mcp-transport-websocket/ # WebSocket transport for real-time communication
├── mcp-client/              # Enhanced MCP client
├── mcp-client-http/         # HTTP client implementation
├── mcp-client-stdio/        # stdio client implementation
└── mcp-rate-limit/          # Rate limiting middleware
```

### Key Architectural Concepts

**Transport Independence**: Tools are registered once on the MCPServer and can run on multiple transports simultaneously. The server supports stdio (for local CLI usage) and HTTP (for production web usage) transports.

**Plugin Architecture**: The MCPServer class (`packages/mcp-server/src/index.ts`) acts as the core framework that accepts:
- Transport plugins (implementing the Transport interface)
- Authentication providers (for HTTP transport)
- Tools, resources, and prompts registered via the server

**Multi-Transport Support**: A single server instance can run multiple transports simultaneously using `server.useTransports()` or multiple `server.useTransport()` calls.

**Context Injection**: Tool handlers receive a `ToolContext` parameter containing user info and request metadata, accessible via `server.setContext()`.

**OAuth 2.1 Compliance**: The auth packages implement OAuth 2.1 with PKCE, dynamic client registration, and proper security practices.

## Technology Stack

- **Language**: TypeScript with ES modules
- **Testing**: Vitest (migrated from Jest)
- **Build**: TypeScript compiler (tsc)
- **Package Management**: npm workspaces (migrated from Lerna)
- **Validation**: Zod schemas for input validation
- **HTTP Framework**: Express.js for HTTP transport
- **Security**: Helmet.js, CORS, session management

## Development Notes

### Package Dependencies
- Internal packages use `0.1.0` protocol for development linking
- All packages build to `dist/` directory with TypeScript compilation
- Each package has its own `tsconfig.json` extending the root configuration

### Testing Patterns
- Tests are located in `tests/` directories within each package
- Coverage thresholds set to 80% (branches, functions, lines, statements)
- Tests use Vitest with Node.js environment

### Authentication Integration
HTTP transport integrates with OAuth providers through the `@tylercoles/mcp-auth` abstraction. The generic OIDC provider in `@tylercoles/mcp-auth-oidc` supports both stateless bearer token auth and optional Passport.js session-based login flows. Pre-configured factories are available for Auth0, Okta, Keycloak, Google, Microsoft, and Authentik.

### Build System
The project uses TypeScript project references for efficient builds. The root `tsconfig.json` defines project references to all packages, enabling proper dependency resolution during builds.