# Changelog

All notable changes to the MCP Framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2024-12-17

### Added
- **Core Framework**: Complete rewrite with plugin architecture
- **Multi-Transport Support**: stdio, HTTP, WebSocket, SSE transports
- **Authentication System**: OAuth 2.1 with PKCE support
- **Enhanced Client Libraries**: Advanced MCP client with additional features
- **Rate Limiting**: Built-in rate limiting middleware
- **Comprehensive Testing**: Full test coverage with Vitest
- **Docker Support**: Production-ready Docker configurations
- **Documentation**: Complete documentation suite

### Framework Components
- `@tylercoles/mcp-server` - Core framework with plugin architecture
- `@tylercoles/mcp-transport-stdio` - stdio transport for CLI usage
- `@tylercoles/mcp-transport-http` - HTTP transport with session management
- `@tylercoles/mcp-transport-websocket` - WebSocket transport for real-time apps
- `@tylercoles/mcp-transport-sse` - Server-sent events transport
- `@tylercoles/mcp-auth` - Authentication abstractions
- `@tylercoles/mcp-auth-oidc` - Generic OIDC authentication provider with session support
- `@tylercoles/mcp-client` - Enhanced MCP client
- `@tylercoles/mcp-client-http` - HTTP client implementation
- `@tylercoles/mcp-client-stdio` - stdio client implementation
- `@tylercoles/mcp-rate-limit` - Rate limiting middleware

### Examples
- **Echo Server**: Basic MCP server with multiple transport examples
- **Kanban Board**: Full-featured kanban application with Docker support
- **Memory Server**: Distributed memory server with NATS integration
- **Multi-Transport Server**: Server running on multiple transports
- **File Server**: File operations MCP server
- **IDE Server**: IDE integration examples
- **JIRA Server**: JIRA integration MCP server
- **SSE Server**: Server-sent events example

### Security Features
- OAuth 2.1 compliance with PKCE
- Session management with secure cookies
- Rate limiting and CORS protection
- Input validation with Zod schemas
- Security headers with Helmet.js
- Comprehensive security documentation

### Developer Experience
- TypeScript support with full type definitions
- Comprehensive test coverage (80%+ threshold)
- Development tools and scripts
- Hot reload in development mode
- Extensive documentation and examples
- Contributing guidelines and security policies

### Migration Notes
- **Breaking Change**: Complete API redesign from 0.1.x
- **Migration Required**: 0.1.x applications need to be rewritten
- **New Architecture**: Plugin-based system with transport independence
- **Enhanced Security**: OAuth 2.1 replaces basic authentication

## [0.1.x] - Previous Versions

### Deprecated
- Legacy architecture has been completely replaced
- Basic authentication system removed in favor of OAuth 2.1
- Single transport design replaced with multi-transport support

---

## Release Process

### Version Numbering
- **Major** (x.0.0): Breaking changes, API redesign
- **Minor** (0.x.0): New features, backwards compatible
- **Patch** (0.0.x): Bug fixes, security updates

### Release Channels
- **Stable**: Production-ready releases
- **Beta**: Pre-release testing versions
- **Alpha**: Early development versions

### Supported Versions
- **0.2.x**: Current stable release with full support
- **0.1.x**: Deprecated, no longer supported

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:
- Development setup
- Code style guidelines
- Testing requirements
- Pull request process

## Security

For security issues, please see our [Security Policy](SECURITY.md) or contact security@tylercoles.dev.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.