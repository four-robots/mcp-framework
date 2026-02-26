# MCP Framework Analysis

**Date**: 2026-02-26
**Version**: 0.2.2

---

## Project Overview

A modular framework for building Model Context Protocol (MCP) servers using npm workspaces. The framework provides a plugin architecture with pluggable transports and authentication providers.

**12 packages** across `packages/`, plus **7 example apps** in `examples/`. Total ~9,000 LOC in package source files.

| Package | LOC | Role | Maturity |
|---------|-----|------|----------|
| `mcp-server` | 2,954 | Core framework — tool/resource/prompt registration, pagination, logging, sessions, tracing | High |
| `mcp-client` | 1,190 | Base client abstraction with enhanced features (retry, caching, health) | Medium |
| `mcp-auth` | 589 | Auth abstraction — OAuth 2.1, PKCE, bearer, session, discovery routes | High |
| `mcp-auth-authentik` | 1,022 | Authentik OIDC provider with Passport.js, dynamic client registration | High |
| `mcp-auth-oidc` | 777 | Generic OIDC provider with pre-built factories (Auth0, Okta, Google, etc.) | Medium |
| `mcp-rate-limit` | 721 | Memory-based rate limiter with sliding windows and Express middleware | Medium |
| `mcp-transport-http` | 483 | HTTP/StreamableHTTP transport with session management, Helmet, CORS | High |
| `mcp-transport-websocket` | 491 | WebSocket transport with heartbeat and connection state machine | Low |
| `mcp-transport-stdio` | 88 | stdio transport for CLI/local use | High |
| `mcp-transport-sse` | 216 | Legacy SSE transport for backwards compat | Low |
| `mcp-client-http` | 242 | HTTP client implementation | Medium |
| `mcp-client-stdio` | 240 | stdio client implementation | Medium |

---

## Strengths

### 1. Clean Architecture

The **Transport interface** (`packages/mcp-server/src/index.ts:181-184`) is simple: just `start(server)` and `stop()`. This makes adding new transports trivial.

The **plugin model** works well — tools are registered once and served over any transport simultaneously. `MCPServer.useTransport()` / `useTransports()` is intuitive.

### 2. Comprehensive MCP Protocol Coverage

The core server supports the full MCP feature set:
- **Tools** with Zod schema validation and context injection
- **Resources** (static + templates with URI pattern matching)
- **Prompts** with argument schemas
- **Completions** for autocomplete
- **Sampling** (createMessage) for LLM requests back to the client
- **Notifications** (progress, logging, resource/tool/prompt list changes, cancellation)
- **Pagination** with HMAC-signed cursors
- **Structured logging** following RFC 5424 levels
- **Request tracing** with correlation IDs, trace/span IDs, performance metrics
- **Session management** with TTL, eviction, and cleanup

### 3. Strong Auth Story

- OAuth 2.1 with PKCE (RFC 7636) in the base auth package
- Discovery routes (RFC 9728) for OAuth Authorization Server Metadata
- Three concrete auth strategies: Authentik, generic OIDC, and dev/no-auth
- OIDC package ships pre-configured factories for Auth0, Okta, Keycloak, Google, Microsoft
- Dynamic client registration support via Authentik API

### 4. Good Developer Experience

- 7 example apps ranging from simple echo servers to a full kanban board with WebSocket UI
- Both module-style (`registerTool(toolModule)`) and legacy (`registerTool(name, config, handler)`) APIs
- Helper utilities: `createSuccessResult()`, `createErrorResult()`, `createSuccessObjectResult()`
- `MCPErrorFactory` with typed error constructors for JSON-RPC errors

### 5. Testing

- **41 test files** across all packages
- Tests cover core functionality, edge cases, error handling, OAuth compliance
- Vitest configured with 80% coverage thresholds (branches, functions, lines, statements)
- CI runs tests on Node 18, 20, and 22

### 6. Examples

- `echo-server` — shows stdio, HTTP, OAuth, multi-transport, and custom router patterns
- `kanban-board` — full-stack app with React frontend, SQLite, WebSocket real-time sync
- `memory-server` — persistent memory with NATS integration
- `jira-server`, `ide-server` — real-world use cases

---

## Issues & Concerns

### Critical

1. **JWT tokens are never signature-verified** — Both `mcp-auth-authentik` (line 524) and `mcp-auth-oidc` (line 392) decode JWTs without verifying signatures against JWKS. Comments in code acknowledge this. An attacker could forge any claims.

2. **Hardcoded default session secret** — `mcp-auth-authentik` uses `"authentik-secret-change-me"` as default (line 232). No warning emitted if unchanged. This is a production security risk.

3. **HMAC "implementation" in pagination is not cryptographic** — `MCPServer.createHMAC()` (line 1149) uses a simple character-code hash loop, not a real HMAC. The comment says "Simple hash for demonstration — in production use proper HMAC." Cursor tokens can be forged.

### Significant

4. **Root tsconfig.json is missing references** — `mcp-transport-sse`, `mcp-client`, `mcp-client-http`, and `mcp-client-stdio` are not listed in `tsconfig.json` references (only 8 of 12 packages referenced). This means `tsc --build` and type-checking from root will skip these packages.

5. **WebSocket transport doesn't actually integrate with MCP** — The WebSocket transport (`mcp-transport-websocket/src/index.ts`) has connection management and heartbeat but the actual MCP message handling at line 407 is a "simplified approach" that just logs method names without executing anything. It can't route to registered tools.

6. **SSE transport has no auth support** — Unlike HTTP transport, SSE transport has zero authentication integration. No auth provider pluggability, no context injection, no user info.

7. **In-memory state everywhere** — PKCE state maps (`mcp-auth/src/index.ts:215`), session data, rate limit windows, pagination — all in-memory with no clustering/distributed story. Fine for single-server dev, problematic for production.

8. **HTTP transport session cleanup gap** — The `transports` Map in HTTP transport (line 55) grows with each new session. There's an `onclose` handler but no timeout for sessions that never close. Long-running servers accumulate stale transport instances.

9. **DNS rebinding protection disabled by default** in HTTP transport (`enableDnsRebindingProtection: false` at line 63). Should be true by default for production safety.

### Minor

10. **`mcp-server/src/index.ts` is 2,954 lines** — This single file contains interfaces, enums, 5 classes (SessionManager, CorrelationManager, PerformanceTracker, RequestTracer, MCPServer), and all registration/notification logic. Could benefit from splitting into separate files.

11. **`generateCursorSecret()` uses `Math.random()`** (line 1092) instead of `crypto.randomBytes()`. Not cryptographically secure.

12. **Discovery metadata caches never expire** in both Authentik (line 329) and OIDC (line 174) providers. Long-running servers could serve stale OIDC configuration.

13. **CORS default is `origin: true`** in SSE transport (line 49) — allows any origin. HTTP transport is more careful but still enables credentials by default.

14. **Race condition in HTTP transport session creation** — Line 215 does check-then-act on sessionId without atomicity. Concurrent requests could create duplicate transports for the same session.

---

## Architecture

### Dependency Graph

```
mcp-server (core, no framework deps)
  +-- mcp-transport-stdio (depends on: mcp-server, @modelcontextprotocol/sdk)
  +-- mcp-transport-http  (depends on: mcp-server, mcp-auth, express, helmet, cors)
  +-- mcp-transport-sse   (depends on: mcp-server, express, cors)
  +-- mcp-transport-websocket (depends on: mcp-server, ws)
  +-- mcp-auth            (depends on: express, crypto)
  |   +-- mcp-auth-authentik (depends on: mcp-auth, passport, express-session)
  |   +-- mcp-auth-oidc     (depends on: mcp-auth, zod)
  +-- mcp-rate-limit      (depends on: zod, express)
  +-- mcp-client          (depends on: @modelcontextprotocol/sdk)
  |   +-- mcp-client-http  (depends on: mcp-client)
  |   +-- mcp-client-stdio (depends on: mcp-client)
  +-- examples/* (consume framework packages)
```

### What's Working Well

- The core server -> transport -> auth layering is clean
- Tools/resources/prompts are spec-compliant
- The SDK integration (`@modelcontextprotocol/sdk`) is done properly — framework wraps the SDK rather than reimplementing protocol details

### What Needs Attention

- Client packages seem newer and less battle-tested than server packages
- WebSocket and SSE transports are clearly secondary to HTTP and stdio
- No integration tests that verify end-to-end transport -> server -> tool flows
- The auth packages are feature-rich but have the JWT verification gap

---

## Summary Assessment

This is a **well-designed early-stage framework** with clean architecture and ambitious scope. The core server and HTTP transport are production-approaching, the auth story is comprehensive, and the examples demonstrate real capability.

The main gaps are:
- Security hardening (JWT verification, real HMAC, secret management)
- The WebSocket transport being incomplete
- The monolithic core server file
- Missing tsconfig references for 4 packages

For a v0.2.2 project, the foundation is solid. The plugin architecture and transport abstraction are the standout design wins.
