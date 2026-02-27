# MCP Framework Analysis

**Date:** 2026-02-27
**Version:** 0.2.2
**Branch:** claude/analyze-framework-mTMvX

---

## Executive Summary

This is a well-engineered monorepo implementing a modular Model Context Protocol (MCP) framework. It contains **12 workspace packages**, **7 example servers**, and comprehensive tooling. The architecture is sound — transport-independent, plugin-based, with proper separation of concerns across authentication, transport, rate limiting, and client layers.

**Current health:**
- **Build:** Passes cleanly across all packages
- **Tests:** 656 passing (mcp-auth-authentik removed — its 24 failing tests are gone)
- **Lint:** Clean
- **Typecheck:** 12 TS6305 warnings (stale build outputs, not real type errors)

**Overall quality: 8/10** — Production-quality architecture with some rough edges to address.

---

## Package Inventory

The CLAUDE.md documents 6 packages but the repo actually contains **12**:

| Package | Purpose | LOC (src) | Tests | Status |
|---------|---------|-----------|-------|--------|
| **mcp-server** | Core framework, plugin architecture | ~2,900 | 274 pass (91% coverage) | Mature |
| **mcp-auth** | Auth abstractions & base implementations | ~800 | 80+ pass | Mature |
| **mcp-auth-oidc** | Generic OIDC provider with session support (Auth0, Okta, Authentik, etc.) | ~900 | 100+ pass | Mature |
| **mcp-transport-http** | HTTP transport w/ sessions, auth, rate limiting | ~480 | Pass | Mature |
| **mcp-transport-stdio** | stdio for local/CLI | ~80 | Pass | Mature |
| **mcp-transport-sse** | Legacy SSE transport | ~210 | Pass (limited) | Minimal tests |
| **mcp-transport-websocket** | WebSocket real-time transport | ~491 | Pass | Mature |
| **mcp-rate-limit** | Rate limiting (HTTP + WebSocket) | ~721 | Pass | Mature |
| **mcp-client** | Base client interfaces & abstractions | ~1,190 | Pass | Mature |
| **mcp-client-http** | HTTP client implementation | ~242 | Pass | Mature |
| **mcp-client-stdio** | stdio client implementation | ~240 | Pass | Mature |

**Undocumented in CLAUDE.md:** mcp-auth-oidc, mcp-client, mcp-client-http, mcp-client-stdio, mcp-rate-limit, mcp-transport-websocket

---

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │         MCPServer (Core)             │
                    │  Tools · Resources · Prompts         │
                    │  Completions · Sampling · Logging    │
                    │  Sessions · Tracing · Pagination     │
                    └──────────┬──────────────────────────┘
                               │
              ┌────────────────┼────────────────┬──────────────┐
              │                │                │              │
     ┌────────▼──────┐ ┌──────▼──────┐ ┌───────▼────┐ ┌──────▼──────┐
     │ HTTP Transport│ │stdio Transp.│ │SSE Transp. │ │ WS Transport│
     │ Express+Helmet│ │ SDK wrapper │ │  (legacy)  │ │  ws library │
     │+Auth+RateLimit│ │             │ │            │ │             │
     └───────────────┘ └─────────────┘ └────────────┘ └─────────────┘
              │
    ┌─────────┼──────────┐
    │         │          │
┌───▼───┐ ┌──▼────┐ ┌───▼────┐
│mcp-auth│ │Rate   │ │OIDC    │
│(base)  │ │Limit  │ │Provider│
└───┬────┘ └───────┘ └────────┘
    │
┌───▼──────────┐
│Authentik Auth │
└──────────────┘

CLIENT SIDE:
┌──────────────────────┐
│  mcp-client (base)   │
│  IMCPClient interface │
│  BaseMCPClient       │
└──────┬───────────────┘
       │
  ┌────┴─────┐
  │          │
┌─▼──────┐ ┌▼────────┐
│HTTP    │ │stdio    │
│Client  │ │Client   │
└────────┘ └─────────┘
```

### Key Architectural Strengths

1. **Transport independence** — Tools registered once, available on all transports simultaneously
2. **Plugin pattern** — Minimal Transport interface (just `start`/`stop`), easy to implement
3. **Context injection** — ToolContext flows through to handlers with user info, tracing, sessions
4. **OAuth 2.1 compliance** — PKCE mandatory, HTTPS enforced, RFC 9728 discovery
5. **Observability built-in** — Correlation IDs, request tracing, structured logging (RFC 5424)
6. **Session management** — Configurable persistence, expiration, LRU eviction
7. **Secure pagination** — HMAC-SHA256 signed cursors with TTL

---

## Core Server Deep Dive (mcp-server)

The MCPServer class at `packages/mcp-server/src/index.ts:1008` is the heart of the framework (~2,900 lines). Key APIs:

**Registration:** `registerTool()`, `registerResource()`, `registerResourceTemplate()`, `registerPrompt()`, `registerCompletion()`, `registerSampling()`

**Transport:** `useTransport()`, `useTransports()`, `start()`, `stop()`

**Context:** `setContext()`, `getContext()`, `setSessionContext()`, `getSessionContext()`

**Observability:** `log()` + 8 convenience levels, `startTrace()`, `endTrace()`, `getPerformanceTracker()`

**Notifications:** Progress, logging, cancellation, resource/tool/prompt list changes

**Pagination:** HMAC-signed cursors for tools, resources, prompts, templates

### Test Coverage (mcp-server)
- **91.22% statements** | 89.44% branches | 97.24% functions
- 274 tests across 13 test suites
- `errors.ts` and `types.ts` at 100%
- `tools.ts` at **9.37%** (essentially untested — possible dead code)

---

## Issues Found

### Resolved: mcp-auth-authentik Removed

The `mcp-auth-authentik` package (with 24 failing tests) has been removed and replaced by the generic `mcp-auth-oidc` provider, which now includes optional Passport.js session support and a `Providers.Authentik()` factory.

### High Priority

| # | Issue | Package | Details |
|---|-------|---------|---------|
| 1 | **Monolithic class** | mcp-server | `index.ts` is ~2,900 lines in a single class. Should decompose into ToolRegistry, ResourceRegistry, CompletionSystem, etc. |
| 2 | ~~Default session secret~~ | ~~mcp-auth-authentik~~ | Resolved: Package removed. OIDC provider requires explicit `session.secret` config. |
| 3 | **tools.ts untested** | mcp-server | 0% function coverage. Exports `createSuccessResult`, `createErrorResult`, `createSuccessObjectResult` — possibly dead code. |
| 4 | **CLAUDE.md outdated** | root | Documents 6 packages, repo has 12. Missing client, rate-limit, websocket, OIDC packages. |
| 5 | **JWT tokens not signature-verified** | mcp-auth-oidc | Decodes JWTs without JWKS verification. Code acknowledges this with comments. |
| 6 | **Pagination HMAC may not be cryptographic** | mcp-server | Previous analysis flagged `createHMAC()` as using a simple hash loop. Should use `crypto.createHmac()`. |

### Medium Priority

| # | Issue | Package | Details |
|---|-------|---------|---------|
| 7 | SSE session ID in query string | mcp-transport-sse | Insecure — IDs should be in headers like HTTP transport |
| 8 | SSE 10MB body limit | mcp-transport-sse | 10x larger than HTTP's 1MB. DoS vector. |
| 9 | ~~Dynamic registration always advertised~~ | ~~mcp-auth-authentik~~ | Resolved: Package removed. |
| 10 | Unused `propagateErrors` param | mcp-server | `handleCompletion()` accepts but never uses this parameter |
| 11 | Fragile Zod detection | mcp-server | Checks `_def`/`shape` internal properties instead of Zod public API |
| 12 | Notifications use `console.error` | mcp-server | Should use the structured logging system |
| 13 | SSE transport minimal tests | mcp-transport-sse | No SSE connection, message, session lifecycle, or cleanup tests |
| 14 | Deprecated dependencies | root | ESLint 8.x (deprecated), supertest 6.x, rimraf 3.x, glob 7.x |
| 15 | HTTP transport session cleanup gap | mcp-transport-http | No timeout for sessions that never close; stale transports accumulate |
| 16 | In-memory state everywhere | multiple | PKCE maps, sessions, rate limits, pagination — no distributed/clustering story |

### Low Priority

| # | Issue | Package | Details |
|---|-------|---------|---------|
| 17 | No transport-level metrics | all transports | No connection counts, latency, error rates |
| 18 | No config validation schemas | transports | Invalid ports/hosts not caught until listen time |
| 19 | Pagination cursor TTL defaults to 1 hour | mcp-server | Undocumented; may be too long |
| 20 | Legacy `jest.config.js` | mcp-transport-stdio | Left from Jest migration |
| 21 | Discovery metadata never expires | auth packages | Long-running servers could serve stale OIDC config |
| 22 | `generateCursorSecret()` uses `Math.random()` | mcp-server | Not cryptographically secure |

---

## Transport Comparison

| Feature | stdio | HTTP | SSE | WebSocket |
|---------|-------|------|-----|-----------|
| **SDK Transport** | StdioServerTransport | StreamableHTTPServerTransport | SSEServerTransport (legacy) | Custom (ws) |
| **Auth Support** | None | Full OAuth 2.1 + custom | None | None |
| **Rate Limiting** | N/A | Yes (global + per-client) | No | Configurable |
| **Security Headers** | N/A | Helmet.js | CORS only | N/A |
| **Body Size Limit** | Unbounded | 1MB | 10MB | Configurable |
| **DNS Rebinding** | N/A | Yes (default) | Yes (default) | N/A |
| **Session Model** | None | Per-request sessions | Map-based | Per-connection |
| **Complexity** | ~80 LOC | ~480 LOC | ~210 LOC | ~491 LOC |
| **Use Case** | CLI/local | Production web | Legacy/streaming | Real-time |

---

## Dependency Health

**Core runtime (solid):**
- `@modelcontextprotocol/sdk` ^1.16.0 — actively maintained
- `express` ^4.x — stable
- `zod` ^3.x — solid validation
- `ws` ^8.x — standard WebSocket

**Needs upgrade:**
- `eslint` ^8.57 — deprecated, upgrade to 9.x flat config
- `supertest` ^6.x — deprecated, upgrade to 7.1.3+
- `rimraf` 3.x transitively — deprecated
- `glob` 7.x transitively — deprecated
- `@humanwhocodes/config-array` — deprecated ESLint internal

---

## Recommendations (Priority Order)

1. **Fix the 24 failing Authentik OAuth compliance tests** — Mock the discovery endpoint properly so HTTPS validation, error handling, and integration tests actually execute
2. **Update CLAUDE.md** to document all 12 packages
3. **Address the default session secret** — fail in production instead of using insecure fallback
4. **Add JWKS-based JWT signature verification** to both auth-authentik and auth-oidc
5. **Upgrade deprecated dependencies** (ESLint 9, supertest 7, rimraf 5+)
6. **Add proper tests for SSE transport** — currently has minimal coverage
7. **Break up the monolithic MCPServer class** — ~2,900 lines is too large for maintainability
8. **Audit tools.ts** — either add tests and use it, or remove if dead code
9. **Add session timeouts** to HTTP transport to prevent stale transport accumulation
10. **Consider distributed state** story for sessions, rate limits, PKCE state for multi-server deployments

---

## Summary

This is a **well-designed framework** with clean architecture and ambitious scope. The core server and HTTP transport are approaching production-readiness, the auth story is comprehensive with OAuth 2.1 compliance, and the examples demonstrate real capability.

The main gaps are security hardening (JWT verification, cryptographic HMAC, secret management), the failing Authentik test suite, the monolithic core file, and outdated documentation. For a v0.2.2 project, the foundation is solid. The plugin architecture and transport abstraction are the standout design wins.
