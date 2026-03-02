# MCP Specification Gap Analysis

**Date:** 2026-03-02
**Latest Spec Version:** 2025-11-25
**Framework Target Version:** 2025-06-18
**SDK Version:** @modelcontextprotocol/sdk ^1.27.1

---

## Summary

The framework currently targets MCP protocol version **2025-06-18**. The latest official spec is **2025-11-25**, which introduces several major new features. This document catalogs all gaps between the framework and the latest spec.

### Gap Severity Legend

- **CRITICAL** - Core spec feature entirely missing; blocks compliance
- **HIGH** - Major feature missing or substantially incomplete
- **MEDIUM** - Feature partially implemented or minor spec requirement missing
- **LOW** - Nice-to-have, cosmetic, or experimental feature

---

## 1. CRITICAL: Tasks (Experimental) — Entirely Missing

**Spec section:** `/specification/2025-11-25/basic/utilities/tasks`
**Status:** Not implemented at all

Tasks are a new experimental feature in 2025-11-25 that enable durable request tracking with polling and deferred result retrieval. This is a significant new capability for expensive computations and batch processing.

### What's needed:

**Server-side:**
- `tasks` capability declaration during initialization (`tasks.list`, `tasks.cancel`, `tasks.requests.tools.call`)
- `tasks/get` — poll for task status
- `tasks/result` — retrieve completed task results (blocks until terminal status)
- `tasks/list` — list all tasks with pagination
- `tasks/cancel` — cancel a running task
- `notifications/tasks/status` — optional notification on status changes
- Task lifecycle state machine: `working` → `input_required` / `completed` / `failed` / `cancelled`
- Task ID generation, TTL management, poll interval guidance
- Tool-level negotiation via `execution.taskSupport` (`required`, `optional`, `forbidden`)
- `io.modelcontextprotocol/related-task` metadata association
- `CreateTaskResult` response type for task-augmented requests
- `_meta.io.modelcontextprotocol/model-immediate-response` for model continuity

**Client-side:**
- `tasks` capability declaration (`tasks.requests.sampling.createMessage`, `tasks.requests.elicitation.create`)
- Task polling logic respecting `pollInterval`
- Task result retrieval
- Task cancellation support

### Affected packages:
- `mcp-server` — server-side task handling
- `mcp-client`, `mcp-client-http`, `mcp-client-stdio` — client-side task support

---

## 2. HIGH: Protocol Version Upgrade to 2025-11-25

**Current:** Framework hardcodes `2025-06-18` as `LATEST_PROTOCOL_VERSION`
**Required:** Support `2025-11-25` as the latest version

### What's needed:
- Update `LATEST_PROTOCOL_VERSION` in `packages/mcp-transport-http/src/index.ts`
- Add `2025-11-25` to `SUPPORTED_PROTOCOL_VERSIONS` array
- Update default `MCP-Protocol-Version` header in `packages/mcp-client-http/src/index.ts`
- Update all test fixtures referencing `2025-06-18`
- Update documentation and READMEs

---

## 3. HIGH: URL Mode Elicitation — Missing

**Spec section:** `/specification/2025-11-25/client/elicitation#url-elicitation-requests`
**Status:** Form mode implemented; URL mode missing

The 2025-11-25 spec adds a second elicitation mode (`url`) for out-of-band interactions (OAuth flows, payment processing, sensitive credential entry) that must NOT pass through the MCP client.

### What's needed:

**Server-side (sending URL elicitation requests):**
- Support `mode: "url"` in `elicitation/create` requests
- `url` and `elicitationId` parameters
- `notifications/elicitation/complete` notification when out-of-band interaction completes
- `URLElicitationRequiredError` (code `-32042`) error response with elicitation list

**Client-side (receiving URL elicitation requests):**
- Declare `elicitation.url` sub-capability (currently only `elicitation.form` exists)
- Handle `mode: "url"` requests — present URL to user for consent, open in secure browser
- Handle `notifications/elicitation/complete` notifications
- Handle `URLElicitationRequiredError` responses and auto-retry logic

### Affected packages:
- `mcp-server` — URL elicitation request creation, completion notification, error code
- `mcp-client` — URL elicitation handling

---

## 4. HIGH: Enhanced Elicitation Enum Schema — Partially Missing

**Spec section:** `/specification/2025-11-25/client/elicitation`
**Status:** Basic enum support exists; new titled/multi-select enums missing

The 2025-11-25 spec overhauls the elicitation enum schema to support:

### What's needed:
- **Single-select enum with titles** using `oneOf` + `const` + `title` pattern
- **Multi-select enum** using `type: "array"` with `items.enum`
- **Multi-select enum with titles** using `type: "array"` with `items.anyOf` containing `const`/`title`
- `minItems` / `maxItems` constraints on multi-select
- `default` values on all primitive schema types (string, number, boolean, enum)
- `pattern` field support on string schemas

---

## 5. HIGH: Tool Calling Support in Sampling — Missing

**Spec section:** `/specification/2025-11-25/client/sampling`
**Status:** Sampling implemented but missing `tools` and `toolChoice` parameters

The 2025-11-25 spec adds tool calling support to sampling requests, allowing servers to include tool definitions in sampling/createMessage requests.

### What's needed:
- `tools` parameter in `sampling/createMessage` — array of tool definitions
- `toolChoice` parameter — `auto`, `none`, or specific tool selection
- Update sampling types/interfaces to include these fields

### Affected packages:
- `mcp-server` — sampling request creation with tools
- `mcp-client` — handling tool-augmented sampling requests

---

## 6. MEDIUM: Icons Format Update

**Spec section:** `/specification/2025-11-25/server/tools`, etc.
**Status:** Icon support exists but may not match new array format

The 2025-11-25 spec defines icons as an **array** of objects with `src`, `mimeType`, and `sizes` fields:

```json
{
  "icons": [
    {
      "src": "https://example.com/icon.png",
      "mimeType": "image/png",
      "sizes": ["48x48"]
    }
  ]
}
```

### What's needed:
- Verify the framework's icon type definition matches the spec's array-of-objects format
- Ensure `src`, `mimeType`, `sizes[]` fields are supported
- Apply to: tools, resources, resource templates, prompts, server/client `Implementation` info

---

## 7. MEDIUM: OpenID Connect Discovery for Authorization Server

**Spec section:** `/specification/2025-11-25/basic/authorization`
**Status:** OAuth discovery implemented; OIDC discovery enhancement may be missing

The 2025-11-25 spec enhances authorization server discovery with support for [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) as an alternative to RFC 8414.

### What's needed:
- Support OIDC Discovery (`/.well-known/openid-configuration`) as a fallback or primary discovery mechanism
- Ensure `mcp-auth-oidc` package integrates this discovery path

---

## 8. MEDIUM: OAuth Client ID Metadata Documents

**Spec section:** Changelog item 8
**Status:** Not implemented

The 2025-11-25 spec adds support for OAuth Client ID Metadata Documents as a recommended client registration mechanism (alternative to dynamic client registration).

### What's needed:
- Support for client metadata document retrieval (RFC 7591 client metadata)
- Client-side support for presenting metadata documents during registration
- Server-side support for accepting metadata document-based registration

---

## 9. MEDIUM: Incremental Scope Consent via WWW-Authenticate

**Spec section:** Changelog item 3
**Status:** Not implemented

Enhanced authorization flows with incremental scope consent through the `WWW-Authenticate` header, plus making `WWW-Authenticate` optional with fallback to `.well-known` endpoint.

### What's needed:
- Parse `insufficient_scope` in `WWW-Authenticate` responses
- Trigger incremental authorization for additional scopes
- Support `.well-known/oauth-protected-resource` as fallback when `WWW-Authenticate` is absent

---

## 10. MEDIUM: Implementation `description` Field

**Spec section:** `/specification/2025-11-25/basic/lifecycle`
**Status:** `title`, `icons`, `websiteUrl` exist; `description` may be missing

The 2025-11-25 spec adds an optional `description` field to the `Implementation` interface used in `clientInfo` and `serverInfo` during initialization.

### What's needed:
- Add `description` field to server/client `Implementation` type
- Pass through in initialization handshake

---

## 11. MEDIUM: HTTP 403 Forbidden for Invalid Origin

**Spec section:** Transports, changelog item 3
**Status:** DNS rebinding protection exists, but may return wrong status code

The 2025-11-25 spec clarifies that servers MUST respond with HTTP 403 Forbidden (not just connection refusal) for invalid Origin headers in Streamable HTTP transport.

### What's needed:
- Verify HTTP transport returns 403 specifically for invalid Origin headers
- Update DNS rebinding protection in `mcp-transport-http`

---

## 12. MEDIUM: Polling SSE Streams

**Spec section:** Transports, changelog items 6-7
**Status:** Not explicitly supported

The 2025-11-25 spec allows servers to disconnect SSE streams at will to support polling patterns, and clarifies that:
- GET streams support polling
- Resumption is always via GET regardless of stream origin
- Event IDs should encode stream identity
- Disconnection includes server-initiated closure

### What's needed:
- Server-side support for intentional SSE stream disconnection for polling
- Client-side handling of server-initiated SSE closure without treating as error
- Event ID management encoding stream identity

---

## 13. LOW: Tool Name Guidance

**Spec section:** `/specification/2025-11-25/server/tools#tool-names`
**Status:** Already implemented

The framework already validates tool names per the 2025-11-25 spec (1-128 chars, A-Z a-z 0-9 _ - .). This appears compliant.

---

## 14. LOW: JSON Schema 2020-12 Default Dialect

**Spec section:** Changelog item 10
**Status:** Likely needs update

The 2025-11-25 spec establishes JSON Schema 2020-12 as the default dialect for MCP schema definitions (when no `$schema` field is present).

### What's needed:
- Ensure schema validation logic defaults to 2020-12 draft
- Document this assumption in schema validation code

---

## 15. LOW: Input Validation Errors as Tool Execution Errors

**Spec section:** Changelog item 5
**Status:** May need verification

The 2025-11-25 spec clarifies that input validation errors (e.g., date in wrong format) should be returned as Tool Execution Errors (`isError: true`) rather than Protocol Errors, to enable model self-correction.

### What's needed:
- Audit tool input validation to ensure validation failures return `isError: true` results rather than JSON-RPC error codes
- Update error handling in tool invocation path

---

## 16. LOW: Resource `size` Field

**Spec section:** `/specification/2025-11-25/server/resources`
**Status:** May be missing

The spec defines an optional `size` field (in bytes) on resource definitions.

### What's needed:
- Add optional `size` field to resource registration interface
- Pass through in `resources/list` responses

---

## Implementation Priority Recommendation

### Phase 1 — Protocol Version Upgrade (Foundation)
1. Update protocol version to 2025-11-25
2. Add `Implementation.description` field
3. Verify icon format compliance
4. Fix HTTP 403 for invalid Origin
5. Input validation as tool execution errors

### Phase 2 — Elicitation Enhancements
6. URL mode elicitation (server + client)
7. Enhanced enum schema (titled, multi-select)
8. Default values in elicitation schemas
9. `notifications/elicitation/complete`
10. `URLElicitationRequiredError` (-32042)

### Phase 3 — Sampling Enhancements
11. Tool calling support in sampling (`tools`, `toolChoice`)

### Phase 4 — Tasks (Experimental)
12. Server-side task handling
13. Client-side task support
14. Tool-level task negotiation

### Phase 5 — Auth Enhancements
15. OIDC Discovery support
16. OAuth Client ID Metadata Documents
17. Incremental scope consent

### Phase 6 — Transport Improvements
18. Polling SSE streams
19. JSON Schema 2020-12 default dialect

---

## Already Implemented (Compliant with 2025-06-18)

The following features from the 2025-06-18 spec are already implemented:

- Tools: list, call, list_changed notifications, annotations, structured output, output schema, resource links
- Resources: list, read, templates, subscribe/unsubscribe, list_changed, updated notifications
- Prompts: list, get, list_changed notifications, argument schemas
- Completions: prompt and resource reference completions
- Sampling: createMessage with model preferences, system prompt, content types
- Roots: list, list_changed notifications
- Elicitation: form mode with JSON schema
- Logging: RFC 5424 levels, structured data, namespaces
- Progress: notifications with token, value, total
- Cancellation: notifications with request ID and reason
- Pagination: cursor-based with HMAC security
- Ping: bidirectional keepalive
- Transports: stdio, Streamable HTTP, SSE (legacy), WebSocket (custom)
- Auth: OAuth 2.1, PKCE, dynamic client registration, protected resource metadata (RFC 9728)
- Content types: text, image, audio, resource, resource_link
- Annotations: audience, priority, lastModified
- Server metadata: name, version, title, icons, websiteUrl
- Tool name validation (1-128 chars, valid character set)
- DNS rebinding protection
- Session management (Mcp-Session-Id)
- MCP-Protocol-Version header
