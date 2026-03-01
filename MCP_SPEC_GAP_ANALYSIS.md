# MCP Spec Gap Analysis: Framework vs 2025-11-25 Specification

**Date**: 2026-03-01
**Current SDK**: `@modelcontextprotocol/sdk` ^1.16.0
**Latest SDK**: `@modelcontextprotocol/sdk` 1.27.1 (supports 2025-11-25 spec)
**Current Protocol Version**: 2025-06-18 (per test files)
**Target Protocol Version**: 2025-11-25

---

## Phase 0: Foundation — SDK Upgrade [CRITICAL]

### Upgrade `@modelcontextprotocol/sdk` ^1.16.0 → ^1.27.1

**Affected packages** (all 8):
- `packages/mcp-server/package.json`
- `packages/mcp-client/package.json`
- `packages/mcp-client-http/package.json`
- `packages/mcp-client-stdio/package.json`
- `packages/mcp-transport-http/package.json`
- `packages/mcp-transport-stdio/package.json`
- `packages/mcp-transport-sse/package.json`
- `packages/mcp-transport-websocket/package.json`

**Why first**: The SDK v1.25+ carries the 2025-11-25 schema types (`Icon`, `outputSchema`, `structuredContent` types, new elicitation types, task types, etc.). Without upgrading, we can't reference the new types.

**Risk**: Breaking changes in SDK. The v1.25+ release notes mention Zod v4 compatibility changes and Express refactoring. Need to verify all existing tests pass after upgrade.

**Action items**:
1. Update all 8 `package.json` files
2. Run `npm install`
3. Run `npm run build` — fix any type errors
4. Run `npm test` — fix any test failures
5. Update protocol version references in tests from `2025-06-18` to `2025-11-25`

---

## Phase 1: Tool Enhancements [HIGH PRIORITY]

### 1A. Tool `outputSchema` Support — NOT IMPLEMENTED

**Spec requirement**: Tools can declare an `outputSchema` (JSON Schema) defining expected output structure. When present, servers MUST provide `structuredContent` conforming to this schema.

**Current state**: `tools.ts` already has `structuredContent` in `createSuccessObjectResult()`, but there's no way to declare `outputSchema` during tool registration.

**Files to modify**:
- `packages/mcp-server/src/tools.ts` — Add `outputSchema` to `SdkToolConfig`
- `packages/mcp-server/src/index.ts` — Add `outputSchema` to `ToolConfig`, `ToolInfo`, and wire it through `registerTool()` to the SDK server's tool registration

### 1B. Tool Icons — NOT IMPLEMENTED

**Spec requirement**: Tools can include an `icons` array for display in UIs.
```typescript
icons?: Array<{ src: string; mimeType?: string; sizes?: string[]; theme?: "light" | "dark" }>
```

**Files to modify**:
- `packages/mcp-server/src/tools.ts` — Add `icons` to `SdkToolConfig`
- `packages/mcp-server/src/index.ts` — Add `icons` to `ToolConfig`, `ToolInfo`, wire through registration

### 1C. Audio Content Type in Tool Results — NOT IMPLEMENTED

**Spec requirement**: Tool results can contain `type: "audio"` content with base64-encoded audio data.

**Current state**: `SdkToolResult` extends `CallToolResult` from SDK, so after SDK upgrade this type should be available automatically. No framework-level changes needed beyond SDK upgrade.

### 1D. Resource Links in Tool Results — NOT IMPLEMENTED

**Spec requirement**: Tool results can contain `type: "resource_link"` with URI, name, description, mimeType.

**Current state**: Same as audio — the SDK types should support this after upgrade. Framework helpers in `tools.ts` could add a `createResourceLinkResult()` helper.

**Files to modify**:
- `packages/mcp-server/src/tools.ts` — Add `createResourceLinkResult()` helper

### 1E. Tool Naming Validation — NOT IMPLEMENTED

**Spec requirement**: Tool names SHOULD be 1-128 chars, case-sensitive, only A-Z, a-z, 0-9, `_`, `-`, `.`

**Files to modify**:
- `packages/mcp-server/src/index.ts` — Add validation in `registerTool()` (warning, not error, since spec says SHOULD)

---

## Phase 2: Resource & Prompt Enhancements [MEDIUM PRIORITY]

### 2A. Resource Icons — NOT IMPLEMENTED

**Spec requirement**: Resources and resource templates can include `icons` array.

**Files to modify**:
- `packages/mcp-server/src/index.ts` — Add `icons` to `ResourceConfig`, `ResourceInfo`, `ResourceTemplateConfig`, `ResourceTemplateInfo`

### 2B. Prompt Icons — NOT IMPLEMENTED

**Spec requirement**: Prompts can include `icons` array.

**Files to modify**:
- `packages/mcp-server/src/index.ts` — Add `icons` to `PromptConfig`, `PromptInfo`

### 2C. Implementation Info Enhancements — NOT IMPLEMENTED

**Spec requirement**: `serverInfo`/`clientInfo` in initialization can include `title`, `description`, `icons`, `websiteUrl` fields.

**Current state**: `ServerConfig` only has `name` and `version`. These are passed directly to `new SDKMcpServer()`.

**Files to modify**:
- `packages/mcp-server/src/index.ts` — Extend `ServerConfig` with `title?`, `description?`, `icons?`, `websiteUrl?`; pass to SDK server
- `packages/mcp-client/src/index.ts` — Extend client config similarly

### 2D. Resource Subscriptions — NOT IMPLEMENTED

**Spec requirement**: Clients can subscribe to specific resources via `resources/subscribe` and `resources/unsubscribe`. Server sends `notifications/resources/updated` when subscribed resources change.

**Current state**: Server has `sendResourceUpdatedNotification(uri)` but no subscription management. No `resources/subscribe` or `resources/unsubscribe` handlers.

**Files to modify**:
- `packages/mcp-server/src/index.ts` — Add subscription tracking, register `resources/subscribe` and `resources/unsubscribe` handlers
- `packages/mcp-client/src/index.ts` — Add `subscribeResource(uri)` and `unsubscribeResource(uri)` methods

---

## Phase 3: Sampling Enhancements [MEDIUM PRIORITY]

### 3A. Sampling with Tools — NOT IMPLEMENTED

**Spec requirement**: Sampling requests can include `tools` and `toolChoice` parameters to enable tool use within LLM sampling. New content types `tool_use` and `tool_result` in messages. New `stopReason: "toolUse"`. Multi-turn tool loop support.

**Current state**:
- `SamplingMessage.content.type` only supports `'text' | 'image'` (missing `'audio'`, `'resource'`, `'tool_use'`, `'tool_result'`)
- `SamplingResponse.stopReason` only supports `'endTurn' | 'stopSequence' | 'maxTokens'` (missing `'toolUse'`)
- `SamplingRequest` has no `tools` or `toolChoice` fields
- No `sampling.tools` capability negotiation

**Files to modify**:
- `packages/mcp-server/src/index.ts`:
  - Update `SamplingMessage` content type union
  - Add `tools` and `toolChoice` to `SamplingRequest`
  - Add `'toolUse'` to `SamplingResponse.stopReason`
  - Add `sampling.tools` to capability negotiation
  - Update validation in sampling handler

### 3B. `includeContext` Deprecation — NEEDS UPDATE

**Spec requirement**: `includeContext` in sampling is soft-deprecated. Should still work but new implementations should not rely on it.

**Current state**: `SamplingRequest.includeContext` is typed as `boolean`. No deprecation notice.

**Action**: Add JSDoc deprecation annotation. No breaking change needed.

---

## Phase 4: Elicitation Overhaul [MEDIUM-HIGH PRIORITY]

### 4A. Elicitation Schema Alignment — NEEDS OVERHAUL

**Spec requirement**: The 2025-11-25 spec defines elicitation using a JSON Schema subset approach:
- Primitive types: `string` (with format), `number`, `integer`, `boolean`
- Enums via `enum` or `oneOf`/`anyOf` for labeled options
- Array with `items` for multi-select
- `default` values for all types
- `title` and `description` on each property
- Server sends `requestedSchema` as JSON Schema, not custom field types

**Current state**: Framework uses completely custom field types:
```typescript
type ElicitationFieldType = 'text' | 'number' | 'boolean' | 'select' | 'multiselect' |
  'textarea' | 'password' | 'email' | 'url' | 'date' | 'time' | 'datetime';
```
With custom validation: `pattern`, `min`, `max`, `minLength`, `maxLength`, `options[]`, `dependencies[]`.

**Impact**: This is a significant divergence. The current implementation is richer in some ways (more field types) but doesn't match the spec.

**Recommendation**: After SDK upgrade, the SDK types will define the spec-compliant elicitation schema. The framework should:
1. Adopt the SDK types as the primary API
2. Optionally keep the rich field types as a framework-level extension with a converter to spec-compliant schemas

**Files to modify**:
- `packages/mcp-client/src/index.ts` — Major refactor of elicitation types and validation
- `packages/mcp-server/src/index.ts` — Add server-side elicitation support (currently no `sendElicitationRequest()` method)

### 4B. URL Mode Elicitation — NOT IMPLEMENTED

**Spec requirement**: New `mode: "url"` for elicitation where server can redirect client to a URL for data collection. Includes:
- `elicitationId` parameter
- `notifications/elicitation/complete` notification
- `URLElicitationRequiredError` (code -32042)
- Capability: `elicitation: { form: {}, url: {} }`

**Files to modify**:
- `packages/mcp-server/src/index.ts` — Add URL mode elicitation support
- `packages/mcp-server/src/errors.ts` — Add `URLElicitationRequiredError`
- `packages/mcp-client/src/index.ts` — Handle URL mode responses

---

## Phase 5: Tasks (Experimental) [LOWER PRIORITY]

### 5A. Tasks System — NOT IMPLEMENTED

**Spec requirement**: Complete async task system for durable, long-running requests:
- Task states: `working`, `input_required`, `completed`, `failed`, `cancelled`
- Operations: `tasks/get`, `tasks/list`, `tasks/result`, `tasks/cancel`
- Server capabilities: `tasks: { list: boolean, cancel: boolean }`
- Request-level: `task: { ttl: number }` field on tool calls
- Response: `CreateTaskResult` with task ID, state, metadata
- Tool-level: `execution: { taskSupport: boolean }` on tool definitions
- Notifications: `notifications/tasks/status`
- Related tasks: `io.modelcontextprotocol/related-task` in `_meta`
- Polling: `pollInterval` field

**This is experimental in the spec.** Consider implementing basic support (task creation, status tracking, polling) without the full complexity.

**Files to modify**:
- `packages/mcp-server/src/index.ts` — Major addition: task manager, task handlers, task capabilities
- New file: `packages/mcp-server/src/tasks.ts` — Task types, state machine, storage
- `packages/mcp-client/src/index.ts` — Task polling, status handling

---

## Phase 6: Roots Support [LOWER PRIORITY]

### 6A. Roots — NOT IMPLEMENTED

**Spec requirement**: Clients can expose filesystem "roots" to servers via `roots/list`. Servers can request the list and receive `notifications/roots/list_changed`.

**Files to modify**:
- `packages/mcp-client/src/index.ts` — Add roots management, `roots/list` handler, `notifications/roots/list_changed` emission
- `packages/mcp-server/src/index.ts` — Add `requestRoots()` method, handle root change notifications

---

## Phase 7: Authorization Updates [MEDIUM PRIORITY]

### 7A. OAuth Client ID Metadata Documents — NOT IMPLEMENTED

**Spec requirement**: New recommended client registration mechanism using HTTPS URLs as client IDs pointing to metadata documents. `client_id_metadata_document_supported` in AS metadata.

**Current state**: Framework supports dynamic client registration and pre-registration, but not Client ID Metadata Documents.

**Files to modify**:
- `packages/mcp-auth/src/index.ts` — Add `client_id_metadata_document_supported` to discovery metadata
- `packages/mcp-auth-oidc/src/index.ts` — Add metadata document validation support

### 7B. OpenID Connect Discovery Enhancement — PARTIALLY IMPLEMENTED

**Spec requirement**: MCP clients MUST support both OAuth 2.0 AS metadata and OIDC Discovery. Must probe multiple well-known endpoints in priority order.

**Current state**: OIDC provider exists but may not probe all required endpoints in the correct order.

**Files to modify**:
- `packages/mcp-auth-oidc/src/index.ts` — Verify/add multi-endpoint discovery probing
- `packages/mcp-client-http/src/index.ts` — Add client-side discovery probing

### 7C. Scope Challenge in WWW-Authenticate — PARTIALLY IMPLEMENTED

**Spec requirement**:
- 401 responses SHOULD include `resource_metadata` and `scope` in `WWW-Authenticate`
- 403 responses with `insufficient_scope` should include specific scope requirements
- Step-up authorization flow for incremental consent

**Current state**:
- 401 includes `WWW-Authenticate: Bearer realm="...", resource="..."` (close but `resource_metadata` format differs)
- Basic `insufficient_scope` handling exists in registration error handling
- No step-up authorization flow

**Files to modify**:
- `packages/mcp-auth/src/index.ts` — Update `WWW-Authenticate` header format
- `packages/mcp-transport-http/src/index.ts` — Update 401 response header format to use `resource_metadata` instead of `resource`

### 7D. MCP-Protocol-Version Header — NOT IMPLEMENTED

**Spec requirement**: HTTP requests after initialization should include `MCP-Protocol-Version` header.

**Files to modify**:
- `packages/mcp-transport-http/src/index.ts` — Add header to responses
- `packages/mcp-client-http/src/index.ts` — Add header to requests

---

## Phase 8: Minor/Clarification Changes [LOW PRIORITY]

### 8A. JSON Schema 2020-12 Default — NEEDS VERIFICATION

**Spec requirement**: Input schemas and output schemas default to JSON Schema 2020-12 if no `$schema` field present.

**Action**: Verify framework doesn't assume a different draft. May need no changes.

### 8B. `_meta` Field Convention — NEEDS VERIFICATION

**Spec requirement**: Reserved key naming with `io.modelcontextprotocol/` prefix format.

**Action**: Ensure any `_meta` usage follows this convention.

### 8C. Content Annotations Enhancement — NEEDS VERIFICATION

**Spec requirement**: All content types support optional annotations with `audience`, `priority`, and `lastModified` fields.

**Current state**: Resources have annotations support. Need to verify tool results and prompt messages also support annotations.

---

## Summary Matrix

| Feature | Status | Priority | Effort |
|---------|--------|----------|--------|
| SDK Upgrade (^1.16 → ^1.27) | NOT DONE | Critical | Medium |
| Tool `outputSchema` | NOT IMPLEMENTED | High | Small |
| Tool/Resource/Prompt Icons | NOT IMPLEMENTED | High | Small |
| Audio content type | SDK UPGRADE | High | Tiny |
| Resource links in results | NOT IMPLEMENTED | Medium | Small |
| Tool name validation | NOT IMPLEMENTED | Medium | Small |
| Implementation info fields | NOT IMPLEMENTED | Medium | Small |
| Resource subscriptions | NOT IMPLEMENTED | Medium | Medium |
| Sampling with tools | NOT IMPLEMENTED | Medium | Large |
| `stopReason: "toolUse"` | NOT IMPLEMENTED | Medium | Small |
| Elicitation schema alignment | NEEDS OVERHAUL | Medium-High | Large |
| URL mode elicitation | NOT IMPLEMENTED | Medium | Medium |
| Tasks system | NOT IMPLEMENTED | Lower | Very Large |
| Roots support | NOT IMPLEMENTED | Lower | Medium |
| Client ID Metadata Docs | NOT IMPLEMENTED | Medium | Medium |
| OIDC discovery enhancement | PARTIAL | Medium | Small |
| Scope challenge / step-up | PARTIAL | Medium | Medium |
| MCP-Protocol-Version header | NOT IMPLEMENTED | Low | Tiny |

---

## Recommended Implementation Order

1. **Phase 0**: SDK Upgrade — unlocks all other work
2. **Phase 1**: Tool enhancements (outputSchema, icons, resource links, naming)
3. **Phase 2**: Resource/prompt enhancements (icons, impl info, subscriptions)
4. **Phase 3**: Sampling with tools
5. **Phase 4**: Elicitation overhaul
6. **Phase 7**: Auth updates
7. **Phase 6**: Roots support
8. **Phase 5**: Tasks (experimental)
9. **Phase 8**: Minor changes
