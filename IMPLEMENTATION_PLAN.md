# MCP 2025-11-25 Spec Implementation Plan

## Overview

This plan covers implementing all gaps identified in `MCP_SPEC_GAP_ANALYSIS.md` to bring the framework to full 2025-11-25 compliance. The SDK (`@modelcontextprotocol/sdk@^1.27.1`) already exports all needed types and schemas for 2025-11-25 features including tasks.

**Organized into 6 phases, 16 features, ~35 file changes.**

---

## Phase 1: Protocol Version Upgrade & Quick Wins (Foundation)

### 1.1 Protocol Version Update

**Files to modify:**
- `packages/mcp-transport-http/src/index.ts`
- `packages/mcp-client-http/src/index.ts`

**Changes:**
```typescript
// packages/mcp-transport-http/src/index.ts
// Before:
export const SUPPORTED_PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26'] as const;
export const LATEST_PROTOCOL_VERSION = '2025-06-18';

// After:
export const SUPPORTED_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26'] as const;
export const LATEST_PROTOCOL_VERSION = '2025-11-25';
```

```typescript
// packages/mcp-client-http/src/index.ts
// Update default MCP-Protocol-Version header from '2025-06-18' to '2025-11-25'
```

**Test updates:**
- `packages/mcp-transport-http/tests/*.test.ts` — update any protocol version assertions
- `packages/mcp-client-http/tests/http-client.test.ts` — update default header expectations

### 1.2 Implementation `description` Field

**Status:** Already implemented in `ServerConfig` (line 1024) and passed to SDK `Implementation` object (line 1183). **No changes needed — verify with test.**

### 1.3 Icons Format Verification

**Status:** Already using SDK's `Icon[]` type on tools, resources, prompts, and server info. The SDK type matches the spec format (`src`, `mimeType`, `sizes`). **No changes needed — verify with test.**

### 1.4 HTTP 403 for Invalid Origin

**File to modify:** `packages/mcp-transport-http/src/index.ts`

**Change:** Add explicit Origin header validation middleware before route handling that returns 403 for invalid Origins. Currently DNS rebinding protection exists but may not return the correct status code.

**New test:** `packages/mcp-transport-http/tests/origin-validation.test.ts`

### 1.5 Input Validation as Tool Execution Errors

**File to modify:** `packages/mcp-server/src/index.ts`

**Change:** In the tool call handler (where Zod schema validation occurs), catch validation errors and return `{ isError: true, content: [...] }` instead of throwing JSON-RPC protocol errors. This allows LLMs to self-correct.

**Test update:** `packages/mcp-server/tests/index.test.ts` — add test for validation error returning isError result

### 1.6 Resource `size` Field

**Files to modify:**
- `packages/mcp-server/src/index.ts` — add optional `size?: number` to `ResourceConfig`, `ResourceInfo`

**Test update:** `packages/mcp-server/tests/index.test.ts` — register resource with size, verify in list

### 1.7 JSON Schema 2020-12 Default Dialect

**Files to modify:**
- `packages/mcp-server/src/index.ts` — add comment documenting 2020-12 as default dialect
- No runtime changes needed since Zod generates compatible schemas and we don't do schema dialect validation

---

## Phase 2: Elicitation Enhancements

### 2.1 URL Mode Elicitation

**Files to modify:**
- `packages/mcp-server/src/index.ts` — rewrite `sendUrlElicitationRequest()` to use proper `mode: "url"` params
- `packages/mcp-server/src/errors.ts` — update `UrlElicitationRequiredError` to use error code `-32042`
- `packages/mcp-client/src/index.ts` — add URL elicitation handler, declare `elicitation.url` capability

**New SDK imports (mcp-server):**
```typescript
import {
  ElicitRequestURLParams,       // URL mode params type
  ElicitationCompleteNotification, // Completion notification type
} from "@modelcontextprotocol/sdk/types.js";
```

**Server changes (`mcp-server/src/index.ts`):**
1. Add `sendUrlElicitationRequest(url, message, elicitationId)` with proper `mode: "url"` params:
   ```typescript
   params: {
     mode: 'url',
     message,
     url,
     elicitationId,
   }
   ```
2. Add `sendElicitationComplete(elicitationId)` method to send `notifications/elicitation/complete`
3. Update capability declaration to include `elicitation: { form: true, url: true }`

**Error code change (`errors.ts`):**
```typescript
// Add new error code:
UrlElicitationRequired = -32042

// Update UrlElicitationRequiredError to use -32042 instead of ServerError
```

**Client changes (`mcp-client/src/index.ts`):**
1. Add `UrlElicitationHandler` type for handling URL mode requests
2. Add `registerUrlElicitationHandler(handler)` method
3. Handle `mode: "url"` in elicitation request processing
4. Add `handleElicitationComplete(notification)` for completion notifications
5. Declare `elicitation.url` in client capabilities

**New tests:**
- `packages/mcp-server/tests/url-elicitation.test.ts`
- `packages/mcp-client/tests/url-elicitation.test.ts`

### 2.2 Enhanced Elicitation Enum Schema

**Files to modify:**
- `packages/mcp-client/src/index.ts` — update validation logic to handle new schema patterns

**Client validation updates:**
1. Support `oneOf` with `const`/`title` for single-select titled enums
2. Support `type: "array"` with `items.enum` for multi-select
3. Support `type: "array"` with `items.anyOf` containing `const`/`title` for titled multi-select
4. Validate `minItems`/`maxItems` on array schemas
5. Support `default` values on all primitive types
6. Support `pattern` on string schemas

**Test update:** `packages/mcp-client/tests/elicitation.test.ts` — add tests for each new schema pattern

---

## Phase 3: Sampling Enhancements

### 3.1 Tool Calling in Sampling

**Status:** Types already exist (`SamplingToolDefinition`, `SamplingToolChoice`, `supportedToolCalling`). Need to verify proper pass-through and validation.

**Files to verify/modify:**
- `packages/mcp-server/src/index.ts` — ensure `tools` and `toolChoice` are passed to SDK's `createMessage` request
- `packages/mcp-server/tests/sampling.test.ts` — verify tool calling tests exist and pass

**Changes needed:**
1. In `createSamplingMessage()`, pass `tools` and `toolChoice` to the SDK request
2. Validate that `tools` array entries have valid `inputSchema`
3. Validate `toolChoice` format matches `{ type: 'auto' }`, `{ type: 'none' }`, or `{ type: 'tool', name: string }`
4. When `supportedToolCalling` is false, reject requests that include `tools`

---

## Phase 4: Tasks (Experimental) — Largest Feature

This is the most substantial addition. We'll leverage SDK types/schemas and the experimental TaskStore/InMemoryTaskStore.

### 4.1 New File: Task Types & Store

**New file:** `packages/mcp-server/src/tasks.ts`

**New SDK imports:**
```typescript
import {
  Task, TaskStatus, TaskMetadata, CreateTaskResult,
  GetTaskRequest, GetTaskResult,
  GetTaskPayloadRequest, GetTaskPayloadResult,
  CancelTaskRequest, CancelTaskResult,
  ListTasksRequest, ListTasksResult,
  TaskStatusNotification, TaskStatusNotificationParams,
  RelatedTaskMetadata, ToolExecution, TaskCreationParams,
  // Schemas
  GetTaskRequestSchema, GetTaskPayloadRequestSchema,
  CancelTaskRequestSchema, ListTasksRequestSchema,
  GetTaskResultSchema, GetTaskPayloadResultSchema,
  CancelTaskResultSchema, ListTasksResultSchema,
  CreateTaskResultSchema, TaskStatusNotificationSchema,
} from "@modelcontextprotocol/sdk/types.js";
```

**Contents:**
1. `TaskConfig` interface — server configuration for task behavior:
   ```typescript
   interface TaskConfig {
     defaultTTL?: number;        // Default TTL in ms (e.g., 3600000 = 1hr)
     defaultPollInterval?: number; // Default poll interval in ms (e.g., 5000)
     maxTasks?: number;           // Max concurrent tasks
     cleanupInterval?: number;    // How often to clean expired tasks (ms)
   }
   ```

2. `InMemoryTaskStore` class — stores task state in memory:
   ```typescript
   class InMemoryTaskStore {
     private tasks: Map<string, StoredTask>;
     private results: Map<string, any>;
     private cleanupTimer: NodeJS.Timeout;

     createTask(options: CreateTaskOptions): Task;
     getTask(taskId: string): Task | null;
     updateTaskStatus(taskId: string, status: TaskStatus, statusMessage?: string): Task;
     storeResult(taskId: string, result: any): void;
     getResult(taskId: string): any | null;
     listTasks(cursor?: string, limit?: number): { tasks: Task[]; nextCursor?: string };
     cancelTask(taskId: string): Task;
     cleanup(): void;
     destroy(): void;  // Clear cleanup timer
   }
   ```

3. `TaskManager` class — orchestrates task lifecycle:
   ```typescript
   class TaskManager {
     private store: InMemoryTaskStore;
     private config: TaskConfig;

     createTask(ttl?: number, pollInterval?: number): Task;
     getTask(taskId: string): Task | null;
     updateStatus(taskId: string, status: TaskStatus, message?: string): Task;
     setResult(taskId: string, result: any): void;
     getResult(taskId: string): any | null;
     listTasks(cursor?: string, limit?: number): ListTasksResult;
     cancelTask(taskId: string): Task;
     isTerminal(status: TaskStatus): boolean;
     destroy(): void;
   }
   ```

4. Re-export SDK types for consumers

### 4.2 Server-Side Task Support

**File to modify:** `packages/mcp-server/src/index.ts`

**Changes:**

1. **New imports:** Import from `./tasks.js` and SDK types/schemas

2. **New capability declaration:** Add `tasks` to server capabilities:
   ```typescript
   // In constructor or capability registration
   capabilities.tasks = {
     list: true,
     cancel: true,
     requests: {
       tools: { call: true },
     },
   };
   ```

3. **New private members:**
   ```typescript
   private taskManager: TaskManager | null = null;
   private taskConfig: TaskConfig | null = null;
   ```

4. **New public method: `enableTasks(config?: TaskConfig)`**
   - Creates TaskManager with config
   - Registers 4 SDK request handlers:
     - `GetTaskRequestSchema` → `tasks/get` handler
     - `GetTaskPayloadRequestSchema` → `tasks/result` handler
     - `ListTasksRequestSchema` → `tasks/list` handler
     - `CancelTaskRequestSchema` → `tasks/cancel` handler

5. **Handler implementations:**

   `tasks/get` handler:
   ```typescript
   // Lookup task by ID, return Task or error
   const task = this.taskManager.getTask(params.taskId);
   if (!task) throw MCPErrorFactory.create(-32004, 'Task not found');
   return task; // GetTaskResult
   ```

   `tasks/result` handler:
   ```typescript
   // Return result if terminal, otherwise return task status
   const task = this.taskManager.getTask(params.taskId);
   if (!task) throw MCPErrorFactory.create(-32004, 'Task not found');
   if (!this.taskManager.isTerminal(task.status)) {
     // Return task status (client should poll)
     return { task }; // or could block — spec says "may block"
   }
   const result = this.taskManager.getResult(params.taskId);
   return result; // GetTaskPayloadResult
   ```

   `tasks/list` handler:
   ```typescript
   // Paginated list using existing pagination helpers
   return this.taskManager.listTasks(params?.cursor, pageSize);
   ```

   `tasks/cancel` handler:
   ```typescript
   const task = this.taskManager.cancelTask(params.taskId);
   return task; // CancelTaskResult
   ```

6. **Modified `callTool()` method for task-augmented calls:**
   When a tool call request includes `_meta.task` (TaskMetadata), create a task and return `CreateTaskResult` instead of blocking for the tool result:
   ```typescript
   // In tool call handler:
   if (request._meta?.task && this.taskManager) {
     const task = this.taskManager.createTask(request._meta.task.ttl);
     // Run tool handler asynchronously
     this.executeToolAsync(toolName, args, task.taskId, context);
     return { task }; // CreateTaskResult
   }
   // Otherwise: synchronous execution as before
   ```

7. **New private method: `executeToolAsync()`**
   ```typescript
   private async executeToolAsync(name, args, taskId, context) {
     try {
       const result = await handler(args, context);
       this.taskManager.updateStatus(taskId, 'completed');
       this.taskManager.setResult(taskId, result);
       this.sendTaskStatusNotification(taskId);
     } catch (error) {
       this.taskManager.updateStatus(taskId, 'failed', error.message);
       this.sendTaskStatusNotification(taskId);
     }
   }
   ```

8. **New private method: `sendTaskStatusNotification()`**
   ```typescript
   private sendTaskStatusNotification(taskId: string) {
     const task = this.taskManager.getTask(taskId);
     if (task) {
       this.sdkServer.server.notification({
         method: 'notifications/tasks/status',
         params: task,
       });
     }
   }
   ```

9. **Tool-level task negotiation:**
   Add optional `execution?: ToolExecution` to `ToolConfig`:
   ```typescript
   interface ToolConfig {
     // ...existing fields...
     execution?: { taskSupport?: 'forbidden' | 'optional' | 'required' };
   }
   ```
   In tool registration, pass `execution` to SDK tool definition.
   In task-augmented call handler, check tool's `taskSupport`:
   - `'forbidden'` → reject with error
   - `'required'` → require task metadata
   - `'optional'` (default) → allow either

10. **Export task types** from `packages/mcp-server/src/index.ts`

### 4.3 Client-Side Task Support

**File to modify:** `packages/mcp-client/src/index.ts`

**Changes:**

1. **New imports:** SDK task types

2. **New interfaces:**
   ```typescript
   interface TaskPollingOptions {
     pollInterval?: number;  // Override task's suggested interval
     maxPolls?: number;      // Max poll attempts before giving up
     timeout?: number;       // Total timeout in ms
     onStatus?: (task: Task) => void;  // Status change callback
   }
   ```

3. **New methods on `IEnhancedMCPClient`:**
   ```typescript
   // Poll for task status
   getTask(taskId: string): Promise<Task>;
   // Get task result (may block)
   getTaskResult(taskId: string): Promise<any>;
   // List tasks
   listTasks(cursor?: string): Promise<ListTasksResult>;
   // Cancel a task
   cancelTask(taskId: string): Promise<Task>;
   // High-level: poll until terminal, return result
   awaitTaskResult(taskId: string, options?: TaskPollingOptions): Promise<any>;
   ```

4. **Implementation in `BaseMCPClient`:**

   `getTask()`:
   ```typescript
   async getTask(taskId: string): Promise<Task> {
     return this.sendRequest('tasks/get', { taskId });
   }
   ```

   `getTaskResult()`:
   ```typescript
   async getTaskResult(taskId: string): Promise<any> {
     return this.sendRequest('tasks/result', { taskId });
   }
   ```

   `awaitTaskResult()`:
   ```typescript
   async awaitTaskResult(taskId: string, options?: TaskPollingOptions): Promise<any> {
     const maxPolls = options?.maxPolls ?? 100;
     const timeout = options?.timeout ?? 300000; // 5 min default
     const start = Date.now();
     let polls = 0;

     while (polls < maxPolls && (Date.now() - start) < timeout) {
       const task = await this.getTask(taskId);
       options?.onStatus?.(task);

       if (this.isTerminalStatus(task.status)) {
         if (task.status === 'completed') {
           return this.getTaskResult(taskId);
         }
         throw new Error(`Task ${task.status}: ${task.statusMessage ?? ''}`);
       }

       const interval = options?.pollInterval ?? task.pollInterval ?? 5000;
       await new Promise(r => setTimeout(r, interval));
       polls++;
     }
     throw new Error('Task polling timeout');
   }
   ```

5. **Handle `notifications/tasks/status`:**
   ```typescript
   // In notification handler setup:
   // Listen for task status notifications, invoke registered callbacks
   private taskStatusCallbacks: Map<string, Set<(task: Task) => void>> = new Map();

   subscribeToTaskStatus(taskId: string, callback: (task: Task) => void): () => void;
   ```

6. **Declare client task capabilities:**
   ```typescript
   capabilities.tasks = {
     requests: {
       sampling: { createMessage: true },
       elicitation: { create: true },
     },
   };
   ```

### 4.4 Task Tests

**New test files:**
- `packages/mcp-server/tests/tasks.test.ts` — server-side task tests:
  - Task creation via task-augmented tool call
  - Task status polling via `tasks/get`
  - Task result retrieval via `tasks/result`
  - Task listing with pagination
  - Task cancellation
  - Task TTL expiry and cleanup
  - Tool-level taskSupport negotiation (forbidden/optional/required)
  - Status notifications
  - Error cases (task not found, already cancelled, etc.)

- `packages/mcp-client/tests/tasks.test.ts` — client-side task tests:
  - `getTask()` sends correct request
  - `getTaskResult()` sends correct request
  - `listTasks()` with pagination
  - `cancelTask()` sends correct request
  - `awaitTaskResult()` polls and returns result
  - `awaitTaskResult()` handles failure/cancellation
  - `awaitTaskResult()` respects timeout and maxPolls
  - Task status notification subscription

---

## Phase 5: Auth Enhancements

### 5.1 OIDC Discovery Enhancement

**File to verify:** `packages/mcp-auth-oidc/src/index.ts`

**Status:** The OIDC provider likely already tries `/.well-known/openid-configuration`. Verify and add test.

**Changes (if needed):**
- Ensure discovery tries OIDC endpoint first (`/.well-known/openid-configuration`), then falls back to OAuth (`/.well-known/oauth-authorization-server`)
- Document the discovery order

### 5.2 OAuth Client ID Metadata Documents

**File to modify:** `packages/mcp-auth/src/index.ts`

**Changes:**
1. Add `resolveClientMetadata(clientId: string)` utility function:
   - If `clientId` is a URL, fetch metadata document from that URL
   - Validate fetched metadata matches expected schema
   - Return `ClientMetadataDocument`

2. Add `validateClientMetadataDocument(doc)` function

3. In `createOAuthDiscoveryRoutes()`, verify the existing client metadata route is working

**Test:** `packages/mcp-auth/tests/client-metadata.test.ts`

### 5.3 Incremental Scope Consent

**File to modify:** `packages/mcp-client-http/src/index.ts`

**Changes:**
1. Parse `WWW-Authenticate: Bearer error="insufficient_scope" scope="read write"` in 403 responses
2. Extract required scopes
3. Trigger re-authorization with additional scopes
4. Retry the original request with new token

**Also modify:** `packages/mcp-auth/src/index.ts`
- Add `parseWWWAuthenticate(header: string)` utility
- Add `IncrementalScopeHandler` interface

**Test:** `packages/mcp-client-http/tests/incremental-scope.test.ts`

---

## Phase 6: Transport Improvements

### 6.1 Polling SSE Streams

**Files to modify:**
- `packages/mcp-transport-http/src/index.ts` — server-side SSE stream management
- `packages/mcp-client-http/src/index.ts` — client-side reconnection handling

**Server changes:**
1. Support intentional SSE stream disconnection via `res.end()`
2. Send `event: close` or use event ID encoding for stream identity
3. Allow GET-based stream resumption with `Last-Event-ID` header

**Client changes:**
1. Handle server-initiated SSE closure gracefully (not as error)
2. Implement reconnection via GET with `Last-Event-ID`
3. Distinguish between server-initiated close (normal) and connection error (retry)

**Test:** `packages/mcp-transport-http/tests/sse-polling.test.ts`

---

## File Change Summary

### New Files (6)
| File | Description |
|------|-------------|
| `packages/mcp-server/src/tasks.ts` | Task types, InMemoryTaskStore, TaskManager |
| `packages/mcp-server/tests/tasks.test.ts` | Server task tests |
| `packages/mcp-client/tests/tasks.test.ts` | Client task tests |
| `packages/mcp-server/tests/url-elicitation.test.ts` | URL elicitation tests |
| `packages/mcp-client/tests/url-elicitation.test.ts` | Client URL elicitation tests |
| `packages/mcp-transport-http/tests/sse-polling.test.ts` | SSE polling tests |

### Modified Files (~15)
| File | Changes |
|------|---------|
| `packages/mcp-server/src/index.ts` | Tasks enablement, task-augmented tool calls, URL elicitation rewrite, resource size, tool execution config, input validation as tool errors |
| `packages/mcp-server/src/errors.ts` | UrlElicitationRequired error code → -32042 |
| `packages/mcp-client/src/index.ts` | Task client methods, URL elicitation handler, enum schema validation, task status subscriptions |
| `packages/mcp-transport-http/src/index.ts` | Protocol version update, Origin 403, SSE polling support |
| `packages/mcp-client-http/src/index.ts` | Protocol version header update, incremental scope consent, SSE reconnection |
| `packages/mcp-auth/src/index.ts` | Client metadata document resolution, WWW-Authenticate parsing |
| `packages/mcp-auth-oidc/src/index.ts` | Verify OIDC discovery compliance |
| `packages/mcp-server/tests/index.test.ts` | Resource size, input validation errors |
| `packages/mcp-server/tests/sampling.test.ts` | Tool calling verification |
| `packages/mcp-client/tests/elicitation.test.ts` | Enhanced enum schema tests |
| `packages/mcp-transport-http/tests/*.test.ts` | Protocol version updates |
| `packages/mcp-client-http/tests/http-client.test.ts` | Protocol version, scope consent |

---

## Dependency Notes

- **SDK version `^1.27.1`** already exports all needed task types and schemas — no version bump needed in `package.json` (npm will resolve to latest 1.x)
- The SDK's `experimental` module exports `TaskStore`, `InMemoryTaskStore` if we want to use them directly, but we'll create our own simpler implementation to avoid coupling to experimental APIs
- No new npm dependencies required for any phase

## Backward Compatibility

- Protocol version negotiation ensures old clients (`2025-06-18`) still work
- Task capability is opt-in via `enableTasks()` — servers that don't call it behave identically to before
- URL elicitation is additive — form mode continues to work
- Tool `execution.taskSupport` defaults to `'optional'` — existing tools work unchanged
- All new methods on client interfaces have default implementations returning errors if not supported

## Implementation Order

Each phase is independently deployable and testable:

1. **Phase 1** (Protocol + quick wins) — ~2 hours — no blockers
2. **Phase 2** (Elicitation) — ~3 hours — no blockers
3. **Phase 3** (Sampling) — ~1 hour — no blockers
4. **Phase 4** (Tasks) — ~6 hours — largest feature, builds on Phases 1-3
5. **Phase 5** (Auth) — ~3 hours — independent
6. **Phase 6** (Transport) — ~2 hours — independent
