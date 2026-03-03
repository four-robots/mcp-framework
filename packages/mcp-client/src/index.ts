import { randomBytes } from 'crypto';
import {
  CallToolResult,
  GetPromptResult,
  ReadResourceResult,
  JSONRPCMessage,
  JSONRPCRequest,
  JSONRPCResponse,
  JSONRPCNotification
} from "@modelcontextprotocol/sdk/types.js";

/**
 * Simplified tool interface
 */
export interface ToolInfo {
  name: string;
  title?: string;
  description: string;
  inputSchema: any;
}

/**
 * Simplified resource interface
 */
export interface ResourceInfo {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

/**
 * Simplified prompt interface
 */
export interface PromptInfo {
  name: string;
  title?: string;
  description?: string;
  arguments?: any[];
}

/**
 * Base interface that all MCP clients must implement
 */
export interface IMCPClient {
  /**
   * Connect to the MCP server
   */
  connect(): Promise<void>;

  /**
   * Disconnect from the MCP server
   */
  disconnect(): Promise<void>;

  /**
   * Check if client is connected
   */
  isConnected(): boolean;

  /**
   * List all available tools
   */
  listTools(): Promise<ToolInfo[]>;

  /**
   * Call a tool with arguments
   */
  callTool(name: string, args?: any): Promise<CallToolResult>;

  /**
   * List all available resources
   */
  listResources(): Promise<ResourceInfo[]>;

  /**
   * Read a resource by URI
   */
  readResource(uri: string): Promise<ReadResourceResult>;

  /**
   * List all available prompts
   */
  listPrompts(): Promise<PromptInfo[]>;

  /**
   * Get a prompt with arguments
   */
  getPrompt(name: string, args?: any): Promise<GetPromptResult>;

  /**
   * Get the underlying SDK client (for advanced usage)
   */
  getSDKClient(): any; // Using any to avoid SDK dependency in interface
}

/**
 * Enhanced MCP client interface with advanced features
 */
export interface IEnhancedMCPClient extends IMCPClient {
  /**
   * Call a tool with advanced options
   */
  callTool(name: string, args?: any, options?: CallOptions): Promise<CallToolResult>;
  
  /**
   * Cancel a request by ID
   */
  cancelRequest(requestId: string): Promise<void>;
  
  /**
   * Subscribe to progress notifications
   */
  subscribeToProgress(callback: ProgressCallback): () => void;
  
  /**
   * Subscribe to connection state changes
   */
  subscribeToConnectionState(callback: ConnectionStateCallback): () => void;
  
  /**
   * Subscribe to all messages
   */
  subscribeToMessages(callback: MessageCallback): () => void;
  
  /**
   * Get current connection state
   */
  getConnectionState(): ConnectionState;
  
  /**
   * Get session context
   */
  getSessionContext(): SessionContext | null;
  
  /**
   * Set session context
   */
  setSessionContext(context: Partial<SessionContext>): void;
  
  /**
   * Clear session context
   */
  clearSessionContext(): void;
  
  /**
   * Send a custom JSON-RPC message
   */
  sendMessage(message: JSONRPCMessage): Promise<JSONRPCResponse | void>;
  
  /**
   * Get client statistics
   */
  getStats(): {
    connectTime?: Date;
    lastActivity?: Date;
    requestCount: number;
    errorCount: number;
    reconnectCount: number;
  };
  
  /**
   * Register an elicitation handler
   */
  registerElicitationHandler(handler: ElicitationHandler): () => void;

  /**
   * Register a URL elicitation handler for mode:'url' flows
   */
  registerUrlElicitationHandler(handler: UrlElicitationHandler): () => void;

  /**
   * Handle elicitation request manually
   */
  handleElicitationRequest(request: ElicitationRequest): Promise<ElicitationResponse>;

  /**
   * Validate elicitation form values
   */
  validateElicitationValues(fields: ElicitationField[], values: Record<string, any>): ElicitationValidationError[];

  /**
   * Get active elicitation requests
   */
  getActiveElicitationRequests(): ElicitationRequest[];

  // Task methods (MCP 2025-11-25 experimental)

  /**
   * Get task status by ID
   */
  getTask(taskId: string): Promise<TaskInfo>;

  /**
   * Get task result (tool call result)
   */
  getTaskResult(taskId: string): Promise<CallToolResult>;

  /**
   * List all tasks
   */
  listTasks(): Promise<TaskInfo[]>;

  /**
   * Cancel a task
   */
  cancelTask(taskId: string): Promise<TaskInfo>;

  /**
   * Poll a task until it reaches a terminal state and return the result
   */
  awaitTaskResult(taskId: string, options?: TaskPollingOptions): Promise<CallToolResult>;
}

/**
 * Multi-server MCP client interface
 */
export interface IMultiServerMCPClient {
  /**
   * Add a server configuration
   */
  addServer(serverConfig: ServerConfig): Promise<void>;
  
  /**
   * Remove a server
   */
  removeServer(serverName: string): Promise<void>;
  
  /**
   * List all configured servers
   */
  listServers(): ServerConfig[];
  
  /**
   * Get tools from all servers
   */
  getAllTools(): Promise<Array<ToolInfo & { serverName: string }>>;
  
  /**
   * Call a tool on a specific server
   */
  callToolOnServer(serverName: string, toolName: string, args?: any, options?: CallOptions): Promise<CallToolResult>;
  
  /**
   * Get the best server for a tool (based on capabilities and priority)
   */
  getBestServerForTool(toolName: string): Promise<string | null>;
}

/**
 * Abstract base class that provides common MCP client functionality
 */
export abstract class BaseMCPClient implements IEnhancedMCPClient {
  protected connectionState = ConnectionState.Disconnected;
  protected config: InternalClientConfig;
  protected sessionContext: SessionContext | null = null;
  protected progressCallbacks: Set<ProgressCallback> = new Set();
  protected connectionStateCallbacks: Set<ConnectionStateCallback> = new Set();
  protected messageCallbacks: Set<MessageCallback> = new Set();
  protected activeRequests: Map<string, CancellationToken> = new Map();
  protected elicitationHandlers: Set<ElicitationHandler> = new Set();
  protected urlElicitationHandlers: Set<UrlElicitationHandler> = new Set();
  protected elicitationCompleteCallbacks: Map<string, (values?: Record<string, any>) => void> = new Map();
  protected activeElicitationRequests: Map<string, ElicitationRequest> = new Map();
  protected stats = {
    connectTime: undefined as Date | undefined,
    lastActivity: undefined as Date | undefined,
    requestCount: 0,
    errorCount: 0,
    reconnectCount: 0
  };
  protected heartbeatTimer?: NodeJS.Timeout;
  protected reconnectTimer?: NodeJS.Timeout;
  protected intentionalDisconnect = false;

  constructor(config: ClientConfig = {}) {
    this.config = {
      timeout: config.timeout ?? 30000,
      retries: config.retries ?? 3,
      debug: config.debug ?? false,
      autoReconnect: config.autoReconnect ?? true,
      maxRetries: config.maxRetries ?? 5,
      retryDelay: config.retryDelay ?? 1000,
      heartbeatInterval: config.heartbeatInterval ?? 30000,
      heartbeatTimeout: config.heartbeatTimeout ?? 10000,
      sessionPersistence: config.sessionPersistence ?? false,
      sessionTimeout: config.sessionTimeout ?? 3600000, // 1 hour
      onProgress: config.onProgress,
      onConnectionStateChange: config.onConnectionStateChange,
      onMessage: config.onMessage,
    };
  }

  abstract connect(): Promise<void>;
  abstract disconnect(): Promise<void>;
  abstract listTools(): Promise<ToolInfo[]>;
  abstract listResources(): Promise<ResourceInfo[]>;
  abstract readResource(uri: string): Promise<ReadResourceResult>;
  abstract listPrompts(): Promise<PromptInfo[]>;
  abstract getPrompt(name: string, args?: any): Promise<GetPromptResult>;
  abstract getSDKClient(): any;
  abstract sendMessage(message: JSONRPCMessage): Promise<JSONRPCResponse | void>;

  /**
   * Enhanced tool calling with options
   */
  async callTool(name: string, args?: any, options?: CallOptions): Promise<CallToolResult> {
    this.ensureConnected();
    this.updateActivity();
    this.stats.requestCount++;

    try {
      const requestId = this.generateRequestId();
      
      // Create cancellation token if needed
      if (options?.cancellationToken) {
        this.activeRequests.set(requestId, options.cancellationToken);
      }

      // Set up progress handling
      let unsubscribeProgress: (() => void) | undefined;
      if (options?.onProgress) {
        unsubscribeProgress = this.subscribeToProgress(options.onProgress);
        options.cancellationToken?.onCancelled(() => unsubscribeProgress?.());
      }

      try {
        const result = await this.doCallTool(name, args, options, requestId);
        return result;
      } finally {
        // Clean up progress subscription and active request
        unsubscribeProgress?.();
        this.activeRequests.delete(requestId);
      }
    } catch (error) {
      this.stats.errorCount++;
      throw error;
    }
  }

  protected abstract doCallTool(name: string, args?: any, options?: CallOptions, requestId?: string): Promise<CallToolResult>;

  /**
   * Cancel a request by ID
   */
  async cancelRequest(requestId: string): Promise<void> {
    const cancellationToken = this.activeRequests.get(requestId);
    if (cancellationToken) {
      cancellationToken.cancel();
      this.activeRequests.delete(requestId);
    }
  }

  /**
   * Subscribe to progress notifications
   */
  subscribeToProgress(callback: ProgressCallback): () => void {
    this.progressCallbacks.add(callback);
    return () => this.progressCallbacks.delete(callback);
  }

  /**
   * Subscribe to connection state changes
   */
  subscribeToConnectionState(callback: ConnectionStateCallback): () => void {
    this.connectionStateCallbacks.add(callback);
    return () => this.connectionStateCallbacks.delete(callback);
  }

  /**
   * Subscribe to all messages
   */
  subscribeToMessages(callback: MessageCallback): () => void {
    this.messageCallbacks.add(callback);
    return () => this.messageCallbacks.delete(callback);
  }

  /**
   * Get current connection state
   */
  getConnectionState(): ConnectionState {
    return this.connectionState;
  }

  /**
   * Check if client is connected
   */
  isConnected(): boolean {
    return this.connectionState === ConnectionState.Connected;
  }

  /**
   * Get session context
   */
  getSessionContext(): SessionContext | null {
    return this.sessionContext;
  }

  /**
   * Set session context
   */
  setSessionContext(context: Partial<SessionContext>): void {
    if (this.sessionContext) {
      this.sessionContext = { ...this.sessionContext, ...context };
    } else {
      this.sessionContext = {
        sessionId: this.generateSessionId(),
        startTime: new Date(),
        lastActivity: new Date(),
        ...context
      };
    }
  }

  /**
   * Clear session context
   */
  clearSessionContext(): void {
    this.sessionContext = null;
  }

  /**
   * Get client statistics
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Set connection state and notify callbacks
   */
  protected setConnectionState(state: ConnectionState, error?: Error): void {
    if (this.connectionState !== state) {
      this.connectionState = state;
      
      if (state === ConnectionState.Connected) {
        this.stats.connectTime = new Date();
        this.startHeartbeat();
      } else {
        this.stopHeartbeat();
      }
      
      // Notify callbacks
      for (const callback of this.connectionStateCallbacks) {
        try {
          callback(state, error);
        } catch (err) {
          console.error('Connection state callback error:', err);
        }
      }
      
      // Handle auto-reconnection (skip if disconnect was intentional)
      if (!this.intentionalDisconnect && (state === ConnectionState.Error || state === ConnectionState.Disconnected)) {
        if (this.config.autoReconnect && this.stats.reconnectCount < this.config.maxRetries) {
          this.scheduleReconnect();
        }
      }
    }
  }

  /**
   * Notify progress callbacks
   */
  protected notifyProgress(progress: {
    progressToken: string | number;
    progress: number;
    total?: number;
    message?: string;
  }): void {
    for (const callback of this.progressCallbacks) {
      try {
        callback(progress);
      } catch (err) {
        console.error('Progress callback error:', err);
      }
    }
  }

  /**
   * Notify message callbacks
   */
  protected notifyMessage(message: JSONRPCMessage): void {
    for (const callback of this.messageCallbacks) {
      try {
        callback(message);
      } catch (err) {
        console.error('Message callback error:', err);
      }
    }
  }

  /**
   * Ensure the client is connected before operations
   */
  protected ensureConnected(): void {
    if (!this.isConnected()) {
      throw new Error("Client is not connected. Call connect() first.");
    }
  }

  /**
   * Update last activity time
   */
  protected updateActivity(): void {
    this.stats.lastActivity = new Date();
    if (this.sessionContext) {
      this.sessionContext.lastActivity = new Date();
    }
  }

  /**
   * Generate unique request ID
   */
  protected generateRequestId(): string {
    return `req_${Date.now()}_${randomBytes(6).toString('hex')}`;
  }

  /**
   * Generate unique session ID
   */
  protected generateSessionId(): string {
    return `session_${Date.now()}_${randomBytes(6).toString('hex')}`;
  }

  /**
   * Start heartbeat mechanism
   */
  protected startHeartbeat(): void {
    this.stopHeartbeat();
    if (this.config.heartbeatInterval > 0) {
      this.heartbeatTimer = setInterval(() => {
        this.sendHeartbeat().catch(err => {
          console.error('Heartbeat failed:', err);
          this.setConnectionState(ConnectionState.Error, err);
        });
      }, this.config.heartbeatInterval);
      this.heartbeatTimer.unref();
    }
  }

  /**
   * Stop heartbeat mechanism
   */
  protected stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }
  }

  /**
   * Send heartbeat ping
   */
  protected abstract sendHeartbeat(): Promise<void>;

  /**
   * Schedule reconnection attempt
   */
  protected scheduleReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    // Cap max delay at 60 seconds
    const maxDelay = 60000;
    const delay = Math.min(
      this.config.retryDelay * Math.pow(2, this.stats.reconnectCount),
      maxDelay
    );

    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = undefined;
      // Abort if user explicitly disconnected while the timer was pending
      if (this.intentionalDisconnect) return;
      try {
        this.stats.reconnectCount++;
        await this.connect();
        // Reset reconnect count on successful reconnect
        this.stats.reconnectCount = 0;
      } catch (error) {
        // Don't reschedule if disconnect was called during the connect attempt
        if (this.intentionalDisconnect) return;
        console.error('Reconnection failed:', error);
        if (this.stats.reconnectCount < this.config.maxRetries) {
          this.scheduleReconnect();
        }
      }
    }, delay);
    this.reconnectTimer?.unref();
  }

  /**
   * Register an elicitation handler
   */
  registerElicitationHandler(handler: ElicitationHandler): () => void {
    this.elicitationHandlers.add(handler);
    return () => this.elicitationHandlers.delete(handler);
  }

  /**
   * Register a URL elicitation handler
   */
  registerUrlElicitationHandler(handler: UrlElicitationHandler): () => void {
    this.urlElicitationHandlers.add(handler);
    return () => this.urlElicitationHandlers.delete(handler);
  }

  /**
   * Register a one-time callback for when a URL elicitation completes
   */
  onElicitationComplete(elicitationId: string, callback: (values?: Record<string, any>) => void): void {
    this.elicitationCompleteCallbacks.set(elicitationId, callback);
  }

  /**
   * Handle elicitation request manually
   */
  async handleElicitationRequest(request: ElicitationRequest): Promise<ElicitationResponse> {
    // Handle URL-mode elicitation
    if (request.mode === 'url' && request.url) {
      for (const handler of this.urlElicitationHandlers) {
        try {
          const handled = await handler(request.url, request.elicitationId || request.id, request);
          if (handled) {
            // URL was opened for the user - return accept (completion comes via notification)
            return {
              id: request.id,
              action: ElicitationAction.Accept,
            };
          }
        } catch (error) {
          console.error('URL elicitation handler failed:', error);
        }
      }
      // No URL handler available
      return {
        id: request.id,
        action: ElicitationAction.Decline,
        reason: 'No URL elicitation handler available',
      };
    }

    // Validate request for form mode
    if (!request.id || !request.title || !Array.isArray(request.fields)) {
      throw new Error('Invalid elicitation request format');
    }

    // Add to active requests
    this.activeElicitationRequests.set(request.id, request);

    try {
      // Try each registered handler until one succeeds
      for (const handler of this.elicitationHandlers) {
        let response: ElicitationResponse;
        try {
          response = await handler(request);
        } catch (error) {
          console.error('Elicitation handler failed:', error);
          continue;
        }

        // Validate response outside the handler try-catch so validation
        // errors are not confused with handler crashes
        if (response.action === ElicitationAction.Accept) {
          if (!response.values) {
            return {
              id: request.id,
              action: ElicitationAction.Cancel,
              reason: 'Accept action requires values'
            };
          }
          const validationErrors = this.validateElicitationValues(request.fields, response.values);
          if (validationErrors.length > 0) {
            return {
              id: request.id,
              action: ElicitationAction.Cancel,
              reason: `Validation failed: ${validationErrors.map(e => e.message).join(', ')}`
            };
          }
        }

        return response;
      }

      // No handler succeeded, return cancel response
      return {
        id: request.id,
        action: ElicitationAction.Cancel,
        reason: 'No elicitation handler available'
      };
    } finally {
      // Remove from active requests
      this.activeElicitationRequests.delete(request.id);
    }
  }

  /**
   * Validate elicitation form values
   */
  validateElicitationValues(fields: ElicitationField[], values: Record<string, any>): ElicitationValidationError[] {
    const errors: ElicitationValidationError[] = [];

    for (const field of fields) {
      const value = values[field.name];
      
      // Check required fields
      if (field.required && (value === undefined || value === null || value === '')) {
        errors.push({
          field: field.name,
          message: `${field.label} is required`,
          code: 'REQUIRED'
        });
        continue;
      }

      // Skip validation for empty optional fields
      if (value === undefined || value === null || value === '') {
        continue;
      }

      // Type-specific validation
      switch (field.type) {
        case 'number':
          if (typeof value !== 'number' && isNaN(Number(value))) {
            errors.push({
              field: field.name,
              message: `${field.label} must be a valid number`,
              code: 'INVALID_TYPE'
            });
          } else {
            const numValue = typeof value === 'number' ? value : Number(value);
            if (field.validation?.min !== undefined && numValue < field.validation.min) {
              errors.push({
                field: field.name,
                message: `${field.label} must be at least ${field.validation.min}`,
                code: 'MIN_VALUE'
              });
            }
            if (field.validation?.max !== undefined && numValue > field.validation.max) {
              errors.push({
                field: field.name,
                message: `${field.label} must be at most ${field.validation.max}`,
                code: 'MAX_VALUE'
              });
            }
          }
          break;

        case 'boolean':
          if (typeof value !== 'boolean') {
            errors.push({
              field: field.name,
              message: `${field.label} must be true or false`,
              code: 'INVALID_TYPE'
            });
          }
          break;

        case 'email':
          if (typeof value === 'string') {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(value)) {
              errors.push({
                field: field.name,
                message: `${field.label} must be a valid email address`,
                code: 'INVALID_EMAIL'
              });
            }
          }
          break;

        case 'url':
          if (typeof value === 'string') {
            try {
              new URL(value);
            } catch {
              errors.push({
                field: field.name,
                message: `${field.label} must be a valid URL`,
                code: 'INVALID_URL'
              });
            }
          }
          break;

        case 'select':
        case 'multiselect':
          if (field.validation?.options) {
            const validValues = field.validation.options.map(opt => opt.value);
            if (field.type === 'select') {
              if (!validValues.includes(value)) {
                errors.push({
                  field: field.name,
                  message: `${field.label} must be one of the provided options`,
                  code: 'INVALID_OPTION'
                });
              }
            } else {
              // multiselect
              if (!Array.isArray(value) || !value.every(v => validValues.includes(v))) {
                errors.push({
                  field: field.name,
                  message: `${field.label} must contain only valid options`,
                  code: 'INVALID_OPTIONS'
                });
              }
            }
          }
          break;

        case 'text':
        case 'textarea':
        case 'password':
          if (typeof value === 'string') {
            if (field.validation?.minLength !== undefined && value.length < field.validation.minLength) {
              errors.push({
                field: field.name,
                message: `${field.label} must be at least ${field.validation.minLength} characters`,
                code: 'MIN_LENGTH'
              });
            }
            if (field.validation?.maxLength !== undefined && value.length > field.validation.maxLength) {
              errors.push({
                field: field.name,
                message: `${field.label} must be at most ${field.validation.maxLength} characters`,
                code: 'MAX_LENGTH'
              });
            }
            if (field.validation?.pattern && field.validation.pattern.length <= 100) {
              // Reject patterns with nested quantifiers to prevent ReDoS
              const hasNestedQuantifiers = /(\+|\*|\{)\s*\)(\+|\*|\?)|\(\?[^)]*(\+|\*)\)(\+|\*|\?)/.test(field.validation.pattern);
              if (!hasNestedQuantifiers) {
                try {
                  const regex = new RegExp(field.validation.pattern);
                  if (!regex.test(value)) {
                    errors.push({
                      field: field.name,
                      message: `${field.label} format is invalid`,
                      code: 'INVALID_PATTERN'
                    });
                  }
                } catch {
                  // Invalid regex pattern from server, skip validation
                }
              }
            }
          }
          break;
      }

      // Check field dependencies
      if (field.dependencies) {
        for (const dep of field.dependencies) {
          if (values[dep.field] !== dep.value) {
            errors.push({
              field: field.name,
              message: `${field.label} is only valid when ${dep.field} is ${dep.value}`,
              code: 'DEPENDENCY_NOT_MET'
            });
          }
        }
      }
    }

    return errors;
  }

  /**
   * Get active elicitation requests
   */
  getActiveElicitationRequests(): ElicitationRequest[] {
    return Array.from(this.activeElicitationRequests.values());
  }

  /**
   * Convert JSON Schema requestedSchema to ElicitationField[] for backward compatibility
   */
  static schemaToFields(schema: ElicitationRequestedSchema): ElicitationField[] {
    const fields: ElicitationField[] = [];
    const required = new Set(schema.required || []);

    for (const [name, prop] of Object.entries(schema.properties)) {
      let fieldType: ElicitationFieldType;

      if (prop.type === 'array') {
        fieldType = 'multiselect';
      } else if (prop.oneOf) {
        fieldType = 'select';
      } else if (prop.enum) {
        fieldType = 'select';
      } else if (prop.format === 'email') {
        fieldType = 'email';
      } else if (prop.format === 'uri') {
        fieldType = 'url';
      } else if (prop.format === 'date' || prop.format === 'date-time') {
        fieldType = 'date';
      } else if (prop.type === 'number' || prop.type === 'integer') {
        fieldType = 'number';
      } else if (prop.type === 'boolean') {
        fieldType = 'boolean';
      } else {
        fieldType = 'text';
      }

      const field: ElicitationField = {
        name,
        type: fieldType,
        label: prop.title || name,
        description: prop.description,
        required: required.has(name),
        defaultValue: prop.default,
        validation: {},
      };

      if (prop.minLength !== undefined) field.validation!.minLength = prop.minLength;
      if (prop.maxLength !== undefined) field.validation!.maxLength = prop.maxLength;
      if (prop.pattern !== undefined) field.validation!.pattern = prop.pattern;
      if (prop.minimum !== undefined) field.validation!.min = prop.minimum;
      if (prop.maximum !== undefined) field.validation!.max = prop.maximum;
      if (prop.oneOf) {
        field.validation!.options = prop.oneOf.map(opt => ({
          value: opt.const,
          label: opt.title ?? String(opt.const),
          description: opt.description,
        }));
      } else if (prop.type === 'array' && prop.items?.enum) {
        field.validation!.options = prop.items.enum.map(value => ({
          value,
          label: String(value),
        }));
      } else if (prop.enum) {
        field.validation!.options = prop.enum.map((value, i) => ({
          value,
          label: prop.enumNames?.[i] ?? String(value),
        }));
      }

      // Remove empty validation object
      if (Object.keys(field.validation!).length === 0) {
        delete field.validation;
      }

      fields.push(field);
    }

    return fields;
  }

  /**
   * Validate values against a JSON Schema (MCP elicitation restricted subset)
   */
  validateElicitationSchemaValues(
    schema: ElicitationRequestedSchema,
    values: Record<string, any>
  ): ElicitationValidationError[] {
    const errors: ElicitationValidationError[] = [];
    const required = new Set(schema.required || []);

    for (const reqField of required) {
      if (values[reqField] === undefined || values[reqField] === null || values[reqField] === '') {
        const prop = schema.properties[reqField];
        errors.push({
          field: reqField,
          message: `${prop?.title || reqField} is required`,
          code: 'REQUIRED',
        });
      }
    }

    for (const [name, prop] of Object.entries(schema.properties)) {
      const value = values[name];
      if (value === undefined || value === null || value === '') continue;

      if (prop.type === 'string' && typeof value !== 'string') {
        errors.push({ field: name, message: `${prop.title || name} must be a string`, code: 'INVALID_TYPE' });
        continue;
      }
      if ((prop.type === 'number' || prop.type === 'integer') && typeof value !== 'number') {
        errors.push({ field: name, message: `${prop.title || name} must be a number`, code: 'INVALID_TYPE' });
        continue;
      }
      if (prop.type === 'boolean' && typeof value !== 'boolean') {
        errors.push({ field: name, message: `${prop.title || name} must be a boolean`, code: 'INVALID_TYPE' });
        continue;
      }

      if (typeof value === 'string') {
        if (prop.minLength !== undefined && value.length < prop.minLength) {
          errors.push({ field: name, message: `${prop.title || name} must be at least ${prop.minLength} characters`, code: 'MIN_LENGTH' });
        }
        if (prop.maxLength !== undefined && value.length > prop.maxLength) {
          errors.push({ field: name, message: `${prop.title || name} must be at most ${prop.maxLength} characters`, code: 'MAX_LENGTH' });
        }
        if (prop.format === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
          errors.push({ field: name, message: `${prop.title || name} must be a valid email`, code: 'INVALID_EMAIL' });
        }
        if (prop.format === 'uri') {
          try { new URL(value); } catch {
            errors.push({ field: name, message: `${prop.title || name} must be a valid URI`, code: 'INVALID_URL' });
          }
        }
      }
      if (typeof value === 'number') {
        if (prop.minimum !== undefined && value < prop.minimum) {
          errors.push({ field: name, message: `${prop.title || name} must be at least ${prop.minimum}`, code: 'MIN_VALUE' });
        }
        if (prop.maximum !== undefined && value > prop.maximum) {
          errors.push({ field: name, message: `${prop.title || name} must be at most ${prop.maximum}`, code: 'MAX_VALUE' });
        }
      }
      // String pattern validation
      if (typeof value === 'string' && prop.pattern && prop.pattern.length <= 100) {
        const hasNestedQuantifiers = /(\+|\*|\{)\s*\)(\+|\*|\?)|\(\?[^)]*(\+|\*)\)(\+|\*|\?)/.test(prop.pattern);
        if (!hasNestedQuantifiers) {
          try {
            const regex = new RegExp(prop.pattern);
            if (!regex.test(value)) {
              errors.push({ field: name, message: `${prop.title || name} format is invalid`, code: 'INVALID_PATTERN' });
            }
          } catch {
            // Invalid regex from server, skip
          }
        }
      }
      // oneOf validation (titled enums)
      if (prop.oneOf) {
        const validValues = prop.oneOf.map(opt => opt.const);
        if (!validValues.includes(value)) {
          errors.push({ field: name, message: `${prop.title || name} must be one of the allowed values`, code: 'INVALID_OPTION' });
        }
      } else if (prop.enum && !prop.enum.includes(value)) {
        errors.push({ field: name, message: `${prop.title || name} must be one of the allowed values`, code: 'INVALID_OPTION' });
      }
      // Array validation (multi-select)
      if (prop.type === 'array') {
        if (!Array.isArray(value)) {
          errors.push({ field: name, message: `${prop.title || name} must be an array`, code: 'INVALID_TYPE' });
        } else {
          if (prop.minItems !== undefined && value.length < prop.minItems) {
            errors.push({ field: name, message: `${prop.title || name} must have at least ${prop.minItems} items`, code: 'MIN_ITEMS' });
          }
          if (prop.maxItems !== undefined && value.length > prop.maxItems) {
            errors.push({ field: name, message: `${prop.title || name} must have at most ${prop.maxItems} items`, code: 'MAX_ITEMS' });
          }
          if (prop.items?.enum) {
            const validValues = prop.items.enum;
            for (const item of value) {
              if (!validValues.includes(item)) {
                errors.push({ field: name, message: `${prop.title || name} contains invalid value: ${item}`, code: 'INVALID_OPTION' });
                break;
              }
            }
          }
        }
      }
    }

    return errors;
  }

  /**
   * Handle incoming elicitation requests from notifications
   */
  protected async handleElicitationNotification(notification: JSONRPCNotification): Promise<void> {
    // Handle elicitation completion notifications (URL mode)
    if (notification.method === 'notifications/elicitation/complete') {
      const raw = notification.params as any;
      const elicitationId = raw?.elicitationId;
      if (elicitationId) {
        const callback = this.elicitationCompleteCallbacks.get(elicitationId);
        if (callback) {
          this.elicitationCompleteCallbacks.delete(elicitationId);
          callback(raw.values);
        }
      }
      return;
    }

    if (notification.method === 'notifications/elicitation/request') {
      const raw = notification.params as any;

      // Handle URL-mode elicitation
      if (raw.mode === 'url' && raw.url) {
        const request: ElicitationRequest = {
          id: raw.id || randomBytes(8).toString('hex'),
          title: raw.message || raw.title || 'URL Interaction Required',
          mode: 'url',
          url: raw.url,
          elicitationId: raw.elicitationId,
          fields: [],
          metadata: raw.metadata,
        };
        try {
          await this.handleElicitationRequest(request);
        } catch (error) {
          console.error('Failed to handle URL elicitation:', error);
        }
        return;
      }

      // Support JSON Schema format (MCP 2025-06-18) by converting to internal format
      let request: ElicitationRequest;
      if (raw.requestedSchema && !raw.fields) {
        const fields = BaseMCPClient.schemaToFields(raw.requestedSchema);
        request = {
          id: raw.id || randomBytes(8).toString('hex'),
          title: raw.message || raw.title || 'Information Request',
          description: raw.description,
          message: raw.message,
          requestedSchema: raw.requestedSchema,
          fields,
          timeout: raw.timeout,
          allowCancel: raw.allowCancel,
          metadata: raw.metadata,
        };
      } else {
        request = raw as ElicitationRequest;
      }

      try {
        const response = await this.handleElicitationRequest(request);

        // Send response back to server
        await this.sendMessage({
          jsonrpc: '2.0',
          method: 'elicitation/response',
          params: response as any
        });
      } catch (error) {
        console.error('Failed to handle elicitation request:', error);

        // Send error response
        await this.sendMessage({
          jsonrpc: '2.0',
          method: 'elicitation/response',
          params: {
            id: request.id,
            action: ElicitationAction.Cancel,
            reason: error instanceof Error ? error.message : 'Unknown error'
          } as any
        });
      }
    }
  }

  // ====================================================================
  // Resource Subscriptions (MCP 2025-11-25)
  // ====================================================================

  /**
   * Subscribe to updates for a specific resource URI.
   * The server will send notifications when the resource changes.
   */
  async subscribeResource(uri: string): Promise<void> {
    const client = this.getSDKClient();
    if (!client) {
      throw new Error('Client is not connected');
    }
    await client.request({
      method: 'resources/subscribe',
      params: { uri }
    } as any, {} as any);
  }

  /**
   * Unsubscribe from updates for a specific resource URI.
   */
  async unsubscribeResource(uri: string): Promise<void> {
    const client = this.getSDKClient();
    if (!client) {
      throw new Error('Client is not connected');
    }
    await client.request({
      method: 'resources/unsubscribe',
      params: { uri }
    } as any, {} as any);
  }

  // ====================================================================
  // Roots Support (MCP 2025-11-25)
  // ====================================================================

  private roots: Array<{ uri: string; name?: string }> = [];
  private rootsChangeCallbacks: Array<() => void> = [];

  /**
   * Set the roots that this client exposes to the server.
   * Sends a roots/list_changed notification if connected.
   */
  setRoots(roots: Array<{ uri: string; name?: string }>): void {
    this.roots = [...roots];
    // Notify server that roots have changed
    if (this.isConnected()) {
      this.sendMessage({
        jsonrpc: '2.0',
        method: 'notifications/roots/list_changed',
        params: {}
      } as any).catch(() => {
        // Ignore notification failures
      });
    }
  }

  /**
   * Get the current roots list.
   */
  getRoots(): Array<{ uri: string; name?: string }> {
    return [...this.roots];
  }

  // ====================================================================
  // Tasks (MCP 2025-11-25 experimental)
  // ====================================================================

  /**
   * Get task status by ID
   */
  async getTask(taskId: string): Promise<TaskInfo> {
    this.ensureConnected();
    const client = this.getSDKClient();
    const result = await client.request(
      { method: 'tasks/get', params: { taskId } } as any,
      {} as any
    );
    return result as TaskInfo;
  }

  /**
   * Get the result of a completed task
   */
  async getTaskResult(taskId: string): Promise<CallToolResult> {
    this.ensureConnected();
    const client = this.getSDKClient();
    const result = await client.request(
      { method: 'tasks/result', params: { taskId } } as any,
      {} as any
    );
    return result as CallToolResult;
  }

  /**
   * List all tasks
   */
  async listTasks(): Promise<TaskInfo[]> {
    this.ensureConnected();
    const client = this.getSDKClient();
    const result = await client.request(
      { method: 'tasks/list', params: {} } as any,
      {} as any
    );
    return (result as any).tasks || [];
  }

  /**
   * Cancel a task
   */
  async cancelTask(taskId: string): Promise<TaskInfo> {
    this.ensureConnected();
    const client = this.getSDKClient();
    const result = await client.request(
      { method: 'tasks/cancel', params: { taskId } } as any,
      {} as any
    );
    return result as TaskInfo;
  }

  /**
   * Poll a task until it reaches a terminal state and return the result
   */
  async awaitTaskResult(taskId: string, options?: TaskPollingOptions): Promise<CallToolResult> {
    const timeout = options?.timeout ?? 300000;
    const startTime = Date.now();

    let task = await this.getTask(taskId);
    const pollInterval = options?.pollInterval ?? task.pollInterval ?? 1000;

    while (!isTerminalTaskStatus(task.status)) {
      if (Date.now() - startTime > timeout) {
        throw new Error(`Task ${taskId} timed out after ${timeout}ms`);
      }
      options?.onStatusChange?.(task);
      await new Promise(resolve => setTimeout(resolve, pollInterval));
      task = await this.getTask(taskId);
    }
    options?.onStatusChange?.(task);

    if (task.status === 'failed') {
      throw new Error(`Task ${taskId} failed: ${task.statusMessage || 'Unknown error'}`);
    }
    if (task.status === 'cancelled') {
      throw new Error(`Task ${taskId} was cancelled`);
    }

    return this.getTaskResult(taskId);
  }

  /**
   * Clean up resources
   */
  protected cleanup(): void {
    this.stopHeartbeat();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    // Only clear transient per-connection state, NOT user-registered handlers
    // (elicitationHandlers, connectionStateCallbacks, messageCallbacks,
    // progressCallbacks) which should persist across reconnections
    this.activeRequests.clear();
    this.activeElicitationRequests.clear();
    this.elicitationCompleteCallbacks.clear();
  }
}

/**
 * Connection state for MCP clients
 */
export enum ConnectionState {
  Disconnected = 'disconnected',
  Connecting = 'connecting',
  Connected = 'connected',
  Disconnecting = 'disconnecting',
  Error = 'error'
}

/**
 * Progress callback for long-running operations
 */
export interface ProgressCallback {
  (progress: {
    progressToken: string | number;
    progress: number;
    total?: number;
    message?: string;
  }): void;
}

/**
 * Connection state change callback
 */
export interface ConnectionStateCallback {
  (state: ConnectionState, error?: Error): void;
}

/**
 * Message handler callback
 */
export interface MessageCallback {
  (message: JSONRPCMessage): void;
}

/**
 * Cancellation token for request cancellation
 */
export interface CancellationToken {
  isCancelled: boolean;
  onCancelled: (callback: () => void) => void;
  cancel: () => void;
}

/**
 * Options for calling tools, prompts, and resources
 */
export interface CallOptions {
  timeout?: number;
  cancellationToken?: CancellationToken;
  onProgress?: ProgressCallback;
  metadata?: Record<string, any>;
}

/**
 * Server configuration for multi-server support
 */
export interface ServerConfig {
  name: string;
  transport: 'stdio' | 'http' | 'websocket';
  config: any; // Transport-specific configuration
  capabilities?: string[];
  priority?: number;
}

/**
 * Session context for maintaining state across requests
 */
export interface SessionContext {
  sessionId: string;
  user?: any;
  metadata?: Record<string, any>;
  startTime: Date;
  lastActivity: Date;
}

/**
 * Elicitation form field types
 */
export type ElicitationFieldType = 'text' | 'number' | 'boolean' | 'select' | 'multiselect' | 'textarea' | 'password' | 'email' | 'url' | 'date' | 'time' | 'datetime';

/**
 * Elicitation form field definition (legacy format)
 */
export interface ElicitationField {
  name: string;
  type: ElicitationFieldType;
  label: string;
  description?: string;
  required?: boolean;
  defaultValue?: any;
  placeholder?: string;
  validation?: {
    pattern?: string;
    min?: number;
    max?: number;
    minLength?: number;
    maxLength?: number;
    options?: Array<{ value: any; label: string; description?: string }>;
  };
  dependencies?: {
    field: string;
    value: any;
  }[];
}

/**
 * JSON Schema property definition for elicitation (MCP 2025-06-18 spec format).
 * Restricted to flat objects with primitive properties only.
 */
export interface ElicitationSchemaProperty {
  type: 'string' | 'number' | 'integer' | 'boolean' | 'array';
  title?: string;
  description?: string;
  default?: string | number | boolean;
  // String constraints
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  format?: 'email' | 'uri' | 'date' | 'date-time';
  // Number constraints
  minimum?: number;
  maximum?: number;
  // Enum
  enum?: (string | number | boolean)[];
  enumNames?: string[];
  // Titled enum (oneOf with const/title)
  oneOf?: Array<{ const: string | number | boolean; title?: string; description?: string }>;
  // Array type (multi-select)
  items?: { type: 'string' | 'number' | 'integer' | 'boolean'; enum?: (string | number | boolean)[] };
  minItems?: number;
  maxItems?: number;
}

/**
 * JSON Schema for elicitation requests (MCP 2025-06-18 spec format)
 */
export interface ElicitationRequestedSchema {
  type: 'object';
  properties: Record<string, ElicitationSchemaProperty>;
  required?: string[];
}

/**
 * Elicitation request from server to client
 */
export interface ElicitationRequest {
  id: string;
  title: string;
  description?: string;
  fields: ElicitationField[];
  /** JSON Schema format from MCP 2025-06-18 spec (alternative to fields) */
  message?: string;
  requestedSchema?: ElicitationRequestedSchema;
  timeout?: number; // milliseconds
  allowCancel?: boolean;
  metadata?: Record<string, any>;
  /** Elicitation mode: 'form' (default) or 'url' (redirect to external URL) */
  mode?: 'form' | 'url';
  /** URL to redirect user to when mode is 'url' */
  url?: string;
  /** Server-assigned elicitation ID for tracking URL-based flows */
  elicitationId?: string;
}

/**
 * Elicitation response actions
 */
export enum ElicitationAction {
  Accept = 'accept',
  Decline = 'decline',
  Cancel = 'cancel'
}

/**
 * Elicitation response from client to server
 */
export interface ElicitationResponse {
  id: string;
  action: ElicitationAction;
  values?: Record<string, any>;
  reason?: string; // For decline/cancel actions
  metadata?: Record<string, any>;
}

/**
 * Elicitation handler callback
 */
export interface ElicitationHandler {
  (request: ElicitationRequest): Promise<ElicitationResponse>;
}

/**
 * URL elicitation handler - invoked when mode is 'url'
 * Should open the URL for the user and return true if handled
 */
export interface UrlElicitationHandler {
  (url: string, elicitationId: string, request: ElicitationRequest): Promise<boolean>;
}

/**
 * Task status values (MCP 2025-11-25 experimental)
 */
export type TaskStatus = 'working' | 'input_required' | 'completed' | 'failed' | 'cancelled';

/**
 * Task information returned from server
 */
export interface TaskInfo {
  taskId: string;
  status: TaskStatus;
  statusMessage?: string;
  createdAt: string;
  lastUpdatedAt: string;
  ttl: number | null;
  pollInterval?: number;
}

/**
 * Options for polling task results
 */
export interface TaskPollingOptions {
  /** Polling interval in ms (default: uses server pollInterval or 1000) */
  pollInterval?: number;
  /** Maximum time to wait in ms (default: 300000 = 5 min) */
  timeout?: number;
  /** Callback for status updates */
  onStatusChange?: (task: TaskInfo) => void;
}

/**
 * Elicitation validation error
 */
export interface ElicitationValidationError {
  field: string;
  message: string;
  code: string;
}

/**
 * Elicitation context for form state management
 */
export interface ElicitationContext {
  requestId: string;
  fields: ElicitationField[];
  values: Record<string, any>;
  errors: ElicitationValidationError[];
  isSubmitting: boolean;
  startTime: Date;
  timeRemaining?: number;
}

/**
 * Configuration interface for enhanced MCP clients
 */
export interface ClientConfig {
  // Connection settings
  timeout?: number;
  retries?: number;
  debug?: boolean;
  
  // Auto-reconnection settings
  autoReconnect?: boolean;
  maxRetries?: number;
  retryDelay?: number;
  
  // Heartbeat settings
  heartbeatInterval?: number;
  heartbeatTimeout?: number;
  
  // Progress tracking
  onProgress?: ProgressCallback;
  onConnectionStateChange?: ConnectionStateCallback;
  onMessage?: MessageCallback;
  
  // Session management
  sessionPersistence?: boolean;
  sessionTimeout?: number;
}

/**
 * Internal configuration with all required properties
 */
interface InternalClientConfig {
  // Connection settings
  timeout: number;
  retries: number;
  debug: boolean;
  
  // Auto-reconnection settings
  autoReconnect: boolean;
  maxRetries: number;
  retryDelay: number;
  
  // Heartbeat settings
  heartbeatInterval: number;
  heartbeatTimeout: number;
  
  // Progress tracking
  onProgress?: ProgressCallback;
  onConnectionStateChange?: ConnectionStateCallback;
  onMessage?: MessageCallback;
  
  // Session management
  sessionPersistence: boolean;
  sessionTimeout: number;
}

/**
 * Utility function to create a cancellation token
 */
export function createCancellationToken(): CancellationToken {
  let cancelled = false;
  const callbacks: (() => void)[] = [];
  
  return {
    get isCancelled() {
      return cancelled;
    },
    onCancelled(callback: () => void) {
      if (cancelled) {
        callback();
      } else {
        callbacks.push(callback);
      }
    },
    cancel() {
      if (!cancelled) {
        cancelled = true;
        callbacks.forEach(cb => {
          try {
            cb();
          } catch (error) {
            console.error('Cancellation callback error:', error);
          }
        });
        callbacks.length = 0;
      }
    }
  };
}

/**
 * Multi-server MCP client implementation
 */
export class MultiServerMCPClient implements IMultiServerMCPClient {
  private servers: Map<string, { config: ServerConfig; client: IEnhancedMCPClient }> = new Map();
  private clientFactory: MCPClientFactory;

  constructor(clientFactory: MCPClientFactory) {
    this.clientFactory = clientFactory;
  }

  /**
   * Add a server configuration
   */
  async addServer(serverConfig: ServerConfig): Promise<void> {
    if (this.servers.has(serverConfig.name)) {
      throw new Error(`Server '${serverConfig.name}' already exists`);
    }

    const client = this.clientFactory.create(serverConfig.config) as IEnhancedMCPClient;
    await client.connect();
    
    this.servers.set(serverConfig.name, { config: serverConfig, client });
  }

  /**
   * Remove a server
   */
  async removeServer(serverName: string): Promise<void> {
    const server = this.servers.get(serverName);
    if (server) {
      await server.client.disconnect();
      this.servers.delete(serverName);
    }
  }

  /**
   * List all configured servers
   */
  listServers(): ServerConfig[] {
    return Array.from(this.servers.values()).map(s => s.config);
  }

  /**
   * Get tools from all servers
   */
  async getAllTools(): Promise<Array<ToolInfo & { serverName: string }>> {
    const allTools: Array<ToolInfo & { serverName: string }> = [];
    
    for (const [serverName, { client }] of this.servers) {
      try {
        const tools = await client.listTools();
        allTools.push(...tools.map(tool => ({ ...tool, serverName })));
      } catch (error) {
        console.error(`Failed to get tools from server '${serverName}':`, error);
      }
    }
    
    return allTools;
  }

  /**
   * Call a tool on a specific server
   */
  async callToolOnServer(
    serverName: string, 
    toolName: string, 
    args?: any, 
    options?: CallOptions
  ): Promise<CallToolResult> {
    const server = this.servers.get(serverName);
    if (!server) {
      throw new Error(`Server '${serverName}' not found`);
    }
    
    return server.client.callTool(toolName, args, options);
  }

  /**
   * Get the best server for a tool (based on capabilities and priority)
   */
  async getBestServerForTool(toolName: string): Promise<string | null> {
    const allTools = await this.getAllTools();
    const toolServers = allTools
      .filter(tool => tool.name === toolName)
      .map(tool => {
        const serverConfig = this.servers.get(tool.serverName)?.config;
        return {
          serverName: tool.serverName,
          priority: serverConfig?.priority || 0
        };
      })
      .sort((a, b) => b.priority - a.priority);
    
    return toolServers.length > 0 ? toolServers[0].serverName : null;
  }

  /**
   * Disconnect all servers
   */
  async disconnectAll(): Promise<void> {
    const disconnectPromises = Array.from(this.servers.values())
      .map(({ client }) => client.disconnect());
    
    await Promise.allSettled(disconnectPromises);
    this.servers.clear();
  }
}

/**
 * Factory interface for creating MCP clients
 */
export interface MCPClientFactory<TConfig extends ClientConfig = ClientConfig> {
  create(config: TConfig): IMCPClient;
  createAndConnect(config: TConfig): Promise<IMCPClient>;
}

/**
 * Check if a task status is terminal
 */
export function isTerminalTaskStatus(status: TaskStatus): boolean {
  return status === 'completed' || status === 'failed' || status === 'cancelled';
}

// All types and classes are already exported where they are defined
