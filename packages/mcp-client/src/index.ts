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
      try {
        this.stats.reconnectCount++;
        await this.connect();
        // Reset reconnect count on successful reconnect
        this.stats.reconnectCount = 0;
      } catch (error) {
        console.error('Reconnection failed:', error);
        if (this.stats.reconnectCount < this.config.maxRetries) {
          this.scheduleReconnect();
        }
      }
    }, delay);
    this.reconnectTimer.unref();
  }

  /**
   * Register an elicitation handler
   */
  registerElicitationHandler(handler: ElicitationHandler): () => void {
    this.elicitationHandlers.add(handler);
    return () => this.elicitationHandlers.delete(handler);
  }

  /**
   * Handle elicitation request manually
   */
  async handleElicitationRequest(request: ElicitationRequest): Promise<ElicitationResponse> {
    // Validate request
    if (!request.id || !request.title || !Array.isArray(request.fields)) {
      throw new Error('Invalid elicitation request format');
    }

    // Add to active requests
    this.activeElicitationRequests.set(request.id, request);

    try {
      // Try each registered handler until one succeeds
      for (const handler of this.elicitationHandlers) {
        try {
          const response = await handler(request);
          
          // Validate response
          if (response.action === ElicitationAction.Accept && response.values) {
            const validationErrors = this.validateElicitationValues(request.fields, response.values);
            if (validationErrors.length > 0) {
              throw new Error(`Validation failed: ${validationErrors.map(e => e.message).join(', ')}`);
            }
          }
          
          return response;
        } catch (error) {
          console.error('Elicitation handler failed:', error);
          continue;
        }
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
   * Handle incoming elicitation requests from notifications
   */
  protected async handleElicitationNotification(notification: JSONRPCNotification): Promise<void> {
    if (notification.method === 'notifications/elicitation/request') {
      const request = notification.params as unknown as ElicitationRequest;
      
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

  /**
   * Clean up resources
   */
  protected cleanup(): void {
    this.stopHeartbeat();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    this.activeRequests.clear();
    this.elicitationHandlers.clear();
    this.activeElicitationRequests.clear();
    this.progressCallbacks.clear();
    this.connectionStateCallbacks.clear();
    this.messageCallbacks.clear();
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
 * Elicitation form field definition
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
 * Elicitation request from server to client
 */
export interface ElicitationRequest {
  id: string;
  title: string;
  description?: string;
  fields: ElicitationField[];
  timeout?: number; // milliseconds
  allowCancel?: boolean;
  metadata?: Record<string, any>;
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

// All types and classes are already exported where they are defined
