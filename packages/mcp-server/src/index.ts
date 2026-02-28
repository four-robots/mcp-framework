import { createHmac, randomBytes } from "node:crypto";
import { ResourceMetadata, McpServer as SDKMcpServer, ToolCallback, ResourceTemplate as SDKResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol";
import { CallToolResult, ServerNotification, ServerRequest, CompleteRequestSchema, CreateMessageRequestSchema, CompleteResult, CreateMessageResult, ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { MCPErrorFactory, MCPErrorClass, MCPError, MCPErrorCode } from "./errors.js";
import { SdkToolConfig, SdkToolResult } from "./tools.js";

export * from './types.js';
export * from './tools.js';

/**
 * MCP Notification interfaces
 */
export interface ProgressNotification {
  method: 'notifications/progress';
  params: {
    progressToken: string | number;
    progress: number;
    total?: number;
    message?: string;
  };
}

export interface LoggingNotification {
  method: 'notifications/message';
  params: {
    level: 'debug' | 'info' | 'notice' | 'warning' | 'error' | 'critical' | 'alert' | 'emergency';
    logger?: string;
    data: any;
  };
}

export interface CancellationNotification {
  method: 'notifications/cancelled';
  params: {
    requestId: string;
    reason?: string;
  };
}

export interface ResourceListChangedNotification {
  method: 'notifications/resources/list_changed';
  params?: {};
}

export interface ResourceUpdatedNotification {
  method: 'notifications/resources/updated';
  params: {
    uri: string;
  };
}

export interface ToolListChangedNotification {
  method: 'notifications/tools/list_changed';
  params?: {};
}

export interface PromptListChangedNotification {
  method: 'notifications/prompts/list_changed';
  params?: {};
}

export type ToolModule<Schema extends z.AnyZodObject = z.AnyZodObject> = {
  name: string;
  config: ToolConfig<Schema>;
  handler: ToolHandler<Schema>;
};

/**
 * RFC 5424 Log Severity Levels
 */
export enum LogLevel {
  Emergency = 0,   // System is unusable
  Alert = 1,       // Action must be taken immediately
  Critical = 2,    // Critical conditions
  Error = 3,       // Error conditions
  Warning = 4,     // Warning conditions
  Notice = 5,      // Normal but significant condition
  Info = 6,        // Informational messages
  Debug = 7        // Debug-level messages
}

/**
 * Log level names mapping to RFC 5424 levels
 */
export type LogLevelName = 'emergency' | 'alert' | 'critical' | 'error' | 'warning' | 'notice' | 'info' | 'debug';

/**
 * Advanced logging configuration
 */
export interface LoggingConfig {
  level: LogLevel;
  structured: boolean;
  includeTimestamp: boolean;
  includeSource: boolean;
  maxMessageLength?: number;
  loggers: Map<string, LogLevel>;
}

/**
 * Performance metrics for request tracking
 */
export interface PerformanceMetrics {
  correlationId: string;
  operation: string;
  duration: number;
  startTime: number;
  endTime: number;
  success: boolean;
  errorCode?: string;
  payloadSize?: number;
  metadata?: Record<string, any>;
}

/**
 * Enhanced structured log entry with correlation and performance tracking
 */
export interface StructuredLogEntry {
  timestamp: string;
  level: LogLevel;
  levelName: LogLevelName;
  logger?: string;
  message: string;
  data?: any;
  source?: {
    file?: string;
    function?: string;
    line?: number;
  };
  // Enhanced correlation fields
  correlationId?: string;
  requestId?: string;
  sessionId?: string;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;
  // Performance fields
  duration?: number;
  performance?: {
    startTime: number;
    endTime?: number;
    cpuUsage?: number;
    memoryUsage?: number;
  };
  // Enhanced metadata
  operation?: string;
  component?: string;
  version?: string;
  userId?: string;
  clientInfo?: {
    userAgent?: string;
    ipAddress?: string;
    clientVersion?: string;
  };
}

/**
 * Logging set level request
 */
export interface LoggingSetLevelRequest {
  level: LogLevel;
  logger?: string;
}

/**
 * Logging capabilities
 */
export interface LoggingCapabilities {
  supportedLevels: LogLevel[];
  supportsStructuredLogs: boolean;
  supportsLoggerNamespaces: boolean;
  maxMessageLength?: number;
}

/**
 * Transport interface that all transports must implement
 */
export interface Transport {
  start(server: MCPServer): Promise<void>;
  stop(): Promise<void>;
}

/**
 * Enhanced tool handler context with correlation tracking
 */
export interface ToolContext {
  user?: any;
  requestId?: string;
  correlationId?: string;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;
  startTime?: number;
  sessionId?: string;
  [key: string]: any;
}

/**
 * Session persistence configuration
 */
export interface SessionConfig {
  /** Enable session persistence */
  enabled: boolean;
  /** Session timeout in milliseconds (default: 24 hours) */
  timeoutMs?: number;
  /** Maximum number of sessions to store (default: 1000) */
  maxSessions?: number;
  /** Session cleanup interval in milliseconds (default: 1 hour) */
  cleanupIntervalMs?: number;
  /** Custom session key generator */
  keyGenerator?: (context: ToolContext) => string | null;
}

/**
 * Stored session data
 */
export interface SessionData {
  context: ToolContext;
  createdAt: number;
  lastAccessedAt: number;
  expiresAt: number;
  accessCount: number;
}

/**
 * Session manager for persistent context storage
 */
export class SessionManager {
  private sessions = new Map<string, SessionData>();
  private cleanupTimer: NodeJS.Timeout | null = null;
  private config: Required<SessionConfig>;

  constructor(config: SessionConfig) {
    this.config = {
      enabled: config.enabled,
      timeoutMs: config.timeoutMs ?? 24 * 60 * 60 * 1000, // 24 hours
      maxSessions: config.maxSessions ?? 1000,
      cleanupIntervalMs: config.cleanupIntervalMs ?? 60 * 60 * 1000, // 1 hour
      keyGenerator: config.keyGenerator ?? this.defaultKeyGenerator.bind(this)
    };

    if (this.config.enabled) {
      this.startCleanupTimer();
    }
  }

  /**
   * Default session key generator using sessionId or user ID
   */
  private defaultKeyGenerator(context: ToolContext): string | null {
    if (context.sessionId) {
      return `session:${context.sessionId}`;
    }
    if (context.user?.id) {
      return `user:${context.user.id}`;
    }
    if (context.correlationId) {
      return `correlation:${context.correlationId}`;
    }
    return null;
  }

  /**
   * Store session context
   */
  storeSession(context: ToolContext): boolean {
    if (!this.config.enabled) return false;

    const key = this.config.keyGenerator(context);
    if (!key) return false;

    const now = Date.now();
    const existing = this.sessions.get(key);

    const sessionData: SessionData = {
      context: { ...context },
      createdAt: existing?.createdAt ?? now,
      lastAccessedAt: now,
      expiresAt: now + this.config.timeoutMs,
      accessCount: (existing?.accessCount ?? 0) + 1
    };

    // Check if we need to remove old sessions to make room for a new session
    if (!existing && this.sessions.size >= this.config.maxSessions) {
      if (!this.evictOldestSession()) {
        return false; // Cannot make room, reject the new session
      }
    }

    this.sessions.set(key, sessionData);
    return true;
  }

  /**
   * Retrieve session context
   */
  retrieveSession(context: ToolContext): ToolContext | null {
    if (!this.config.enabled) return null;

    const key = this.config.keyGenerator(context);
    if (!key) return null;

    const sessionData = this.sessions.get(key);
    if (!sessionData) return null;

    const now = Date.now();

    // Check if session has expired
    if (now > sessionData.expiresAt) {
      this.sessions.delete(key);
      return null;
    }

    // Update last accessed time and extend expiration
    sessionData.lastAccessedAt = now;
    sessionData.expiresAt = now + this.config.timeoutMs;
    sessionData.accessCount++;

    return { ...sessionData.context };
  }

  /**
   * Delete a specific session
   */
  deleteSession(context: ToolContext): boolean {
    if (!this.config.enabled) return false;

    const key = this.config.keyGenerator(context);
    if (!key) return false;

    return this.sessions.delete(key);
  }

  /**
   * Get session statistics
   */
  getSessionStats() {
    return {
      totalSessions: this.sessions.size,
      maxSessions: this.config.maxSessions,
      enabled: this.config.enabled,
      activeSessions: Array.from(this.sessions.values()).filter(
        session => Date.now() <= session.expiresAt
      ).length
    };
  }

  /**
   * Clean up expired sessions
   */
  private cleanupExpiredSessions(): number {
    const now = Date.now();
    let removed = 0;

    for (const [key, sessionData] of this.sessions.entries()) {
      if (now > sessionData.expiresAt) {
        this.sessions.delete(key);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Evict the oldest session to make room for new ones
   */
  private evictOldestSession(): boolean {
    let oldestKey: string | null = null;
    let oldestTime = Number.MAX_SAFE_INTEGER;

    for (const [key, sessionData] of this.sessions.entries()) {
      if (sessionData.lastAccessedAt < oldestTime) {
        oldestTime = sessionData.lastAccessedAt;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.sessions.delete(oldestKey);
      return true;
    }

    return false;
  }

  /**
   * Start automatic cleanup timer
   */
  private startCleanupTimer(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }

    this.cleanupTimer = setInterval(() => {
      this.cleanupExpiredSessions();
    }, this.config.cleanupIntervalMs);
    // Allow Node.js to exit even if cleanup interval is still active
    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /**
   * Stop the session manager and cleanup resources
   */
  stop(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.sessions.clear();
  }
}

/**
 * Tool handler function type
 */
export type ToolHandler<Schema extends z.AnyZodObject = z.AnyZodObject> = (
  args: z.infer<Schema>,
  context: ToolContext
) => Promise<SdkToolResult>;

/**
 * Tool configuration
 */
export interface ToolConfig<Schema extends z.AnyZodObject = z.AnyZodObject> {
  title?: string;
  description: string;
  inputSchema: Schema;
}

/**
 * Resource configuration
 */
export interface ResourceConfig {
  title?: string;
  description?: string;
  mimeType?: string;
}

/**
 * Resource template interface for dynamic resources
 */
export interface ResourceTemplate {
  uriTemplate: string; // e.g., "file:///users/{userId}/documents/{docId}"
  name: string;
  title?: string;
  description?: string;
  mimeType?: string;
  annotations?: Record<string, any>;
}

/**
 * Resource template configuration
 */
export interface ResourceTemplateConfig {
  title?: string;
  description?: string;
  mimeType?: string;
  annotations?: Record<string, any>;
  parameterSchema?: Record<string, any>; // JSON schema for template parameters
}

/**
 * Resource template handler function type
 */
export type ResourceTemplateHandler = (
  uri: URL,
  params: Record<string, string>,
  templateParams?: Record<string, any>
) => Promise<{
  contents: Array<{
    uri: string;
    text?: string;
    blob?: string;
    mimeType?: string;
  }>;
}>;

/**
 * Resource template information
 */
export interface ResourceTemplateInfo {
  name: string;
  uriTemplate: string;
  title?: string;
  description?: string;
  mimeType?: string;
  annotations?: Record<string, any>;
  parameterSchema?: Record<string, any>;
}

/**
 * Completion request interface
 */
export interface CompletionRequest {
  ref: {
    type: 'ref/prompt' | 'ref/resource';
    name: string;
  };
  argument: {
    name: string;
    value: string;
  };
}

/**
 * Completion result interface
 */
// Use the SDK's CompleteResult type instead of our custom one
export type CompletionResult = CompleteResult;

/**
 * Completion handler function type
 */
export type CompletionHandler = (
  request: CompletionRequest
) => Promise<CompletionResult>;

/**
 * Completion configuration
 */
export interface CompletionConfig {
  name: string;
  description?: string;
  supportedTypes: Array<'ref/prompt' | 'ref/resource'>;
  supportedArguments?: string[];
}

/**
 * Sampling message interface
 */
export interface SamplingMessage {
  role: 'user' | 'assistant' | 'system';
  content: {
    type: 'text' | 'image';
    text?: string;
    data?: string; // Base64 encoded data for images
    mimeType?: string;
  };
  name?: string;
  annotations?: Record<string, any>;
}

/**
 * Model preferences for sampling
 */
export interface ModelPreferences {
  hints?: string[];
  costPriority?: number; // 0-1, where 0 is lowest cost, 1 is highest quality
  speedPriority?: number; // 0-1, where 0 is slowest, 1 is fastest
  intelligencePriority?: number; // 0-1, where 0 is simplest, 1 is most intelligent
}

/**
 * Sampling request interface
 */
export interface SamplingRequest {
  messages: SamplingMessage[];
  modelPreferences?: ModelPreferences;
  systemPrompt?: string;
  includeContext?: boolean;
  maxTokens?: number;
  temperature?: number;
  metadata?: Record<string, any>;
}

/**
 * Sampling response interface
 */
export interface SamplingResponse {
  model?: string;
  stopReason?: 'endTurn' | 'stopSequence' | 'maxTokens';
  role: 'assistant';
  content: {
    type: 'text';
    text: string;
  };
  usage?: {
    inputTokens?: number;
    outputTokens?: number;
    totalTokens?: number;
  };
  metadata?: Record<string, any>;
}

/**
 * Sampling handler function type
 */
export type SamplingHandler = (
  request: SamplingRequest
) => Promise<CreateMessageResult>;

/**
 * Sampling configuration
 */
export interface SamplingConfig {
  createMessage: SamplingHandler;
  includeContext?: boolean;
  supportedModels?: string[];
  maxTokensLimit?: number;
  temperatureRange?: { min: number; max: number };
  metadata?: Record<string, any>;
}

/**
 * Resource handler function type
 */
export type ResourceHandler = (uri: URL, params?: any) => Promise<{
  contents: Array<{
    uri: string;
    text?: string;
    blob?: string;
    mimeType?: string;
  }>;
}>;

/**
 * Prompt configuration
 */
export interface PromptConfig {
  title?: string;
  description?: string;
  argsSchema?: any; // JSON schema object with properties structure
}

/**
 * Prompt handler function type
 */
export type PromptHandler<T = any> = (args: T) => {
  messages: Array<{
    role: 'user' | 'assistant';
    content: {
      type: 'text';
      text: string;
    };
  }>;
} | Promise<{
  messages: Array<{
    role: 'user' | 'assistant';
    content: {
      type: 'text';
      text: string;
    };
  }>;
}>;

/**
 * Correlation ID and performance tracking utilities
 */
export class CorrelationManager {
  /**
   * Generate a unique correlation ID
   */
  static generateCorrelationId(): string {
    return `corr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Generate a unique request ID
   */
  static generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Generate a unique trace ID
   */
  static generateTraceId(): string {
    // Using crypto.randomUUID if available, fallback to timestamp+random
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
      return crypto.randomUUID();
    }
    return `trace_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Generate a unique span ID
   */
  static generateSpanId(): string {
    return `span_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Inject correlation context into existing context
   */
  static enhanceContext(context: ToolContext = {}): ToolContext {
    const now = performance.now();
    return {
      ...context,
      correlationId: context.correlationId || this.generateCorrelationId(),
      requestId: context.requestId || this.generateRequestId(),
      traceId: context.traceId || this.generateTraceId(),
      spanId: context.spanId || this.generateSpanId(),
      startTime: context.startTime || now,
    };
  }
}

/**
 * Performance tracking for operations
 */
export class PerformanceTracker {
  private metrics: Map<string, PerformanceMetrics> = new Map();
  private onMetricCompleted?: (metric: PerformanceMetrics) => void;

  constructor(onMetricCompleted?: (metric: PerformanceMetrics) => void) {
    this.onMetricCompleted = onMetricCompleted;
  }

  /**
   * Start tracking an operation
   */
  private static STALE_THRESHOLD = 300000; // 5 minutes

  startTracking(correlationId: string, operation: string, metadata?: Record<string, any>): void {
    const startTime = performance.now();
    this.metrics.set(correlationId, {
      correlationId,
      operation,
      startTime,
      endTime: 0,
      duration: 0,
      success: false,
      metadata
    });

    // Periodic cleanup of stale entries to prevent memory leaks
    if (this.metrics.size > 100) {
      const now = performance.now();
      for (const [id, metric] of this.metrics) {
        if (now - metric.startTime > PerformanceTracker.STALE_THRESHOLD) {
          this.metrics.delete(id);
        }
      }
    }
  }

  /**
   * End tracking an operation
   */
  endTracking(correlationId: string, success: boolean, errorCode?: string, payloadSize?: number): PerformanceMetrics | null {
    const metric = this.metrics.get(correlationId);
    if (!metric) {
      return null;
    }

    const endTime = performance.now();
    metric.endTime = endTime;
    metric.duration = endTime - metric.startTime;
    metric.success = success;
    metric.errorCode = errorCode;
    metric.payloadSize = payloadSize;

    this.metrics.delete(correlationId);

    // Notify callback if provided
    if (this.onMetricCompleted) {
      this.onMetricCompleted(metric);
    }

    return metric;
  }

  /**
   * Get current active tracking count
   */
  getActiveTrackingCount(): number {
    return this.metrics.size;
  }

  /**
   * Get all active tracking correlations
   */
  getActiveCorrelations(): string[] {
    return Array.from(this.metrics.keys());
  }

  /**
   * Clear all tracking (useful for cleanup)
   */
  clearAll(): void {
    this.metrics.clear();
  }
}

/**
 * Request tracing middleware
 */
export class RequestTracer {
  private performanceTracker: PerformanceTracker;
  private logger?: (entry: StructuredLogEntry) => void;

  constructor(logger?: (entry: StructuredLogEntry) => void) {
    this.logger = logger;
    this.performanceTracker = new PerformanceTracker((metric) => {
      this.logPerformanceMetric(metric);
    });
  }

  /**
   * Start tracing a request
   */
  startTrace(operation: string, context?: ToolContext): ToolContext {
    const enhancedContext = CorrelationManager.enhanceContext(context);

    this.performanceTracker.startTracking(
      enhancedContext.correlationId!,
      operation,
      { component: 'mcp-server' }
    );

    this.logTraceStart(operation, enhancedContext);
    return enhancedContext;
  }

  /**
   * End tracing a request
   */
  endTrace(context: ToolContext, success: boolean, errorCode?: string, payloadSize?: number): PerformanceMetrics | null {
    if (!context.correlationId) {
      return null;
    }

    const metric = this.performanceTracker.endTracking(
      context.correlationId,
      success,
      errorCode,
      payloadSize
    );

    if (metric) {
      this.logTraceEnd(metric, context);
    }

    return metric;
  }

  /**
   * Log trace start
   */
  private logTraceStart(operation: string, context: ToolContext): void {
    if (!this.logger) return;

    this.logger({
      timestamp: new Date().toISOString(),
      level: LogLevel.Debug,
      levelName: 'debug',
      logger: 'RequestTracer',
      message: `Starting operation: ${operation}`,
      correlationId: context.correlationId,
      requestId: context.requestId,
      traceId: context.traceId,
      spanId: context.spanId,
      operation,
      component: 'mcp-server',
      performance: {
        startTime: context.startTime || performance.now()
      }
    });
  }

  /**
   * Log trace end
   */
  private logTraceEnd(metric: PerformanceMetrics, context: ToolContext): void {
    if (!this.logger) return;

    this.logger({
      timestamp: new Date().toISOString(),
      level: metric.success ? LogLevel.Debug : LogLevel.Error,
      levelName: metric.success ? 'debug' : 'error',
      logger: 'RequestTracer',
      message: `Completed operation: ${metric.operation} (${metric.duration.toFixed(2)}ms)`,
      correlationId: metric.correlationId,
      requestId: context.requestId,
      traceId: context.traceId,
      spanId: context.spanId,
      operation: metric.operation,
      component: 'mcp-server',
      duration: metric.duration,
      performance: {
        startTime: metric.startTime,
        endTime: metric.endTime
      },
      data: {
        success: metric.success,
        errorCode: metric.errorCode,
        payloadSize: metric.payloadSize,
        metadata: metric.metadata
      }
    });
  }

  /**
   * Log performance metric
   */
  private logPerformanceMetric(metric: PerformanceMetrics): void {
    if (!this.logger) return;

    this.logger({
      timestamp: new Date().toISOString(),
      level: LogLevel.Info,
      levelName: 'info',
      logger: 'PerformanceTracker',
      message: `Performance metric: ${metric.operation}`,
      correlationId: metric.correlationId,
      operation: metric.operation,
      component: 'mcp-server',
      duration: metric.duration,
      data: metric
    });
  }

  /**
   * Get performance tracker for direct access
   */
  getPerformanceTracker(): PerformanceTracker {
    return this.performanceTracker;
  }
}

/**
 * Server configuration
 */
export interface ServerConfig {
  name: string;
  version: string;
  capabilities?: object;
  propagateErrors?: boolean;
  pagination?: {
    defaultPageSize?: number;
    maxPageSize?: number;
    cursorTTL?: number; // milliseconds
  };
  logging?: {
    level?: LogLevel;
    structured?: boolean;
    includeTimestamp?: boolean;
    includeSource?: boolean;
    maxMessageLength?: number;
    loggerLevels?: Record<string, LogLevel>;
  };
  session?: SessionConfig;
}

/**
 * Core MCP Server framework class
 * Provides a plugin architecture for transports and tools
 */
/**
 * Tool information
 */
export interface ToolInfo<Schema extends z.AnyZodObject = z.AnyZodObject> {
  name: string;
  title?: string;
  description: string;
  inputSchema: Schema;
}

/**
 * Resource information
 */
export interface ResourceInfo {
  name: string;
  uri: string;
  title?: string;
  description?: string;
  mimeType?: string;
}

/**
 * Prompt information
 */
export interface PromptInfo {
  name: string;
  title?: string;
  description?: string;
  arguments?: any[];
}

/**
 * Pagination cursor for stable pagination
 */
export interface PaginationCursor {
  token: string;
  timestamp: number;
  sortKey: string;
}

/**
 * Pagination options for list requests
 */
export interface PaginationOptions {
  cursor?: string;
  limit?: number;
}

/**
 * Paginated list result
 */
export interface PaginatedResult<T> {
  items: T[];
  nextCursor?: string;
  hasMore: boolean;
  total?: number;
}

/**
 * Paginated tools result
 */
export interface PaginatedToolsResult extends PaginatedResult<ToolInfo> { }

/**
 * Paginated resources result
 */
export interface PaginatedResourcesResult extends PaginatedResult<ResourceInfo> { }

/**
 * Paginated prompts result
 */
export interface PaginatedPromptsResult extends PaginatedResult<PromptInfo> { }

/**
 * Paginated resource templates result
 */
export interface PaginatedResourceTemplatesResult extends PaginatedResult<ResourceTemplateInfo> { }

export class MCPServer {
  private config: ServerConfig;
  private sdkServer: SDKMcpServer;
  private transports: Transport[] = [];
  private context: ToolContext = {};
  private started = false;

  // Track registered items for introspection
  private tools: Map<string, ToolInfo> = new Map();
  private resources: Map<string, ResourceInfo> = new Map();
  private resourceTemplates: Map<string, ResourceTemplateInfo> = new Map();
  private prompts: Map<string, PromptInfo> = new Map();
  private completionHandlers: Map<string, { config: CompletionConfig; handler: CompletionHandler }> = new Map();
  private completionRequestHandlerRegistered: boolean = false;
  private samplingConfig: SamplingConfig | null = null;

  // Pagination management
  private cursorSecret: string;
  private paginationDefaults: {
    defaultPageSize: number;
    maxPageSize: number;
    cursorTTL: number;
  };

  // Logging management
  private loggingConfig: LoggingConfig;

  // Request tracing and performance monitoring
  private requestTracer: RequestTracer;

  // Session management
  private sessionManager: SessionManager | null = null;

  constructor(config: ServerConfig) {
    this.config = config;
    this.sdkServer = new SDKMcpServer({
      name: config.name,
      version: config.version,
      capabilities: config.capabilities
    });

    // Initialize pagination configuration
    this.paginationDefaults = {
      defaultPageSize: config.pagination?.defaultPageSize || 50,
      maxPageSize: config.pagination?.maxPageSize || 1000,
      cursorTTL: config.pagination?.cursorTTL || 3600000 // 1 hour default
    };

    // Generate secure cursor secret for HMAC
    this.cursorSecret = this.generateCursorSecret();

    // Initialize logging configuration
    this.loggingConfig = {
      level: config.logging?.level ?? LogLevel.Info,
      structured: config.logging?.structured || false,
      includeTimestamp: config.logging?.includeTimestamp !== undefined ? config.logging.includeTimestamp : true,
      includeSource: config.logging?.includeSource || false,
      maxMessageLength: config.logging && 'maxMessageLength' in config.logging ? config.logging.maxMessageLength : 8192,
      loggers: new Map()
    };

    // Initialize logger levels from config
    if (config.logging?.loggerLevels) {
      for (const [logger, level] of Object.entries(config.logging.loggerLevels)) {
        this.loggingConfig.loggers.set(logger, level);
      }
    }

    // Initialize request tracer with logging integration
    this.requestTracer = new RequestTracer((entry: StructuredLogEntry) => {
      this.logStructuredEntry(entry);
    });

    // Initialize session manager if configured
    if (config.session) {
      this.sessionManager = new SessionManager(config.session);
    }

    // Register logging/setLevel endpoint
    this.registerLoggingEndpoints();
  }

  /**
   * Generate a secure random secret for cursor HMAC
   */
  private generateCursorSecret(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Create a cursor token for pagination
   */
  private createCursor(sortKey: string, timestamp: number = Date.now()): string {
    const cursor: PaginationCursor = {
      token: Math.random().toString(36).substring(2, 15),
      timestamp,
      sortKey
    };

    const payload = JSON.stringify(cursor);
    const signature = this.createHMAC(payload);

    return Buffer.from(JSON.stringify({
      payload,
      signature
    })).toString('base64');
  }

  /**
   * Validate and parse a cursor token
   */
  private parseCursor(cursorString: string): PaginationCursor | null {
    try {
      const decoded = JSON.parse(Buffer.from(cursorString, 'base64').toString());
      const { payload, signature } = decoded;

      // Verify signature
      if (this.createHMAC(payload) !== signature) {
        return null;
      }

      const cursor: PaginationCursor = JSON.parse(payload);

      // Check expiration
      if (Date.now() - cursor.timestamp > this.paginationDefaults.cursorTTL) {
        return null;
      }

      return cursor;
    } catch {
      return null;
    }
  }

  /**
   * Create HMAC-SHA256 signature for cursor validation
   */
  private createHMAC(data: string): string {
    return createHmac('sha256', this.cursorSecret).update(data).digest('hex');
  }

  /**
   * Paginate an array of items
   */
  private paginateItems<T extends { name: string }>(
    items: T[],
    options: PaginationOptions = {}
  ): PaginatedResult<T> {
    const limit = Math.min(
      options.limit || this.paginationDefaults.defaultPageSize,
      this.paginationDefaults.maxPageSize
    );

    // Sort items by name for stable pagination
    const sortedItems = [...items].sort((a, b) => a.name.localeCompare(b.name));

    let startIndex = 0;

    // If cursor provided, find starting position
    if (options.cursor) {
      const cursor = this.parseCursor(options.cursor);
      if (cursor) {
        startIndex = sortedItems.findIndex(item => item.name > cursor.sortKey);
        if (startIndex === -1) {
          startIndex = sortedItems.length;
        }
      }
    }

    const endIndex = startIndex + limit;
    const paginatedItems = sortedItems.slice(startIndex, endIndex);
    const hasMore = endIndex < sortedItems.length;

    let nextCursor: string | undefined;
    if (hasMore && paginatedItems.length > 0) {
      const lastItem = paginatedItems[paginatedItems.length - 1];
      nextCursor = this.createCursor(lastItem.name);
    }

    return {
      items: paginatedItems,
      nextCursor,
      hasMore,
      total: sortedItems.length
    };
  }

  /**
   * Add a transport to this server (supports multiple transports)
   */
  useTransport(transport: Transport): void {
    if (this.started) {
      throw new Error('Cannot add transport after server has started');
    }
    this.transports.push(transport);
  }

  /**
   * Add multiple transports at once
   */
  useTransports(...transports: Transport[]): void {
    transports.forEach(t => this.useTransport(t));
  }

  /**
   * Set or update the context that will be passed to all tool handlers
   */
  setContext(context: Partial<ToolContext>): void {
    this.context = { ...this.context, ...context };

    // Store session if session management is enabled and context has session ID
    if (this.sessionManager && this.context.sessionId) {
      // Get existing session context to merge with
      const existingSession = this.sessionManager.retrieveSession(this.context);
      const sessionContext = existingSession ?
        { ...existingSession, ...this.context } :
        this.context;
      this.sessionManager.storeSession(sessionContext);
    }
  }

  /**
   * Get the current context with session restoration
   */
  getContext(): ToolContext {
    let resultContext = { ...this.context };

    // Attempt to restore session if available
    if (this.sessionManager) {
      const restoredContext = this.sessionManager.retrieveSession(this.context);
      if (restoredContext) {
        // Merge restored context with current context, preferring current values
        resultContext = { ...restoredContext, ...this.context };
      }
    }

    return resultContext;
  }

  /**
   * Set context with session key for persistent storage
   */
  setSessionContext(sessionKey: string, context: Partial<ToolContext>): boolean {
    if (!this.sessionManager) return false;

    const sessionContext = { ...context, sessionId: sessionKey };
    return this.sessionManager.storeSession(sessionContext);
  }

  /**
   * Get context for a specific session
   */
  getSessionContext(sessionKey: string): ToolContext | null {
    if (!this.sessionManager) return null;

    return this.sessionManager.retrieveSession({ sessionId: sessionKey });
  }

  /**
   * Delete a specific session
   */
  deleteSession(sessionKey: string): boolean {
    if (!this.sessionManager) return false;

    return this.sessionManager.deleteSession({ sessionId: sessionKey });
  }

  /**
   * Get session management statistics
   */
  getSessionStats() {
    if (!this.sessionManager) {
      return { enabled: false, totalSessions: 0, maxSessions: 0, activeSessions: 0 };
    }

    return this.sessionManager.getSessionStats();
  }

  registerTool<Schema extends z.AnyZodObject>(
    toolModule: ToolModule<Schema>
  ): void;

  registerTool<Schema extends z.AnyZodObject>(
    name: string,
    config: ToolConfig<Schema>,
    handler: ToolHandler<Schema>
  ): void;

  registerTool<Schema extends z.AnyZodObject>(
    nameOrModule: string | ToolModule<Schema>,
    maybeConfig?: ToolConfig<Schema>,
    maybeHandler?: ToolHandler<Schema>
  ): void {
    // First check if nameOrModule is a valid string for the legacy API
    if (typeof nameOrModule === 'string') {
      // Legacy API: registerTool(name, config, handler)
      if (!nameOrModule || nameOrModule.length === 0) {
        throw MCPErrorFactory.invalidParams('Tool name must be a non-empty string');
      }
      
      const name = nameOrModule;
      const config = maybeConfig!;
      const handler = maybeHandler!;

      this.registerToolInternal(name, config, handler);
      return;
    }

    // Check for invalid non-string, non-object types (null, undefined, number, etc.)
    if (!nameOrModule || typeof nameOrModule !== 'object' || Array.isArray(nameOrModule)) {
      throw MCPErrorFactory.invalidParams('Tool name must be a non-empty string');
    }

    // Module API: registerTool(toolModule)
    if (maybeConfig || maybeHandler) {
      throw MCPErrorFactory.invalidParams(
        'When passing a tool module object, do not pass additional arguments.'
      );
    }

    const name = nameOrModule.name;
    const config = nameOrModule.config;
    const handler = nameOrModule.handler;

    // Validate tool name from module
    if (!name || typeof name !== 'string') {
      throw MCPErrorFactory.invalidParams('Tool name must be a non-empty string');
    }

    this.registerToolInternal(name, config, handler);
  }

  private registerToolInternal<Schema extends z.AnyZodObject>(
    name: string,
    config: ToolConfig<Schema>,
    handler: ToolHandler<Schema>
  ): void {

    // Check for duplicates
    if (this.tools.has(name)) {
      throw MCPErrorFactory.invalidParams(`Tool '${name}' is already registered`);
    }

    // Validate schema shape
    if (!config.inputSchema || typeof config.inputSchema !== 'object') {
      throw MCPErrorFactory.invalidParams('Tool inputSchema must be a Zod schema object');
    }

    if (!('_def' in config.inputSchema) || !('shape' in config.inputSchema)) {
      throw MCPErrorFactory.invalidParams(
        'Tool inputSchema must be a Zod schema object, not a plain JSON schema. Use z.object({ ... }) instead.'
      );
    }

    this.tools.set(name, {
      name,
      title: config.title,
      description: config.description,
      inputSchema: config.inputSchema,
    });

    const toolConfig: SdkToolConfig = {
      description: config.description,
      inputSchema: config.inputSchema.shape,
    };

    if (config.title) {
      toolConfig.title = config.title;
    }

    this.sdkServer.registerTool(
      name,
      toolConfig as any,
      async (args: any, extra: any) => {
        const tracedContext = this.requestTracer.startTrace(`tool_call:${name}`, this.getContext());

        try {
          const result = await handler(args, tracedContext);

          const payloadSize = result?.content
            ? result.content.reduce((sum: number, c: any) => sum + (c.text?.length || c.blob?.length || 0), 0)
            : 0;
          this.requestTracer.endTrace(tracedContext, true, undefined, payloadSize);
          return result;
        } catch (error) {
          const mcpError = MCPErrorFactory.fromError(error);
          this.requestTracer.endTrace(tracedContext, false, mcpError.code?.toString());
          throw mcpError;
        }
      }
    );

    if (this.started) {
      this.sendToolListChangedNotification().catch(err => {
        console.error('Failed to send tool list changed notification:', err);
      });
    }
  }

  /**
   * Register a resource with the server
   */
  registerResource(
    name: string,
    uriTemplate: string | any, // String or ResourceTemplate
    config: Omit<ResourceInfo, "name" | "uri">,
    handler: ResourceHandler
  ): void {
    // Validate resource name
    if (!name || typeof name !== 'string') {
      throw MCPErrorFactory.invalidParams('Resource name must be a non-empty string');
    }

    // Check if resource already exists
    if (this.resources.has(name)) {
      throw MCPErrorFactory.invalidParams(`Resource '${name}' is already registered`);
    }

    // Track resource info
    this.resources.set(name, {
      name,
      uri: typeof uriTemplate === 'string' ? uriTemplate : uriTemplate.uriTemplate,
      title: config.title,
      description: config.description,
      mimeType: config.mimeType
    });

    // Wrap handler with error handling and tracing
    const wrappedHandler = async (uri: URL, params?: any) => {
      // Start request tracing
      const tracedContext = this.requestTracer.startTrace(`resource_read:${name}`, this.getContext());

      try {
        const result = await handler(uri, params);

        // End tracing successfully
        this.requestTracer.endTrace(tracedContext, true, undefined, JSON.stringify(result).length);

        return result;
      } catch (error) {
        // End tracing with error
        const mcpError = MCPErrorFactory.fromError(error);
        this.requestTracer.endTrace(tracedContext, false, mcpError.code?.toString());

        throw mcpError;
      }
    };

    this.sdkServer.registerResource(name, uriTemplate, config as any, wrappedHandler as any);

    // Notify that resource list has changed
    if (this.started) {
      this.sendResourceListChangedNotification().catch(err => {
        console.error('Failed to send resource list changed notification:', err);
      });
    }
  }

  /**
   * Register a prompt with the server
   */
  registerPrompt<T = any>(
    name: string,
    config: PromptConfig,
    handler: PromptHandler<T>
  ): void {
    // Validate prompt name
    if (!name || typeof name !== 'string') {
      throw MCPErrorFactory.invalidParams('Prompt name must be a non-empty string');
    }

    // Check if prompt already exists
    if (this.prompts.has(name)) {
      throw MCPErrorFactory.invalidParams(`Prompt '${name}' is already registered`);
    }

    // Track prompt info
    this.prompts.set(name, {
      name,
      title: config.title,
      description: config.description,
      arguments: config.argsSchema && config.argsSchema.properties ? Object.keys(config.argsSchema.properties) : []
    });

    // Create the prompt config object for SDK
    const promptConfig: any = {};

    if (config.title) {
      promptConfig.title = config.title;
    }
    if (config.description) {
      promptConfig.description = config.description;
    }
    if (config.argsSchema) {
      // Convert JSON schema to Zod schema shape for SDK compatibility
      promptConfig.argsSchema = this.jsonSchemaToZodShape(config.argsSchema);
    }

    // Wrap handler with error handling and tracing
    const wrappedHandler = async (args: T) => {
      // Start request tracing
      const tracedContext = this.requestTracer.startTrace(`prompt_get:${name}`, this.getContext());

      try {
        const result = await handler(args);

        // End tracing successfully
        this.requestTracer.endTrace(tracedContext, true, undefined, JSON.stringify(result).length);

        return result;
      } catch (error) {
        // End tracing with error
        const mcpError = MCPErrorFactory.fromError(error);
        this.requestTracer.endTrace(tracedContext, false, mcpError.code?.toString());

        throw mcpError;
      }
    };

    // Pass through to SDK's registerPrompt
    this.sdkServer.registerPrompt(
      name,
      promptConfig,
      wrappedHandler as any
    );

    // Notify that prompt list has changed
    if (this.started) {
      this.sendPromptListChangedNotification().catch(err => {
        console.error('Failed to send prompt list changed notification:', err);
      });
    }
  }

  /**
   * Convert JSON schema to Zod schema shape for MCP SDK compatibility
   */
  private jsonSchemaToZodShape(jsonSchema: any): any {
    if (!jsonSchema || typeof jsonSchema !== 'object') {
      return {};
    }

    if (jsonSchema.type === 'object' && jsonSchema.properties) {
      const shape: any = {};
      const required = jsonSchema.required || [];

      for (const [key, prop] of Object.entries(jsonSchema.properties)) {
        const propSchema = prop as any;
        let zodType: any;

        // Handle enum values before type-based matching
        if (propSchema.enum && Array.isArray(propSchema.enum) && propSchema.enum.length > 0) {
          zodType = z.enum(propSchema.enum as [string, ...string[]]);
        } else {
          switch (propSchema.type) {
            case 'string':
              zodType = z.string();
              break;
            case 'number':
              zodType = z.number();
              break;
            case 'integer':
              zodType = z.number().int();
              break;
            case 'boolean':
              zodType = z.boolean();
              break;
            case 'array':
              zodType = z.array(z.any());
              break;
            case 'object':
              zodType = z.object(this.jsonSchemaToZodShape(propSchema));
              break;
            default:
              zodType = z.any();
          }
        }

        // Add description if present
        if (propSchema.description) {
          zodType = zodType.describe(propSchema.description);
        }

        // Make optional if not in required array
        if (!required.includes(key)) {
          zodType = zodType.optional();
        }

        shape[key] = zodType;
      }

      return shape;
    }

    return {};
  }

  /**
   * Get the underlying SDK server instance
   * This allows transports to access the raw server for connection
   */
  getSDKServer(): SDKMcpServer {
    return this.sdkServer;
  }

  /**
   * Send a progress notification for long-running operations
   */
  async sendProgressNotification(
    progressToken: string | number,
    progress: number,
    total?: number,
    message?: string
  ): Promise<void> {
    if (this.sdkServer.server && this.sdkServer.server.notification) {
      try {
        await this.sdkServer.server.notification({
          method: 'notifications/progress',
          params: {
            progressToken,
            progress,
            ...(total !== undefined && { total }),
            ...(message && { message })
          }
        });
      } catch (error) {
        console.error('Failed to send progress notification:', error);
      }
    }
  }

  /**
   * Send a logging notification (enhanced version)
   */
  async sendLogNotification(
    level: LogLevelName,
    data: any,
    logger?: string
  ): Promise<void> {
    // Send log notification via SDK server
    if (this.sdkServer.server && this.sdkServer.server.notification) {
      try {
        await this.sdkServer.server.notification({
          method: 'notifications/message',
          params: {
            level,
            logger,
            data
          }
        });
      } catch (error) {
        console.error('Failed to send log notification:', error);
      }
    }
  }

  /**
   * Send a cancellation notification
   */
  async sendCancellationNotification(
    requestId: string,
    reason?: string
  ): Promise<void> {
    if (this.sdkServer.server && this.sdkServer.server.notification) {
      try {
        await this.sdkServer.server.notification({
          method: 'notifications/cancelled',
          params: {
            requestId,
            ...(reason && { reason })
          }
        });
      } catch (error) {
        console.error('Failed to send cancellation notification:', error);
      }
    }
  }

  /**
   * Send notification that resource list has changed
   */
  async sendResourceListChangedNotification(): Promise<void> {
    if (this.sdkServer.server && this.sdkServer.server.notification) {
      try {
        await this.sdkServer.server.notification({
          method: 'notifications/resources/list_changed',
          params: {}
        });
      } catch (error) {
        console.error('Failed to send resource list changed notification:', error);
      }
    }
  }

  /**
   * Send notification that a resource has been updated
   */
  async sendResourceUpdatedNotification(uri: string): Promise<void> {
    if (this.sdkServer.server && this.sdkServer.server.notification) {
      try {
        await this.sdkServer.server.notification({
          method: 'notifications/resources/updated',
          params: { uri }
        });
      } catch (error) {
        console.error('Failed to send resource updated notification:', error);
      }
    }
  }

  /**
   * Send notification that tool list has changed
   */
  async sendToolListChangedNotification(): Promise<void> {
    if (this.sdkServer.server && this.sdkServer.server.notification) {
      try {
        await this.sdkServer.server.notification({
          method: 'notifications/tools/list_changed',
          params: {}
        });
      } catch (error) {
        console.error('Failed to send tool list changed notification:', error);
      }
    }
  }

  /**
   * Send notification that prompt list has changed
   */
  async sendPromptListChangedNotification(): Promise<void> {
    if (this.sdkServer.server && this.sdkServer.server.notification) {
      try {
        await this.sdkServer.server.notification({
          method: 'notifications/prompts/list_changed',
          params: {}
        });
      } catch (error) {
        console.error('Failed to send prompt list changed notification:', error);
      }
    }
  }

  /**
   * Register logging endpoints with the SDK server
   */
  private registerLoggingEndpoints(): void {
    // Register logging/setLevel endpoint 
    const LoggingRequestSchema = z.object({
      method: z.literal('logging/setLevel'),
      params: z.object({
        level: z.string(),
        logger: z.string().optional()
      })
    });

    if (this.sdkServer.server && this.sdkServer.server.setRequestHandler) {
      try {
        this.sdkServer.server.setRequestHandler(LoggingRequestSchema, async (request: any) => {
          const { level, logger } = request.params;
          const logLevel = this.nameToLogLevel(level);
          await this.setLogLevel(logLevel, logger);
          return { success: true };
        });
      } catch (error) {
        // Ignore logging registration errors in test environments
        // The SDK server may not support logging capabilities
      }
    }
  }

  /**
   * Set logging level for global or specific logger
   */
  async setLogLevel(level: LogLevel, logger?: string): Promise<void> {
    if (logger) {
      this.loggingConfig.loggers.set(logger, level);
    } else {
      this.loggingConfig.level = level;
    }

    // Send notification about level change
    await this.sendLogNotification(
      this.logLevelToName(LogLevel.Info),
      {
        message: `Log level changed to ${this.logLevelToName(level)}`,
        level,
        logger
      },
      'mcp.server.logging'
    );
  }

  /**
   * Get current logging configuration
   */
  getLoggingConfig(): LoggingConfig {
    return {
      ...this.loggingConfig,
      loggers: new Map(this.loggingConfig.loggers)
    };
  }

  /**
   * Get logging capabilities
   */
  getLoggingCapabilities(): LoggingCapabilities {
    return {
      supportedLevels: Object.values(LogLevel).filter(v => typeof v === 'number') as LogLevel[],
      supportsStructuredLogs: true,
      supportsLoggerNamespaces: true,
      maxMessageLength: this.loggingConfig.maxMessageLength
    };
  }

  /**
   * Enhanced logging method with RFC 5424 levels and structured logging
   */
  async log(
    level: LogLevel,
    message: string,
    data?: any,
    logger?: string,
    source?: { file?: string; function?: string; line?: number },
    requestId?: string,
    sessionId?: string
  ): Promise<void> {
    // Normalize invalid log levels to Info for validation and processing
    const normalizedLevel = this.isValidLogLevel(level) ? level : LogLevel.Info;

    // Check if this log should be sent based on level filtering
    if (!this.shouldLog(normalizedLevel, logger)) {
      return;
    }

    // Truncate message if too long
    let finalMessage = message;
    if (this.loggingConfig.maxMessageLength != null && this.loggingConfig.maxMessageLength > 3 && message.length > this.loggingConfig.maxMessageLength) {
      finalMessage = message.substring(0, this.loggingConfig.maxMessageLength - 3) + '...';
    }

    if (this.loggingConfig.structured) {
      // Send structured log
      const logEntry: StructuredLogEntry = {
        timestamp: this.loggingConfig.includeTimestamp ? new Date().toISOString() : '',
        level: normalizedLevel,
        levelName: this.logLevelToName(normalizedLevel),
        logger,
        message: finalMessage,
        data,
        source: this.loggingConfig.includeSource ? source : undefined,
        requestId,
        sessionId
      };

      await this.sendLogNotification(
        this.logLevelToName(normalizedLevel),
        logEntry,
        logger
      );
    } else {
      // Send simple log
      await this.sendLogNotification(
        this.logLevelToName(normalizedLevel),
        data ? { message: finalMessage, data } : finalMessage,
        logger
      );
    }
  }

  /**
   * Convenience logging methods
   */
  async logDebug(message: string, data?: any, logger?: string): Promise<void> {
    await this.log(LogLevel.Debug, message, data, logger);
  }

  async logInfo(message: string, data?: any, logger?: string): Promise<void> {
    await this.log(LogLevel.Info, message, data, logger);
  }

  async logNotice(message: string, data?: any, logger?: string): Promise<void> {
    await this.log(LogLevel.Notice, message, data, logger);
  }

  async logWarning(message: string, data?: any, logger?: string): Promise<void> {
    await this.log(LogLevel.Warning, message, data, logger);
  }

  async logError(message: string, data?: any, logger?: string): Promise<void> {
    await this.log(LogLevel.Error, message, data, logger);
  }

  async logCritical(message: string, data?: any, logger?: string): Promise<void> {
    await this.log(LogLevel.Critical, message, data, logger);
  }

  async logAlert(message: string, data?: any, logger?: string): Promise<void> {
    await this.log(LogLevel.Alert, message, data, logger);
  }

  async logEmergency(message: string, data?: any, logger?: string): Promise<void> {
    await this.log(LogLevel.Emergency, message, data, logger);
  }

  /**
   * Check if a log level is valid
   */
  private isValidLogLevel(level: LogLevel): boolean {
    return level >= LogLevel.Emergency && level <= LogLevel.Debug;
  }

  /**
   * Check if a log should be sent based on level filtering
   */
  private shouldLog(level: LogLevel, logger?: string): boolean {
    if (logger) {
      // First try exact match
      if (this.loggingConfig.loggers.has(logger)) {
        return level <= this.loggingConfig.loggers.get(logger)!;
      }

      // Then try hierarchical matching (e.g., 'app.debug' -> 'app')
      const parts = logger.split('.');
      for (let i = parts.length - 1; i > 0; i--) {
        const parentLogger = parts.slice(0, i).join('.');
        if (this.loggingConfig.loggers.has(parentLogger)) {
          return level <= this.loggingConfig.loggers.get(parentLogger)!;
        }
      }
    }

    // Fall back to global level
    return level <= this.loggingConfig.level;
  }

  /**
   * Convert LogLevel enum to string name
   */
  private logLevelToName(level: LogLevel): LogLevelName {
    switch (level) {
      case LogLevel.Emergency: return 'emergency';
      case LogLevel.Alert: return 'alert';
      case LogLevel.Critical: return 'critical';
      case LogLevel.Error: return 'error';
      case LogLevel.Warning: return 'warning';
      case LogLevel.Notice: return 'notice';
      case LogLevel.Info: return 'info';
      case LogLevel.Debug: return 'debug';
      default: return 'info';
    }
  }

  /**
   * Convert log level name to LogLevel enum
   */
  private nameToLogLevel(levelName: string): LogLevel {
    switch (levelName.toLowerCase()) {
      case 'emergency': return LogLevel.Emergency;
      case 'alert': return LogLevel.Alert;
      case 'critical': return LogLevel.Critical;
      case 'error': return LogLevel.Error;
      case 'warning': return LogLevel.Warning;
      case 'notice': return LogLevel.Notice;
      case 'info': return LogLevel.Info;
      case 'debug': return LogLevel.Debug;
      default: return LogLevel.Info;
    }
  }


  /**
   * Start the server with all configured transports
   */
  async start(): Promise<void> {
    if (this.transports.length === 0) {
      throw new Error('No transports configured. Use useTransport() to add transports.');
    }

    if (this.started) {
      throw new Error('Server has already been started');
    }

    // Start transports sequentially so we can clean up on partial failure
    const startedTransports: Transport[] = [];
    try {
      for (const t of this.transports) {
        await t.start(this);
        startedTransports.push(t);
      }
      this.started = true;
    } catch (error) {
      // Clean up transports that successfully started
      await Promise.allSettled(startedTransports.map(t => t.stop()));
      throw error;
    }
  }

  /**
   * Stop the server and all transports
   */
  async stop(): Promise<void> {
    if (!this.started) {
      return;
    }

    // Stop all transports - use allSettled so one failure doesn't prevent others from cleaning up
    const results = await Promise.allSettled(this.transports.map(t => t.stop()));
    for (const result of results) {
      if (result.status === 'rejected') {
        console.error('Transport failed to stop:', result.reason);
      }
    }

    // Stop session manager if enabled
    if (this.sessionManager) {
      this.sessionManager.stop();
    }

    this.started = false;
  }

  /**
   * Check if the server is running
   */
  isStarted(): boolean {
    return this.started;
  }

  /**
   * Get information about all registered tools
   */
  getTools(): ToolInfo[] {
    return Array.from(this.tools.values());
  }

  /**
   * Get information about a specific tool
   */
  getTool(name: string): ToolInfo | undefined {
    if (!name || typeof name !== 'string') {
      throw MCPErrorFactory.invalidParams('Tool name must be a non-empty string');
    }
    return this.tools.get(name);
  }

  /**
   * Get information about all registered resources
   */
  getResources(): ResourceInfo[] {
    return Array.from(this.resources.values());
  }

  /**
   * Get information about a specific resource
   */
  getResource(name: string): ResourceInfo | undefined {
    if (!name || typeof name !== 'string') {
      throw MCPErrorFactory.invalidParams('Resource name must be a non-empty string');
    }
    return this.resources.get(name);
  }

  /**
   * Get information about all registered prompts
   */
  getPrompts(): PromptInfo[] {
    return Array.from(this.prompts.values());
  }

  /**
   * Get information about a specific prompt
   */
  getPrompt(name: string): PromptInfo | undefined {
    if (!name || typeof name !== 'string') {
      throw MCPErrorFactory.invalidParams('Prompt name must be a non-empty string');
    }
    return this.prompts.get(name);
  }

  /**
   * Get paginated tools list
   */
  getToolsPaginated(options: PaginationOptions = {}): PaginatedToolsResult {
    this.validatePaginationOptions(options);
    return this.paginateItems(Array.from(this.tools.values()), options);
  }

  /**
   * Get paginated resources list
   */
  getResourcesPaginated(options: PaginationOptions = {}): PaginatedResourcesResult {
    this.validatePaginationOptions(options);
    return this.paginateItems(Array.from(this.resources.values()), options);
  }

  /**
   * Get paginated prompts list
   */
  getPromptsPaginated(options: PaginationOptions = {}): PaginatedPromptsResult {
    this.validatePaginationOptions(options);
    return this.paginateItems(Array.from(this.prompts.values()), options);
  }

  /**
   * Get paginated resource templates list
   */
  getResourceTemplatesPaginated(options: PaginationOptions = {}): PaginatedResourceTemplatesResult {
    this.validatePaginationOptions(options);
    return this.paginateItems(Array.from(this.resourceTemplates.values()), options);
  }

  /**
   * Validate pagination options
   */
  private validatePaginationOptions(options: PaginationOptions): void {
    if (options.limit !== undefined) {
      if (typeof options.limit !== 'number' || options.limit < 1) {
        throw MCPErrorFactory.invalidParams('Limit must be a positive number');
      }
      if (options.limit > this.paginationDefaults.maxPageSize) {
        throw MCPErrorFactory.invalidParams(`Limit cannot exceed ${this.paginationDefaults.maxPageSize}`);
      }
    }

    if (options.cursor !== undefined) {
      if (typeof options.cursor !== 'string' || options.cursor.length === 0) {
        throw MCPErrorFactory.invalidParams('Cursor must be a non-empty string');
      }

      const parsedCursor = this.parseCursor(options.cursor);
      if (!parsedCursor) {
        throw MCPErrorFactory.invalidParams('Invalid or expired cursor');
      }
    }
  }

  /**
   * Register a resource template with the server
   */
  registerResourceTemplate(
    name: string,
    uriTemplate: string,
    config: ResourceTemplateConfig,
    handler: ResourceTemplateHandler
  ): void {
    // Validate template name
    if (!name || typeof name !== 'string') {
      throw MCPErrorFactory.invalidParams('Resource template name must be a non-empty string');
    }

    // Validate URI template
    if (!uriTemplate || typeof uriTemplate !== 'string') {
      throw MCPErrorFactory.invalidParams('URI template must be a non-empty string');
    }

    // Check if template already exists
    if (this.resourceTemplates.has(name)) {
      throw MCPErrorFactory.invalidParams(`Resource template '${name}' is already registered`);
    }

    // Validate URI template format
    if (!this.isValidUriTemplate(uriTemplate)) {
      throw MCPErrorFactory.invalidParams(`Invalid URI template format: ${uriTemplate}`);
    }

    // Track resource template info
    this.resourceTemplates.set(name, {
      name,
      uriTemplate,
      title: config.title,
      description: config.description,
      mimeType: config.mimeType,
      annotations: config.annotations,
      parameterSchema: config.parameterSchema
    });

    // Create template object for SDK
    const templateConfig = {
      uriTemplate,
      name,
      title: config.title,
      description: config.description,
      mimeType: config.mimeType,
      annotations: config.annotations
    };

    // Wrap handler with error handling and parameter validation
    const wrappedHandler = async (uri: URL) => {
      try {
        // Extract template parameters from URI
        const templateParams = this.extractTemplateParams(uriTemplate, uri.toString());

        // Validate parameters against schema if provided
        if (config.parameterSchema) {
          this.validateTemplateParams(templateParams, config.parameterSchema);
        }

        return await handler(uri, templateParams);
      } catch (error) {
        // Convert any error to MCP error format
        const mcpError = MCPErrorFactory.fromError(error);
        throw mcpError;
      }
    };

    // Create proper ResourceTemplate object for MCP SDK
    const resourceTemplate = new SDKResourceTemplate(templateConfig.uriTemplate, { list: undefined });
    this.sdkServer.registerResource(name, resourceTemplate, config as any, wrappedHandler as any);

    // Notify that resource list has changed
    if (this.started) {
      this.sendResourceListChangedNotification().catch(err => {
        console.error('Failed to send resource list changed notification:', err);
      });
    }
  }

  /**
   * List all registered resource templates
   */
  listResourceTemplates(): ResourceTemplateInfo[] {
    return Array.from(this.resourceTemplates.values());
  }

  /**
   * Get information about a specific resource template
   */
  getResourceTemplate(name: string): ResourceTemplateInfo | undefined {
    if (!name || typeof name !== 'string') {
      throw MCPErrorFactory.invalidParams('Resource template name must be a non-empty string');
    }
    return this.resourceTemplates.get(name);
  }

  /**
   * Generate a resource URI from a template
   */
  generateResourceUri(templateName: string, params: Record<string, string>): string {
    const template = this.getResourceTemplate(templateName);
    if (!template) {
      throw MCPErrorFactory.resourceNotFound(`Resource template '${templateName}' not found`);
    }

    return this.populateUriTemplate(template.uriTemplate, params);
  }

  /**
   * Validate if a URI template format is valid
   */
  private isValidUriTemplate(uriTemplate: string): boolean {
    // Check for balanced braces first
    let braceCount = 0;
    for (const char of uriTemplate) {
      if (char === '{') {
        braceCount++;
      } else if (char === '}') {
        braceCount--;
        if (braceCount < 0) {
          return false; // More closing braces than opening
        }
      }
    }
    if (braceCount !== 0) {
      return false; // Unmatched braces
    }

    // Check for properly formatted variables
    const bracePattern = /\{([^}]+)\}/g;
    const matches = uriTemplate.match(bracePattern);

    if (!matches) {
      return true; // No template variables is valid
    }

    // Check that all variables are properly formatted
    return matches.every(match => {
      const varName = match.slice(1, -1); // Remove braces
      return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(varName); // Valid identifier
    });
  }

  /**
   * Extract template parameters from a URI using a template
   */
  private extractTemplateParams(uriTemplate: string, uri: string): Record<string, string> {
    // Convert URI template to regex pattern
    // First escape regex metacharacters in static parts, then replace template vars
    const regexPattern = uriTemplate
      .replace(/([.+?^${}()|[\]\\])/g, (match, char) => {
        // Don't escape braces that are part of template variables
        if (char === '{' || char === '}') return char;
        return '\\' + char;
      })
      .replace(/\{([^}]+)\}/g, '([^/]+)');
    const regex = new RegExp(`^${regexPattern}$`);

    const match = uri.match(regex);
    if (!match) {
      throw MCPErrorFactory.invalidParams(`URI '${uri}' does not match template '${uriTemplate}'`);
    }

    // Extract variable names from template
    const varNames = [];
    const varPattern = /\{([^}]+)\}/g;
    let varMatch;
    while ((varMatch = varPattern.exec(uriTemplate)) !== null) {
      varNames.push(varMatch[1]);
    }

    // Map captured groups to variable names, URL-decoding to match populateUriTemplate's encoding
    const params: Record<string, string> = {};
    for (let i = 0; i < varNames.length; i++) {
      params[varNames[i]] = decodeURIComponent(match[i + 1]);
    }

    return params;
  }

  /**
   * Populate a URI template with parameters
   */
  private populateUriTemplate(uriTemplate: string, params: Record<string, string>): string {
    return uriTemplate.replace(/\{([^}]+)\}/g, (match, varName) => {
      const value = params[varName];
      if (value === undefined) {
        throw MCPErrorFactory.invalidParams(`Missing parameter '${varName}' for URI template`);
      }
      return encodeURIComponent(value);
    });
  }

  /**
   * Validate template parameters against JSON schema
   */
  private validateTemplateParams(params: Record<string, string>, schema: Record<string, any>): void {
    // Basic validation - in a real implementation, you'd use a JSON schema validator
    if (schema.required && Array.isArray(schema.required)) {
      for (const requiredParam of schema.required) {
        if (!(requiredParam in params)) {
          throw MCPErrorFactory.invalidParams(`Missing required parameter: ${requiredParam}`);
        }
      }
    }

    // Validate parameter types if specified
    if (schema.properties) {
      for (const [paramName, paramValue] of Object.entries(params)) {
        const paramSchema = schema.properties[paramName];
        if (paramSchema && paramSchema.type === 'number') {
          if (isNaN(Number(paramValue))) {
            throw MCPErrorFactory.invalidParams(`Parameter '${paramName}' must be a number`);
          }
        }
      }
    }
  }

  /**
   * Register a completion handler with the server
   */
  registerCompletion(
    config: CompletionConfig,
    handler: CompletionHandler
  ): void {
    // Validate completion name
    if (!config.name || typeof config.name !== 'string') {
      throw MCPErrorFactory.invalidParams('Completion name must be a non-empty string');
    }

    // Check if completion already exists
    if (this.completionHandlers.has(config.name)) {
      throw MCPErrorFactory.invalidParams(`Completion '${config.name}' is already registered`);
    }

    // Validate supported types
    if (!config.supportedTypes || !Array.isArray(config.supportedTypes) || config.supportedTypes.length === 0) {
      throw MCPErrorFactory.invalidParams('Completion must support at least one reference type');
    }

    const validTypes = ['ref/prompt', 'ref/resource'];
    for (const type of config.supportedTypes) {
      if (!validTypes.includes(type)) {
        throw MCPErrorFactory.invalidParams(`Invalid completion type: ${type}`);
      }
    }

    // Store completion handler
    this.completionHandlers.set(config.name, { config, handler });

    // Note: We don't register our own completion handler with the SDK server
    // because the SDK server automatically registers completion handlers when
    // we register prompts/resources. Our completion system works by intercepting
    // completion requests through the existing SDK handlers.
  }

  /**
   * Handle completion requests
   */
  private async handleCompletion(request: CompletionRequest, propagateErrors: boolean = false): Promise<CompletionResult> {
    // Convert handlers to array and sort by specificity (more specific handlers first)
    const handlers = Array.from(this.completionHandlers.entries()).sort(([nameA, configA], [nameB, configB]) => {
      // Handlers with supportedArguments are more specific
      const aHasArgs = configA.config.supportedArguments && configA.config.supportedArguments.length > 0;
      const bHasArgs = configB.config.supportedArguments && configB.config.supportedArguments.length > 0;

      if (aHasArgs && !bHasArgs) return -1; // a is more specific
      if (!aHasArgs && bHasArgs) return 1;  // b is more specific
      return 0; // same specificity
    });

    let lastError: Error | null = null;
    let matchingHandlerCount = 0;

    // Find appropriate completion handler
    for (const [name, { config, handler }] of handlers) {
      // Check if this handler supports the reference type
      if (!config.supportedTypes.includes(request.ref.type)) {
        continue;
      }

      // Check if this handler supports the specific argument (if specified)
      if (config.supportedArguments && !config.supportedArguments.includes(request.argument.name)) {
        continue;
      }

      // Check if the referenced item exists
      if (!this.referenceExists(request.ref)) {
        continue;
      }

      // We found a matching handler
      matchingHandlerCount++;

      try {
        return await handler(request);
      } catch (error) {
        // Store the error for potential propagation
        lastError = error instanceof Error ? error : new Error(String(error));
        console.error(`Completion handler '${name}' failed:`, error);
        continue;
      }
    }

    // If we had matching handlers but they all failed, propagate the last error (when configured to do so)
    if (propagateErrors && matchingHandlerCount > 0 && lastError) {
      throw lastError;
    }

    // Return empty completion if no handler matches or reference doesn't exist
    return {
      completion: {
        values: [],
        total: 0,
        hasMore: false
      }
    };
  }

  /**
   * Check if a reference exists
   */
  private referenceExists(ref: { type: string; name: string }): boolean {
    switch (ref.type) {
      case 'ref/prompt':
        return this.prompts.has(ref.name);
      case 'ref/resource':
        return this.resources.has(ref.name) || this.resourceTemplates.has(ref.name);
      default:
        return false;
    }
  }

  /**
   * List all registered completion handlers
   */
  listCompletions(): CompletionConfig[] {
    return Array.from(this.completionHandlers.values()).map(({ config }) => config);
  }

  /**
   * Get a specific completion handler configuration
   */
  getCompletion(name: string): CompletionConfig | undefined {
    if (!name || typeof name !== 'string') {
      throw MCPErrorFactory.invalidParams('Completion name must be a non-empty string');
    }
    return this.completionHandlers.get(name)?.config;
  }

  /**
   * Get completions for a specific reference and argument
   */
  async getCompletions(
    ref: { type: 'ref/prompt' | 'ref/resource'; name: string },
    argument: { name: string; value: string }
  ): Promise<CompletionResult> {
    const request: CompletionRequest = { ref, argument };
    return this.handleCompletion(request);
  }

  /**
   * Create a default completion handler for prompts
   */
  registerDefaultPromptCompletion(): void {
    this.registerCompletion(
      {
        name: 'default-prompt-completion',
        description: 'Default completion for prompt arguments',
        supportedTypes: ['ref/prompt']
      },
      async (request) => {
        const prompt = this.getPrompt(request.ref.name);
        if (!prompt) {
          throw MCPErrorFactory.invalidParams(`Prompt '${request.ref.name}' not found`);
        }

        // Extract possible values from prompt arguments schema
        const values: string[] = [];

        // If the prompt has argument schema, provide completions
        if (prompt.arguments && Array.isArray(prompt.arguments)) {
          // Check if the requested argument is defined in the prompt schema
          if (prompt.arguments.includes(request.argument.name)) {
            // Add common completion suggestions based on argument name and value
            values.push(...this.getCommonCompletions(request.argument.name, request.argument.value));
          }
        }

        // Always provide basic completions even if no specific argument schema exists
        if (values.length === 0) {
          values.push(...this.getCommonCompletions(request.argument.name, request.argument.value));
        }

        return {
          completion: {
            values: values.slice(0, 10), // Limit to 10 suggestions
            total: values.length,
            hasMore: values.length > 10
          }
        };
      }
    );
  }

  /**
   * Create a default completion handler for resources
   */
  registerDefaultResourceCompletion(): void {
    this.registerCompletion(
      {
        name: 'default-resource-completion',
        description: 'Default completion for resource references',
        supportedTypes: ['ref/resource']
      },
      async (request) => {
        const resource = this.getResource(request.ref.name);
        const template = this.getResourceTemplate(request.ref.name);

        if (!resource && !template) {
          throw MCPErrorFactory.invalidParams(`Resource '${request.ref.name}' not found`);
        }

        const values: string[] = [];

        // For templates, suggest parameter completions
        if (template && request.argument.name === 'uri') {
          const templateVars = this.extractTemplateVariables(template.uriTemplate);
          values.push(...templateVars.map(v => `{${v}}`));
        }

        // Add common completions based on argument name and value
        values.push(...this.getCommonCompletions(request.argument.name, request.argument.value));

        return {
          completion: {
            values: values.slice(0, 10),
            total: values.length,
            hasMore: values.length > 10
          }
        };
      }
    );
  }

  /**
   * Get common completion suggestions based on argument name and partial value
   */
  private getCommonCompletions(argumentName: string, partialValue: string): string[] {
    const suggestions: string[] = [];
    const lowerArgName = argumentName.toLowerCase();
    const lowerValue = partialValue.toLowerCase();

    // Common completions based on argument name patterns
    if (lowerArgName.includes('file') || lowerArgName.includes('path')) {
      // For file arguments, append extensions to the current value
      suggestions.push(
        partialValue + '.txt',
        partialValue + '.json',
        partialValue + '.md',
        partialValue + '.csv',
        partialValue + '.xml'
      );
    } else if (lowerArgName.includes('format') || lowerArgName.includes('type')) {
      // For format arguments, filter by prefix
      const formatOptions = ['json', 'xml', 'csv', 'txt', 'markdown'];
      suggestions.push(...formatOptions
        .filter(s => s.toLowerCase().startsWith(lowerValue))
        .map(s => s));
    } else if (lowerArgName.includes('lang') || lowerArgName.includes('language')) {
      // For language arguments, filter by prefix  
      const langOptions = ['en', 'es', 'fr', 'de', 'ja', 'zh'];
      suggestions.push(...langOptions
        .filter(s => s.toLowerCase().startsWith(lowerValue))
        .map(s => s));
    } else if (lowerArgName.includes('mode') || lowerArgName.includes('method')) {
      // For mode arguments, filter by prefix
      const modeOptions = ['create', 'read', 'update', 'delete', 'list'];
      suggestions.push(...modeOptions
        .filter(s => s.toLowerCase().startsWith(lowerValue))
        .map(s => s));
    }

    return suggestions;
  }

  /**
   * Extract template variables from URI template
   */
  private extractTemplateVariables(uriTemplate: string): string[] {
    const variables: string[] = [];
    const varPattern = /\{([^}]+)\}/g;
    let match;

    while ((match = varPattern.exec(uriTemplate)) !== null) {
      variables.push(match[1]);
    }

    return variables;
  }

  /**
   * Get a summary of all registered capabilities
   */
  getCapabilities(): {
    tools: ToolInfo[];
    resources: ResourceInfo[];
    resourceTemplates: ResourceTemplateInfo[];
    prompts: PromptInfo[];
    completions: CompletionConfig[];
    sampling?: SamplingConfig;
  } {
    return {
      tools: this.getTools(),
      resources: this.getResources(),
      resourceTemplates: this.listResourceTemplates(),
      prompts: this.getPrompts(),
      completions: this.listCompletions(),
      ...(this.samplingConfig && { sampling: this.samplingConfig })
    };
  }

  /**
   * Register sampling functionality with the server
   */
  registerSampling(config: SamplingConfig): void {
    // Validate sampling configuration
    if (!config.createMessage || typeof config.createMessage !== 'function') {
      throw MCPErrorFactory.invalidParams('Sampling createMessage handler must be a function');
    }

    // Validate temperature range if provided
    if (config.temperatureRange) {
      const { min, max } = config.temperatureRange;
      if (typeof min !== 'number' || typeof max !== 'number' || min < 0 || max > 2 || min > max) {
        throw MCPErrorFactory.invalidParams('Invalid temperature range: must be between 0-2 and min <= max');
      }
    }

    // Validate max tokens limit if provided
    if (config.maxTokensLimit !== undefined && (typeof config.maxTokensLimit !== 'number' || config.maxTokensLimit <= 0)) {
      throw MCPErrorFactory.invalidParams('Max tokens limit must be a positive number');
    }

    this.samplingConfig = config;

    // Register with SDK server using sampling/createMessage method

    // Register sampling handler with SDK server (skip in test environment)
    if (this.sdkServer.server && this.sdkServer.server.setRequestHandler) {
      this.sdkServer.server.setRequestHandler(CreateMessageRequestSchema, async (request: any) => {
        const result = await this.handleSampling(request.params);
        return result;
      });
    }
  }

  /**
   * Handle sampling requests
   */
  private async handleSampling(request: SamplingRequest): Promise<CreateMessageResult> {
    if (!this.samplingConfig) {
      throw MCPErrorFactory.invalidRequest('Sampling is not configured on this server');
    }

    // Validate request parameters
    this.validateSamplingRequest(request);

    // Apply server-side limits and defaults
    const processedRequest = this.processSamplingRequest(request);

    try {
      const response = await this.samplingConfig.createMessage(processedRequest);

      // Validate response format
      this.validateSamplingResponse(response);

      return response;
    } catch (error) {
      if (error instanceof MCPErrorClass) {
        throw error; // Preserve already-formatted MCP errors
      }
      if (error instanceof Error) {
        throw MCPErrorFactory.internalError(`Sampling failed: ${error.message}`);
      }
      throw MCPErrorFactory.internalError('Sampling failed with unknown error');
    }
  }

  /**
   * Validate sampling request parameters
   */
  private validateSamplingRequest(request: SamplingRequest): void {
    if (!request.messages || !Array.isArray(request.messages) || request.messages.length === 0) {
      throw MCPErrorFactory.invalidParams('Sampling request must include at least one message');
    }

    // Validate each message
    for (const [index, message] of request.messages.entries()) {
      if (!message.role || !['user', 'assistant', 'system'].includes(message.role)) {
        throw MCPErrorFactory.invalidParams(`Invalid role at message ${index}: must be user, assistant, or system`);
      }

      if (!message.content || typeof message.content !== 'object') {
        throw MCPErrorFactory.invalidParams(`Invalid content at message ${index}: must be an object`);
      }

      if (!message.content.type || !['text', 'image'].includes(message.content.type)) {
        throw MCPErrorFactory.invalidParams(`Invalid content type at message ${index}: must be text or image`);
      }

      if (message.content.type === 'text' && !message.content.text) {
        throw MCPErrorFactory.invalidParams(`Text message at index ${index} must have text content`);
      }

      if (message.content.type === 'image' && (!message.content.data || !message.content.mimeType)) {
        throw MCPErrorFactory.invalidParams(`Image message at index ${index} must have data and mimeType`);
      }
    }

    // Validate model preferences if provided
    if (request.modelPreferences) {
      const prefs = request.modelPreferences;
      if (prefs.costPriority !== undefined && (prefs.costPriority < 0 || prefs.costPriority > 1)) {
        throw MCPErrorFactory.invalidParams('Cost priority must be between 0 and 1');
      }
      if (prefs.speedPriority !== undefined && (prefs.speedPriority < 0 || prefs.speedPriority > 1)) {
        throw MCPErrorFactory.invalidParams('Speed priority must be between 0 and 1');
      }
      if (prefs.intelligencePriority !== undefined && (prefs.intelligencePriority < 0 || prefs.intelligencePriority > 1)) {
        throw MCPErrorFactory.invalidParams('Intelligence priority must be between 0 and 1');
      }
    }

    // Validate temperature if provided
    if (request.temperature !== undefined) {
      if (typeof request.temperature !== 'number' || request.temperature < 0 || request.temperature > 2) {
        throw MCPErrorFactory.invalidParams('Temperature must be a number between 0 and 2');
      }

      // Check against server limits
      if (this.samplingConfig?.temperatureRange) {
        const { min, max } = this.samplingConfig.temperatureRange;
        if (request.temperature < min || request.temperature > max) {
          throw MCPErrorFactory.invalidParams(`Temperature must be between ${min} and ${max}`);
        }
      }
    }

    // Validate max tokens if provided
    if (request.maxTokens !== undefined) {
      if (typeof request.maxTokens !== 'number' || request.maxTokens <= 0) {
        throw MCPErrorFactory.invalidParams('Max tokens must be a positive number');
      }

      // Check against server limits
      if (this.samplingConfig?.maxTokensLimit && request.maxTokens > this.samplingConfig.maxTokensLimit) {
        throw MCPErrorFactory.invalidParams(`Max tokens cannot exceed ${this.samplingConfig.maxTokensLimit}`);
      }
    }
  }

  /**
   * Process sampling request with server defaults and context
   */
  private processSamplingRequest(request: SamplingRequest): SamplingRequest {
    const processed = { ...request };

    // Add context if enabled and available
    if (this.samplingConfig?.includeContext !== false && request.includeContext !== false) {
      // Add server context to the request
      if (!processed.metadata) {
        processed.metadata = {};
      }
      processed.metadata.serverContext = {
        name: this.config.name,
        version: this.config.version,
        capabilities: {
          tools: this.tools.size,
          resources: this.resources.size,
          prompts: this.prompts.size
        },
        timestamp: new Date().toISOString()
      };
    }

    // Apply server defaults
    if (this.samplingConfig?.maxTokensLimit && !processed.maxTokens) {
      processed.maxTokens = Math.min(this.samplingConfig.maxTokensLimit, 4096); // Default max tokens
    }

    if (this.samplingConfig?.temperatureRange && !processed.temperature) {
      // Use middle of the allowed range as default
      const { min, max } = this.samplingConfig.temperatureRange;
      processed.temperature = (min + max) / 2;
    }

    return processed;
  }

  /**
   * Validate sampling response format
   */
  private validateSamplingResponse(response: CreateMessageResult): void {
    if (!response || typeof response !== 'object') {
      throw MCPErrorFactory.internalError('Sampling response must be an object');
    }

    if (!response.model || typeof response.model !== 'string') {
      throw MCPErrorFactory.internalError('Sampling response must have a model string');
    }

    if (!['user', 'assistant'].includes(response.role)) {
      throw MCPErrorFactory.internalError('Sampling response role must be user or assistant');
    }

    if (!response.content || typeof response.content !== 'object') {
      throw MCPErrorFactory.internalError('Sampling response must have content object');
    }

    if (response.content.type !== 'text' || typeof response.content.text !== 'string') {
      throw MCPErrorFactory.internalError('Sampling response content must be text type with string text');
    }

    if (response.stopReason && !['endTurn', 'stopSequence', 'maxTokens'].includes(response.stopReason)) {
      throw MCPErrorFactory.internalError('Invalid stop reason in sampling response');
    }

    // Usage validation is handled by the SDK schema validation
  }

  /**
   * Check if sampling is available
   */
  isSamplingAvailable(): boolean {
    return this.samplingConfig !== null;
  }

  /**
   * Get sampling configuration (without sensitive handler)
   */
  getSamplingInfo(): Omit<SamplingConfig, 'createMessage'> | null {
    if (!this.samplingConfig) {
      return null;
    }

    const { createMessage, ...info } = this.samplingConfig;
    return info;
  }

  /**
   * Create a sampling request for testing or internal use
   */
  async createSamplingMessage(request: SamplingRequest): Promise<CreateMessageResult> {
    if (!this.samplingConfig) {
      throw MCPErrorFactory.invalidRequest('Sampling is not configured on this server');
    }

    return this.handleSampling(request);
  }

  /**
   * Get the request tracer for direct access to tracing capabilities
   */
  getRequestTracer(): RequestTracer {
    return this.requestTracer;
  }

  /**
   * Get performance tracker for metrics access
   */
  getPerformanceTracker(): PerformanceTracker {
    return this.requestTracer.getPerformanceTracker();
  }

  /**
   * Start manual tracing for custom operations
   */
  startTrace(operation: string, context?: ToolContext): ToolContext {
    return this.requestTracer.startTrace(operation, context || this.getContext());
  }

  /**
   * End manual tracing for custom operations
   */
  endTrace(context: ToolContext, success: boolean, errorCode?: string, payloadSize?: number): PerformanceMetrics | null {
    return this.requestTracer.endTrace(context, success, errorCode, payloadSize);
  }

  /**
   * Get current active tracing count
   */
  getActiveTracingCount(): number {
    return this.requestTracer.getPerformanceTracker().getActiveTrackingCount();
  }

  /**
   * Get all active correlation IDs
   */
  getActiveCorrelations(): string[] {
    return this.requestTracer.getPerformanceTracker().getActiveCorrelations();
  }

  /**
   * Enhanced structured logging with correlation context
   */
  private logStructuredEntry(entry: StructuredLogEntry): void {
    // Send the structured log entry as a notification
    this.sendLogNotification(entry.levelName, entry, entry.logger).catch(err => {
      // Fallback to console if notification fails
      console.error('Failed to send structured log notification:', err);
      console.log('Log entry:', entry);
    });
  }
}

// Re-export common types from the SDK
export { z } from "zod";
export type { CallToolResult as ToolResult } from "@modelcontextprotocol/sdk/types";

// Re-export error types
export {
  MCPErrorFactory,
  MCPErrorClass,
  MCPErrorCode,
  isMCPError,
  formatMCPError
} from "./errors.js";
export type { MCPError } from "./errors.js";

// Tool type for external use
export type Tool<Schema extends z.AnyZodObject = z.AnyZodObject> = ToolConfig<Schema>;

