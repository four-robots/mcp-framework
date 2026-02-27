import { z } from 'zod';

/**
 * Rate limiting result
 */
export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number;
  totalRequests: number;
  retryAfter?: number;
}

/**
 * Rate limit statistics
 */
export interface RateLimitStats {
  key: string;
  requests: number;
  remaining: number;
  resetTime: number;
  windowMs: number;
  limit: number;
}

/**
 * Rate limiter interface
 */
export interface RateLimiter {
  check(key: string, limit: number, windowMs: number): Promise<RateLimitResult>;
  decrement(key: string): Promise<void>;
  reset(key: string): Promise<void>;
  getStats(key: string): Promise<RateLimitStats | null>;
  cleanup(): Promise<void>;
}

/**
 * Rate limit window entry
 */
interface RateLimitWindow {
  requests: number;
  resetTime: number;
  windowMs: number;
  limit: number;
}

/**
 * Memory-based rate limiter implementation
 */
export class MemoryRateLimiter implements RateLimiter {
  private windows: Map<string, RateLimitWindow> = new Map();
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(cleanupIntervalMs: number = 60000) {
    // Clean up expired windows periodically
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredWindows();
    }, cleanupIntervalMs);
    // Allow Node.js to exit even if cleanup interval is still active
    this.cleanupInterval.unref();
  }

  async check(key: string, limit: number, windowMs: number): Promise<RateLimitResult> {
    const now = Date.now();
    let window = this.windows.get(key);

    // Create new window if doesn't exist or is expired
    if (!window || now >= window.resetTime) {
      window = {
        requests: 0,
        resetTime: now + windowMs,
        windowMs,
        limit
      };
      this.windows.set(key, window);
    }

    // Update window parameters if they changed
    if (window.limit !== limit || window.windowMs !== windowMs) {
      window.limit = limit;
      window.windowMs = windowMs;
    }

    // Check if request is allowed
    const allowed = window.requests < limit;
    
    if (allowed) {
      window.requests++;
    }

    const remaining = Math.max(0, limit - window.requests);
    const retryAfter = allowed ? undefined : Math.ceil((window.resetTime - now) / 1000);

    return {
      allowed,
      remaining,
      resetTime: window.resetTime,
      totalRequests: window.requests,
      retryAfter
    };
  }

  async decrement(key: string): Promise<void> {
    const window = this.windows.get(key);
    if (window && window.requests > 0 && Date.now() < window.resetTime) {
      window.requests--;
    }
  }

  async reset(key: string): Promise<void> {
    this.windows.delete(key);
  }

  async getStats(key: string): Promise<RateLimitStats | null> {
    const window = this.windows.get(key);
    if (!window) {
      return null;
    }

    return {
      key,
      requests: window.requests,
      remaining: Math.max(0, window.limit - window.requests),
      resetTime: window.resetTime,
      windowMs: window.windowMs,
      limit: window.limit
    };
  }

  async cleanup(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.windows.clear();
  }

  private cleanupExpiredWindows(): void {
    const now = Date.now();
    for (const [key, window] of this.windows.entries()) {
      if (now >= window.resetTime) {
        this.windows.delete(key);
      }
    }
  }

  /**
   * Get current number of active windows (for monitoring)
   */
  getActiveWindowCount(): number {
    return this.windows.size;
  }

  /**
   * Get all active keys (for monitoring)
   */
  getActiveKeys(): string[] {
    return Array.from(this.windows.keys());
  }
}

/**
 * HTTP rate limiting configuration
 */
export interface HttpRateLimitConfig {
  // Global limits
  global?: {
    windowMs: number;
    maxRequests: number;
    skipSuccessfulRequests?: boolean;
    skipFailedRequests?: boolean;
  };
  
  // Per-client limits (IP, session, or OAuth client)
  perClient?: {
    windowMs: number;
    maxRequests: number;
    keyGenerator?: (req: any) => string;
  };
  
  // Per-endpoint limits
  perEndpoint?: {
    [endpoint: string]: {
      windowMs: number;
      maxRequests: number;
    };
  };
  
  // OAuth client-specific limits
  oauthClientLimits?: {
    [clientId: string]: {
      windowMs: number;
      maxRequests: number;
    };
  };
  
  // Rate limit headers
  headers?: {
    includeHeaders?: boolean;
    headerNames?: {
      remaining?: string;
      reset?: string;
      limit?: string;
      retryAfter?: string;
    };
  };
  
  // Error handling
  onLimitReached?: (req: any, res: any, result: RateLimitResult) => void;
  skipOnError?: boolean;
  
  // Storage
  store?: RateLimiter;
}

/**
 * WebSocket rate limiting configuration
 */
export interface WebSocketRateLimitConfig {
  // Connection limits
  connectionLimits?: {
    perIp?: {
      maxConnections: number;
      windowMs?: number;
    };
    global?: {
      maxConnections: number;
    };
  };
  
  // Message limits
  messageLimits?: {
    perConnection?: {
      maxMessages: number;
      windowMs: number;
    };
    perMethod?: {
      [method: string]: {
        maxMessages: number;
        windowMs: number;
      };
    };
  };
  
  // Enforcement actions
  actions?: {
    onConnectionLimitReached?: 'reject' | 'close_oldest';
    onMessageLimitReached?: 'drop' | 'close_connection' | 'throttle';
  };
  
  // Cleanup and monitoring
  cleanupInterval?: number;
  enableMetrics?: boolean;
  
  // Storage
  store?: RateLimiter;
}

/**
 * Rate limiting utility functions
 */
export class RateLimitUtils {
  /**
   * Generate rate limit key from IP address
   */
  static ipKey(ip: string, prefix: string = 'ip'): string {
    return `${prefix}:${ip}`;
  }

  /**
   * Generate rate limit key from session ID
   */
  static sessionKey(sessionId: string, prefix: string = 'session'): string {
    return `${prefix}:${sessionId}`;
  }

  /**
   * Generate rate limit key from OAuth client ID
   */
  static oauthClientKey(clientId: string, prefix: string = 'oauth'): string {
    return `${prefix}:${clientId}`;
  }

  /**
   * Generate rate limit key from user ID
   */
  static userKey(userId: string, prefix: string = 'user'): string {
    return `${prefix}:${userId}`;
  }

  /**
   * Generate composite key from multiple components
   */
  static compositeKey(...components: string[]): string {
    return components.join(':');
  }

  /**
   * Extract IP address from request with proxy support
   */
  static getClientIp(req: any): string {
    return req.ip || 
           req.connection?.remoteAddress || 
           req.socket?.remoteAddress ||
           req.headers?.['x-forwarded-for']?.split(',')[0]?.trim() ||
           '127.0.0.1';
  }

  /**
   * Calculate retry-after header value in seconds
   */
  static calculateRetryAfter(resetTime: number): number {
    return Math.ceil((resetTime - Date.now()) / 1000);
  }

  /**
   * Format rate limit error message
   */
  static formatErrorMessage(result: RateLimitResult): string {
    const retryAfter = result.retryAfter || 0;
    return `Rate limit exceeded. Try again in ${retryAfter} seconds.`;
  }
}

/**
 * HTTP rate limit middleware factory
 */
export class HttpRateLimitMiddleware {
  private store: RateLimiter;
  private config: HttpRateLimitConfig;

  constructor(config: HttpRateLimitConfig) {
    this.config = config;
    this.store = config.store || new MemoryRateLimiter();
  }

  /**
   * Create Express middleware for global rate limiting
   */
  createGlobalMiddleware() {
    if (!this.config.global) {
      return (req: any, res: any, next: any) => next();
    }

    const { windowMs, maxRequests, skipSuccessfulRequests, skipFailedRequests } = this.config.global;

    return async (req: any, res: any, next: any) => {
      try {
        // Skip rate limiting for initialize requests to allow session creation
        if (req.body?.method === 'initialize') {
          next();
          return;
        }
        
        const key = RateLimitUtils.ipKey(RateLimitUtils.getClientIp(req), 'global');
        const result = await this.store.check(key, maxRequests, windowMs);

        if (!result.allowed) {
          return this.handleRateLimit(req, res, result);
        }

        // Track response status for skip logic
        if (skipSuccessfulRequests || skipFailedRequests) {
          const store = this.store;
          const originalSend = res.send;
          res.send = function(data: any) {
            const statusCode = res.statusCode;
            const shouldSkip = (skipSuccessfulRequests && statusCode < 400) ||
                             (skipFailedRequests && statusCode >= 400);

            if (shouldSkip) {
              store.decrement(key).catch(() => {});
            }

            return originalSend.call(this, data);
          };
        }

        this.addHeaders(res, result, maxRequests);
        next();
      } catch (error) {
        if (this.config.skipOnError) {
          next();
        } else {
          next(error);
        }
      }
    };
  }

  /**
   * Create Express middleware for per-client rate limiting
   */
  createClientMiddleware() {
    if (!this.config.perClient) {
      return (req: any, res: any, next: any) => next();
    }

    const { windowMs, maxRequests, keyGenerator } = this.config.perClient;

    return async (req: any, res: any, next: any) => {
      try {
        // Skip rate limiting for initialize requests to allow session creation
        if (req.body?.method === 'initialize') {
          next();
          return;
        }
        let key: string;
        
        if (keyGenerator) {
          key = keyGenerator(req);
        } else {
          // Default key generation strategy
          if (req.user?.clientId) {
            // OAuth client rate limiting
            key = RateLimitUtils.oauthClientKey(req.user.clientId);
          } else if (req.headers['mcp-session-id']) {
            // Session-based rate limiting
            key = RateLimitUtils.sessionKey(req.headers['mcp-session-id']);
          } else {
            // IP-based rate limiting
            key = RateLimitUtils.ipKey(RateLimitUtils.getClientIp(req));
          }
        }

        const result = await this.store.check(key, maxRequests, windowMs);

        if (!result.allowed) {
          return this.handleRateLimit(req, res, result);
        }

        this.addHeaders(res, result, maxRequests);
        next();
      } catch (error) {
        if (this.config.skipOnError) {
          next();
        } else {
          next(error);
        }
      }
    };
  }

  /**
   * Handle rate limit exceeded
   */
  private handleRateLimit(req: any, res: any, result: RateLimitResult) {
    if (this.config.onLimitReached) {
      this.config.onLimitReached(req, res, result);
      return;
    }

    // Default rate limit response
    const retryAfter = result.retryAfter || RateLimitUtils.calculateRetryAfter(result.resetTime);
    
    this.addHeaders(res, result, 0);
    res.header('Retry-After', retryAfter.toString());

    res.status(429).json({
      jsonrpc: '2.0',
      error: {
        code: -32009, // Custom MCP rate limit error code
        message: RateLimitUtils.formatErrorMessage(result),
        data: { 
          retryAfter,
          limit: result.totalRequests,
          remaining: result.remaining,
          resetTime: result.resetTime
        }
      },
      id: req.body?.id || null
    });
  }

  /**
   * Add rate limit headers to response
   */
  private addHeaders(res: any, result: RateLimitResult, limit: number) {
    if (!this.config.headers?.includeHeaders) {
      return;
    }

    const headerNames = this.config.headers.headerNames || {
      remaining: 'X-RateLimit-Remaining',
      reset: 'X-RateLimit-Reset', 
      limit: 'X-RateLimit-Limit',
      retryAfter: 'Retry-After'
    };

    res.header(headerNames.remaining || 'X-RateLimit-Remaining', result.remaining.toString());
    res.header(headerNames.reset || 'X-RateLimit-Reset', Math.ceil(result.resetTime / 1000).toString());
    res.header(headerNames.limit || 'X-RateLimit-Limit', limit.toString());
    
    if (result.retryAfter) {
      res.header(headerNames.retryAfter || 'Retry-After', result.retryAfter.toString());
    }
  }

  /**
   * Get rate limiter store
   */
  getStore(): RateLimiter {
    return this.store;
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    await this.store.cleanup();
  }
}

/**
 * WebSocket rate limit manager
 */
export class WebSocketRateLimitManager {
  private store: RateLimiter;
  private config: WebSocketRateLimitConfig;
  private connectionCounts: Map<string, number> = new Map();
  private activeConnections: Map<string, any[]> = new Map();

  constructor(config: WebSocketRateLimitConfig) {
    this.config = config;
    this.store = config.store || new MemoryRateLimiter();
  }

  /**
   * Check if new connection is allowed
   */
  async checkConnectionLimit(ip: string, connection: any): Promise<boolean> {
    if (!this.config.connectionLimits) {
      return true;
    }

    // Check per-IP connection limit
    if (this.config.connectionLimits.perIp) {
      const { maxConnections, windowMs = 3600000 } = this.config.connectionLimits.perIp;
      const key = RateLimitUtils.ipKey(ip, 'ws-conn');
      
      const result = await this.store.check(key, maxConnections, windowMs);
      if (!result.allowed) {
        return false;
      }
    }

    // Check global connection limit
    if (this.config.connectionLimits.global) {
      const { maxConnections } = this.config.connectionLimits.global;
      const totalConnections = Array.from(this.activeConnections.values())
        .reduce((total, connections) => total + connections.length, 0);
      
      if (totalConnections >= maxConnections) {
        if (this.config.actions?.onConnectionLimitReached === 'close_oldest') {
          this.closeOldestConnection();
        } else {
          return false;
        }
      }
    }

    // Track connection
    this.trackConnection(ip, connection);
    return true;
  }

  /**
   * Check if message is allowed
   */
  async checkMessageLimit(connection: any, message: any): Promise<boolean> {
    if (!this.config.messageLimits) {
      return true;
    }

    const connectionId = this.getConnectionId(connection);

    // Check per-connection message limit
    if (this.config.messageLimits.perConnection) {
      const { maxMessages, windowMs } = this.config.messageLimits.perConnection;
      const key = RateLimitUtils.compositeKey('ws-msg', connectionId);
      
      const result = await this.store.check(key, maxMessages, windowMs);
      if (!result.allowed) {
        return this.handleMessageRateLimit(connection, result);
      }
    }

    // Check per-method message limit
    if (this.config.messageLimits.perMethod && message.method) {
      const methodLimits = this.config.messageLimits.perMethod[message.method];
      if (methodLimits) {
        const { maxMessages, windowMs } = methodLimits;
        const key = RateLimitUtils.compositeKey('ws-method', connectionId, message.method);
        
        const result = await this.store.check(key, maxMessages, windowMs);
        if (!result.allowed) {
          return this.handleMessageRateLimit(connection, result);
        }
      }
    }

    return true;
  }

  /**
   * Handle message rate limit exceeded
   */
  private handleMessageRateLimit(connection: any, result: RateLimitResult): boolean {
    const action = this.config.actions?.onMessageLimitReached || 'drop';

    switch (action) {
      case 'drop':
        return false;
      
      case 'close_connection':
        if (typeof connection.close === 'function') {
          connection.close(1013, 'Message rate limit exceeded');
        }
        return false;
      
      case 'throttle':
        // For throttling, we could implement a delay mechanism
        // For now, just drop the message
        return false;
      
      default:
        return false;
    }
  }

  /**
   * Track new connection
   */
  private trackConnection(ip: string, connection: any): void {
    if (!this.activeConnections.has(ip)) {
      this.activeConnections.set(ip, []);
    }
    
    this.activeConnections.get(ip)!.push(connection);
    
    // Update count
    const count = this.connectionCounts.get(ip) || 0;
    this.connectionCounts.set(ip, count + 1);

    // Setup cleanup on connection close
    const cleanup = () => this.untrackConnection(ip, connection);

    if (typeof connection.on === 'function') {
      connection.on('close', cleanup);
      connection.on('error', cleanup);
    } else {
      // No event support - schedule periodic cleanup check
      setTimeout(() => {
        if (typeof connection.readyState !== 'undefined' && connection.readyState > 1) {
          cleanup();
        }
      }, 30000);
    }
  }

  /**
   * Untrack closed connection
   */
  private untrackConnection(ip: string, connection: any): void {
    const connections = this.activeConnections.get(ip);
    if (connections) {
      const index = connections.indexOf(connection);
      if (index >= 0) {
        connections.splice(index, 1);
        
        if (connections.length === 0) {
          this.activeConnections.delete(ip);
          this.connectionCounts.delete(ip);
        } else {
          this.connectionCounts.set(ip, connections.length);
        }
      }
    }
  }

  /**
   * Close oldest connection for global limit enforcement
   */
  private closeOldestConnection(): void {
    let oldestConnection: any = null;
    let oldestTime = Date.now();

    for (const connections of this.activeConnections.values()) {
      for (const connection of connections) {
        // Assuming connections have a createdAt timestamp
        const createdAt = connection.createdAt || 0;
        if (createdAt < oldestTime) {
          oldestTime = createdAt;
          oldestConnection = connection;
        }
      }
    }

    if (oldestConnection && typeof oldestConnection.close === 'function') {
      oldestConnection.close(1013, 'Connection limit exceeded - closing oldest');
    }
  }

  /**
   * Get unique connection identifier
   */
  private getConnectionId(connection: any): string {
    return connection.id || 
           connection._id || 
           connection.remoteAddress || 
           Math.random().toString(36);
  }

  /**
   * Get connection statistics
   */
  getConnectionStats(): { totalConnections: number; connectionsPerIp: Record<string, number> } {
    const totalConnections = Array.from(this.connectionCounts.values())
      .reduce((total, count) => total + count, 0);
    
    const connectionsPerIp: Record<string, number> = {};
    for (const [ip, count] of this.connectionCounts.entries()) {
      connectionsPerIp[ip] = count;
    }

    return { totalConnections, connectionsPerIp };
  }

  /**
   * Cleanup resources
   */
  async cleanup(): Promise<void> {
    await this.store.cleanup();
    this.connectionCounts.clear();
    this.activeConnections.clear();
  }
}

// All exports are defined above in this file