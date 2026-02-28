import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { 
  MemoryRateLimiter, 
  HttpRateLimitMiddleware, 
  WebSocketRateLimitManager,
  RateLimitUtils,
  type HttpRateLimitConfig,
  type WebSocketRateLimitConfig,
  type RateLimitResult
} from '../src/index.js';

describe('Rate Limiting System', () => {
  describe('MemoryRateLimiter', () => {
    let rateLimiter: MemoryRateLimiter;

    beforeEach(() => {
      rateLimiter = new MemoryRateLimiter(1000); // 1 second cleanup interval
    });

    afterEach(async () => {
      await rateLimiter.cleanup();
    });

    it('should allow requests within limit', async () => {
      const key = 'test-key';
      const limit = 5;
      const windowMs = 60000;

      // First request should be allowed
      const result1 = await rateLimiter.check(key, limit, windowMs);
      expect(result1.allowed).toBe(true);
      expect(result1.remaining).toBe(4);
      expect(result1.totalRequests).toBe(1);

      // Second request should be allowed
      const result2 = await rateLimiter.check(key, limit, windowMs);
      expect(result2.allowed).toBe(true);
      expect(result2.remaining).toBe(3);
      expect(result2.totalRequests).toBe(2);
    });

    it('should reject requests exceeding limit', async () => {
      const key = 'test-key';
      const limit = 2;
      const windowMs = 60000;

      // Allow first two requests
      await rateLimiter.check(key, limit, windowMs);
      await rateLimiter.check(key, limit, windowMs);

      // Third request should be rejected
      const result = await rateLimiter.check(key, limit, windowMs);
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
      expect(result.totalRequests).toBe(2);
      expect(result.retryAfter).toBeTypeOf('number');
      expect(result.retryAfter).toBeGreaterThan(0);
    });

    it('should reset window after expiration', async () => {
      const key = 'test-key';
      const limit = 2;
      const windowMs = 100; // 100ms window

      // Exhaust limit
      await rateLimiter.check(key, limit, windowMs);
      await rateLimiter.check(key, limit, windowMs);

      // Should be rejected
      const rejectedResult = await rateLimiter.check(key, limit, windowMs);
      expect(rejectedResult.allowed).toBe(false);

      // Wait for window to reset
      await new Promise(resolve => setTimeout(resolve, 150));

      // Should be allowed again
      const allowedResult = await rateLimiter.check(key, limit, windowMs);
      expect(allowedResult.allowed).toBe(true);
      expect(allowedResult.totalRequests).toBe(1);
    });

    it('should handle different keys independently', async () => {
      const limit = 2;
      const windowMs = 60000;

      // Exhaust limit for key1
      await rateLimiter.check('key1', limit, windowMs);
      await rateLimiter.check('key1', limit, windowMs);

      // key1 should be rejected
      const result1 = await rateLimiter.check('key1', limit, windowMs);
      expect(result1.allowed).toBe(false);

      // key2 should still be allowed
      const result2 = await rateLimiter.check('key2', limit, windowMs);
      expect(result2.allowed).toBe(true);
    });

    it('should reset specific key', async () => {
      const key = 'test-key';
      const limit = 2;
      const windowMs = 60000;

      // Use up the limit
      await rateLimiter.check(key, limit, windowMs);
      await rateLimiter.check(key, limit, windowMs);

      // Should be rejected
      const rejectedResult = await rateLimiter.check(key, limit, windowMs);
      expect(rejectedResult.allowed).toBe(false);

      // Reset the key
      await rateLimiter.reset(key);

      // Should be allowed again
      const allowedResult = await rateLimiter.check(key, limit, windowMs);
      expect(allowedResult.allowed).toBe(true);
      expect(allowedResult.totalRequests).toBe(1);
    });

    it('should provide accurate stats', async () => {
      const key = 'test-key';
      const limit = 5;
      const windowMs = 60000;

      // Make some requests
      await rateLimiter.check(key, limit, windowMs);
      await rateLimiter.check(key, limit, windowMs);

      const stats = await rateLimiter.getStats(key);
      expect(stats).toBeDefined();
      expect(stats!.key).toBe(key);
      expect(stats!.requests).toBe(2);
      expect(stats!.remaining).toBe(3);
      expect(stats!.limit).toBe(limit);
      expect(stats!.windowMs).toBe(windowMs);
    });

    it('should return null stats for non-existent key', async () => {
      const stats = await rateLimiter.getStats('non-existent');
      expect(stats).toBeNull();
    });

    it('should track active windows', () => {
      expect(rateLimiter.getActiveWindowCount()).toBe(0);
      expect(rateLimiter.getActiveKeys()).toEqual([]);
    });
  });

  describe('RateLimitUtils', () => {
    it('should generate correct key formats', () => {
      expect(RateLimitUtils.ipKey('192.168.1.1')).toBe('ip:192.168.1.1');
      expect(RateLimitUtils.sessionKey('abc123')).toBe('session:abc123');
      expect(RateLimitUtils.oauthClientKey('client-1')).toBe('oauth:client-1');
      expect(RateLimitUtils.userKey('user-1')).toBe('user:user-1');
      expect(RateLimitUtils.compositeKey('a', 'b', 'c')).toBe('a:b:c');
    });

    it('should extract client IP correctly', () => {
      const req1 = { ip: '192.168.1.1' };
      expect(RateLimitUtils.getClientIp(req1)).toBe('192.168.1.1');

      const req2 = { 
        connection: { remoteAddress: '192.168.1.2' },
        headers: {}
      };
      expect(RateLimitUtils.getClientIp(req2)).toBe('192.168.1.2');

      // x-forwarded-for is intentionally NOT used as fallback (spoofable without proxy config)
      const req3 = {
        headers: { 'x-forwarded-for': '192.168.1.3, 10.0.0.1' }
      };
      expect(RateLimitUtils.getClientIp(req3)).toBe('127.0.0.1');

      // socket.remoteAddress fallback
      const req5 = { socket: { remoteAddress: '10.0.0.5' } };
      expect(RateLimitUtils.getClientIp(req5)).toBe('10.0.0.5');

      const req4 = {};
      expect(RateLimitUtils.getClientIp(req4)).toBe('127.0.0.1');
    });

    it('should calculate retry-after correctly', () => {
      const futureTime = Date.now() + 30000; // 30 seconds in future
      const retryAfter = RateLimitUtils.calculateRetryAfter(futureTime);
      expect(retryAfter).toBeGreaterThan(25);
      expect(retryAfter).toBeLessThanOrEqual(30);
    });

    it('should format error messages', () => {
      const result: RateLimitResult = {
        allowed: false,
        remaining: 0,
        resetTime: Date.now() + 30000,
        totalRequests: 5,
        retryAfter: 30
      };

      const message = RateLimitUtils.formatErrorMessage(result);
      expect(message).toContain('Rate limit exceeded');
      expect(message).toContain('30 seconds');
    });
  });

  describe('HttpRateLimitMiddleware', () => {
    let middleware: HttpRateLimitMiddleware;
    let mockReq: any;
    let mockRes: any;
    let mockNext: any;

    beforeEach(() => {
      mockReq = {
        ip: '192.168.1.1',
        headers: {},
        body: {}
      };

      mockRes = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn().mockReturnThis(),
        header: vi.fn().mockReturnThis(),
        send: vi.fn().mockReturnThis(),
        statusCode: 200
      };

      mockNext = vi.fn();
    });

    afterEach(async () => {
      if (middleware) {
        await middleware.cleanup();
      }
    });

    it('should create global middleware with rate limiting', async () => {
      const config: HttpRateLimitConfig = {
        global: {
          windowMs: 60000,
          maxRequests: 2
        },
        headers: {
          includeHeaders: true
        }
      };

      middleware = new HttpRateLimitMiddleware(config);
      const globalMiddleware = middleware.createGlobalMiddleware();

      // First request should pass
      await globalMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockRes.header).toHaveBeenCalledWith('X-RateLimit-Remaining', '1');

      // Second request should pass
      mockNext.mockClear();
      await globalMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(mockRes.header).toHaveBeenCalledWith('X-RateLimit-Remaining', '0');

      // Third request should be rate limited
      mockNext.mockClear();
      await globalMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(429);
      expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
        jsonrpc: '2.0',
        error: expect.objectContaining({
          code: -32009,
          message: expect.stringContaining('Rate limit exceeded')
        })
      }));
    });

    it('should create client middleware with OAuth client rate limiting', async () => {
      const config: HttpRateLimitConfig = {
        perClient: {
          windowMs: 60000,
          maxRequests: 1
        }
      };

      middleware = new HttpRateLimitMiddleware(config);
      const clientMiddleware = middleware.createClientMiddleware();

      // Set up OAuth client
      mockReq.user = { clientId: 'test-client' };

      // First request should pass
      await clientMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);

      // Second request should be rate limited
      mockNext.mockClear();
      await clientMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(429);
    });

    it('should use session-based rate limiting when available', async () => {
      const config: HttpRateLimitConfig = {
        perClient: {
          windowMs: 60000,
          maxRequests: 1
        }
      };

      middleware = new HttpRateLimitMiddleware(config);
      const clientMiddleware = middleware.createClientMiddleware();

      // Set up session
      mockReq.headers['mcp-session-id'] = 'session-123';

      // First request should pass
      await clientMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);

      // Second request with same session should be rate limited
      mockNext.mockClear();
      await clientMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).not.toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(429);

      // Different session should be allowed
      mockReq.headers['mcp-session-id'] = 'session-456';
      mockNext.mockClear();
      await clientMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should use custom key generator when provided', async () => {
      const customKeyGenerator = vi.fn().mockReturnValue('custom-key');
      const config: HttpRateLimitConfig = {
        perClient: {
          windowMs: 60000,
          maxRequests: 1,
          keyGenerator: customKeyGenerator
        }
      };

      middleware = new HttpRateLimitMiddleware(config);
      const clientMiddleware = middleware.createClientMiddleware();

      await clientMiddleware(mockReq, mockRes, mockNext);
      expect(customKeyGenerator).toHaveBeenCalledWith(mockReq);
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should handle custom onLimitReached callback', async () => {
      const onLimitReached = vi.fn();
      const config: HttpRateLimitConfig = {
        global: {
          windowMs: 60000,
          maxRequests: 1
        },
        onLimitReached
      };

      middleware = new HttpRateLimitMiddleware(config);
      const globalMiddleware = middleware.createGlobalMiddleware();

      // Exhaust limit
      await globalMiddleware(mockReq, mockRes, mockNext);

      // Next request should trigger custom handler
      mockNext.mockClear();
      await globalMiddleware(mockReq, mockRes, mockNext);
      expect(onLimitReached).toHaveBeenCalledWith(
        mockReq, 
        mockRes, 
        expect.objectContaining({ allowed: false })
      );
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should skip on error when configured', async () => {
      const config: HttpRateLimitConfig = {
        global: {
          windowMs: 60000,
          maxRequests: 1
        },
        skipOnError: true,
        store: {
          check: vi.fn().mockRejectedValue(new Error('Store error')),
          reset: vi.fn(),
          getStats: vi.fn(),
          cleanup: vi.fn()
        }
      };

      middleware = new HttpRateLimitMiddleware(config);
      const globalMiddleware = middleware.createGlobalMiddleware();

      await globalMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should customize header names', async () => {
      const config: HttpRateLimitConfig = {
        global: {
          windowMs: 60000,
          maxRequests: 1
        },
        headers: {
          includeHeaders: true,
          headerNames: {
            remaining: 'X-Custom-Remaining',
            limit: 'X-Custom-Limit',
            reset: 'X-Custom-Reset'
          }
        }
      };

      middleware = new HttpRateLimitMiddleware(config);
      const globalMiddleware = middleware.createGlobalMiddleware();

      await globalMiddleware(mockReq, mockRes, mockNext);
      expect(mockRes.header).toHaveBeenCalledWith('X-Custom-Remaining', '0');
      expect(mockRes.header).toHaveBeenCalledWith('X-Custom-Limit', '1');
      expect(mockRes.header).toHaveBeenCalledWith('X-Custom-Reset', expect.any(String));
    });
  });

  describe('WebSocketRateLimitManager', () => {
    let manager: WebSocketRateLimitManager;
    let mockConnection: any;

    beforeEach(() => {
      mockConnection = {
        id: 'conn-123',
        createdAt: Date.now(),
        on: vi.fn(),
        close: vi.fn()
      };
    });

    afterEach(async () => {
      if (manager) {
        await manager.cleanup();
      }
    });

    it('should allow connections within IP limit', async () => {
      const config: WebSocketRateLimitConfig = {
        connectionLimits: {
          perIp: {
            maxConnections: 2,
            windowMs: 60000
          }
        }
      };

      manager = new WebSocketRateLimitManager(config);

      // First connection should be allowed
      const allowed1 = await manager.checkConnectionLimit('192.168.1.1', mockConnection);
      expect(allowed1).toBe(true);

      // Second connection from same IP should be allowed
      const mockConnection2 = { ...mockConnection, id: 'conn-456' };
      const allowed2 = await manager.checkConnectionLimit('192.168.1.1', mockConnection2);
      expect(allowed2).toBe(true);

      // Third connection from same IP should be rejected
      const mockConnection3 = { ...mockConnection, id: 'conn-789' };
      const allowed3 = await manager.checkConnectionLimit('192.168.1.1', mockConnection3);
      expect(allowed3).toBe(false);
    });

    it('should enforce global connection limit', async () => {
      const config: WebSocketRateLimitConfig = {
        connectionLimits: {
          global: {
            maxConnections: 2
          }
        }
      };

      manager = new WebSocketRateLimitManager(config);

      // First two connections should be allowed
      const allowed1 = await manager.checkConnectionLimit('192.168.1.1', mockConnection);
      expect(allowed1).toBe(true);

      const mockConnection2 = { ...mockConnection, id: 'conn-456' };
      const allowed2 = await manager.checkConnectionLimit('192.168.1.2', mockConnection2);
      expect(allowed2).toBe(true);

      // Third connection should be rejected
      const mockConnection3 = { ...mockConnection, id: 'conn-789' };
      const allowed3 = await manager.checkConnectionLimit('192.168.1.3', mockConnection3);
      expect(allowed3).toBe(false);
    });

    it('should close oldest connection when configured', async () => {
      const config: WebSocketRateLimitConfig = {
        connectionLimits: {
          global: {
            maxConnections: 1
          }
        },
        actions: {
          onConnectionLimitReached: 'close_oldest'
        }
      };

      manager = new WebSocketRateLimitManager(config);

      // First connection
      const oldConnection = { 
        ...mockConnection, 
        id: 'old-conn',
        createdAt: Date.now() - 10000,
        close: vi.fn()
      };
      await manager.checkConnectionLimit('192.168.1.1', oldConnection);

      // Second connection should close the first
      const newConnection = { 
        ...mockConnection, 
        id: 'new-conn',
        createdAt: Date.now(),
        close: vi.fn()
      };
      const allowed = await manager.checkConnectionLimit('192.168.1.2', newConnection);
      expect(allowed).toBe(true);
      expect(oldConnection.close).toHaveBeenCalledWith(1013, expect.stringContaining('oldest'));
    });

    it('should limit messages per connection', async () => {
      const config: WebSocketRateLimitConfig = {
        messageLimits: {
          perConnection: {
            maxMessages: 2,
            windowMs: 60000
          }
        }
      };

      manager = new WebSocketRateLimitManager(config);

      const message = { id: 1, method: 'test', params: {} };

      // First two messages should be allowed
      const allowed1 = await manager.checkMessageLimit(mockConnection, message);
      expect(allowed1).toBe(true);

      const allowed2 = await manager.checkMessageLimit(mockConnection, message);
      expect(allowed2).toBe(true);

      // Third message should be rejected
      const allowed3 = await manager.checkMessageLimit(mockConnection, message);
      expect(allowed3).toBe(false);
    });

    it('should limit messages per method', async () => {
      const config: WebSocketRateLimitConfig = {
        messageLimits: {
          perMethod: {
            'tools/call': {
              maxMessages: 1,
              windowMs: 60000
            }
          }
        }
      };

      manager = new WebSocketRateLimitManager(config);

      const toolMessage = { id: 1, method: 'tools/call', params: {} };
      const resourceMessage = { id: 2, method: 'resources/read', params: {} };

      // First tool message should be allowed
      const allowed1 = await manager.checkMessageLimit(mockConnection, toolMessage);
      expect(allowed1).toBe(true);

      // Second tool message should be rejected
      const allowed2 = await manager.checkMessageLimit(mockConnection, toolMessage);
      expect(allowed2).toBe(false);

      // Resource message should still be allowed (different method)
      const allowed3 = await manager.checkMessageLimit(mockConnection, resourceMessage);
      expect(allowed3).toBe(true);
    });

    it('should close connection on message rate limit when configured', async () => {
      const config: WebSocketRateLimitConfig = {
        messageLimits: {
          perConnection: {
            maxMessages: 1,
            windowMs: 60000
          }
        },
        actions: {
          onMessageLimitReached: 'close_connection'
        }
      };

      manager = new WebSocketRateLimitManager(config);

      const message = { id: 1, method: 'test', params: {} };

      // First message should be allowed
      await manager.checkMessageLimit(mockConnection, message);

      // Second message should close connection
      const allowed = await manager.checkMessageLimit(mockConnection, message);
      expect(allowed).toBe(false);
      expect(mockConnection.close).toHaveBeenCalledWith(1013, 'Message rate limit exceeded');
    });

    it('should provide connection statistics', async () => {
      const config: WebSocketRateLimitConfig = {
        connectionLimits: {
          perIp: {
            maxConnections: 5,
            windowMs: 60000
          }
        }
      };

      manager = new WebSocketRateLimitManager(config);

      // Add some connections
      await manager.checkConnectionLimit('192.168.1.1', mockConnection);
      const mockConnection2 = { ...mockConnection, id: 'conn-456' };
      await manager.checkConnectionLimit('192.168.1.1', mockConnection2);
      const mockConnection3 = { ...mockConnection, id: 'conn-789' };
      await manager.checkConnectionLimit('192.168.1.2', mockConnection3);

      const stats = manager.getConnectionStats();
      expect(stats.totalConnections).toBe(3);
      expect(stats.connectionsPerIp['192.168.1.1']).toBe(2);
      expect(stats.connectionsPerIp['192.168.1.2']).toBe(1);
    });

    it('should handle connections without configuration', async () => {
      const config: WebSocketRateLimitConfig = {};
      manager = new WebSocketRateLimitManager(config);

      const allowed = await manager.checkConnectionLimit('192.168.1.1', mockConnection);
      expect(allowed).toBe(true);

      const message = { id: 1, method: 'test', params: {} };
      const messageAllowed = await manager.checkMessageLimit(mockConnection, message);
      expect(messageAllowed).toBe(true);
    });
  });
});