import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  MemoryRateLimiter,
  HttpRateLimitMiddleware,
  WebSocketRateLimitManager,
  RateLimitUtils,
  type HttpRateLimitConfig,
  type WebSocketRateLimitConfig,
  type RateLimitResult,
} from '../src/index.js';

describe('Rate Limiting Edge Cases', () => {
  describe('MemoryRateLimiter - retryAfter guarantees', () => {
    let rateLimiter: MemoryRateLimiter;

    beforeEach(() => {
      rateLimiter = new MemoryRateLimiter(60000);
    });

    afterEach(async () => {
      await rateLimiter.cleanup();
    });

    it('should never return a negative retryAfter value', async () => {
      const key = 'retry-test';
      const limit = 1;
      const windowMs = 100; // Very short window

      // Exhaust limit
      await rateLimiter.check(key, limit, windowMs);

      // Wait for window to nearly expire
      await new Promise(resolve => setTimeout(resolve, 120));

      // Even if window has passed, retryAfter must be >= 1
      const result = await rateLimiter.check(key, limit, windowMs);
      // After window expiry, a new window is created so it should be allowed
      // But if somehow we get a rejected result, retryAfter must be positive
      if (!result.allowed && result.retryAfter !== undefined) {
        expect(result.retryAfter).toBeGreaterThanOrEqual(1);
      }
    });

    it('should guarantee retryAfter >= 1 when rate limited', async () => {
      const key = 'min-retry';
      const limit = 1;
      const windowMs = 1000;

      // Exhaust limit
      await rateLimiter.check(key, limit, windowMs);

      // Immediately check again — should be rejected with retryAfter >= 1
      const result = await rateLimiter.check(key, limit, windowMs);
      expect(result.allowed).toBe(false);
      expect(result.retryAfter).toBeDefined();
      expect(result.retryAfter).toBeGreaterThanOrEqual(1);
    });

    it('should handle decrement correctly', async () => {
      const key = 'decrement-test';
      const limit = 2;
      const windowMs = 60000;

      // Use both slots
      await rateLimiter.check(key, limit, windowMs);
      await rateLimiter.check(key, limit, windowMs);

      // Should be rejected
      const rejected = await rateLimiter.check(key, limit, windowMs);
      expect(rejected.allowed).toBe(false);

      // Decrement to free a slot
      await rateLimiter.decrement(key);

      // Should now be allowed
      const allowed = await rateLimiter.check(key, limit, windowMs);
      expect(allowed.allowed).toBe(true);
    });

    it('should not decrement below zero', async () => {
      const key = 'no-negative';
      const limit = 5;
      const windowMs = 60000;

      // Use 1 slot
      await rateLimiter.check(key, limit, windowMs);

      // Decrement multiple times
      await rateLimiter.decrement(key);
      await rateLimiter.decrement(key);
      await rateLimiter.decrement(key);

      // Stats should show 0 requests, not negative
      const stats = await rateLimiter.getStats(key);
      expect(stats).toBeDefined();
      expect(stats!.requests).toBe(0);
    });

    it('should not decrement for expired window', async () => {
      const key = 'expired-decrement';
      const limit = 5;
      const windowMs = 50;

      await rateLimiter.check(key, limit, windowMs);

      // Wait for window to expire
      await new Promise(resolve => setTimeout(resolve, 100));

      // Decrement should be a no-op for expired windows
      await rateLimiter.decrement(key);

      // New check should start a fresh window
      const result = await rateLimiter.check(key, limit, windowMs);
      expect(result.allowed).toBe(true);
      expect(result.totalRequests).toBe(1);
    });

    it('should handle cleanup of expired windows', async () => {
      const rateLimiterWithCleanup = new MemoryRateLimiter(50); // 50ms cleanup interval
      const windowMs = 50;

      await rateLimiterWithCleanup.check('key-1', 5, windowMs);
      await rateLimiterWithCleanup.check('key-2', 5, windowMs);

      expect(rateLimiterWithCleanup.getActiveWindowCount()).toBe(2);

      // Wait for windows to expire and cleanup to run
      await new Promise(resolve => setTimeout(resolve, 150));

      expect(rateLimiterWithCleanup.getActiveWindowCount()).toBe(0);

      await rateLimiterWithCleanup.cleanup();
    });

    it('should update window parameters when they change mid-window', async () => {
      const key = 'param-change';

      // Create window with limit 5
      await rateLimiter.check(key, 5, 60000);
      await rateLimiter.check(key, 5, 60000);

      // Change limit to 2 — already used 2 slots so next should be rejected
      // because requests (2) >= limit (2)
      const result = await rateLimiter.check(key, 2, 60000);
      expect(result.allowed).toBe(false);
    });

    it('should track active windows and keys', async () => {
      await rateLimiter.check('key-a', 5, 60000);
      await rateLimiter.check('key-b', 5, 60000);
      await rateLimiter.check('key-c', 5, 60000);

      expect(rateLimiter.getActiveWindowCount()).toBe(3);
      expect(rateLimiter.getActiveKeys()).toEqual(
        expect.arrayContaining(['key-a', 'key-b', 'key-c'])
      );
    });
  });

  describe('RateLimitUtils - edge cases', () => {
    it('should ensure calculateRetryAfter is never negative', () => {
      // Reset time in the past (clock skew scenario)
      const pastResetTime = Date.now() - 5000;
      const retryAfter = RateLimitUtils.calculateRetryAfter(pastResetTime);
      expect(retryAfter).toBeGreaterThanOrEqual(1);
    });

    it('should handle calculateRetryAfter at exactly current time', () => {
      const retryAfter = RateLimitUtils.calculateRetryAfter(Date.now());
      expect(retryAfter).toBeGreaterThanOrEqual(1);
    });

    it('should generate composite keys correctly with special characters', () => {
      const key = RateLimitUtils.compositeKey('prefix', 'user:123', 'method/call');
      expect(key).toBe('prefix:user:123:method/call');
    });

    it('should handle empty string in composite key', () => {
      const key = RateLimitUtils.compositeKey('', 'b');
      expect(key).toBe(':b');
    });

    it('should handle custom key prefixes', () => {
      expect(RateLimitUtils.ipKey('10.0.0.1', 'custom')).toBe('custom:10.0.0.1');
      expect(RateLimitUtils.sessionKey('sess-1', 'custom')).toBe('custom:sess-1');
      expect(RateLimitUtils.oauthClientKey('client-1', 'custom')).toBe('custom:client-1');
      expect(RateLimitUtils.userKey('user-1', 'custom')).toBe('custom:user-1');
    });

    it('should format error message with zero retryAfter', () => {
      const result: RateLimitResult = {
        allowed: false,
        remaining: 0,
        resetTime: Date.now(),
        totalRequests: 5,
      };
      const message = RateLimitUtils.formatErrorMessage(result);
      expect(message).toContain('Rate limit exceeded');
      expect(message).toContain('0 seconds');
    });
  });

  describe('HttpRateLimitMiddleware - edge cases', () => {
    let middleware: HttpRateLimitMiddleware;
    let mockReq: any;
    let mockRes: any;
    let mockNext: any;

    beforeEach(() => {
      mockReq = {
        ip: '192.168.1.1',
        headers: {},
        body: {},
      };
      mockRes = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn().mockReturnThis(),
        header: vi.fn().mockReturnThis(),
        send: vi.fn().mockReturnThis(),
        statusCode: 200,
        on: vi.fn(),
      };
      mockNext = vi.fn();
    });

    afterEach(async () => {
      if (middleware) {
        await middleware.cleanup();
      }
    });

    it('should skip rate limiting for initialize requests (global)', async () => {
      const config: HttpRateLimitConfig = {
        global: { windowMs: 60000, maxRequests: 1 },
      };
      middleware = new HttpRateLimitMiddleware(config);
      const globalMiddleware = middleware.createGlobalMiddleware();

      // Initialize request should always pass
      mockReq.body = { method: 'initialize' };
      await globalMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);

      // Send again — should still pass because initialize is always skipped
      mockNext.mockClear();
      await globalMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should skip rate limiting for initialize requests (per-client)', async () => {
      const config: HttpRateLimitConfig = {
        perClient: { windowMs: 60000, maxRequests: 1 },
      };
      middleware = new HttpRateLimitMiddleware(config);
      const clientMiddleware = middleware.createClientMiddleware();

      mockReq.body = { method: 'initialize' };
      await clientMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should pass through when no global config', async () => {
      const config: HttpRateLimitConfig = {};
      middleware = new HttpRateLimitMiddleware(config);
      const globalMiddleware = middleware.createGlobalMiddleware();

      await globalMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should pass through when no client config', async () => {
      const config: HttpRateLimitConfig = {};
      middleware = new HttpRateLimitMiddleware(config);
      const clientMiddleware = middleware.createClientMiddleware();

      await clientMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should handle skipSuccessfulRequests', async () => {
      const config: HttpRateLimitConfig = {
        global: { windowMs: 60000, maxRequests: 1, skipSuccessfulRequests: true },
      };
      middleware = new HttpRateLimitMiddleware(config);
      const globalMiddleware = middleware.createGlobalMiddleware();

      // First request
      await globalMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);

      // Simulate 'finish' event with success status (200)
      const finishHandler = mockRes.on.mock.calls.find(
        (call: any[]) => call[0] === 'finish'
      );
      expect(finishHandler).toBeDefined();

      // Trigger the finish callback
      mockRes.statusCode = 200;
      finishHandler![1]();

      // After decrement, should be allowed again
      // Small delay to let decrement settle
      await new Promise(resolve => setTimeout(resolve, 10));
      mockNext.mockClear();
      await globalMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should forward error when skipOnError is false', async () => {
      const config: HttpRateLimitConfig = {
        global: { windowMs: 60000, maxRequests: 1 },
        skipOnError: false,
        store: {
          check: vi.fn().mockRejectedValue(new Error('Store error')),
          decrement: vi.fn(),
          reset: vi.fn(),
          getStats: vi.fn(),
          cleanup: vi.fn(),
        },
      };

      middleware = new HttpRateLimitMiddleware(config);
      const globalMiddleware = middleware.createGlobalMiddleware();

      await globalMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledWith(expect.any(Error));
    });

    it('should expose the rate limiter store', () => {
      const config: HttpRateLimitConfig = {};
      middleware = new HttpRateLimitMiddleware(config);
      expect(middleware.getStore()).toBeDefined();
    });

    it('should use IP-based key as fallback for client middleware', async () => {
      const config: HttpRateLimitConfig = {
        perClient: { windowMs: 60000, maxRequests: 1 },
      };
      middleware = new HttpRateLimitMiddleware(config);
      const clientMiddleware = middleware.createClientMiddleware();

      // No user, no session — should fall back to IP
      mockReq.ip = '10.0.0.1';
      await clientMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);

      // Same IP should be rate limited
      mockNext.mockClear();
      await clientMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).not.toHaveBeenCalled();

      // Different IP should pass
      mockReq.ip = '10.0.0.2';
      mockNext.mockClear();
      await clientMiddleware(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(1);
    });
  });

  describe('WebSocketRateLimitManager - edge cases', () => {
    let manager: WebSocketRateLimitManager;
    let mockConnection: any;

    beforeEach(() => {
      mockConnection = {
        id: 'conn-test',
        createdAt: Date.now(),
        on: vi.fn(),
        close: vi.fn(),
      };
    });

    afterEach(async () => {
      if (manager) {
        await manager.cleanup();
      }
    });

    it('should assign stable IDs to anonymous connections', async () => {
      const config: WebSocketRateLimitConfig = {
        messageLimits: {
          perConnection: { maxMessages: 10, windowMs: 60000 },
        },
      };
      manager = new WebSocketRateLimitManager(config);

      // Connection without any id properties
      const anonConn = { on: vi.fn(), close: vi.fn() };
      await manager.checkMessageLimit(anonConn, { method: 'test' });

      // Should have assigned an ID
      expect((anonConn as any).__rateLimitId).toBeDefined();
      expect((anonConn as any).__rateLimitId).toMatch(/^anon_/);

      // Same connection should get same ID on next check
      const firstId = (anonConn as any).__rateLimitId;
      await manager.checkMessageLimit(anonConn, { method: 'test' });
      expect((anonConn as any).__rateLimitId).toBe(firstId);
    });

    it('should handle connection cleanup via close event', async () => {
      const config: WebSocketRateLimitConfig = {
        connectionLimits: {
          perIp: { maxConnections: 5, windowMs: 60000 },
        },
      };
      manager = new WebSocketRateLimitManager(config);

      await manager.checkConnectionLimit('10.0.0.1', mockConnection);

      const stats = manager.getConnectionStats();
      expect(stats.totalConnections).toBe(1);

      // Simulate close event
      const closeHandler = mockConnection.on.mock.calls.find(
        (call: any[]) => call[0] === 'close'
      );
      expect(closeHandler).toBeDefined();
      closeHandler![1](); // Trigger cleanup

      const statsAfter = manager.getConnectionStats();
      expect(statsAfter.totalConnections).toBe(0);
    });

    it('should guard against double cleanup on close+error', async () => {
      const config: WebSocketRateLimitConfig = {
        connectionLimits: {
          perIp: { maxConnections: 5, windowMs: 60000 },
        },
      };
      manager = new WebSocketRateLimitManager(config);

      await manager.checkConnectionLimit('10.0.0.1', mockConnection);

      // Get both close and error handlers
      const closeHandler = mockConnection.on.mock.calls.find(
        (call: any[]) => call[0] === 'close'
      );
      const errorHandler = mockConnection.on.mock.calls.find(
        (call: any[]) => call[0] === 'error'
      );

      // Trigger both — should not throw or double-decrement
      closeHandler![1]();
      errorHandler![1]();

      const stats = manager.getConnectionStats();
      expect(stats.totalConnections).toBe(0);
    });

    it('should handle messages without method for per-method limits', async () => {
      const config: WebSocketRateLimitConfig = {
        messageLimits: {
          perMethod: {
            'tools/call': { maxMessages: 1, windowMs: 60000 },
          },
        },
      };
      manager = new WebSocketRateLimitManager(config);

      // Message without method should pass (no matching per-method limit)
      const allowed = await manager.checkMessageLimit(mockConnection, { id: 1 });
      expect(allowed).toBe(true);
    });

    it('should cleanup all state on cleanup()', async () => {
      const config: WebSocketRateLimitConfig = {
        connectionLimits: {
          perIp: { maxConnections: 10, windowMs: 60000 },
        },
      };
      manager = new WebSocketRateLimitManager(config);

      await manager.checkConnectionLimit('10.0.0.1', mockConnection);
      const conn2 = { ...mockConnection, id: 'conn-2' };
      await manager.checkConnectionLimit('10.0.0.2', conn2);

      expect(manager.getConnectionStats().totalConnections).toBe(2);

      await manager.cleanup();

      expect(manager.getConnectionStats().totalConnections).toBe(0);
    });
  });
});
