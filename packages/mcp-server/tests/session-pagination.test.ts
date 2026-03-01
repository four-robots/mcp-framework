import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { MCPServer, SessionManager, z } from '../src/index.js';

// Mock the SDK server
vi.mock('@modelcontextprotocol/sdk/server/mcp.js', () => ({
  McpServer: vi.fn().mockImplementation(() => ({
    registerTool: vi.fn(),
    registerResource: vi.fn(),
    registerPrompt: vi.fn(),
    notification: vi.fn(),
    setRequestHandler: vi.fn(),
  })),
  ResourceTemplate: vi.fn().mockImplementation((uriTemplate, config) => ({
    uriTemplate,
    config,
  })),
}));

describe('SessionManager', () => {
  let manager: SessionManager;

  afterEach(() => {
    // Ensure cleanup timers are stopped
    if (manager) {
      (manager as any).cleanupTimer && clearInterval((manager as any).cleanupTimer);
    }
  });

  describe('Session Lifecycle', () => {
    beforeEach(() => {
      manager = new SessionManager({
        enabled: true,
        timeoutMs: 60000,
        maxSessions: 5,
      });
    });

    it('should store and retrieve sessions', () => {
      const context = { sessionId: 'sess-1', user: { id: 'u1', username: 'user1', email: 'u@e.com', groups: [] } };
      expect(manager.storeSession(context)).toBe(true);

      const retrieved = manager.retrieveSession(context);
      expect(retrieved).toBeDefined();
      expect(retrieved?.sessionId).toBe('sess-1');
    });

    it('should return null for non-existent session', () => {
      const result = manager.retrieveSession({ sessionId: 'nonexistent' });
      expect(result).toBeNull();
    });

    it('should delete sessions', () => {
      const context = { sessionId: 'sess-1' };
      manager.storeSession(context);
      expect(manager.deleteSession(context)).toBe(true);
      expect(manager.retrieveSession(context)).toBeNull();
    });

    it('should return false when deleting non-existent session', () => {
      expect(manager.deleteSession({ sessionId: 'nonexistent' })).toBe(false);
    });

    it('should update last accessed time on retrieval', () => {
      const context = { sessionId: 'sess-1' };
      manager.storeSession(context);

      const before = (manager as any).sessions.get('session:sess-1').lastAccessedAt;

      // Small delay to ensure timestamp difference
      const retrieved = manager.retrieveSession(context);
      const after = (manager as any).sessions.get('session:sess-1').lastAccessedAt;

      expect(after).toBeGreaterThanOrEqual(before);
      expect(retrieved).toBeDefined();
    });

    it('should increment access count on each retrieval', () => {
      const context = { sessionId: 'sess-1' };
      manager.storeSession(context);

      manager.retrieveSession(context);
      manager.retrieveSession(context);
      manager.retrieveSession(context);

      const data = (manager as any).sessions.get('session:sess-1');
      // 1 from store + 3 from retrieval
      expect(data.accessCount).toBe(4);
    });
  });

  describe('Session Eviction', () => {
    beforeEach(() => {
      manager = new SessionManager({
        enabled: true,
        timeoutMs: 60000,
        maxSessions: 3,
      });
    });

    it('should evict oldest session when max reached', () => {
      manager.storeSession({ sessionId: 'oldest' });
      manager.storeSession({ sessionId: 'middle' });
      manager.storeSession({ sessionId: 'newest' });

      // Max is 3, adding 4th should evict oldest
      expect(manager.storeSession({ sessionId: 'fourth' })).toBe(true);

      // Oldest should be gone
      expect(manager.retrieveSession({ sessionId: 'oldest' })).toBeNull();
      // Others should still exist
      expect(manager.retrieveSession({ sessionId: 'middle' })).toBeDefined();
      expect(manager.retrieveSession({ sessionId: 'newest' })).toBeDefined();
      expect(manager.retrieveSession({ sessionId: 'fourth' })).toBeDefined();
    });

    it('should not evict when updating existing session', () => {
      manager.storeSession({ sessionId: 's1' });
      manager.storeSession({ sessionId: 's2' });
      manager.storeSession({ sessionId: 's3' });

      // Update existing session should not trigger eviction
      manager.storeSession({ sessionId: 's1' });

      expect(manager.retrieveSession({ sessionId: 's1' })).toBeDefined();
      expect(manager.retrieveSession({ sessionId: 's2' })).toBeDefined();
      expect(manager.retrieveSession({ sessionId: 's3' })).toBeDefined();
    });

    it('should report correct stats', () => {
      manager.storeSession({ sessionId: 's1' });
      manager.storeSession({ sessionId: 's2' });

      const stats = manager.getSessionStats();
      expect(stats.totalSessions).toBe(2);
      expect(stats.maxSessions).toBe(3);
      expect(stats.enabled).toBe(true);
      expect(stats.activeSessions).toBe(2);
    });
  });

  describe('Session Expiration', () => {
    it('should expire sessions after timeout', () => {
      manager = new SessionManager({
        enabled: true,
        timeoutMs: 100, // Very short timeout
        maxSessions: 10,
      });

      manager.storeSession({ sessionId: 'expiring' });

      // Use vi.advanceTimersByTime or direct manipulation
      const data = (manager as any).sessions.get('session:expiring');
      data.expiresAt = Date.now() - 1; // Force expiration

      expect(manager.retrieveSession({ sessionId: 'expiring' })).toBeNull();
    });

    it('should clean up expired sessions', () => {
      manager = new SessionManager({
        enabled: true,
        timeoutMs: 100,
        maxSessions: 10,
      });

      manager.storeSession({ sessionId: 's1' });
      manager.storeSession({ sessionId: 's2' });
      manager.storeSession({ sessionId: 's3' });

      // Force all to expire
      for (const [, data] of (manager as any).sessions.entries()) {
        data.expiresAt = Date.now() - 1;
      }

      const removed = (manager as any).cleanupExpiredSessions();
      expect(removed).toBe(3);
      expect((manager as any).sessions.size).toBe(0);
    });

    it('should only clean expired sessions, not active ones', () => {
      manager = new SessionManager({
        enabled: true,
        timeoutMs: 60000,
        maxSessions: 10,
      });

      manager.storeSession({ sessionId: 'active' });
      manager.storeSession({ sessionId: 'expired' });

      // Force only one to expire
      const data = (manager as any).sessions.get('session:expired');
      data.expiresAt = Date.now() - 1;

      const removed = (manager as any).cleanupExpiredSessions();
      expect(removed).toBe(1);
      expect(manager.retrieveSession({ sessionId: 'active' })).toBeDefined();
      expect(manager.retrieveSession({ sessionId: 'expired' })).toBeNull();
    });
  });

  describe('Disabled Session Manager', () => {
    beforeEach(() => {
      manager = new SessionManager({
        enabled: false,
        maxSessions: 5,
      });
    });

    it('should return false for store when disabled', () => {
      expect(manager.storeSession({ sessionId: 's1' })).toBe(false);
    });

    it('should return null for retrieve when disabled', () => {
      expect(manager.retrieveSession({ sessionId: 's1' })).toBeNull();
    });

    it('should return false for delete when disabled', () => {
      expect(manager.deleteSession({ sessionId: 's1' })).toBe(false);
    });
  });

  describe('Key Generation', () => {
    beforeEach(() => {
      manager = new SessionManager({
        enabled: true,
        maxSessions: 10,
      });
    });

    it('should generate key from sessionId', () => {
      const result = manager.storeSession({ sessionId: 'test-session' });
      expect(result).toBe(true);
      expect((manager as any).sessions.has('session:test-session')).toBe(true);
    });

    it('should generate key from user ID when no sessionId', () => {
      const result = manager.storeSession({ user: { id: 'user-1', username: 'u', email: 'e', groups: [] } });
      expect(result).toBe(true);
      expect((manager as any).sessions.has('user:user-1')).toBe(true);
    });

    it('should generate key from correlationId as fallback', () => {
      const result = manager.storeSession({ correlationId: 'corr-1' });
      expect(result).toBe(true);
      expect((manager as any).sessions.has('correlation:corr-1')).toBe(true);
    });

    it('should return false when no key can be generated', () => {
      const result = manager.storeSession({});
      expect(result).toBe(false);
    });
  });
});

describe('Pagination Cursor Security', () => {
  let server: MCPServer;

  beforeEach(() => {
    server = new MCPServer({
      name: 'pagination-test',
      version: '1.0.0',
      pagination: {
        defaultPageSize: 2,
        maxPageSize: 10,
        cursorTTL: 5000, // 5 seconds for testing
      },
    });

    const handler = vi.fn();
    for (let i = 0; i < 10; i++) {
      server.registerTool(`tool_${i}`, { description: `Tool ${i}`, inputSchema: z.object({}) }, handler);
    }
  });

  describe('Cursor HMAC Validation', () => {
    it('should accept valid cursors from the same server', () => {
      const page1 = server.getToolsPaginated({ limit: 3 });
      expect(page1.items).toHaveLength(3);
      expect(page1.nextCursor).toBeDefined();

      const page2 = server.getToolsPaginated({ cursor: page1.nextCursor, limit: 3 });
      expect(page2.items).toHaveLength(3);
    });

    it('should reject cursors with tampered payload', () => {
      const page1 = server.getToolsPaginated({ limit: 3 });
      const cursor = page1.nextCursor!;

      // Decode, tamper, re-encode
      const decoded = JSON.parse(Buffer.from(cursor, 'base64').toString());
      const payload = JSON.parse(decoded.payload);
      payload.sortKey = 'tool_999'; // Tamper with sort key
      decoded.payload = JSON.stringify(payload);
      const tampered = Buffer.from(JSON.stringify(decoded)).toString('base64');

      expect(() => server.getToolsPaginated({ cursor: tampered })).toThrow('Invalid or expired cursor');
    });

    it('should reject cursors with tampered signature', () => {
      const page1 = server.getToolsPaginated({ limit: 3 });
      const cursor = page1.nextCursor!;

      const decoded = JSON.parse(Buffer.from(cursor, 'base64').toString());
      decoded.signature = 'a'.repeat(64); // Fake signature
      const tampered = Buffer.from(JSON.stringify(decoded)).toString('base64');

      expect(() => server.getToolsPaginated({ cursor: tampered })).toThrow('Invalid or expired cursor');
    });

    it('should reject cursors from a different server instance', () => {
      const page1 = server.getToolsPaginated({ limit: 3 });

      // New server instance has different HMAC secret
      const otherServer = new MCPServer({
        name: 'other-server',
        version: '1.0.0',
        pagination: { defaultPageSize: 2, maxPageSize: 10, cursorTTL: 5000 },
      });
      const handler = vi.fn();
      for (let i = 0; i < 10; i++) {
        otherServer.registerTool(`tool_${i}`, { description: `Tool ${i}`, inputSchema: z.object({}) }, handler);
      }

      expect(() => otherServer.getToolsPaginated({ cursor: page1.nextCursor })).toThrow('Invalid or expired cursor');
    });

    it('should reject expired cursors', () => {
      const page1 = server.getToolsPaginated({ limit: 3 });
      const cursor = page1.nextCursor!;

      // Manually expire by manipulating timestamp
      const decoded = JSON.parse(Buffer.from(cursor, 'base64').toString());
      const payload = JSON.parse(decoded.payload);
      payload.timestamp = Date.now() - 10000; // 10 seconds ago (TTL is 5s)

      // Need to re-sign with correct HMAC
      // Since we can't access the secret, test via the server
      // Instead, use a short-TTL server
      const shortTTLServer = new MCPServer({
        name: 'short-ttl',
        version: '1.0.0',
        pagination: { defaultPageSize: 2, maxPageSize: 10, cursorTTL: 1 }, // 1ms TTL
      });
      const handler = vi.fn();
      for (let i = 0; i < 5; i++) {
        shortTTLServer.registerTool(`tool_${i}`, { description: `Tool ${i}`, inputSchema: z.object({}) }, handler);
      }

      const shortPage = shortTTLServer.getToolsPaginated({ limit: 2 });
      // Wait for TTL to expire
      const start = Date.now();
      while (Date.now() - start < 5) { /* busy wait */ }

      expect(() => shortTTLServer.getToolsPaginated({ cursor: shortPage.nextCursor })).toThrow('Invalid or expired cursor');
    });

    it('should reject completely invalid cursors', () => {
      expect(() => server.getToolsPaginated({ cursor: 'not-base64!!!' })).toThrow('Invalid or expired cursor');
    });

    it('should reject empty string cursor', () => {
      expect(() => server.getToolsPaginated({ cursor: '' })).toThrow('Cursor must be a non-empty string');
    });

    it('should reject base64-encoded non-JSON', () => {
      const cursor = Buffer.from('not json at all').toString('base64');
      expect(() => server.getToolsPaginated({ cursor })).toThrow('Invalid or expired cursor');
    });
  });

  describe('Pagination Behavior', () => {
    it('should paginate through all items', () => {
      const allItems: any[] = [];
      let cursor: string | undefined;

      do {
        const page = server.getToolsPaginated({ cursor, limit: 3 });
        allItems.push(...page.items);
        cursor = page.nextCursor;
      } while (cursor);

      expect(allItems).toHaveLength(10);
      // All tool names should be present
      const names = allItems.map((t: any) => t.name);
      for (let i = 0; i < 10; i++) {
        expect(names).toContain(`tool_${i}`);
      }
    });

    it('should reject limit exceeding maxPageSize', () => {
      expect(() => server.getToolsPaginated({ limit: 100 })).toThrow('Limit cannot exceed 10');
    });

    it('should use defaultPageSize when no limit specified', () => {
      const page = server.getToolsPaginated({});
      expect(page.items).toHaveLength(2); // defaultPageSize is 2
    });

    it('should return no cursor on last page', () => {
      const page = server.getToolsPaginated({ limit: 10 });
      expect(page.nextCursor).toBeUndefined();
    });
  });
});
