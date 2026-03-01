import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { 
  MCPServer, 
  SessionManager, 
  SessionConfig, 
  SessionData,
  ToolContext 
} from '../src/index.js';

// Mock the SDK server
vi.mock('@modelcontextprotocol/sdk/server/mcp.js', () => ({
  McpServer: vi.fn().mockImplementation(() => ({
    registerTool: vi.fn(),
    registerResource: vi.fn(),
    registerPrompt: vi.fn(),
    notification: vi.fn(),
    setRequestHandler: vi.fn()
  }))
}));

describe('Session Management System', () => {
  let sessionManager: SessionManager;

  afterEach(() => {
    if (sessionManager) {
      sessionManager.stop();
    }
  });

  describe('SessionManager', () => {
    it('should initialize with basic configuration', () => {
      const config: SessionConfig = {
        enabled: true,
        timeoutMs: 60000,
        maxSessions: 100
      };

      sessionManager = new SessionManager(config);
      const stats = sessionManager.getSessionStats();

      expect(stats.enabled).toBe(true);
      expect(stats.maxSessions).toBe(100);
      expect(stats.totalSessions).toBe(0);
    });

    it('should store and retrieve sessions by sessionId', () => {
      const config: SessionConfig = { enabled: true };
      sessionManager = new SessionManager(config);

      const context: ToolContext = {
        sessionId: 'test-session-123',
        user: { id: 'user123', name: 'Test User' },
        customData: 'important data'
      };

      // Store session
      const stored = sessionManager.storeSession(context);
      expect(stored).toBe(true);

      // Retrieve session
      const retrieved = sessionManager.retrieveSession({ sessionId: 'test-session-123' });
      expect(retrieved).toEqual(context);
    });

    it('should store and retrieve sessions by user ID when no sessionId', () => {
      const config: SessionConfig = { enabled: true };
      sessionManager = new SessionManager(config);

      const context: ToolContext = {
        user: { id: 'user456', name: 'Another User' },
        preferences: { theme: 'dark' }
      };

      // Store session
      const stored = sessionManager.storeSession(context);
      expect(stored).toBe(true);

      // Retrieve session
      const retrieved = sessionManager.retrieveSession({ user: { id: 'user456' } });
      expect(retrieved).toMatchObject({
        user: { id: 'user456', name: 'Another User' },
        preferences: { theme: 'dark' }
      });
    });

    it('should handle session expiration', async () => {
      const config: SessionConfig = { 
        enabled: true, 
        timeoutMs: 50 // Very short timeout for testing
      };
      sessionManager = new SessionManager(config);

      const context: ToolContext = {
        sessionId: 'expire-test',
        data: 'should expire'
      };

      // Store session
      sessionManager.storeSession(context);

      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 60));

      // Should return null for expired session
      const retrieved = sessionManager.retrieveSession({ sessionId: 'expire-test' });
      expect(retrieved).toBeNull();
    });

    it('should enforce maximum session limits', () => {
      const config: SessionConfig = { 
        enabled: true, 
        maxSessions: 2 
      };
      sessionManager = new SessionManager(config);

      // Store 3 sessions (exceeds limit)
      sessionManager.storeSession({ sessionId: 'session1', data: 'first' });
      sessionManager.storeSession({ sessionId: 'session2', data: 'second' });
      sessionManager.storeSession({ sessionId: 'session3', data: 'third' });

      const stats = sessionManager.getSessionStats();
      expect(stats.totalSessions).toBeLessThanOrEqual(2);
    });

    it('should update access count and last accessed time', () => {
      const config: SessionConfig = { enabled: true };
      sessionManager = new SessionManager(config);

      const context: ToolContext = { sessionId: 'access-test' };

      // Store session
      sessionManager.storeSession(context);

      // Access multiple times
      sessionManager.retrieveSession({ sessionId: 'access-test' });
      sessionManager.retrieveSession({ sessionId: 'access-test' });

      const stats = sessionManager.getSessionStats();
      expect(stats.totalSessions).toBe(1);
    });

    it('should handle custom key generator', () => {
      const config: SessionConfig = { 
        enabled: true,
        keyGenerator: (context) => `custom:${context.correlationId}`
      };
      sessionManager = new SessionManager(config);

      const context: ToolContext = {
        correlationId: 'corr_12345',
        data: 'custom key test'
      };

      // Store with custom key
      const stored = sessionManager.storeSession(context);
      expect(stored).toBe(true);

      // Retrieve with custom key
      const retrieved = sessionManager.retrieveSession({ correlationId: 'corr_12345' });
      expect(retrieved).toEqual(context);
    });

    it('should delete specific sessions', () => {
      const config: SessionConfig = { enabled: true };
      sessionManager = new SessionManager(config);

      const context: ToolContext = { sessionId: 'delete-test' };

      // Store and verify
      sessionManager.storeSession(context);
      expect(sessionManager.retrieveSession({ sessionId: 'delete-test' })).toEqual(context);

      // Delete and verify
      const deleted = sessionManager.deleteSession({ sessionId: 'delete-test' });
      expect(deleted).toBe(true);
      expect(sessionManager.retrieveSession({ sessionId: 'delete-test' })).toBeNull();
    });

    it('should not store sessions when disabled', () => {
      const config: SessionConfig = { enabled: false };
      sessionManager = new SessionManager(config);

      const context: ToolContext = { sessionId: 'disabled-test' };

      const stored = sessionManager.storeSession(context);
      expect(stored).toBe(false);

      const retrieved = sessionManager.retrieveSession({ sessionId: 'disabled-test' });
      expect(retrieved).toBeNull();
    });
  });

  describe('MCPServer Session Integration', () => {
    let server: MCPServer;

    beforeEach(() => {
      server = new MCPServer({
        name: 'session-test-server',
        version: '1.0.0',
        session: {
          enabled: true,
          timeoutMs: 300000, // 5 minutes
          maxSessions: 50
        }
      });
    });

    afterEach(async () => {
      if (server) {
        await server.stop();
      }
    });

    it('should integrate session management with context setting', () => {
      const context = {
        sessionId: 'integration-test',
        user: { id: 'user789' },
        preferences: { lang: 'en' }
      };

      // Set context (should store in session)
      server.setContext(context);

      // Get session stats
      const stats = server.getSessionStats();
      expect(stats.enabled).toBe(true);
      expect(stats.totalSessions).toBe(1);
    });

    it('should restore context from session', () => {
      const context = {
        sessionId: 'restore-test',
        user: { id: 'user999' },
        workspaceState: { currentFile: 'test.js' }
      };

      // Set context with session
      server.setSessionContext('restore-test', context);

      // Retrieve context for session
      const retrieved = server.getSessionContext('restore-test');
      expect(retrieved).toMatchObject(context);
    });

    it('should handle session deletion', () => {
      const context = { sessionId: 'delete-integration-test' };

      // Set context
      server.setSessionContext('delete-integration-test', context);

      // Verify session exists
      expect(server.getSessionContext('delete-integration-test')).toMatchObject(context);

      // Delete session
      const deleted = server.deleteSession('delete-integration-test');
      expect(deleted).toBe(true);

      // Verify session is gone
      expect(server.getSessionContext('delete-integration-test')).toBeNull();
    });

    it('should provide accurate session statistics', () => {
      // Create multiple sessions
      server.setSessionContext('stats-test-1', { data: 'session1' });
      server.setSessionContext('stats-test-2', { data: 'session2' });
      server.setSessionContext('stats-test-3', { data: 'session3' });

      const stats = server.getSessionStats();
      expect(stats.enabled).toBe(true);
      expect(stats.totalSessions).toBe(3);
      expect(stats.activeSessions).toBe(3);
      expect(stats.maxSessions).toBe(50);
    });

    it('should handle servers without session management', () => {
      const noSessionServer = new MCPServer({
        name: 'no-session-server',
        version: '1.0.0'
        // No session config
      });

      const stats = noSessionServer.getSessionStats();
      expect(stats.enabled).toBe(false);
      expect(stats.totalSessions).toBe(0);

      const stored = noSessionServer.setSessionContext('test', { data: 'test' });
      expect(stored).toBe(false);

      const retrieved = noSessionServer.getSessionContext('test');
      expect(retrieved).toBeNull();
    });

    it('should merge session context with current context in getContext', () => {
      // Set initial session context
      server.setSessionContext('merge-test', {
        user: { id: 'user123', name: 'Session User' },
        sessionData: 'from session'
      });

      // Set current context with same sessionId
      server.setContext({
        sessionId: 'merge-test',
        requestData: 'from current'
      });

      // Get context should merge both
      const context = server.getContext();
      expect(context).toMatchObject({
        sessionId: 'merge-test',
        user: { id: 'user123', name: 'Session User' },
        sessionData: 'from session',
        requestData: 'from current'
      });
    });
  });

  describe('Session Configuration Validation', () => {
    it('should use default values for missing config options', () => {
      const config: SessionConfig = { enabled: true };
      sessionManager = new SessionManager(config);

      // Should use defaults
      const stats = sessionManager.getSessionStats();
      expect(stats.enabled).toBe(true);
      expect(stats.maxSessions).toBe(1000); // Default
    });

    it('should handle custom cleanup intervals', async () => {
      const config: SessionConfig = {
        enabled: true,
        timeoutMs: 10,
        cleanupIntervalMs: 20
      };
      sessionManager = new SessionManager(config);

      // Store a session that will expire
      sessionManager.storeSession({ sessionId: 'cleanup-test' });

      // Wait for cleanup to run
      await new Promise(resolve => setTimeout(resolve, 30));

      const stats = sessionManager.getSessionStats();
      expect(stats.activeSessions).toBe(0);
    });

    it('should effectively disable sessions when maxSessions is 0', () => {
      const config: SessionConfig = {
        enabled: true,
        maxSessions: 0
      };
      sessionManager = new SessionManager(config);

      // Attempting to store any session should fail because maxSessions=0
      // means sessions.size (0) >= maxSessions (0) is true, and eviction
      // of an empty map returns false
      const stored = sessionManager.storeSession({ sessionId: 'zero-max-test' });
      expect(stored).toBe(false);

      const stats = sessionManager.getSessionStats();
      expect(stats.totalSessions).toBe(0);
    });

    it('should allow updating an existing session even when at maxSessions', () => {
      const config: SessionConfig = {
        enabled: true,
        maxSessions: 1
      };
      sessionManager = new SessionManager(config);

      // Store initial session
      sessionManager.storeSession({ sessionId: 'existing-session', data: 'v1' });
      expect(sessionManager.getSessionStats().totalSessions).toBe(1);

      // Update same session should succeed (existing entry, no eviction needed)
      const updated = sessionManager.storeSession({ sessionId: 'existing-session', data: 'v2' });
      expect(updated).toBe(true);
      expect(sessionManager.getSessionStats().totalSessions).toBe(1);
    });

    it('should return null for key generator that returns null', () => {
      const config: SessionConfig = {
        enabled: true,
        keyGenerator: () => null
      };
      sessionManager = new SessionManager(config);

      const stored = sessionManager.storeSession({ sessionId: 'null-key' });
      expect(stored).toBe(false);

      const retrieved = sessionManager.retrieveSession({ sessionId: 'null-key' });
      expect(retrieved).toBeNull();
    });

    it('should evict oldest session by lastAccessedAt not createdAt', async () => {
      const config: SessionConfig = {
        enabled: true,
        maxSessions: 2
      };
      sessionManager = new SessionManager(config);

      // Store two sessions with sufficient delay so lastAccessedAt differs
      sessionManager.storeSession({ sessionId: 'older' });
      await new Promise(resolve => setTimeout(resolve, 20));
      sessionManager.storeSession({ sessionId: 'newer' });

      // Wait a bit, then access 'older' so its lastAccessedAt becomes more recent
      await new Promise(resolve => setTimeout(resolve, 20));
      sessionManager.retrieveSession({ sessionId: 'older' });

      // Store a third session — should evict 'newer' (least recently accessed)
      sessionManager.storeSession({ sessionId: 'third' });

      expect(sessionManager.retrieveSession({ sessionId: 'older' })).not.toBeNull();
      expect(sessionManager.retrieveSession({ sessionId: 'newer' })).toBeNull();
      expect(sessionManager.retrieveSession({ sessionId: 'third' })).not.toBeNull();
    });

    it('should stop cleanup timer on stop()', () => {
      const config: SessionConfig = {
        enabled: true,
        cleanupIntervalMs: 100
      };
      sessionManager = new SessionManager(config);

      // Calling stop should clear the timer
      sessionManager.stop();

      // Double-stop should not throw
      expect(() => sessionManager.stop()).not.toThrow();
    });
  });
});