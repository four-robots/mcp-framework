import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { HttpTransport, HttpConfig } from '../src/index.js';
import { MCPServer } from '@tylercoles/mcp-server';
import { AuthProvider, User } from '@tylercoles/mcp-auth';

// Mock dependencies
vi.mock('@modelcontextprotocol/sdk/server/streamableHttp.js', () => ({
  StreamableHTTPServerTransport: vi.fn(() => ({
    _sessionId: 'test-session-123',
    get sessionId() { return this._sessionId; },
    set sessionId(value: string | null) { this._sessionId = value; },
    handleRequest: vi.fn(async (req, res) => {
      res.status(200).json({ success: true });
    }),
    close: vi.fn(),
    onclose: null
  }))
}));

class MockAuthProvider implements AuthProvider {
  async authenticate(req: any): Promise<User | null> {
    return null;
  }
  
  getUser(req: any): User | null {
    return null;
  }
}

describe('HttpTransport Edge Cases', () => {
  let transport: HttpTransport;
  let server: MCPServer;

  beforeEach(() => {
    server = {
      getSDKServer: vi.fn().mockReturnValue({
        connect: vi.fn().mockResolvedValue(undefined)
      })
    } as any;
  });

  afterEach(async () => {
    if (transport) {
      await transport.stop();
    }
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle missing app in registerRouter', () => {
      transport = new HttpTransport({ port: 0 });
      
      const router = transport.createRouter(false);
      
      expect(() => {
        transport.registerRouter('/test', router);
      }).toThrow('Transport not started yet');
    });

    it('should handle auth middleware creation without auth provider', () => {
      transport = new HttpTransport({ port: 0 });
      
      const middleware = transport.getAuthMiddleware();
      expect(middleware).toBeNull();
    });

    it('should handle auth middleware creation with auth provider', async () => {
      const authProvider = new MockAuthProvider();
      const config: HttpConfig = {
        port: 0,
        auth: authProvider
      };

      transport = new HttpTransport(config);
      await transport.start(server);
      
      const middleware = transport.getAuthMiddleware();
      expect(middleware).toBeDefined();
      expect(typeof middleware).toBe('function');
    });

    it('should handle createRouter without auth provider', () => {
      transport = new HttpTransport({ port: 0 });
      
      const router = transport.createRouter(true); // requireAuth = true but no auth provider
      expect(router).toBeDefined();
    });

    it('should handle getPort when server is not listening', () => {
      transport = new HttpTransport({ port: 0 });
      
      const port = transport.getPort();
      expect(port).toBeUndefined();
    });

    it('should handle getPort with invalid address', async () => {
      transport = new HttpTransport({ port: 0 });
      await transport.start(server);
      
      // Mock server address to return non-object
      const mockServer = (transport as any).server;
      if (mockServer) {
        vi.spyOn(mockServer, 'address').mockReturnValue('invalid-address');
      }
      
      const port = transport.getPort();
      expect(port).toBeUndefined();
    });

    it('should handle helmet disabled', async () => {
      const config: HttpConfig = {
        port: 0,
        helmetOptions: false
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      expect(transport.getApp()).toBeDefined();
    });

    it('should handle no cors configuration', async () => {
      const config: HttpConfig = {
        port: 0
        // No CORS configuration
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      expect(transport.getApp()).toBeDefined();
    });

    it('should handle empty transport list on stop', async () => {
      transport = new HttpTransport({ port: 0 });
      await transport.start(server);
      
      // Clear transports manually
      (transport as any).transports = new Map();
      
      // Should not throw
      await expect(transport.stop()).resolves.not.toThrow();
    });

    it('should handle stop without server', async () => {
      transport = new HttpTransport({ port: 0 });
      await transport.start(server);
      
      // Clear server manually
      (transport as any).server = null;
      
      // Should not throw
      await expect(transport.stop()).resolves.not.toThrow();
    });

    it('should handle stop without rate limit middleware', async () => {
      transport = new HttpTransport({ port: 0 });
      await transport.start(server);
      
      // Clear rate limit middleware manually
      (transport as any).rateLimitMiddleware = null;
      
      // Should not throw
      await expect(transport.stop()).resolves.not.toThrow();
    });

    it('should handle trust proxy configuration', async () => {
      const config: HttpConfig = {
        port: 0,
        trustProxy: true
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      const app = transport.getApp()!;
      expect(app.get('trust proxy')).toBe(1);
    });

    it('should return JSON error responses for GET without session', async () => {
      transport = new HttpTransport({ port: 0 });
      await transport.start(server);

      const app = transport.getApp()!;

      // Simulate GET request without session header
      const { default: supertest } = await import('supertest');
      const response = await supertest(app)
        .get('/mcp')
        .set('Accept', 'application/json');

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Invalid or missing session ID');
    });

    it('should return JSON error responses for DELETE without session', async () => {
      transport = new HttpTransport({ port: 0 });
      await transport.start(server);

      const app = transport.getApp()!;

      const { default: supertest } = await import('supertest');
      const response = await supertest(app)
        .delete('/mcp')
        .set('Accept', 'application/json');

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error');
      expect(response.body.error).toBe('Invalid or missing session ID');
    });

    it('should accept deprecated sessionConfig without errors', async () => {
      const config: HttpConfig = {
        port: 0,
        sessionConfig: {
          secret: 'test-secret',
          maxAge: 3600000,
        }
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      // sessionConfig is accepted but not used (deprecated)
      expect((transport as any).config.sessionConfig).toBeDefined();
    });
  });

  describe('DELETE handler transport cleanup', () => {
    it('should close transport when DELETE handler throws', async () => {
      transport = new HttpTransport({ port: 0 });
      await transport.start(server);

      const app = transport.getApp()!;
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      // Manually add a mock transport that throws on handleRequest
      const mockClose = vi.fn().mockResolvedValue(undefined);
      const failingTransport = {
        sessionId: 'fail-session',
        handleRequest: vi.fn().mockRejectedValue(new Error('DELETE failed')),
        close: mockClose,
        onclose: null,
      };
      (transport as any).transports.set('fail-session', failingTransport);

      const { default: supertest } = await import('supertest');
      const response = await supertest(app)
        .delete('/mcp')
        .set('mcp-session-id', 'fail-session')
        .set('Accept', 'application/json');

      expect(response.status).toBe(500);
      // Transport should be removed from the map
      expect((transport as any).transports.has('fail-session')).toBe(false);
      // Transport close should be called to release resources
      expect(mockClose).toHaveBeenCalled();

      consoleSpy.mockRestore();
    });

    it('should handle transport close failure in DELETE gracefully', async () => {
      transport = new HttpTransport({ port: 0 });
      await transport.start(server);

      const app = transport.getApp()!;
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      // Transport that throws on both handleRequest and close
      const failingTransport = {
        sessionId: 'double-fail',
        handleRequest: vi.fn().mockRejectedValue(new Error('DELETE failed')),
        close: vi.fn().mockRejectedValue(new Error('Close also failed')),
        onclose: null,
      };
      (transport as any).transports.set('double-fail', failingTransport);

      const { default: supertest } = await import('supertest');
      const response = await supertest(app)
        .delete('/mcp')
        .set('mcp-session-id', 'double-fail')
        .set('Accept', 'application/json');

      // Should still return error response, not crash
      expect(response.status).toBe(500);
      expect((transport as any).transports.has('double-fail')).toBe(false);

      consoleSpy.mockRestore();
    });
  });
});