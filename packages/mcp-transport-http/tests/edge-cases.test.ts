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

    it('should handle custom session config', async () => {
      const config: HttpConfig = {
        port: 0,
        sessionConfig: {
          secret: 'test-secret',
          maxAge: 3600000,
          secure: true,
          sameSite: 'strict'
        }
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      expect((transport as any).config.sessionConfig).toEqual({
        secret: 'test-secret',
        maxAge: 3600000,
        secure: true,
        sameSite: 'strict'
      });
    });
  });
});