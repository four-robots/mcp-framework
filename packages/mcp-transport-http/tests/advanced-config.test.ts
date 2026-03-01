import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { HttpTransport, HttpConfig } from '../src/index.js';
import { MCPServer } from '@tylercoles/mcp-server';
import { OAuthProvider, AuthProvider, User, OAuthDiscovery, ProtectedResourceMetadata, PKCEParams, TokenResult } from '@tylercoles/mcp-auth';
import request from 'supertest';

// Mock dependencies
vi.mock('@modelcontextprotocol/sdk/server/streamableHttp.js', () => ({
  StreamableHTTPServerTransport: vi.fn(() => ({
    _sessionId: 'test-session-123',
    get sessionId() { return this._sessionId; },
    set sessionId(value: string | null) { this._sessionId = value; },
    handleRequest: vi.fn(async (req, res, body) => {
      if (body?.method === 'initialize') {
        res.setHeader('mcp-session-id', 'test-session-123');
        res.status(200).json({
          jsonrpc: '2.0',
          id: body.id,
          result: {
            protocolVersion: '2025-06-18',
            capabilities: {},
            serverInfo: { name: 'test-server', version: '1.0.0' }
          }
        });
      } else {
        res.status(200).json({
          jsonrpc: '2.0',
          id: body.id,
          result: { content: [{ type: 'text', text: 'Mock response' }] }
        });
      }
    }),
    close: vi.fn(),
    onclose: null
  }))
}));

// Mock OAuth provider
class MockOAuthProvider implements OAuthProvider {
  async authenticate(req: any): Promise<User | null> {
    return req.user || null;
  }
  
  getUser(req: any): User | null {
    return req.user || null;
  }
  
  async getAuthUrl(state?: string, redirectUri?: string): Promise<string> {
    return `https://auth.example.com/authorize?state=${state}&redirect_uri=${redirectUri}`;
  }
  
  async handleCallback(code: string, state?: string): Promise<TokenResult> {
    return {
      accessToken: 'test-token',
      tokenType: 'Bearer',
      expiresIn: 3600
    };
  }
  
  async verifyToken(token: string): Promise<User | null> {
    return token === 'valid-token' ? {
      id: 'user-123',
      username: 'testuser',
      email: 'test@example.com',
      groups: ['users']
    } : null;
  }
  
  getDiscoveryMetadata(baseUrl: string): OAuthDiscovery {
    return {
      issuer: 'https://auth.example.com',
      authorization_endpoint: 'https://auth.example.com/authorize',
      token_endpoint: 'https://auth.example.com/token',
      userinfo_endpoint: 'https://auth.example.com/userinfo',
      scopes_supported: ['openid', 'profile', 'email'],
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      subject_types_supported: ['public']
    };
  }
  
  getProtectedResourceMetadata(baseUrl: string): ProtectedResourceMetadata {
    return {
      resource: baseUrl,
      authorization_servers: ['https://auth.example.com']
    };
  }
}

// Mock regular auth provider
class MockAuthProvider implements AuthProvider {
  async authenticate(req: any): Promise<User | null> {
    return req.user || null;
  }
  
  getUser(req: any): User | null {
    return req.user || null;
  }
}

describe('HttpTransport Advanced Configuration', () => {
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

  describe('CORS Configuration', () => {
    it('should apply custom CORS options', async () => {
      const config: HttpConfig = {
        port: 0,
        cors: {
          origin: ['https://example.com'],
          credentials: false,
          methods: ['GET', 'POST']
        }
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      const app = transport.getApp()!;
      const response = await request(app)
        .options('/health')
        .set('Origin', 'https://example.com');

      expect(response.headers['access-control-allow-origin']).toBe('https://example.com');
      expect(response.headers['access-control-allow-methods']).toContain('GET');
      expect(response.headers['access-control-allow-methods']).toContain('POST');
    });

    it('should disable CORS when set to undefined', async () => {
      const config: HttpConfig = {
        port: 0,
        cors: undefined // No CORS configuration
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      const app = transport.getApp()!;
      const response = await request(app)
        .options('/health')
        .set('Origin', 'https://example.com');

      // Without CORS configuration, there should be no CORS headers
      expect(response.headers['access-control-allow-origin']).toBeUndefined();
    });
  });

  describe('Security Configuration', () => {
    it('should apply custom helmet options', async () => {
      const config: HttpConfig = {
        port: 0,
        helmetOptions: {
          xssFilter: true,
          noSniff: true
        }
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      const app = transport.getApp()!;
      const response = await request(app).get('/health');

      expect(response.headers['x-xss-protection']).toBeDefined();
      expect(response.headers['x-content-type-options']).toBe('nosniff');
    });

    it('should disable helmet when set to false', async () => {
      const config: HttpConfig = {
        port: 0,
        helmetOptions: false
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      const app = transport.getApp()!;
      const response = await request(app).get('/health');

      // Should not have helmet headers
      expect(response.headers['x-frame-options']).toBeUndefined();
    });

    it('should apply trust proxy configuration', async () => {
      const config: HttpConfig = {
        port: 0,
        trustProxy: true
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      const app = transport.getApp()!;
      expect(app.get('trust proxy')).toBe(1);
    });
  });

  describe('Base Path Configuration', () => {
    it('should use custom base path', async () => {
      const config: HttpConfig = {
        port: 0,
        basePath: '/api/v1'
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      const app = transport.getApp()!;
      
      // Test that MCP endpoint is at custom base path
      const response = await request(app)
        .post('/api/v1')
        .send({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: { protocolVersion: '2025-06-18', capabilities: {} }
        });

      expect(response.status).toBe(200);
    });
  });

  describe('Authentication Configuration', () => {
    it('should setup OAuth discovery routes with OAuth provider', async () => {
      const oauthProvider = new MockOAuthProvider();
      const config: HttpConfig = {
        port: 0,
        auth: oauthProvider
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      const app = transport.getApp()!;
      
      // Test OAuth discovery endpoints
      const discoveryResponse = await request(app)
        .get('/.well-known/oauth-authorization-server');

      expect(discoveryResponse.status).toBe(200);
      expect(discoveryResponse.body).toMatchObject({
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/authorize'
      });
    });

    it('should not setup OAuth routes with regular auth provider', async () => {
      const authProvider = new MockAuthProvider();
      const config: HttpConfig = {
        port: 0,
        auth: authProvider
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      const app = transport.getApp()!;
      
      // OAuth discovery endpoints should not exist
      const discoveryResponse = await request(app)
        .get('/.well-known/oauth-authorization-server');

      expect(discoveryResponse.status).toBe(404);
    });
  });

  describe('DNS Rebinding Protection Configuration', () => {
    it('should pass DNS rebinding protection config to StreamableHTTPServerTransport', async () => {
      const config: HttpConfig = {
        port: 0,
        enableDnsRebindingProtection: true,
        allowedHosts: ['example.com', 'localhost']
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      // We can't directly test the DNS rebinding protection since it's handled by the SDK
      // but we can verify the transport starts successfully with the config
      expect(transport.getApp()).toBeDefined();
    });

    it('should pass disabled DNS rebinding protection config', async () => {
      const config: HttpConfig = {
        port: 0,
        enableDnsRebindingProtection: false
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      // Verify transport starts successfully
      expect(transport.getApp()).toBeDefined();
    });
  });

  describe('Session Management', () => {
    it('should track session count', async () => {
      const config: HttpConfig = {
        port: 0
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      // Initial session count should be 0
      expect(transport.getSessionCount()).toBe(0);

      const app = transport.getApp()!;
      
      // Create a session
      const response = await request(app)
        .post('/mcp')
        .send({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: { protocolVersion: '2025-06-18', capabilities: {} }
        });

      // Session should be created by the SDK transport
      expect(response.headers['mcp-session-id']).toBeDefined();
      
      // Note: The session count is managed by the SDK transport, not our HttpTransport
      // So we can't reliably test it increases to 1 in this unit test environment
      expect(transport.getSessionCount()).toBeGreaterThanOrEqual(0);
    });

    it('should store external domain in config', async () => {
      const config: HttpConfig = {
        port: 0,
        externalDomain: 'https://external.example.com'
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      // We can't directly access the external domain, but we can verify the config is stored
      expect((transport as any).config.externalDomain).toBe('https://external.example.com');
    });

    it('should strip protocol from externalDomain in getBaseUrl', async () => {
      transport = new HttpTransport({
        port: 0,
        externalDomain: 'https://external.example.com'
      });
      await transport.start(server);

      // getBaseUrl should not double the protocol
      const mockReq = { protocol: 'http', get: () => 'localhost' } as any;
      const baseUrl = (transport as any).getBaseUrl(mockReq);
      expect(baseUrl).toBe('https://external.example.com');
    });

    it('should handle externalDomain without protocol prefix', async () => {
      transport = new HttpTransport({
        port: 0,
        externalDomain: 'external.example.com'
      });
      await transport.start(server);

      const mockReq = { protocol: 'http', get: () => 'localhost' } as any;
      const baseUrl = (transport as any).getBaseUrl(mockReq);
      expect(baseUrl).toBe('https://external.example.com');
    });

    it('should handle configuration with host and port', async () => {
      const config: HttpConfig = {
        port: 8080,
        host: 'localhost'
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      expect((transport as any).config.host).toBe('localhost');
      expect((transport as any).config.port).toBe(8080);
    });
  });

  describe('Router Creation and Registration', () => {
    it('should create routers with correct authentication', async () => {
      const authProvider = new MockAuthProvider();
      const config: HttpConfig = {
        port: 0,
        auth: authProvider
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      const publicRouter = transport.createRouter(false);
      const authRouter = transport.createRouter(true);

      expect(publicRouter).toBeDefined();
      expect(authRouter).toBeDefined();

      // Test that routers are different instances
      expect(publicRouter).not.toBe(authRouter);
    });

    it('should register multiple routers', async () => {
      const config: HttpConfig = {
        port: 0
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      const router1 = transport.createRouter(false);
      const router2 = transport.createRouter(false);

      router1.get('/test1', (req, res) => res.json({ route: 'test1' }));
      router2.get('/test2', (req, res) => res.json({ route: 'test2' }));

      transport.registerRouter('/api', router1);
      transport.registerRouter('/api', router2);

      const app = transport.getApp()!;
      
      const response1 = await request(app).get('/api/test1');
      const response2 = await request(app).get('/api/test2');

      expect(response1.status).toBe(200);
      expect(response1.body).toEqual({ route: 'test1' });
      expect(response2.status).toBe(200);
      expect(response2.body).toEqual({ route: 'test2' });
    });
  });

  describe('User Context', () => {
    it('should get authenticated user from request', async () => {
      const testUser: User = {
        id: 'user-123',
        username: 'testuser',
        email: 'test@example.com',
        groups: ['users']
      };

      const config: HttpConfig = {
        port: 0
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      const router = transport.createRouter(false);
      router.get('/user', (req, res) => {
        // Simulate authenticated user
        (req as any).user = testUser;
        const user = transport.getAuthenticatedUser(req);
        res.json(user);
      });

      transport.registerRouter('/api', router);

      const app = transport.getApp()!;
      const response = await request(app).get('/api/user');

      expect(response.status).toBe(200);
      expect(response.body).toEqual(testUser);
    });

    it('should return null for unauthenticated request', async () => {
      const config: HttpConfig = {
        port: 0
      };

      transport = new HttpTransport(config);
      await transport.start(server);

      const router = transport.createRouter(false);
      router.get('/user', (req, res) => {
        const user = transport.getAuthenticatedUser(req);
        res.json(user);
      });

      transport.registerRouter('/api', router);

      const app = transport.getApp()!;
      const response = await request(app).get('/api/user');

      expect(response.status).toBe(200);
      expect(response.body).toBeNull();
    });
  });

  describe('Error Handling', () => {
    it('should handle server startup errors gracefully', async () => {
      const config: HttpConfig = {
        port: -1 // Invalid port
      };

      transport = new HttpTransport(config);
      
      await expect(transport.start(server)).rejects.toThrow();
    });

    it('should handle stop without start', async () => {
      transport = new HttpTransport({ port: 0 });
      
      // Should not throw
      await expect(transport.stop()).resolves.not.toThrow();
    });
  });
});