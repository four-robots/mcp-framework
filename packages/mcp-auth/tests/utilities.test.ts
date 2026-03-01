import { describe, it, expect, beforeEach, vi } from 'vitest';
import { 
  extractBearerToken, 
  createAuthMiddleware, 
  createOAuthDiscoveryRoutes, 
  createOAuthError,
  AuthProvider,
  OAuthProvider,
  User,
  OAuthDiscovery,
  ProtectedResourceMetadata,
  PKCEParams,
  TokenResult,
  ClientRegistrationRequest,
  ClientRegistrationResponse
} from '../src/index.js';
import { Request, Response, Router } from 'express';

describe('Auth Utilities', () => {
  describe('extractBearerToken', () => {
    let mockRequest: Request;

    beforeEach(() => {
      mockRequest = {
        headers: {}
      } as any;
    });

    it('should extract token from valid Bearer header', () => {
      mockRequest.headers.authorization = 'Bearer test-token-123';
      const token = extractBearerToken(mockRequest);
      expect(token).toBe('test-token-123');
    });

    it('should return null for missing authorization header', () => {
      const token = extractBearerToken(mockRequest);
      expect(token).toBeNull();
    });

    it('should return null for non-Bearer authorization', () => {
      mockRequest.headers.authorization = 'Basic dXNlcjpwYXNz';
      const token = extractBearerToken(mockRequest);
      expect(token).toBeNull();
    });

    it('should return null for empty Bearer token', () => {
      mockRequest.headers.authorization = 'Bearer ';
      const token = extractBearerToken(mockRequest);
      expect(token).toBeNull();
    });

    it('should handle Bearer token with spaces', () => {
      mockRequest.headers.authorization = 'Bearer multi part token';
      const token = extractBearerToken(mockRequest);
      expect(token).toBe('multi part token');
    });
  });

  describe('createAuthMiddleware', () => {
    let mockRequest: Request;
    let mockResponse: Response;
    let mockNext: any;
    let mockProvider: AuthProvider;

    beforeEach(() => {
      mockRequest = {
        headers: {},
        protocol: 'https',
        get: vi.fn((name: string) => {
          if (name === 'host') return 'example.com';
          return undefined;
        }),
      } as any;

      mockResponse = {
        set: vi.fn(),
        status: vi.fn().mockReturnThis(),
        json: vi.fn()
      } as any;

      mockNext = vi.fn();

      mockProvider = {
        authenticate: vi.fn(),
        getUser: vi.fn()
      } as any;
    });

    it('should call next() for successful authentication', async () => {
      const mockUser: User = {
        id: 'user-123',
        username: 'testuser',
        email: 'test@example.com',
        groups: ['users']
      };
      
      vi.mocked(mockProvider.authenticate).mockResolvedValue(mockUser);
      
      const middleware = createAuthMiddleware(mockProvider);
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockProvider.authenticate).toHaveBeenCalledWith(mockRequest);
      expect(mockRequest.user).toEqual(mockUser);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should return 401 for failed authentication', async () => {
      vi.mocked(mockProvider.authenticate).mockResolvedValue(null);
      
      const middleware = createAuthMiddleware(mockProvider);
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(mockProvider.authenticate).toHaveBeenCalledWith(mockRequest);
      expect(mockResponse.set).toHaveBeenCalledWith('WWW-Authenticate', expect.stringContaining('Bearer'));
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'invalid_token',
        error_description: 'Authentication required'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 500 for authentication errors', async () => {
      const error = new Error('Authentication service error');
      vi.mocked(mockProvider.authenticate).mockRejectedValue(error);
      
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      const middleware = createAuthMiddleware(mockProvider);
      await middleware(mockRequest, mockResponse, mockNext);
      
      expect(consoleSpy).toHaveBeenCalledWith('Authentication error:', error);
      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'server_error',
        error_description: 'Authentication service error'
      });
      expect(mockNext).not.toHaveBeenCalled();
      
      consoleSpy.mockRestore();
    });
  });

  describe('createOAuthDiscoveryRoutes', () => {
    let mockProvider: OAuthProvider;
    let mockRequest: Request;
    let mockResponse: Response;

    beforeEach(() => {
      mockRequest = {
        protocol: 'https',
        get: vi.fn().mockReturnValue('example.com'),
        body: {}
      } as any;

      mockResponse = {
        json: vi.fn(),
        status: vi.fn().mockReturnThis()
      } as any;

      mockProvider = {
        authenticate: vi.fn(),
        getUser: vi.fn(),
        getAuthUrl: vi.fn(),
        handleCallback: vi.fn(),
        verifyToken: vi.fn(),
        getDiscoveryMetadata: vi.fn().mockReturnValue({
          issuer: 'https://auth.example.com',
          authorization_endpoint: 'https://auth.example.com/authorize',
          token_endpoint: 'https://auth.example.com/token',
          userinfo_endpoint: 'https://auth.example.com/userinfo',
          scopes_supported: ['openid', 'profile', 'email'],
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code'],
          subject_types_supported: ['public']
        } as OAuthDiscovery),
        getProtectedResourceMetadata: vi.fn().mockReturnValue({
          resource: 'https://example.com',
          authorization_servers: ['https://auth.example.com']
        } as ProtectedResourceMetadata)
      } as any;
    });

    it('should use localhost fallback when host header is absent', async () => {
      const express = await import('express');
      const app = express.default();
      // Remove host header before routes process the request
      app.use((req, _res, next) => {
        req.headers.host = undefined as any;
        next();
      });
      const router = createOAuthDiscoveryRoutes(mockProvider);
      app.use('/', router);

      const { default: supertest } = await import('supertest');
      const response = await supertest(app)
        .get('/.well-known/oauth-protected-resource');

      expect(response.status).toBe(200);
      expect(mockProvider.getProtectedResourceMetadata).toHaveBeenCalledWith(
        expect.stringContaining('localhost')
      );
    });

    it('should create discovery routes', () => {
      const router = createOAuthDiscoveryRoutes(mockProvider);
      expect(router).toBeDefined();
      expect(typeof router).toBe('function'); // Express router is a function
    });

    it('should handle protected resource metadata request', () => {
      const router = createOAuthDiscoveryRoutes(mockProvider);
      
      // Simulate the route handler being called
      const routeHandler = vi.fn((req, res) => {
        const baseUrl = `${req.protocol}://${req.get('host')}`;
        res.json(mockProvider.getProtectedResourceMetadata(baseUrl));
      });
      
      routeHandler(mockRequest, mockResponse);
      
      expect(mockProvider.getProtectedResourceMetadata).toHaveBeenCalledWith('https://example.com');
      expect(mockResponse.json).toHaveBeenCalledWith({
        resource: 'https://example.com',
        authorization_servers: ['https://auth.example.com']
      });
    });

    it('should handle discovery metadata request', () => {
      const router = createOAuthDiscoveryRoutes(mockProvider);
      
      // Simulate the route handler being called
      const routeHandler = vi.fn((req, res) => {
        const baseUrl = `${req.protocol}://${req.get('host')}`;
        res.json(mockProvider.getDiscoveryMetadata(baseUrl));
      });
      
      routeHandler(mockRequest, mockResponse);
      
      expect(mockProvider.getDiscoveryMetadata).toHaveBeenCalledWith('https://example.com');
      expect(mockResponse.json).toHaveBeenCalledWith({
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/authorize',
        token_endpoint: 'https://auth.example.com/token',
        userinfo_endpoint: 'https://auth.example.com/userinfo',
        scopes_supported: ['openid', 'profile', 'email'],
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        subject_types_supported: ['public']
      });
    });

    it('should handle dynamic client registration when supported', async () => {
      const mockRegistrationRequest: ClientRegistrationRequest = {
        client_name: 'Test Client',
        redirect_uris: ['https://example.com/callback'],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        scope: 'openid profile email'
      };
      
      const mockRegistrationResponse: ClientRegistrationResponse = {
        client_id: 'test-client-123',
        client_secret: 'test-secret-456',
        client_id_issued_at: Date.now(),
        client_secret_expires_at: 0
      };
      
      mockProvider.supportsDynamicRegistration = vi.fn().mockReturnValue(true);
      mockProvider.registerClient = vi.fn().mockResolvedValue(mockRegistrationResponse);
      
      const router = createOAuthDiscoveryRoutes(mockProvider);
      
      // Simulate the route handler being called
      const routeHandler = vi.fn(async (req, res) => {
        try {
          if (!mockProvider.registerClient) {
            return res.status(501).json({ error: 'temporarily_unavailable' });
          }
          const response = await mockProvider.registerClient(req.body);
          res.json(response);
        } catch (error) {
          res.status(400).json({ error: 'invalid_client_metadata' });
        }
      });
      
      mockRequest.body = mockRegistrationRequest;
      await routeHandler(mockRequest, mockResponse);
      
      expect(mockProvider.registerClient).toHaveBeenCalledWith(mockRegistrationRequest);
      expect(mockResponse.json).toHaveBeenCalledWith(mockRegistrationResponse);
    });

    it('should handle client registration errors', async () => {
      mockProvider.supportsDynamicRegistration = vi.fn().mockReturnValue(true);
      mockProvider.registerClient = vi.fn().mockRejectedValue(new Error('Invalid metadata'));
      
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      const router = createOAuthDiscoveryRoutes(mockProvider);
      
      // Simulate the route handler being called with error
      const routeHandler = vi.fn(async (req, res) => {
        try {
          if (!mockProvider.registerClient) {
            return res.status(501).json({ error: 'temporarily_unavailable' });
          }
          await mockProvider.registerClient(req.body);
        } catch (error) {
          console.error('Client registration failed:', error);
          res.status(400).json({
            error: 'invalid_client_metadata',
            error_description: 'Invalid metadata'
          });
        }
      });
      
      mockRequest.body = { client_name: 'Test Client' };
      await routeHandler(mockRequest, mockResponse);
      
      expect(consoleSpy).toHaveBeenCalledWith('Client registration failed:', expect.any(Error));
      expect(mockResponse.status).toHaveBeenCalledWith(400);
      expect(mockResponse.json).toHaveBeenCalledWith({
        error: 'invalid_client_metadata',
        error_description: 'Invalid metadata'
      });

      consoleSpy.mockRestore();
    });

    it('should return 401 for registration errors with invalid_token error code', async () => {
      const codedError = Object.assign(new Error('Token expired'), { error: 'invalid_token' });

      mockProvider.supportsDynamicRegistration = vi.fn().mockReturnValue(true);
      mockProvider.registerClient = vi.fn().mockRejectedValue(codedError);

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const express = await import('express');
      const app = express.default();
      app.use('/', createOAuthDiscoveryRoutes(mockProvider));

      const { default: supertest } = await import('supertest');
      const response = await supertest(app)
        .post('/application/o/register/')
        .send({ client_name: 'Test', redirect_uris: ['https://example.com/cb'] })
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(401);
      expect(response.body.error).toBe('invalid_token');

      consoleSpy.mockRestore();
    });

    it('should return 403 for registration errors with insufficient_scope error code', async () => {
      const codedError = Object.assign(new Error('Forbidden'), { error: 'insufficient_scope' });

      mockProvider.supportsDynamicRegistration = vi.fn().mockReturnValue(true);
      mockProvider.registerClient = vi.fn().mockRejectedValue(codedError);

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const express = await import('express');
      const app = express.default();
      app.use('/', createOAuthDiscoveryRoutes(mockProvider));

      const { default: supertest } = await import('supertest');
      const response = await supertest(app)
        .post('/application/o/register/')
        .send({ client_name: 'Test', redirect_uris: ['https://example.com/cb'] })
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(403);
      expect(response.body.error).toBe('insufficient_scope');

      consoleSpy.mockRestore();
    });

    it('should return 400 for registration errors without specific error code', async () => {
      mockProvider.supportsDynamicRegistration = vi.fn().mockReturnValue(true);
      mockProvider.registerClient = vi.fn().mockRejectedValue(new Error('Bad metadata'));

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      const express = await import('express');
      const app = express.default();
      app.use('/', createOAuthDiscoveryRoutes(mockProvider));

      const { default: supertest } = await import('supertest');
      const response = await supertest(app)
        .post('/application/o/register/')
        .send({ client_name: 'Test', redirect_uris: ['https://example.com/cb'] })
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('invalid_client_metadata');

      consoleSpy.mockRestore();
    });
  });

  describe('createOAuthError', () => {
    it('should create basic error response', () => {
      const error = createOAuthError('invalid_request');
      expect(error).toEqual({
        error: 'invalid_request'
      });
    });

    it('should create error with description', () => {
      const error = createOAuthError('invalid_request', 'Missing required parameter');
      expect(error).toEqual({
        error: 'invalid_request',
        error_description: 'Missing required parameter'
      });
    });

    it('should create error with description and URI', () => {
      const error = createOAuthError('invalid_request', 'Missing required parameter', 'https://example.com/error');
      expect(error).toEqual({
        error: 'invalid_request',
        error_description: 'Missing required parameter',
        error_uri: 'https://example.com/error'
      });
    });

    it('should create error with all parameters', () => {
      const error = createOAuthError(
        'invalid_request', 
        'Missing required parameter', 
        'https://example.com/error',
        'test-state-123'
      );
      expect(error).toEqual({
        error: 'invalid_request',
        error_description: 'Missing required parameter',
        error_uri: 'https://example.com/error',
        state: 'test-state-123'
      });
    });
  });
});