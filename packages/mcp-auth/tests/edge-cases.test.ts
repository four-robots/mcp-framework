import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  extractBearerToken,
  BearerTokenAuth,
  createAuthMiddleware,
  User,
  NoAuth,
} from '../src/index.js';
import { Request, Response } from 'express';

describe('Auth Edge Cases', () => {
  let mockRequest: Request;

  beforeEach(() => {
    mockRequest = {
      headers: {},
      protocol: 'https',
      get: vi.fn((name: string) => {
        if (name === 'host') return 'example.com';
        return (mockRequest.headers as any)[name.toLowerCase()];
      }),
    } as any;
  });

  describe('extractBearerToken Edge Cases', () => {
    it('should handle case-insensitive bearer prefix', () => {
      mockRequest.headers.authorization = 'BEARER mytoken';
      expect(extractBearerToken(mockRequest)).toBe('mytoken');
    });

    it('should handle mixed case bearer prefix', () => {
      mockRequest.headers.authorization = 'BeArEr mytoken';
      expect(extractBearerToken(mockRequest)).toBe('mytoken');
    });

    it('should trim whitespace from token', () => {
      mockRequest.headers.authorization = 'Bearer   mytoken   ';
      expect(extractBearerToken(mockRequest)).toBe('mytoken');
    });

    it('should return empty string for bearer with only spaces', () => {
      mockRequest.headers.authorization = 'Bearer    ';
      expect(extractBearerToken(mockRequest)).toBe('');
    });

    it('should return null for undefined authorization', () => {
      delete mockRequest.headers.authorization;
      expect(extractBearerToken(mockRequest)).toBeNull();
    });

    it('should return null for empty authorization header', () => {
      mockRequest.headers.authorization = '';
      expect(extractBearerToken(mockRequest)).toBeNull();
    });

    it('should handle bearer token with special characters', () => {
      const token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature';
      mockRequest.headers.authorization = `Bearer ${token}`;
      expect(extractBearerToken(mockRequest)).toBe(token);
    });

    it('should handle token with equals signs (base64 padding)', () => {
      const token = 'abc123def456==';
      mockRequest.headers.authorization = `Bearer ${token}`;
      expect(extractBearerToken(mockRequest)).toBe(token);
    });
  });

  describe('BearerTokenAuth Edge Cases', () => {
    class TestBearerAuth extends BearerTokenAuth {
      async verifyToken(token: string, expectedAudience?: string): Promise<User | null> {
        if (token === 'valid') {
          return { id: '1', username: 'user', email: 'u@e.com', groups: [] };
        }
        return null;
      }
    }

    it('should extract audience from request', async () => {
      const auth = new TestBearerAuth();
      const spy = vi.spyOn(auth, 'verifyToken');
      mockRequest.headers.authorization = 'Bearer valid';

      await auth.authenticate(mockRequest);

      expect(spy).toHaveBeenCalledWith('valid', 'https://example.com');
    });

    it('should handle http protocol for audience', async () => {
      const auth = new TestBearerAuth();
      const spy = vi.spyOn(auth, 'verifyToken');
      mockRequest.protocol = 'http';
      (mockRequest.get as any).mockImplementation((name: string) => {
        if (name === 'host') return 'localhost:3000';
        return undefined;
      });
      mockRequest.headers.authorization = 'Bearer valid';

      await auth.authenticate(mockRequest);

      expect(spy).toHaveBeenCalledWith('valid', 'http://localhost:3000');
    });

    it('should return null from getUser (sync)', () => {
      const auth = new TestBearerAuth();
      mockRequest.headers.authorization = 'Bearer valid';
      expect(auth.getUser(mockRequest)).toBeNull();
    });

    it('should handle BEARER uppercase prefix', async () => {
      const auth = new TestBearerAuth();
      mockRequest.headers.authorization = 'BEARER valid';

      const user = await auth.authenticate(mockRequest);
      expect(user).toBeDefined();
      expect(user?.id).toBe('1');
    });

    it('should reject token with wrong scheme', async () => {
      const auth = new TestBearerAuth();
      mockRequest.headers.authorization = 'Token valid';

      const user = await auth.authenticate(mockRequest);
      expect(user).toBeNull();
    });

    it('should reject Digest auth scheme', async () => {
      const auth = new TestBearerAuth();
      mockRequest.headers.authorization = 'Digest username="admin"';

      const user = await auth.authenticate(mockRequest);
      expect(user).toBeNull();
    });
  });

  describe('NoAuth Provider', () => {
    it('should always authenticate successfully', async () => {
      const auth = new NoAuth();
      const user = await auth.authenticate(mockRequest);
      expect(user).toBeDefined();
    });

    it('should return a user from getUser', () => {
      const auth = new NoAuth();
      const user = auth.getUser(mockRequest);
      expect(user).toBeDefined();
    });
  });

  describe('createAuthMiddleware Edge Cases', () => {
    let mockResponse: Response;
    let mockNext: any;

    beforeEach(() => {
      mockResponse = {
        set: vi.fn(),
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      } as any;
      mockNext = vi.fn();
    });

    it('should set user on request when authenticated', async () => {
      const mockUser: User = { id: '1', username: 'u', email: 'e@e.com', groups: [] };
      const provider = { authenticate: vi.fn().mockResolvedValue(mockUser), getUser: vi.fn() } as any;

      const middleware = createAuthMiddleware(provider);
      await middleware(mockRequest, mockResponse, mockNext);

      expect((mockRequest as any).user).toEqual(mockUser);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should set WWW-Authenticate header on 401', async () => {
      const provider = { authenticate: vi.fn().mockResolvedValue(null), getUser: vi.fn() } as any;

      const middleware = createAuthMiddleware(provider);
      await middleware(mockRequest, mockResponse, mockNext);

      expect(mockResponse.set).toHaveBeenCalledWith('WWW-Authenticate', 'Bearer');
      expect(mockResponse.status).toHaveBeenCalledWith(401);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 500 with error description on exception', async () => {
      const provider = {
        authenticate: vi.fn().mockRejectedValue(new Error('DB down')),
        getUser: vi.fn(),
      } as any;

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const middleware = createAuthMiddleware(provider);
      await middleware(mockRequest, mockResponse, mockNext);

      expect(mockResponse.status).toHaveBeenCalledWith(500);
      expect(mockResponse.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'server_error',
          error_description: expect.any(String),
        })
      );
      expect(mockNext).not.toHaveBeenCalled();
      consoleSpy.mockRestore();
    });
  });
});
