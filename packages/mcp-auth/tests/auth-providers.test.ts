import { describe, it, expect, beforeEach, vi } from 'vitest';
import { 
  AuthProvider, 
  NoAuth, 
  DevAuth, 
  BearerTokenAuth, 
  SessionAuth, 
  User 
} from '../src/index.js';
import { Request } from 'express';

describe('Additional Auth Providers', () => {
  let mockRequest: Request;

  beforeEach(() => {
    mockRequest = {
      headers: {},
      session: {},
      user: undefined,
      protocol: 'https',
      get: vi.fn((name: string) => {
        if (name === 'host') return 'example.com';
        return mockRequest.headers[name.toLowerCase()];
      }),
      isAuthenticated: vi.fn(() => false)
    } as any;
  });

  describe('DevAuth', () => {
    it('should create with default mock user', () => {
      const provider = new DevAuth();
      const user = provider.getUser(mockRequest);
      
      expect(user).toBeDefined();
      expect(user?.id).toBe('dev-user-123');
      expect(user?.username).toBe('developer');
      expect(user?.email).toBe('dev@example.com');
      expect(user?.groups).toEqual(['developers']);
    });

    it('should create with custom mock user', () => {
      const customUser = {
        id: 'custom-dev-456',
        username: 'custom-dev',
        email: 'custom@example.com',
        groups: ['custom-group'],
        department: 'engineering'
      };
      
      const provider = new DevAuth(customUser);
      const user = provider.getUser(mockRequest);
      
      expect(user).toBeDefined();
      expect(user?.id).toBe('custom-dev-456');
      expect(user?.username).toBe('custom-dev');
      expect(user?.email).toBe('custom@example.com');
      expect(user?.groups).toEqual(['custom-group']);
      expect(user?.department).toBe('engineering');
    });

    it('should merge custom user with defaults', () => {
      const partialUser = {
        username: 'partial-dev',
        customField: 'custom-value'
      };
      
      const provider = new DevAuth(partialUser);
      const user = provider.getUser(mockRequest);
      
      expect(user).toBeDefined();
      expect(user?.id).toBe('dev-user-123'); // Default
      expect(user?.username).toBe('partial-dev'); // Custom
      expect(user?.email).toBe('dev@example.com'); // Default
      expect(user?.groups).toEqual(['developers']); // Default
      expect(user?.customField).toBe('custom-value'); // Custom
    });

    it('should always authenticate successfully', async () => {
      const provider = new DevAuth();
      const user = await provider.authenticate(mockRequest);
      
      expect(user).toBeDefined();
      expect(user?.id).toBe('dev-user-123');
    });

    it('should return same user for getUser and authenticate', async () => {
      const provider = new DevAuth();
      
      const authUser = await provider.authenticate(mockRequest);
      const getUser = provider.getUser(mockRequest);
      
      expect(authUser).toEqual(getUser);
    });
  });

  describe('BearerTokenAuth', () => {
    class TestBearerTokenAuth extends BearerTokenAuth {
      async verifyToken(token: string, expectedAudience?: string): Promise<User | null> {
        // Mock token verification - return user for 'valid-token'
        if (token === 'valid-token') {
          return {
            id: 'token-user-123',
            username: 'tokenuser',
            email: 'token@example.com',
            groups: ['token-users']
          };
        }
        return null;
      }
    }

    it('should authenticate with valid Bearer token', async () => {
      const provider = new TestBearerTokenAuth();
      mockRequest.headers.authorization = 'Bearer valid-token';
      
      const user = await provider.authenticate(mockRequest);
      expect(user).toBeDefined();
      expect(user?.id).toBe('token-user-123');
    });

    it('should handle missing Authorization header', async () => {
      const provider = new TestBearerTokenAuth();
      
      const user = await provider.authenticate(mockRequest);
      expect(user).toBeNull();
    });

    it('should handle malformed Authorization header', async () => {
      const provider = new TestBearerTokenAuth();
      mockRequest.headers.authorization = 'Invalid header format';
      
      const user = await provider.authenticate(mockRequest);
      expect(user).toBeNull();
    });

    it('should handle non-Bearer authorization', async () => {
      const provider = new TestBearerTokenAuth();
      mockRequest.headers.authorization = 'Basic dXNlcjpwYXNz';
      
      const user = await provider.authenticate(mockRequest);
      expect(user).toBeNull();
    });

    it('should handle empty Bearer token', async () => {
      const provider = new TestBearerTokenAuth();
      mockRequest.headers.authorization = 'Bearer ';
      
      const user = await provider.authenticate(mockRequest);
      expect(user).toBeNull();
    });

    it('should accept case-insensitive Bearer prefix per RFC 7235', async () => {
      const provider = new TestBearerTokenAuth();
      mockRequest.headers.authorization = 'bearer valid-token';

      const user = await provider.authenticate(mockRequest);
      expect(user).not.toBeNull();
      expect(user?.id).toBe('token-user-123');
    });

    it('should extract token and call verifyToken with expected audience', async () => {
      const provider = new TestBearerTokenAuth();
      const spy = vi.spyOn(provider, 'verifyToken');
      
      mockRequest.headers.authorization = 'Bearer test-token';
      await provider.authenticate(mockRequest);
      
      expect(spy).toHaveBeenCalledWith('test-token', 'https://example.com');
    });

    it('should return null from getUser (sync method)', () => {
      const provider = new TestBearerTokenAuth();
      mockRequest.headers.authorization = 'Bearer valid-token';
      
      const user = provider.getUser(mockRequest);
      expect(user).toBeNull();
    });
  });

  describe('SessionAuth', () => {
    class TestSessionAuth extends SessionAuth {
      async authenticate(req: Request): Promise<User | null> {
        // Check isAuthenticated if available
        if (req.isAuthenticated && typeof req.isAuthenticated === 'function') {
          if (!req.isAuthenticated()) {
            return null;
          }
        }
        return this.getUser(req);
      }
    }

    it('should return user from session', () => {
      const mockUser: User = {
        id: 'session-user-123',
        username: 'sessionuser',
        email: 'session@example.com',
        groups: ['session-users']
      };

      const provider = new TestSessionAuth();
      mockRequest.user = mockUser;
      
      const user = provider.getUser(mockRequest);
      expect(user).toEqual(mockUser);
    });

    it('should return null when no user in session', () => {
      const provider = new TestSessionAuth();
      
      const user = provider.getUser(mockRequest);
      expect(user).toBeNull();
    });

    it('should authenticate using session', async () => {
      const mockUser: User = {
        id: 'session-auth-123',
        username: 'sessionauth',
        email: 'auth@example.com',
        groups: ['auth-users']
      };

      const provider = new TestSessionAuth();
      mockRequest.user = mockUser;
      mockRequest.isAuthenticated = vi.fn().mockReturnValue(true);
      
      const user = await provider.authenticate(mockRequest);
      expect(user).toEqual(mockUser);
    });

    it('should return null when authenticating without session user', async () => {
      const provider = new TestSessionAuth();
      
      const user = await provider.authenticate(mockRequest);
      expect(user).toBeNull();
    });

    it('should check isAuthenticated method if available', async () => {
      const mockUser: User = {
        id: 'authenticated-user',
        username: 'authuser',
        email: 'auth@example.com',
        groups: ['users']
      };

      const provider = new TestSessionAuth();
      mockRequest.user = mockUser;
      mockRequest.isAuthenticated = vi.fn().mockReturnValue(true);
      
      const user = await provider.authenticate(mockRequest);
      expect(user).toEqual(mockUser);
      expect(mockRequest.isAuthenticated).toHaveBeenCalled();
    });

    it('should return null when isAuthenticated returns false', async () => {
      const mockUser: User = {
        id: 'unauthenticated-user',
        username: 'unauthuser',
        email: 'unauth@example.com',
        groups: ['users']
      };

      const provider = new TestSessionAuth();
      mockRequest.user = mockUser;
      mockRequest.isAuthenticated = vi.fn().mockReturnValue(false);
      
      const user = await provider.authenticate(mockRequest);
      expect(user).toBeNull();
      expect(mockRequest.isAuthenticated).toHaveBeenCalled();
    });
  });

  describe('AuthProvider Abstract Class', () => {
    class TestAuthProvider extends AuthProvider {
      async authenticate(req: Request): Promise<User | null> {
        return {
          id: 'test-user',
          username: 'testuser',
          email: 'test@example.com',
          groups: ['test']
        };
      }
      
      getUser(req: Request): User | null {
        return req.user || null;
      }
    }

    it('should be extendable', () => {
      const provider = new TestAuthProvider();
      expect(provider).toBeInstanceOf(AuthProvider);
    });

    it('should require authenticate method implementation', async () => {
      const provider = new TestAuthProvider();
      const user = await provider.authenticate(mockRequest);
      
      expect(user).toBeDefined();
      expect(user?.id).toBe('test-user');
    });

    it('should require getUser method implementation', () => {
      const provider = new TestAuthProvider();
      
      mockRequest.user = {
        id: 'stored-user',
        username: 'stored',
        email: 'stored@example.com',
        groups: ['stored']
      };
      
      const user = provider.getUser(mockRequest);
      expect(user).toEqual(mockRequest.user);
    });
  });

  describe('User Interface', () => {
    it('should allow additional properties', () => {
      const user: User = {
        id: 'user-123',
        username: 'testuser',
        email: 'test@example.com',
        groups: ['users'],
        customProperty: 'custom-value',
        department: 'engineering',
        roles: ['admin', 'user']
      };

      expect(user.id).toBe('user-123');
      expect(user.username).toBe('testuser');
      expect(user.email).toBe('test@example.com');
      expect(user.groups).toEqual(['users']);
      expect(user.customProperty).toBe('custom-value');
      expect(user.department).toBe('engineering');
      expect(user.roles).toEqual(['admin', 'user']);
    });

    it('should require basic properties', () => {
      // This test ensures TypeScript compilation requires basic properties
      const user: User = {
        id: 'required-id',
        username: 'required-username',
        email: 'required@example.com',
        groups: ['required-group']
      };

      expect(user.id).toBeDefined();
      expect(user.username).toBeDefined();
      expect(user.email).toBeDefined();
      expect(user.groups).toBeDefined();
    });
  });
});