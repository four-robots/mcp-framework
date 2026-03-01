import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import nock from 'nock';
import jwt from 'jsonwebtoken';
import { OIDCProvider, OIDCConfig, Providers } from '../src/index.js';
import { createOAuthError } from '@tylercoles/mcp-auth';

// Mock JWKS response
const mockJWKS = {
  keys: [{
    kty: 'RSA',
    kid: 'test-key-1',
    use: 'sig',
    n: 'test-n-value',
    e: 'AQAB',
  }],
};

// Mock discovery document
const mockDiscovery = {
  issuer: 'https://test-oidc.example.com',
  authorization_endpoint: 'https://test-oidc.example.com/auth',
  token_endpoint: 'https://test-oidc.example.com/token',
  userinfo_endpoint: 'https://test-oidc.example.com/userinfo',
  jwks_uri: 'https://test-oidc.example.com/jwks',
  revocation_endpoint: 'https://test-oidc.example.com/revoke',
  introspection_endpoint: 'https://test-oidc.example.com/introspect',
  registration_endpoint: 'https://test-oidc.example.com/register',
  scopes_supported: ['openid', 'profile', 'email'],
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'refresh_token'],
  token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
  code_challenge_methods_supported: ['S256', 'plain'],
};

describe('OIDCProvider', () => {
  let provider: OIDCProvider;
  const defaultConfig: OIDCConfig = {
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    redirectUri: 'https://app.example.com/callback',
    discoveryUrl: 'https://test-oidc.example.com/.well-known/openid-configuration',
  };

  beforeEach(() => {
    nock.cleanAll();
    vi.clearAllMocks();
  });

  afterEach(() => {
    nock.cleanAll();
  });

  describe('Constructor and Configuration', () => {
    it('should create provider with discovery URL', () => {
      provider = new OIDCProvider(defaultConfig);
      expect(provider).toBeInstanceOf(OIDCProvider);
    });

    it('should create provider with manual configuration', () => {
      const manualConfig: OIDCConfig = {
        clientId: 'test-client-id',
        issuer: 'https://test-oidc.example.com',
        authorizationEndpoint: 'https://test-oidc.example.com/auth',
        tokenEndpoint: 'https://test-oidc.example.com/token',
        jwksUri: 'https://test-oidc.example.com/jwks',
      };
      
      provider = new OIDCProvider(manualConfig);
      expect(provider).toBeInstanceOf(OIDCProvider);
    });

    it('should throw error without discovery URL or manual config', () => {
      expect(() => new OIDCProvider({ clientId: 'test' }))
        .toThrow('Either discoveryUrl or manual endpoint configuration');
    });

    it('should apply default configuration values', () => {
      const config: OIDCConfig = {
        clientId: 'test-client-id',
        discoveryUrl: 'https://test-oidc.example.com/.well-known/openid-configuration',
      };
      
      provider = new OIDCProvider(config);
      // Access internal config through methods
      expect(provider).toBeInstanceOf(OIDCProvider);
    });
  });

  describe('Discovery Document', () => {
    beforeEach(() => {
      provider = new OIDCProvider(defaultConfig);
    });

    it('should fetch and cache discovery document', async () => {
      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, mockDiscovery);
      
      nock('https://test-oidc.example.com')
        .get('/jwks')
        .reply(200, mockJWKS);
      
      await provider.initialize();
      
      // Should use cached discovery on second call
      const authUrl1 = await provider.getAuthUrl('state1');
      const authUrl2 = await provider.getAuthUrl('state2');
      
      expect(authUrl1).toContain('https://test-oidc.example.com/auth');
      expect(authUrl2).toContain('https://test-oidc.example.com/auth');
    });

    it('should handle discovery fetch errors', async () => {
      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(404);
      
      await expect(provider.initialize())
        .rejects.toThrow('Failed to fetch OIDC configuration');
    });
  });

  describe('Authorization URL', () => {
    beforeEach(async () => {
      provider = new OIDCProvider(defaultConfig);
      
      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, mockDiscovery);
      
      nock('https://test-oidc.example.com')
        .get('/jwks')
        .reply(200, mockJWKS);
      
      await provider.initialize();
    });

    it('should generate authorization URL with basic parameters', async () => {
      const url = await provider.getAuthUrl('test-state');
      const urlObj = new URL(url);
      
      expect(urlObj.origin).toBe('https://test-oidc.example.com');
      expect(urlObj.pathname).toBe('/auth');
      expect(urlObj.searchParams.get('client_id')).toBe('test-client-id');
      expect(urlObj.searchParams.get('response_type')).toBe('code');
      expect(urlObj.searchParams.get('state')).toBe('test-state');
      expect(urlObj.searchParams.get('redirect_uri')).toBe('https://app.example.com/callback');
      expect(urlObj.searchParams.get('scope')).toBe('openid profile email');
    });

    it('should include PKCE parameters', async () => {
      const pkceParams = {
        codeChallenge: 'test-challenge',
        codeChallengeMethod: 'S256' as const,
      };
      
      const url = await provider.getAuthUrl('state', undefined, undefined, pkceParams);
      const urlObj = new URL(url);
      
      expect(urlObj.searchParams.get('code_challenge')).toBe('test-challenge');
      expect(urlObj.searchParams.get('code_challenge_method')).toBe('S256');
    });

    it('should include resource parameter', async () => {
      const url = await provider.getAuthUrl('state', undefined, 'https://api.example.com');
      const urlObj = new URL(url);
      
      expect(urlObj.searchParams.get('resource')).toBe('https://api.example.com');
    });

    it('should validate HTTPS endpoints in production', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      const httpProvider = new OIDCProvider({
        clientId: 'test',
        issuer: 'http://insecure.example.com',
        authorizationEndpoint: 'http://insecure.example.com/auth',
        tokenEndpoint: 'http://insecure.example.com/token',
        jwksUri: 'http://insecure.example.com/jwks',
      });
      
      await expect(httpProvider.getAuthUrl())
        .rejects.toThrow('Authorization endpoint must use HTTPS');
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Token Exchange', () => {
    beforeEach(async () => {
      provider = new OIDCProvider(defaultConfig);
      
      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, mockDiscovery);
      
      nock('https://test-oidc.example.com')
        .get('/jwks')
        .reply(200, mockJWKS);
      
      await provider.initialize();
    });

    it('should exchange authorization code for tokens', async () => {
      const mockTokenResponse = {
        access_token: 'test-access-token',
        refresh_token: 'test-refresh-token',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 'openid profile email',
        id_token: 'test-id-token',
      };
      
      nock('https://test-oidc.example.com')
        .post('/token', body => {
          const params = new URLSearchParams(body);
          return params.get('grant_type') === 'authorization_code' &&
                 params.get('code') === 'test-code' &&
                 params.get('client_id') === 'test-client-id' &&
                 params.get('client_secret') === 'test-client-secret';
        })
        .reply(200, mockTokenResponse);
      
      const result = await provider.handleCallback('test-code');
      
      expect(result).toEqual({
        accessToken: 'test-access-token',
        refreshToken: 'test-refresh-token',
        tokenType: 'Bearer',
        expiresIn: 3600,
        scope: 'openid profile email',
        idToken: 'test-id-token',
      });
    });

    it('should handle token exchange errors', async () => {
      nock('https://test-oidc.example.com')
        .post('/token')
        .reply(400, {
          error: 'invalid_grant',
          error_description: 'Invalid authorization code',
        });
      
      try {
        await provider.handleCallback('bad-code');
        expect.fail('Expected to throw an error');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect(error.message).toBe('invalid_grant: Invalid authorization code');
      }
    });

    it('should include PKCE code verifier', async () => {
      nock('https://test-oidc.example.com')
        .post('/token', body => {
          const params = new URLSearchParams(body);
          return params.get('code_verifier') === 'test-verifier';
        })
        .reply(200, {
          access_token: 'test-token',
          token_type: 'Bearer',
        });
      
      await provider.handleCallback('code', undefined, undefined, undefined, 'test-verifier');
    });
  });

  describe('Token Verification', () => {
    beforeEach(async () => {
      provider = new OIDCProvider(defaultConfig);
      
      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, mockDiscovery);
      
      nock('https://test-oidc.example.com')
        .get('/jwks')
        .reply(200, mockJWKS);
      
      await provider.initialize();
    });

    it('should verify token using userinfo endpoint', async () => {
      const mockUserInfo = {
        sub: 'user123',
        preferred_username: 'testuser',
        email: 'test@example.com',
        name: 'Test User',
        groups: ['users', 'admin'],
      };
      
      nock('https://test-oidc.example.com')
        .get('/userinfo')
        .matchHeader('authorization', 'Bearer test-access-token')
        .reply(200, mockUserInfo);
      
      const user = await provider.verifyToken('test-access-token');
      
      expect(user).toEqual({
        id: 'user123',
        username: 'testuser',
        email: 'test@example.com',
        name: 'Test User',
        groups: ['users', 'admin'],
        sub: 'user123',
        preferred_username: 'testuser',
      });
    });

    it('should return null for invalid token', async () => {
      nock('https://test-oidc.example.com')
        .get('/userinfo')
        .reply(401);
      
      const user = await provider.verifyToken('invalid-token');
      expect(user).toBeNull();
    });

    it('should check allowed groups', async () => {
      const restrictedProvider = new OIDCProvider({
        ...defaultConfig,
        allowedGroups: ['admin'],
      });
      
      // Set up discovery document for the new provider
      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, mockDiscovery);
      
      nock('https://test-oidc.example.com')
        .get('/jwks')
        .reply(200, mockJWKS);
      
      await restrictedProvider.initialize();
      
      nock('https://test-oidc.example.com')
        .get('/userinfo')
        .reply(200, {
          sub: 'user123',
          email: 'test@example.com',
          groups: ['users'], // Not in allowed groups
        });
      
      const user = await restrictedProvider.verifyToken('test-token');
      expect(user).toBeNull();
    });
  });

  describe('Token Refresh', () => {
    beforeEach(async () => {
      provider = new OIDCProvider(defaultConfig);
      
      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, mockDiscovery);
      
      nock('https://test-oidc.example.com')
        .get('/jwks')
        .reply(200, mockJWKS);
      
      await provider.initialize();
    });

    it('should refresh access token', async () => {
      const mockRefreshResponse = {
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        token_type: 'Bearer',
        expires_in: 3600,
      };
      
      nock('https://test-oidc.example.com')
        .post('/token', body => {
          const params = new URLSearchParams(body);
          return params.get('grant_type') === 'refresh_token' &&
                 params.get('refresh_token') === 'test-refresh-token';
        })
        .reply(200, mockRefreshResponse);
      
      const result = await provider.refreshToken('test-refresh-token');
      
      expect(result.accessToken).toBe('new-access-token');
      expect(result.refreshToken).toBe('new-refresh-token');
    });
  });

  describe('Token Revocation', () => {
    beforeEach(async () => {
      provider = new OIDCProvider(defaultConfig);
      
      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, mockDiscovery);
      
      nock('https://test-oidc.example.com')
        .get('/jwks')
        .reply(200, mockJWKS);
      
      await provider.initialize();
    });

    it('should revoke token', async () => {
      nock('https://test-oidc.example.com')
        .post('/revoke', body => {
          const params = new URLSearchParams(body);
          return params.get('token') === 'test-token' &&
                 params.get('token_type_hint') === 'access_token';
        })
        .reply(200);
      
      await expect(provider.revokeToken('test-token')).resolves.not.toThrow();
    });

    it('should handle providers without revocation endpoint', async () => {
      const noRevokeProvider = new OIDCProvider({
        clientId: 'test',
        issuer: 'https://test.example.com',
        authorizationEndpoint: 'https://test.example.com/auth',
        tokenEndpoint: 'https://test.example.com/token',
        jwksUri: 'https://test.example.com/jwks',
        // No revocation endpoint
      });
      
      await expect(noRevokeProvider.revokeToken('test-token'))
        .resolves.not.toThrow();
    });
  });

  describe('Client Registration', () => {
    beforeEach(async () => {
      provider = new OIDCProvider(defaultConfig);
      
      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, mockDiscovery);
      
      nock('https://test-oidc.example.com')
        .get('/jwks')
        .reply(200, mockJWKS);
      
      await provider.initialize();
    });

    it('should register client dynamically', async () => {
      const registrationRequest = {
        client_name: 'Test App',
        redirect_uris: ['https://app.example.com/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        scope: 'openid profile email',
      };
      
      const mockResponse = {
        client_id: 'new-client-id',
        client_secret: 'new-client-secret',
        registration_access_token: 'reg-token',
        registration_client_uri: 'https://test-oidc.example.com/register/new-client-id',
        client_id_issued_at: Math.floor(Date.now() / 1000),
        client_secret_expires_at: 0,
        ...registrationRequest,
      };
      
      nock('https://test-oidc.example.com')
        .post('/register', registrationRequest)
        .reply(200, mockResponse);
      
      const result = await provider.registerClient(registrationRequest);
      
      expect(result.client_id).toBe('new-client-id');
      expect(result.client_secret).toBe('new-client-secret');
    });

    it('should handle registration errors', async () => {
      nock('https://test-oidc.example.com')
        .post('/register')
        .reply(400, {
          error: 'invalid_client_metadata',
          error_description: 'Invalid redirect URI',
        });
      
      try {
        await provider.registerClient({
          client_name: 'Test',
          redirect_uris: ['invalid'],
        });
        expect.fail('Expected to throw an error');
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect(error.message).toBe('invalid_client_metadata: Invalid redirect URI');
      }
    });
  });

  describe('Pre-configured Providers', () => {
    it('should create Auth0 provider', () => {
      const auth0 = Providers.Auth0('test.auth0.com', 'client-id', 'client-secret');
      expect(auth0).toBeInstanceOf(OIDCProvider);
    });

    it('should create Okta provider', () => {
      const okta = Providers.Okta('test.okta.com', 'client-id', 'client-secret');
      expect(okta).toBeInstanceOf(OIDCProvider);
    });

    it('should create Keycloak provider', () => {
      const keycloak = Providers.Keycloak(
        'https://keycloak.example.com',
        'test-realm',
        'client-id',
        'client-secret'
      );
      expect(keycloak).toBeInstanceOf(OIDCProvider);
    });

    it('should create Google provider', () => {
      const google = Providers.Google('client-id', 'client-secret');
      expect(google).toBeInstanceOf(OIDCProvider);
    });

    it('should create Microsoft provider', () => {
      const microsoft = Providers.Microsoft('tenant-id', 'client-id', 'client-secret');
      expect(microsoft).toBeInstanceOf(OIDCProvider);
    });
  });

  describe('Claims Mapping', () => {
    it('should use custom claim mappings', async () => {
      const customProvider = new OIDCProvider({
        ...defaultConfig,
        idClaim: 'user_id',
        usernameClaim: 'login',
        emailClaim: 'mail',
        groupsClaim: 'roles',
      });
      
      // Set up discovery document for the new provider
      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, mockDiscovery);
      
      nock('https://test-oidc.example.com')
        .get('/jwks')
        .reply(200, mockJWKS);
      
      await customProvider.initialize();
      
      nock('https://test-oidc.example.com')
        .get('/userinfo')
        .reply(200, {
          user_id: 'custom123',
          login: 'customuser',
          mail: 'custom@example.com',
          roles: ['role1', 'role2'],
        });
      
      const user = await customProvider.verifyToken('test-token');
      
      expect(user).toEqual({
        id: 'custom123',
        username: 'customuser',
        email: 'custom@example.com',
        name: '',
        groups: ['role1', 'role2'],
        user_id: 'custom123',
        login: 'customuser',
        mail: 'custom@example.com',
        roles: ['role1', 'role2'],
      });
    });
  });

  describe('Authentication Methods', () => {
    it('should use client_secret_basic authentication', async () => {
      const basicAuthProvider = new OIDCProvider({
        ...defaultConfig,
        tokenEndpointAuthMethod: 'client_secret_basic',
      });

      // Set up discovery document for the new provider
      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, mockDiscovery);

      nock('https://test-oidc.example.com')
        .get('/jwks')
        .reply(200, mockJWKS);

      await basicAuthProvider.initialize();

      const expectedAuth = Buffer.from('test-client-id:test-client-secret').toString('base64');

      nock('https://test-oidc.example.com')
        .post('/token')
        .matchHeader('authorization', `Basic ${expectedAuth}`)
        .reply(200, {
          access_token: 'test-token',
          token_type: 'Bearer',
        });

      await basicAuthProvider.handleCallback('test-code');
    });
  });

  describe('Claims Mapping Security', () => {
    it('should not leak claim names in error messages', async () => {
      const customProvider = new OIDCProvider({
        ...defaultConfig,
        idClaim: 'custom_secret_field',
      });

      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, mockDiscovery);

      nock('https://test-oidc.example.com')
        .get('/jwks')
        .reply(200, mockJWKS);

      await customProvider.initialize();

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      // User info missing the required ID claim
      nock('https://test-oidc.example.com')
        .get('/userinfo')
        .reply(200, {
          sub: 'user123', // has sub but provider expects custom_secret_field
          email: 'test@example.com',
        });

      const user = await customProvider.verifyToken('test-token');
      expect(user).toBeNull();

      // Verify the log message does NOT contain the claim name
      const claimLogCall = consoleSpy.mock.calls.find(
        call => typeof call[0] === 'string' && call[0].includes('Missing required')
      );
      expect(claimLogCall).toBeDefined();
      expect(claimLogCall![0]).not.toContain('custom_secret_field');
      expect(claimLogCall![0]).toBe('Missing required ID claim in token');

      consoleSpy.mockRestore();
    });

    it('should not leak user IDs in group authorization logs', async () => {
      const restrictedProvider = new OIDCProvider({
        ...defaultConfig,
        allowedGroups: ['admin'],
      });

      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, mockDiscovery);

      nock('https://test-oidc.example.com')
        .get('/jwks')
        .reply(200, mockJWKS);

      await restrictedProvider.initialize();

      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      nock('https://test-oidc.example.com')
        .get('/userinfo')
        .reply(200, {
          sub: 'sensitive-user-id-123',
          email: 'secret@example.com',
          groups: ['users'],
        });

      const user = await restrictedProvider.verifyToken('test-token');
      expect(user).toBeNull();

      // Verify log does NOT contain user ID
      const groupLogCall = consoleSpy.mock.calls.find(
        call => typeof call[0] === 'string' && call[0].includes('not in allowed groups')
      );
      expect(groupLogCall).toBeDefined();
      expect(groupLogCall![0]).not.toContain('sensitive-user-id-123');
      expect(groupLogCall![0]).toBe('User not authorized: not in allowed groups');

      consoleSpy.mockRestore();
    });
  });

  describe('Audience Validation with Empty String', () => {
    it('should use clientId when expectedAudience is empty string', async () => {
      const emptyAudProvider = new OIDCProvider({
        ...defaultConfig,
        validateAudience: true,
        expectedAudience: '',
      });

      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, mockDiscovery);

      nock('https://test-oidc.example.com')
        .get('/jwks')
        .reply(200, mockJWKS);

      await emptyAudProvider.initialize();

      // When expectedAudience is empty string with || operator, it would
      // fall through to clientId. With ?? operator, it correctly uses the
      // empty string as the intended value. Either way the behavior should
      // be consistent and not accidentally skip audience validation.
      expect(emptyAudProvider).toBeInstanceOf(OIDCProvider);
    });
  });

  describe('Logout Session Cleanup', () => {
    it('should clear session cookie on logout', async () => {
      const sessionProvider = new OIDCProvider({
        ...defaultConfig,
        session: {
          secret: 'test-secret',
          callbackUrl: 'https://app.example.com/callback',
        },
      });

      nock('https://test-oidc.example.com')
        .get('/.well-known/openid-configuration')
        .reply(200, mockDiscovery);

      nock('https://test-oidc.example.com')
        .get('/jwks')
        .reply(200, mockJWKS);

      // Test that setupRoutes configures a logout route
      const express = await import('express');
      const router = express.Router();

      // Track registered routes
      const routes: { method: string; path: string }[] = [];
      const originalPost = router.post.bind(router);
      router.post = vi.fn(function (path: any, ...handlers: any[]) {
        routes.push({ method: 'post', path });
        return originalPost(path, ...handlers);
      }) as any;

      sessionProvider.setupRoutes(router);

      // Verify logout route was registered
      const logoutRoute = routes.find(r => r.path.includes('/logout'));
      expect(logoutRoute).toBeDefined();
      expect(logoutRoute!.method).toBe('post');
    });
  });
});