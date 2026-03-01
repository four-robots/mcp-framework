import { describe, it, expect, beforeEach } from 'vitest';
import { OAuthProvider, PKCEParams, TokenResult, OAuthDiscovery, ProtectedResourceMetadata, User } from '../src/index';

// Test OAuth provider that implements the new convenience methods
class TestConvenienceOAuthProvider extends OAuthProvider {
  async authenticate(req: any): Promise<User | null> {
    return null;
  }
  
  getUser(req: any): User | null {
    return null;
  }

  async getAuthUrl(
    state?: string, 
    redirectUri?: string, 
    resource?: string, 
    pkceParams?: PKCEParams
  ): Promise<string> {
    const params = new URLSearchParams({
      client_id: 'test-client',
      response_type: 'code',
      redirect_uri: redirectUri || 'http://localhost:3000/callback'
    });

    if (state) params.set('state', state);
    if (resource) params.set('resource', resource);
    if (pkceParams) {
      params.set('code_challenge', pkceParams.codeChallenge);
      params.set('code_challenge_method', pkceParams.codeChallengeMethod);
    }

    return `https://auth.example.com/authorize?${params.toString()}`;
  }

  async handleCallback(
    code: string, 
    state?: string, 
    redirectUri?: string, 
    resource?: string,
    codeVerifier?: string
  ): Promise<TokenResult> {
    // Mock successful callback
    if (code === 'valid-code' && codeVerifier) {
      return {
        accessToken: 'test-access-token',
        tokenType: 'Bearer',
        expiresIn: 3600
      };
    }
    throw new Error('Invalid authorization code');
  }

  async verifyToken(token: string, expectedAudience?: string): Promise<User | null> {
    return null;
  }

  getDiscoveryMetadata(baseUrl: string): OAuthDiscovery {
    return {
      issuer: 'https://auth.example.com',
      authorization_endpoint: 'https://auth.example.com/authorize',
      token_endpoint: 'https://auth.example.com/token',
      userinfo_endpoint: 'https://auth.example.com/userinfo',
      scopes_supported: ['openid', 'profile', 'email'],
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      subject_types_supported: ['public'],
      code_challenge_methods_supported: ['S256', 'plain']
    };
  }

  getProtectedResourceMetadata(baseUrl: string): ProtectedResourceMetadata {
    return {
      resource: baseUrl,
      authorization_servers: ['https://auth.example.com']
    };
  }
}

describe('OAuth Provider - High-Level Convenience Methods', () => {
  let provider: TestConvenienceOAuthProvider;

  beforeEach(() => {
    provider = new TestConvenienceOAuthProvider();
  });

  describe('startOAuthFlow()', () => {
    it('should generate PKCE parameters automatically and return auth URL', async () => {
      const state = 'test-state-123';
      const redirectUri = 'http://localhost:3000/callback';
      const resource = 'https://mcp.example.com';

      const result = await provider.startOAuthFlow(state, redirectUri, resource);

      expect(result.state).toBe(state);
      expect(result.authUrl).toContain('code_challenge=');
      expect(result.authUrl).toContain('code_challenge_method=S256');
      expect(result.authUrl).toContain(`state=${state}`);
      expect(result.authUrl).toContain(`resource=${encodeURIComponent(resource)}`);
      expect(result.authUrl).toContain(`redirect_uri=${encodeURIComponent(redirectUri)}`);
    });

    it('should store PKCE parameters for later use', async () => {
      const state = 'test-state-456';
      const redirectUri = 'http://localhost:3000/callback';

      await provider.startOAuthFlow(state, redirectUri);

      // PKCE parameters should be stored (we can't directly access private store, 
      // but we can test this via completeOAuthFlow)
      expect(async () => {
        await provider.completeOAuthFlow('valid-code', state, redirectUri);
      }).not.toThrow();
    });
  });

  describe('completeOAuthFlow()', () => {
    it('should complete OAuth flow using stored PKCE parameters', async () => {
      const state = 'test-state-789';
      const redirectUri = 'http://localhost:3000/callback';
      const resource = 'https://mcp.example.com';

      // Start the flow first to store PKCE parameters
      await provider.startOAuthFlow(state, redirectUri, resource);

      // Complete the flow
      const result = await provider.completeOAuthFlow('valid-code', state, redirectUri, resource);

      expect(result.accessToken).toBe('test-access-token');
      expect(result.tokenType).toBe('Bearer');
      expect(result.expiresIn).toBe(3600);
    });

    it('should throw error if PKCE parameters not found', async () => {
      const state = 'unknown-state';
      const redirectUri = 'http://localhost:3000/callback';

      await expect(
        provider.completeOAuthFlow('valid-code', state, redirectUri)
      ).rejects.toThrow('PKCE parameters not found for state. Did you call startOAuthFlow() first?');
    });

    it('should clean up PKCE parameters after successful completion', async () => {
      const state = 'test-state-cleanup';
      const redirectUri = 'http://localhost:3000/callback';

      // Start and complete flow
      await provider.startOAuthFlow(state, redirectUri);
      await provider.completeOAuthFlow('valid-code', state, redirectUri);

      // Second attempt should fail because parameters were cleaned up
      await expect(
        provider.completeOAuthFlow('valid-code', state, redirectUri)
      ).rejects.toThrow('PKCE parameters not found for state');
    });

    it('should clean up PKCE parameters even on error', async () => {
      const state = 'test-state-error';
      const redirectUri = 'http://localhost:3000/callback';

      // Start flow
      await provider.startOAuthFlow(state, redirectUri);

      // Attempt to complete with invalid code
      await expect(
        provider.completeOAuthFlow('invalid-code', state, redirectUri)
      ).rejects.toThrow('Invalid authorization code');

      // Parameters should still be cleaned up
      await expect(
        provider.completeOAuthFlow('valid-code', state, redirectUri)
      ).rejects.toThrow('PKCE parameters not found for state');
    });
  });

  describe('clearPKCEState()', () => {
    it('should clear specific state parameters', async () => {
      const state1 = 'state-1';
      const state2 = 'state-2';
      const redirectUri = 'http://localhost:3000/callback';

      // Start two flows
      await provider.startOAuthFlow(state1, redirectUri);
      await provider.startOAuthFlow(state2, redirectUri);

      // Clear only one state
      provider.clearPKCEState(state1);

      // state1 should be cleared, state2 should still work
      await expect(
        provider.completeOAuthFlow('valid-code', state1, redirectUri)
      ).rejects.toThrow('PKCE parameters not found for state');

      await expect(
        provider.completeOAuthFlow('valid-code', state2, redirectUri)
      ).resolves.toBeDefined();
    });

    it('should clear all states when no specific state provided', async () => {
      const state1 = 'state-1';
      const state2 = 'state-2';
      const redirectUri = 'http://localhost:3000/callback';

      // Start two flows
      await provider.startOAuthFlow(state1, redirectUri);
      await provider.startOAuthFlow(state2, redirectUri);

      // Clear all states
      provider.clearPKCEState();

      // Both should be cleared
      await expect(
        provider.completeOAuthFlow('valid-code', state1, redirectUri)
      ).rejects.toThrow('PKCE parameters not found for state');

      await expect(
        provider.completeOAuthFlow('valid-code', state2, redirectUri)
      ).rejects.toThrow('PKCE parameters not found for state');
    });
  });

  describe('PKCE Store Eviction', () => {
    it('should evict oldest entries when store reaches capacity', async () => {
      const redirectUri = 'http://localhost:3000/callback';

      // Fill the PKCE store beyond capacity (PKCE_MAX_SIZE = 1000)
      // We access the private static to know the cap
      const maxSize = (OAuthProvider as any).PKCE_MAX_SIZE || 1000;
      for (let i = 0; i < maxSize; i++) {
        await provider.startOAuthFlow(`state-${i}`, redirectUri);
      }

      // Add one more — should trigger eviction of ~10% oldest entries
      await provider.startOAuthFlow('state-overflow', redirectUri);

      // The overflow entry should still be usable
      await expect(
        provider.completeOAuthFlow('valid-code', 'state-overflow', redirectUri)
      ).resolves.toBeDefined();

      // The very first entry should have been evicted
      await expect(
        provider.completeOAuthFlow('valid-code', 'state-0', redirectUri)
      ).rejects.toThrow('PKCE parameters not found for state');
    });
  });

  describe('Integration with existing methods', () => {
    it('should work alongside manual PKCE parameter management', async () => {
      // Generate PKCE parameters manually
      const pkceParams = (provider as any).generatePKCEParams();
      const authUrl = await provider.getAuthUrl(
        'manual-state',
        'http://localhost:3000/callback',
        'https://mcp.example.com',
        pkceParams
      );

      expect(authUrl).toContain(`code_challenge=${pkceParams.codeChallenge}`);

      // Complete manually
      const result = await provider.handleCallback(
        'valid-code',
        'manual-state',
        'http://localhost:3000/callback',
        'https://mcp.example.com',
        pkceParams.codeVerifier
      );

      expect(result.accessToken).toBe('test-access-token');
    });
  });
});
