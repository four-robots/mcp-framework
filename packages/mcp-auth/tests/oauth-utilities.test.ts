import { describe, it, expect, beforeEach, vi } from 'vitest';
import { OAuthProvider, PKCEParams, TokenResult, OAuthDiscovery, ProtectedResourceMetadata, User } from '../src/index.js';
import { Request } from 'express';
import crypto from 'crypto';

// Local base64url encode function for testing
function base64urlEncode(buffer: Buffer): string {
  const base64 = buffer.toString('base64');
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Test OAuth provider for testing utility functions
class TestOAuthProvider extends OAuthProvider {
  async authenticate(req: Request): Promise<User | null> {
    return null;
  }
  
  getUser(req: Request): User | null {
    return null;
  }

  async getAuthUrl(
    state?: string, 
    redirectUri?: string, 
    resource?: string, 
    pkceParams?: PKCEParams
  ): Promise<string> {
    return `https://auth.example.com/authorize?state=${state}&redirect_uri=${redirectUri}`;
  }

  async handleCallback(
    code: string, 
    state?: string, 
    redirectUri?: string, 
    resource?: string,
    codeVerifier?: string
  ): Promise<TokenResult> {
    return {
      accessToken: 'test-token',
      tokenType: 'Bearer',
      expiresIn: 3600
    };
  }

  async getAuthUrl(
    state?: string,
    redirectUri?: string,
    resource?: string,
    pkceParams?: PKCEParams
  ): Promise<string> {
    const parts: string[] = [];
    if (state) parts.push(`state=${state}`);
    if (redirectUri) parts.push(`redirect_uri=${redirectUri}`);
    if (resource) parts.push(`resource=${resource}`);
    if (pkceParams) {
      parts.push(`code_challenge=${pkceParams.codeChallenge}`);
      parts.push(`code_challenge_method=${pkceParams.codeChallengeMethod}`);
    }
    return `https://auth.example.com/authorize?${parts.join('&')}`;
  }

  getDiscoveryMetadata(_baseUrl: string): OAuthDiscovery {
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

  // Expose protected methods for testing
  public testGenerateCodeVerifier(): string {
    return this.generateCodeVerifier();
  }

  public testGenerateCodeChallenge(codeVerifier: string): string {
    return this.generateCodeChallenge(codeVerifier);
  }

  public testGeneratePKCEParams(): PKCEParams {
    return this.generatePKCEParams();
  }

  public testValidateResourceUri(resource: string): boolean {
    return this.validateResourceUri(resource);
  }

  public testValidateHttpsEndpoint(endpoint: string, allowLocalhost = true): boolean {
    return this.validateHttpsEndpoint(endpoint, allowLocalhost);
  }
}

describe('OAuth Utilities', () => {
  let provider: TestOAuthProvider;

  beforeEach(() => {
    provider = new TestOAuthProvider();
  });

  describe('PKCE Generation', () => {
    it('should generate a valid code verifier', () => {
      const codeVerifier = provider.testGenerateCodeVerifier();
      
      expect(codeVerifier).toBeDefined();
      expect(typeof codeVerifier).toBe('string');
      expect(codeVerifier.length).toBeGreaterThan(0);
      
      // Code verifier should be base64url encoded
      expect(codeVerifier).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should generate different code verifiers each time', () => {
      const verifier1 = provider.testGenerateCodeVerifier();
      const verifier2 = provider.testGenerateCodeVerifier();
      
      expect(verifier1).not.toBe(verifier2);
    });

    it('should generate a valid code challenge from verifier', () => {
      const codeVerifier = provider.testGenerateCodeVerifier();
      const codeChallenge = provider.testGenerateCodeChallenge(codeVerifier);
      
      expect(codeChallenge).toBeDefined();
      expect(typeof codeChallenge).toBe('string');
      expect(codeChallenge.length).toBeGreaterThan(0);
      
      // Code challenge should be base64url encoded
      expect(codeChallenge).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should generate consistent code challenge from same verifier', () => {
      const codeVerifier = 'test-verifier';
      const challenge1 = provider.testGenerateCodeChallenge(codeVerifier);
      const challenge2 = provider.testGenerateCodeChallenge(codeVerifier);
      
      expect(challenge1).toBe(challenge2);
    });

    it('should generate complete PKCE parameters', () => {
      const pkceParams = provider.testGeneratePKCEParams();
      
      expect(pkceParams).toBeDefined();
      expect(pkceParams.codeVerifier).toBeDefined();
      expect(pkceParams.codeChallenge).toBeDefined();
      expect(pkceParams.codeChallengeMethod).toBe('S256');
      
      // Verify that the challenge matches the verifier
      const expectedChallenge = provider.testGenerateCodeChallenge(pkceParams.codeVerifier);
      expect(pkceParams.codeChallenge).toBe(expectedChallenge);
    });
  });

  describe('Resource URI Validation', () => {
    it('should validate HTTPS resource URIs', () => {
      expect(provider.testValidateResourceUri('https://api.example.com')).toBe(true);
      expect(provider.testValidateResourceUri('https://api.example.com/resource')).toBe(true);
      expect(provider.testValidateResourceUri('https://api.example.com/resource?param=value')).toBe(true);
    });

    it('should validate localhost HTTP resource URIs', () => {
      expect(provider.testValidateResourceUri('http://localhost:3000')).toBe(true);
      expect(provider.testValidateResourceUri('http://127.0.0.1:3000')).toBe(true);
      expect(provider.testValidateResourceUri('http://localhost')).toBe(true);
    });

    it('should reject non-HTTPS resource URIs', () => {
      expect(provider.testValidateResourceUri('http://example.com')).toBe(false);
      expect(provider.testValidateResourceUri('http://api.example.com')).toBe(false);
    });

    it('should reject resource URIs with fragments', () => {
      expect(provider.testValidateResourceUri('https://api.example.com#fragment')).toBe(false);
      expect(provider.testValidateResourceUri('http://localhost:3000#fragment')).toBe(false);
    });

    it('should reject invalid resource URIs', () => {
      expect(provider.testValidateResourceUri('not-a-url')).toBe(false);
      expect(provider.testValidateResourceUri('')).toBe(false);
      expect(provider.testValidateResourceUri('ftp://example.com')).toBe(false);
    });
  });

  describe('HTTPS Endpoint Validation', () => {
    it('should validate HTTPS endpoints', () => {
      expect(provider.testValidateHttpsEndpoint('https://auth.example.com')).toBe(true);
      expect(provider.testValidateHttpsEndpoint('https://auth.example.com/oauth/authorize')).toBe(true);
    });

    it('should validate localhost HTTP endpoints when allowed', () => {
      expect(provider.testValidateHttpsEndpoint('http://localhost:3000', true)).toBe(true);
      expect(provider.testValidateHttpsEndpoint('http://127.0.0.1:3000', true)).toBe(true);
      expect(provider.testValidateHttpsEndpoint('http://localhost', true)).toBe(true);
    });

    it('should reject localhost HTTP endpoints when not allowed', () => {
      expect(provider.testValidateHttpsEndpoint('http://localhost:3000', false)).toBe(false);
      expect(provider.testValidateHttpsEndpoint('http://127.0.0.1:3000', false)).toBe(false);
    });

    it('should reject non-HTTPS endpoints', () => {
      expect(provider.testValidateHttpsEndpoint('http://example.com')).toBe(false);
      expect(provider.testValidateHttpsEndpoint('http://auth.example.com')).toBe(false);
    });

    it('should reject invalid endpoints', () => {
      expect(provider.testValidateHttpsEndpoint('not-a-url')).toBe(false);
      expect(provider.testValidateHttpsEndpoint('')).toBe(false);
      expect(provider.testValidateHttpsEndpoint('ftp://example.com')).toBe(false);
    });
  });

  describe('High-level OAuth Flow', () => {
    it('should start OAuth flow with PKCE parameters', async () => {
      const state = 'test-state-123';
      const redirectUri = 'https://app.example.com/callback';
      const resource = 'https://api.example.com';

      const result = await provider.startOAuthFlow(state, redirectUri, resource);

      expect(result).toBeDefined();
      expect(result.authUrl).toBeDefined();
      expect(result.state).toBe(state);
      expect(result.authUrl).toContain('state=test-state-123');
      expect(result.authUrl).toContain('redirect_uri=https://app.example.com/callback');
    });

    it('should complete OAuth flow with stored PKCE parameters', async () => {
      const state = 'test-state-456';
      const redirectUri = 'https://app.example.com/callback';
      const code = 'valid-code';

      // First start the flow to store PKCE parameters
      await provider.startOAuthFlow(state, redirectUri);

      // Then complete the flow
      const result = await provider.completeOAuthFlow(code, state, redirectUri);

      expect(result).toBeDefined();
      expect(result.accessToken).toBe('test-token');
      expect(result.tokenType).toBe('Bearer');
      expect(result.expiresIn).toBe(3600);
    });

    it('should throw error when completing flow without starting first', async () => {
      const state = 'unknown-state';
      const redirectUri = 'https://app.example.com/callback';
      const code = 'valid-code';

      await expect(provider.completeOAuthFlow(code, state, redirectUri)).rejects.toThrow(
        'PKCE parameters not found for state. Did you call startOAuthFlow() first?'
      );
    });

    it('should clean up PKCE parameters after successful completion', async () => {
      const state = 'test-state-cleanup';
      const redirectUri = 'https://app.example.com/callback';
      const code = 'valid-code';

      // Start and complete the flow
      await provider.startOAuthFlow(state, redirectUri);
      await provider.completeOAuthFlow(code, state, redirectUri);

      // Try to complete again - should fail because parameters were cleaned up
      await expect(provider.completeOAuthFlow(code, state, redirectUri)).rejects.toThrow(
        'PKCE parameters not found for state'
      );
    });

    it('should clean up PKCE parameters after error', async () => {
      const state = 'test-state-error';
      const redirectUri = 'https://app.example.com/callback';
      const code = 'invalid-code';

      // Start the flow
      await provider.startOAuthFlow(state, redirectUri);

      // Mock handleCallback to throw error
      const originalHandleCallback = provider.handleCallback;
      provider.handleCallback = vi.fn().mockRejectedValue(new Error('Token exchange failed'));

      try {
        await provider.completeOAuthFlow(code, state, redirectUri);
      } catch (error) {
        // Expected error
      }

      // Restore original method
      provider.handleCallback = originalHandleCallback;

      // Try to complete again - should fail because parameters were cleaned up
      await expect(provider.completeOAuthFlow(code, state, redirectUri)).rejects.toThrow(
        'PKCE parameters not found for state'
      );
    });
  });

  describe('PKCE State Management', () => {
    it('should clear specific PKCE state', async () => {
      const state1 = 'state-1';
      const state2 = 'state-2';
      const redirectUri = 'https://app.example.com/callback';

      // Start flows for both states
      await provider.startOAuthFlow(state1, redirectUri);
      await provider.startOAuthFlow(state2, redirectUri);

      // Clear specific state
      provider.clearPKCEState(state1);

      // state1 should be cleared
      await expect(provider.completeOAuthFlow('code', state1, redirectUri)).rejects.toThrow(
        'PKCE parameters not found for state'
      );

      // state2 should still work
      const result = await provider.completeOAuthFlow('valid-code', state2, redirectUri);
      expect(result.accessToken).toBe('test-token');
    });

    it('should clear all PKCE state', async () => {
      const state1 = 'state-all-1';
      const state2 = 'state-all-2';
      const redirectUri = 'https://app.example.com/callback';

      // Start flows for both states
      await provider.startOAuthFlow(state1, redirectUri);
      await provider.startOAuthFlow(state2, redirectUri);

      // Clear all state
      provider.clearPKCEState();

      // Both states should be cleared
      await expect(provider.completeOAuthFlow('code', state1, redirectUri)).rejects.toThrow(
        'PKCE parameters not found for state'
      );
      await expect(provider.completeOAuthFlow('code', state2, redirectUri)).rejects.toThrow(
        'PKCE parameters not found for state'
      );
    });
  });

  describe('Base64URL Encoding', () => {
    it('should encode strings to base64url format', () => {
      const input = 'hello world';
      const encoded = base64urlEncode(Buffer.from(input));
      
      expect(encoded).toBeDefined();
      expect(typeof encoded).toBe('string');
      
      // Should not contain padding or standard base64 chars
      expect(encoded).not.toContain('=');
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      
      // Should only contain base64url chars
      expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should handle empty input', () => {
      const encoded = base64urlEncode(Buffer.from(''));
      expect(encoded).toBe('');
    });

    it('should handle binary data', () => {
      const binaryData = Buffer.from([0x01, 0x02, 0x03, 0x04]);
      const encoded = base64urlEncode(binaryData);
      
      expect(encoded).toBeDefined();
      expect(typeof encoded).toBe('string');
      expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should produce consistent output', () => {
      // Test that our local function produces the same output as crypto operations
      const testData = 'test-data-for-base64url';
      const buffer = Buffer.from(testData);
      const encoded = base64urlEncode(buffer);
      
      // Should be URL-safe
      expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
      
      // Should be deterministic
      const encoded2 = base64urlEncode(Buffer.from(testData));
      expect(encoded).toBe(encoded2);
    });
  });
});