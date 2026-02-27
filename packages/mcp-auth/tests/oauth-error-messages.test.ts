import { describe, it, expect, vi } from 'vitest';
import { OAuthProvider, TokenResult, ClientRegistrationRequest, ClientRegistrationResponse } from '../src/index.js';
import { Request, Router } from 'express';

// Create a test implementation of OAuthProvider
class TestOAuthProvider extends OAuthProvider {
  async getAuthUrl(
    _state?: string,
    _redirectUri?: string,
    _resource?: string,
    _pkceParams?: any
  ): Promise<string> {
    return 'https://auth.test.com/authorize';
  }

  async handleCallback(
    code: string,
    state: string,
    redirectUri: string,
    resource?: string,
    codeVerifier?: string
  ): Promise<TokenResult> {
    return {
      accessToken: 'test-token',
      tokenType: 'Bearer',
      expiresIn: 3600
    };
  }

  async authenticate(req: Request): Promise<any> {
    return { id: 'test-user' };
  }

  getUser(_req: Request): any {
    return { id: 'test-user' };
  }

  getDiscoveryMetadata(_baseUrl: string) {
    return {
      authorization_endpoint: 'https://auth.test.com/authorize',
      token_endpoint: 'https://auth.test.com/token',
      userinfo_endpoint: 'https://auth.test.com/userinfo',
      issuer: 'https://auth.test.com'
    };
  }

  getProtectedResourceMetadata(baseUrl: string) {
    return {
      resource: baseUrl,
      audience: baseUrl,
      issuer: 'https://auth.test.com',
      allowedScopes: ['read', 'write']
    };
  }
}

describe('OAuth Error Messages', () => {
  describe('OAuthProvider base class', () => {
    let provider: TestOAuthProvider;

    beforeEach(() => {
      provider = new TestOAuthProvider();
    });

    describe('refreshToken method', () => {
      it('should throw descriptive error with class name', async () => {
        await expect(provider.refreshToken!('test-refresh-token')).rejects.toThrow(
          'Token refresh not implemented by TestOAuthProvider. Override this method to support token refresh.'
        );
      });

      it('should include resource parameter in error context', async () => {
        await expect(provider.refreshToken!('test-refresh-token', 'https://api.test.com')).rejects.toThrow(
          'Token refresh not implemented by TestOAuthProvider. Override this method to support token refresh.'
        );
      });
    });

    describe('registerClient method', () => {
      it('should throw descriptive error with class name', async () => {
        const request: ClientRegistrationRequest = {
          application_type: 'web',
          client_name: 'Test Client',
          redirect_uris: ['https://app.test.com/callback'],
          grant_types: ['authorization_code'],
          response_types: ['code']
        };

        await expect(provider.registerClient!(request)).rejects.toThrow(
          'Dynamic client registration not implemented by TestOAuthProvider. Override this method to support dynamic client registration.'
        );
      });
    });

    describe('error message format', () => {
      it('should include the actual class name in error messages', async () => {
        // Create a custom provider with different name
        class CustomAuthProvider extends OAuthProvider {
          async getAuthUrl(
            _state?: string,
            _redirectUri?: string,
            _resource?: string,
            _pkceParams?: any
          ): Promise<string> {
            return 'https://custom.test.com/authorize';
          }

          async handleCallback(
            code: string,
            state: string,
            redirectUri: string,
            resource?: string,
            codeVerifier?: string
          ): Promise<TokenResult> {
            return {
              accessToken: 'custom-token',
              tokenType: 'Bearer',
              expiresIn: 3600
            };
          }

          async authenticate(req: Request): Promise<any> {
            return { id: 'custom-user' };
          }

          getUser(_req: Request): any {
            return { id: 'custom-user' };
          }

          getDiscoveryMetadata(_baseUrl: string) {
            return {
              authorization_endpoint: 'https://custom.test.com/authorize',
              token_endpoint: 'https://custom.test.com/token',
              userinfo_endpoint: 'https://custom.test.com/userinfo',
              issuer: 'https://custom.test.com'
            };
          }

          getProtectedResourceMetadata(baseUrl: string) {
            return {
              resource: baseUrl,
              audience: baseUrl,
              issuer: 'https://custom.test.com',
              allowedScopes: ['read', 'write']
            };
          }
        }

        const customProvider = new CustomAuthProvider();
        
        await expect(customProvider.refreshToken!('token')).rejects.toThrow(
          'Token refresh not implemented by CustomAuthProvider. Override this method to support token refresh.'
        );
        
        await expect(customProvider.registerClient!({} as any)).rejects.toThrow(
          'Dynamic client registration not implemented by CustomAuthProvider. Override this method to support dynamic client registration.'
        );
      });
    });

    describe('optional method behavior', () => {
      it('should allow providers to override refreshToken', async () => {
        class ProviderWithRefresh extends TestOAuthProvider {
          async refreshToken(refreshToken: string, resource?: string): Promise<TokenResult> {
            return {
              accessToken: 'refreshed-token',
              refreshToken: 'new-refresh-token',
              tokenType: 'Bearer',
              expiresIn: 3600
            };
          }
        }

        const provider = new ProviderWithRefresh();
        const result = await provider.refreshToken!('old-token');
        
        expect(result).toEqual({
          accessToken: 'refreshed-token',
          refreshToken: 'new-refresh-token',
          tokenType: 'Bearer',
          expiresIn: 3600
        });
      });

      it('should allow providers to override registerClient', async () => {
        class ProviderWithRegistration extends TestOAuthProvider {
          async registerClient(request: ClientRegistrationRequest): Promise<ClientRegistrationResponse> {
            return {
              client_id: 'new-client-id',
              client_secret: 'new-client-secret',
              client_id_issued_at: Math.floor(Date.now() / 1000),
              client_secret_expires_at: 0
            };
          }
        }

        const provider = new ProviderWithRegistration();
        const result = await provider.registerClient!({
          application_type: 'web',
          client_name: 'Test'
        } as any);
        
        expect(result).toMatchObject({
          client_id: 'new-client-id',
          client_secret: 'new-client-secret'
        });
      });
    });
  });
});