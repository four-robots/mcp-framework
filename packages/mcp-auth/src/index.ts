import express, { Request, Response, Router } from 'express';
import crypto from 'crypto';

/**
 * User interface representing an authenticated user
 */
/**
 * PKCE (Proof Key for Code Exchange) parameters
 */
export interface PKCEParams {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256' | 'plain';
}

/**
 * OAuth authorization parameters
 */
export interface OAuthAuthorizationParams {
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state?: string;
  resource?: string; // RFC 8707 Resource Indicators
  codeChallenge?: string;
  codeChallengeMethod?: 'S256' | 'plain';
}

/**
 * OAuth token exchange parameters
 */
export interface OAuthTokenParams {
  code: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  resource?: string; // RFC 8707 Resource Indicators
  codeVerifier?: string; // PKCE
}

export interface User {
  id: string;
  username: string;
  email: string;
  groups: string[];
  [key: string]: any;
}

/**
 * Token result from OAuth flow
 */
export interface TokenResult {
  accessToken: string;
  refreshToken?: string;
  tokenType: string;
  expiresIn?: number;
  scope?: string;
}

/**
 * OAuth error response (RFC 6749)
 */
export interface OAuthErrorResponse {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

/**
 * OAuth discovery metadata
 */
export interface OAuthDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri?: string;
  registration_endpoint?: string;
  scopes_supported: string[];
  response_types_supported: string[];
  grant_types_supported: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported?: string[];
  token_endpoint_auth_methods_supported?: string[];
  code_challenge_methods_supported?: string[];
}

/**
 * Protected resource metadata (RFC 9728)
 */
export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
}

/**
 * Dynamic client registration request/response
 */
export interface ClientRegistrationRequest {
  client_name: string;
  redirect_uris: string[];
  grant_types?: string[];
  response_types?: string[];
  scope?: string;
  [key: string]: any;
}

export interface ClientRegistrationResponse {
  client_id: string;
  client_secret?: string;
  registration_access_token?: string;
  registration_client_uri?: string;
  client_id_issued_at?: number;
  client_secret_expires_at?: number;
  [key: string]: any;
}

/**
 * Base authentication provider interface
 */
export abstract class AuthProvider {
  /**
   * Authenticate a request and return the user if valid
   */
  abstract authenticate(req: Request): Promise<User | null>;
  
  /**
   * Get the current user from a request (sync version for middleware)
   */
  abstract getUser(req: Request): User | null;
  
  /**
   * Optional: Initialize the auth provider
   */
  async initialize?(): Promise<void>;
  
  /**
   * Optional: Clean up resources
   */
  async shutdown?(): Promise<void>;
}

/**
 * OAuth-specific authentication provider
 */
export abstract class OAuthProvider extends AuthProvider {
  /**
   * Get the authorization URL for starting OAuth flow
   */
  abstract getAuthUrl(
    state?: string, 
    redirectUri?: string, 
    resource?: string, 
    pkceParams?: PKCEParams
  ): string | Promise<string>;
  
  /**
   * Handle the OAuth callback and exchange code for tokens
   */
  abstract handleCallback(
    code: string, 
    state?: string, 
    redirectUri?: string, 
    resource?: string,
    codeVerifier?: string
  ): Promise<TokenResult>;
  
  /**
   * Verify an access token and return the user
   */
  abstract verifyToken(token: string, expectedAudience?: string): Promise<User | null>;
  
  /**
   * Get OAuth discovery metadata
   */
  abstract getDiscoveryMetadata(baseUrl: string): OAuthDiscovery;
  
  /**
   * Get protected resource metadata
   */
  abstract getProtectedResourceMetadata(baseUrl: string): ProtectedResourceMetadata;
  
  /**
   * Optional: Refresh an access token
   * Override this method in subclasses to support token refresh
   */
  async refreshToken?(refreshToken: string, resource?: string): Promise<TokenResult> {
    throw new Error(`Token refresh not implemented by ${this.constructor.name}. Override this method to support token refresh.`);
  }
  
  /**
   * Optional: Handle dynamic client registration
   * Override this method in subclasses to support dynamic client registration
   */
  async registerClient?(request: ClientRegistrationRequest): Promise<ClientRegistrationResponse> {
    throw new Error(`Dynamic client registration not implemented by ${this.constructor.name}. Override this method to support dynamic client registration.`);
  }
  
  /**
   * Optional: Setup OAuth routes (login, callback, etc.)
   */
  setupRoutes?(router: Router): void {
    // Default implementation can be overridden
  }
  
  /**
   * Optional: Check if provider supports dynamic registration
   */
  supportsDynamicRegistration?(): boolean {
    return false;
  }

  // State storage for PKCE parameters (in-memory for single instance)
  private pkceStore = new Map<string, PKCEParams>();

  /**
   * High-level convenience method: Start OAuth flow with automatic PKCE generation
   * This method automatically generates PKCE parameters and stores them for later use
   */
  async startOAuthFlow(
    state: string,
    redirectUri: string,
    resource?: string
  ): Promise<{ authUrl: string; state: string }> {
    // Generate PKCE parameters automatically
    const pkceParams = this.generatePKCEParams();
    
    // Store PKCE parameters keyed by state for later retrieval
    this.pkceStore.set(state, pkceParams);
    
    // Get authorization URL with PKCE parameters
    const authUrl = await this.getAuthUrl(state, redirectUri, resource, pkceParams);
    
    return { authUrl, state };
  }

  /**
   * High-level convenience method: Complete OAuth flow using stored PKCE parameters
   * This method automatically retrieves and uses the PKCE code verifier
   */
  async completeOAuthFlow(
    code: string,
    state: string,
    redirectUri: string,
    resource?: string
  ): Promise<TokenResult> {
    // Retrieve stored PKCE parameters
    const pkceParams = this.pkceStore.get(state);
    if (!pkceParams) {
      throw new Error('PKCE parameters not found for state. Did you call startOAuthFlow() first?');
    }
    
    try {
      // Exchange code for tokens using stored PKCE verifier
      const result = await this.handleCallback(code, state, redirectUri, resource, pkceParams.codeVerifier);
      
      // Clean up stored PKCE parameters
      this.pkceStore.delete(state);
      
      return result;
    } catch (error) {
      // Clean up on error too
      this.pkceStore.delete(state);
      throw error;
    }
  }

  /**
   * Clear stored PKCE parameters (useful for cleanup)
   */
  clearPKCEState(state?: string): void {
    if (state) {
      this.pkceStore.delete(state);
    } else {
      this.pkceStore.clear();
    }
  }

  /**
   * Generate PKCE code verifier (OAuth 2.1 requirement)
   */
  protected generateCodeVerifier(): string {
    return base64urlEncode(crypto.randomBytes(32));
  }

  /**
   * Generate PKCE code challenge from verifier (OAuth 2.1 requirement)
   */
  protected generateCodeChallenge(codeVerifier: string): string {
    const hash = crypto.createHash('sha256').update(codeVerifier).digest();
    return base64urlEncode(hash);
  }

  /**
   * Generate complete PKCE parameters
   */
  protected generatePKCEParams(): PKCEParams {
    const codeVerifier = this.generateCodeVerifier();
    const codeChallenge = this.generateCodeChallenge(codeVerifier);
    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: 'S256'
    };
  }

  /**
   * Validate resource URI format (RFC 8707)
   */
  protected validateResourceUri(resource: string): boolean {
    try {
      const url = new URL(resource);
      // Must be HTTPS or localhost HTTP
      if (url.protocol !== 'https:' && !(url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1'))) {
        return false;
      }
      // Must not contain fragment
      if (url.hash) {
        return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Validate that OAuth endpoints use HTTPS (OAuth 2.1 requirement)
   */
  protected validateHttpsEndpoint(endpoint: string, allowLocalhost = true): boolean {
    try {
      const url = new URL(endpoint);
      if (url.protocol === 'https:') {
        return true;
      }
      if (allowLocalhost && url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1')) {
        return true;
      }
      return false;
    } catch {
      return false;
    }
  }

}

/**
 * No authentication provider (for development/testing)
 */
export class NoAuth extends AuthProvider {
  async authenticate(_req: Request): Promise<User | null> {
    return null;
  }
  
  getUser(_req: Request): User | null {
    return null;
  }
}

/**
 * Development authentication provider with mock users
 */
export class DevAuth extends AuthProvider {
  private mockUser: User;
  
  constructor(mockUser?: Partial<User>) {
    super();
    this.mockUser = {
      id: mockUser?.id || 'dev-user-123',
      username: mockUser?.username || 'developer',
      email: mockUser?.email || 'dev@example.com',
      groups: mockUser?.groups || ['developers'],
      ...mockUser
    };
  }
  
  async authenticate(_req: Request): Promise<User | null> {
    // In dev mode, always return the mock user
    return this.mockUser;
  }
  
  getUser(_req: Request): User | null {
    // In dev mode, always return the mock user
    return this.mockUser;
  }
}

/**
 * Bearer token authentication provider
 */
export abstract class BearerTokenAuth extends AuthProvider {
  async authenticate(req: Request): Promise<User | null> {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }

    const token = authHeader.substring(7).trim();
    if (!token) {
      return null;
    }

    // Extract expected audience from request (base URL)
    const expectedAudience = `${req.protocol}://${req.get('host')}`;
    return this.verifyToken(token, expectedAudience);
  }
  
  getUser(req: Request): User | null {
    // For sync middleware, we can't verify tokens synchronously
    // The authenticate method should be used instead
    return null;
  }
  
  /**
   * Verify a bearer token and return the user
   */
  abstract verifyToken(token: string, expectedAudience?: string): Promise<User | null>;
}

/**
 * Session-based authentication provider
 */
export abstract class SessionAuth extends AuthProvider {
  getUser(req: Request): User | null {
    // Assuming the user is stored in req.user by session middleware
    return (req as any).user || null;
  }
  
  async authenticate(req: Request): Promise<User | null> {
    return this.getUser(req);
  }
}

/**
 * Utility function to extract bearer token from request
 */
export function extractBearerToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.substring(7).trim();
}

/**
 * Utility function to create auth middleware
 */
export function createAuthMiddleware(provider: AuthProvider) {
  return async (req: Request, res: Response, next: any) => {
    try {
      const user = await provider.authenticate(req);
      if (user) {
        (req as any).user = user;
        next();
      } else {
        // Set WWW-Authenticate header as required by OAuth 2.1
        res.set('WWW-Authenticate', 'Bearer');
        const errorResponse = createOAuthError(
          'unauthorized',
          'Authentication required'
        );
        res.status(401).json(errorResponse);
      }
    } catch (error) {
      console.error('Authentication error:', error);
      const errorResponse = createOAuthError(
        'server_error',
        'Authentication service error'
      );
      res.status(500).json(errorResponse);
    }
  };
}

/**
 * Create OAuth discovery routes for MCP compliance
 */
export function createOAuthDiscoveryRoutes(provider: OAuthProvider): Router {
  const router = Router();
  
  // Protected Resource Metadata (RFC 9728)
  router.get('/.well-known/oauth-protected-resource', (req: Request, res: Response) => {
    const baseUrl = getBaseUrl(req);
    res.json(provider.getProtectedResourceMetadata(baseUrl));
  });
  
  // OAuth Authorization Server Metadata
  router.get('/.well-known/oauth-authorization-server', (req: Request, res: Response) => {
    const baseUrl = getBaseUrl(req);
    res.json(provider.getDiscoveryMetadata(baseUrl));
  });
  
  // Dynamic Client Registration (if supported)
  if (provider.supportsDynamicRegistration && provider.supportsDynamicRegistration()) {
    router.post('/application/o/register/', express.json(), async (req: Request, res: Response) => {
      try {
        if (!provider.registerClient) {
          const errorResponse = createOAuthError(
            'temporarily_unavailable',
            'Dynamic registration not available'
          );
          res.status(501).json(errorResponse);
          return;
        }
        
        if (!req.body || typeof req.body !== 'object') {
          const errorResponse = createOAuthError(
            'invalid_client_metadata',
            'Request body must be a JSON object'
          );
          res.status(400).json(errorResponse);
          return;
        }

        const response = await provider.registerClient(req.body);
        res.json(response);
      } catch (error) {
        console.error('Client registration failed:', error);
        
        // Determine appropriate error code based on error type
        let errorCode = 'invalid_client_metadata';
        let statusCode = 400;
        let description = 'Failed to register client';
        
        if (error instanceof Error) {
          if (error.message.includes('token') || error.message.includes('authentication')) {
            errorCode = 'invalid_token';
            statusCode = 401;
            description = 'Invalid or missing authentication token';
          } else if (error.message.includes('permission') || error.message.includes('forbidden')) {
            errorCode = 'insufficient_scope';
            statusCode = 403;
            description = 'Insufficient permissions for client registration';
          } else if (error.message.includes('metadata') || error.message.includes('invalid')) {
            errorCode = 'invalid_client_metadata';
            description = error.message;
          }
        }
        
        const errorResponse = createOAuthError(errorCode, description);
        res.status(statusCode).json(errorResponse);
      }
    });
  }
  
  // Let provider setup additional routes (login, callback, etc.)
  if (provider.setupRoutes) {
    provider.setupRoutes(router);
  }
  
  return router;
}

/**
 * Base64url encode (without padding) - RFC 7636
 */
function base64urlEncode(buffer: Buffer): string {
  const base64 = buffer.toString('base64');
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Helper to get base URL from request
 */
function getBaseUrl(req: Request): string {
  const protocol = req.protocol;
  const host = req.get('host');
  return `${protocol}://${host}`;
}

/**
 * Create standardized OAuth error response (RFC 6749)
 */
export function createOAuthError(
  error: string,
  description?: string,
  uri?: string,
  state?: string
): OAuthErrorResponse {
  const errorResponse: OAuthErrorResponse = { error };
  
  if (description) {
    errorResponse.error_description = description;
  }
  
  if (uri) {
    errorResponse.error_uri = uri;
  }
  
  if (state) {
    errorResponse.state = state;
  }
  
  return errorResponse;
}

// Re-export express for convenience
export { express };
