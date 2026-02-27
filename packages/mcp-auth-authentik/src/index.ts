import axios from 'axios';
import { Request, Router } from 'express';
import session from 'express-session';
import passport from 'passport';
import { Strategy as OpenIDConnectStrategy } from 'passport-openidconnect';
import {
  OAuthProvider,
  User,
  TokenResult,
  OAuthDiscovery,
  ProtectedResourceMetadata,
  ClientRegistrationRequest,
  ClientRegistrationResponse,
  PKCEParams,
  createOAuthError,
  OAuthErrorResponse
} from '@tylercoles/mcp-auth';

/**
 * Authentik OAuth provider configuration
 */
export interface AuthentikConfig {
  url: string;
  clientId: string;
  authorizationFlowId: string;
  invalidationFlowId: string;
  clientSecret?: string;
  scopes?: string[];
  redirectUri?: string;
  applicationSlug?: string; // Authentik application slug (default: derived from clientId)
  allowedGroups?: string[]; // Optional: restrict access to specific groups
  sessionSecret?: string; // For passport session management
  registrationApiToken?: string; // API token for dynamic client registration (required for non-Claude clients)
  authenticationFlowId?: string;
  signingKeyId?: string;
}

/**
 * Authentik user info response
 */
interface AuthentikUserInfo {
  sub: string;
  email: string;
  email_verified: boolean;
  name: string;
  given_name?: string;
  family_name?: string;
  preferred_username: string;
  nickname?: string;
  groups?: string[];
  [key: string]: any;
}

/**
 * Helper class for creating standardized Authentik OAuth errors
 */
class AuthentikErrorHandler {
  /**
   * Map Authentik API errors to OAuth error codes
   */
  static mapApiError(error: any): { code: string; description: string; status: number } {
    if (axios.isAxiosError(error)) {
      const status = error.response?.status;
      const data = error.response?.data;
      
      switch (status) {
        case 400:
          return {
            code: 'invalid_client_metadata',
            description: `Invalid request: ${this.extractErrorDescription(data)}`,
            status: 400
          };
        case 401:
          return {
            code: 'invalid_token',
            description: 'Invalid or missing authentication token',
            status: 401
          };
        case 403:
          return {
            code: 'insufficient_scope',
            description: 'Insufficient permissions for the requested operation',
            status: 403
          };
        case 404:
          return {
            code: 'invalid_request',
            description: 'Resource not found',
            status: 404
          };
        case 409:
          return {
            code: 'invalid_client_metadata',
            description: 'Client with this configuration already exists',
            status: 409
          };
        case 429:
          return {
            code: 'temporarily_unavailable',
            description: 'Rate limit exceeded. Please try again later.',
            status: 429
          };
        case 500:
        case 502:
        case 503:
        case 504:
          return {
            code: 'server_error',
            description: 'Authentik server error. Please try again later.',
            status: 500
          };
        default:
          return {
            code: 'server_error',
            description: `Unexpected error: ${error.message}`,
            status: 500
          };
      }
    }
    
    // Non-Axios errors
    if (error instanceof Error) {
      if (error.message.includes('timeout')) {
        return {
          code: 'temporarily_unavailable',
          description: 'Request timeout. Please try again.',
          status: 503
        };
      }
      
      if (error.message.includes('network') || error.message.includes('connection')) {
        return {
          code: 'temporarily_unavailable',
          description: 'Network error. Please check connectivity.',
          status: 503
        };
      }
    }
    
    return {
      code: 'server_error',
      description: error instanceof Error ? error.message : 'Unknown error',
      status: 500
    };
  }
  
  /**
   * Extract meaningful error description from Authentik API response
   */
  private static extractErrorDescription(data: any): string {
    if (!data) return 'Unknown error';
    
    if (typeof data === 'string') return data;
    
    if (data.detail) return data.detail;
    
    if (data.error_description) return data.error_description;
    
    if (data.message) return data.message;
    
    // Handle field validation errors
    if (data.errors || data.non_field_errors) {
      const errors = data.errors || data.non_field_errors;
      if (Array.isArray(errors)) {
        return errors.join(', ');
      }
      if (typeof errors === 'object') {
        return Object.values(errors).flat().join(', ');
      }
    }
    
    return JSON.stringify(data);
  }
  
  /**
   * Create OAuth error for token exchange failures
   */
  static createTokenError(error: any): OAuthErrorResponse {
    if (axios.isAxiosError(error)) {
      const status = error.response?.status;
      const data = error.response?.data;
      
      if (data?.error) {
        // Authentik returns OAuth-compliant errors for token endpoint
        return createOAuthError(
          data.error,
          data.error_description,
          data.error_uri
        );
      }
      
      switch (status) {
        case 400:
          return createOAuthError(
            'invalid_grant',
            'Invalid authorization code or redirect URI'
          );
        case 401:
          return createOAuthError(
            'invalid_client',
            'Client authentication failed'
          );
        default:
          return createOAuthError(
            'server_error',
            'Token exchange failed'
          );
      }
    }
    
    return createOAuthError(
      'server_error',
      error instanceof Error ? error.message : 'Token exchange failed'
    );
  }
}

/**
 * Authentik OAuth provider implementation with full MCP support
 */
export class AuthentikAuth extends OAuthProvider {
  private config: AuthentikConfig;
  private discoveryCache: any = null;
  private passportInitialized = false;

  constructor(config: AuthentikConfig) {
    super();

    const DEFAULT_SECRET = 'authentik-secret-change-me';
    const sessionSecret = config.sessionSecret || DEFAULT_SECRET;

    if (sessionSecret === DEFAULT_SECRET) {
      console.warn(
        '[mcp-auth-authentik] WARNING: Using default session secret. ' +
        'This is insecure for production. Set a strong, unique sessionSecret in your AuthentikConfig.'
      );
    }

    this.config = {
      scopes: ['openid', 'profile', 'email'],
      applicationSlug: config.clientId,
      sessionSecret,
      ...config
    };
  }

  /**
   * Initialize passport if needed
   */
  async initialize(): Promise<void> {
    if (this.passportInitialized) return;

    // Configure passport strategy
    passport.use('authentik', new OpenIDConnectStrategy({
      issuer: `${this.config.url}/application/o/${this.config.applicationSlug}/`,
      authorizationURL: `${this.config.url}/application/o/authorize/`,
      tokenURL: `${this.config.url}/application/o/token/`,
      userInfoURL: `${this.config.url}/application/o/userinfo/`,
      clientID: this.config.clientId,
      clientSecret: this.config.clientSecret || '',
      callbackURL: this.config.redirectUri || '',
      scope: this.config.scopes,
      skipUserProfile: false,
      // state: true
    }, this.verifyCallback.bind(this)) as any);

    // Serialize/deserialize user
    passport.serializeUser((user: any, done) => {
      done(null, user.id);
    });

    passport.deserializeUser(async (id: string, done) => {
      // Simple deserialization - in production, fetch from database
      done(null, { id });
    });

    this.passportInitialized = true;
  }

  /**
   * Passport verify callback
   */
  private async verifyCallback(
    _issuer: string,
    profile: any,
    done: (error: any, user?: any) => void
  ): Promise<void> {
    try {
      const user = this.profileToUser(profile);
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  }

  /**
   * Convert passport profile to User
   */
  private profileToUser(profile: any): User {
    const userId = profile.id || profile.sub || profile.user_id || profile.pk;
    const username = profile.username || profile.preferred_username || profile.nickname || profile.name;
    const email = profile.email || profile.emails?.[0]?.value || profile.emails?.[0] || '';
    const groups = profile.groups || profile.roles || [];

    if (!userId || !username) {
      throw new Error('Invalid profile data');
    }

    // Check group restrictions if configured
    if (this.config.allowedGroups && this.config.allowedGroups.length > 0) {
      const hasAllowedGroup = this.config.allowedGroups.some(
        group => groups.includes(group)
      );

      if (!hasAllowedGroup) {
        throw new Error('User not in allowed groups');
      }
    }

    return {
      id: String(userId),
      username: String(username),
      email: String(email),
      groups: Array.isArray(groups) ? groups.map(g => String(g)) : []
    };
  }

  /**
   * Get OAuth endpoints from Authentik discovery
   */
  private async getDiscovery(): Promise<any> {
    if (this.discoveryCache) {
      return this.discoveryCache;
    }

    const discoveryUrl = `${this.config.url}/application/o/${this.config.applicationSlug}/.well-known/openid-configuration`;

    try {
      const response = await axios.get(discoveryUrl);
      this.discoveryCache = response.data;
      return this.discoveryCache;
    } catch (error) {
      console.error('Failed to fetch Authentik discovery document:', error);
      throw new Error('Failed to fetch OAuth configuration from Authentik');
    }
  }

  /**
   * Get the authorization URL for starting OAuth flow
   */
  async getAuthUrl(
    state?: string, 
    redirectUri?: string, 
    resource?: string, 
    pkceParams?: PKCEParams
  ): Promise<string> {
    const discovery = await this.getDiscovery();
    
    // Validate HTTPS endpoint (OAuth 2.1 requirement)
    if (!this.validateHttpsEndpoint(discovery.authorization_endpoint)) {
      throw new Error('Authorization endpoint must use HTTPS in production');
    }
    
    // Validate resource URI if provided (RFC 8707)
    if (resource && !this.validateResourceUri(resource)) {
      throw new Error('Invalid resource URI format');
    }
    
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      response_type: 'code',
      scope: this.config.scopes!.join(' '),
      redirect_uri: redirectUri || this.config.redirectUri || '',
    });

    if (state) {
      params.set('state', state);
    }
    
    // Add resource parameter (RFC 8707)
    if (resource) {
      params.set('resource', resource);
    }
    
    // Add PKCE parameters (OAuth 2.1 requirement)
    if (pkceParams) {
      params.set('code_challenge', pkceParams.codeChallenge);
      params.set('code_challenge_method', pkceParams.codeChallengeMethod);
    }

    return `${discovery.authorization_endpoint}?${params.toString()}`;
  }

  /**
   * Handle the OAuth callback and exchange code for tokens
   */
  async handleCallback(
    code: string, 
    state?: string, 
    redirectUri?: string, 
    resource?: string,
    codeVerifier?: string
  ): Promise<TokenResult> {
    const discovery = await this.getDiscovery();
    
    // Validate HTTPS endpoint (OAuth 2.1 requirement)
    if (!this.validateHttpsEndpoint(discovery.token_endpoint)) {
      throw new Error('Token endpoint must use HTTPS in production');
    }

    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri || this.config.redirectUri || '',
      client_id: this.config.clientId,
    });

    if (this.config.clientSecret) {
      params.set('client_secret', this.config.clientSecret);
    }
    
    // Add resource parameter (RFC 8707)
    if (resource) {
      params.set('resource', resource);
    }
    
    // Add PKCE code verifier (OAuth 2.1 requirement)
    if (codeVerifier) {
      params.set('code_verifier', codeVerifier);
    }

    try {
      const response = await axios.post(discovery.token_endpoint, params.toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });

      return {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token,
        tokenType: response.data.token_type,
        expiresIn: response.data.expires_in,
        scope: response.data.scope,
      };
    } catch (error) {
      console.error('Failed to exchange code for tokens:', error);
      const oauthError = AuthentikErrorHandler.createTokenError(error);
      const errorObj = new Error(`OAuth error: ${oauthError.error} - ${oauthError.error_description}`);
      (errorObj as any).oauthError = oauthError;
      throw errorObj;
    }
  }

  /**
   * Verify an access token and return the user
   */
  async verifyToken(token: string, expectedAudience?: string): Promise<User | null> {
    const discovery = await this.getDiscovery();
    
    // Validate HTTPS endpoint (OAuth 2.1 requirement)
    if (!this.validateHttpsEndpoint(discovery.userinfo_endpoint)) {
      throw new Error('Userinfo endpoint must use HTTPS in production');
    }
    
    // If audience validation is required, validate the token JWT
    if (expectedAudience) {
      try {
        // Decode JWT without verification to check audience
        const payload = this.decodeJwtPayload(token);
        
        // Check audience claim (aud)
        if (payload.aud) {
          const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
          if (!audiences.includes(expectedAudience)) {
            console.warn(`Token audience mismatch. Expected: ${expectedAudience}, Got: ${audiences.join(', ')}`);
            return null;
          }
        } else {
          console.warn(`Token missing audience claim. Expected: ${expectedAudience}`);
          return null;
        }
      } catch (error) {
        console.error('Failed to validate token audience:', error);
        return null;
      }
    }

    try {
      const response = await axios.get<AuthentikUserInfo>(discovery.userinfo_endpoint, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const userInfo = response.data;

      // Check group restrictions if configured
      if (this.config.allowedGroups && this.config.allowedGroups.length > 0) {
        const userGroups = userInfo.groups || [];
        const hasAllowedGroup = this.config.allowedGroups.some(
          group => userGroups.includes(group)
        );

        if (!hasAllowedGroup) {
          console.warn(`User ${userInfo.sub} not in allowed groups`);
          return null;
        }
      }

      return {
        ...userInfo, // Include any additional claims
        id: userInfo.sub,
        username: userInfo.preferred_username || userInfo.nickname || userInfo.email,
        email: userInfo.email,
        groups: userInfo.groups || [],
        name: userInfo.name,
        given_name: userInfo.given_name,
        family_name: userInfo.family_name,
        email_verified: userInfo.email_verified,
      };
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 401) {
        // Invalid token
        return null;
      }
      console.error('Failed to verify token:', error);
      throw new Error('Failed to verify access token');
    }
  }

  /**
   * Decode JWT payload without verification (for audience checking)
   */
  private decodeJwtPayload(token: string): any {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }
      
      // Decode base64url payload
      const payload = parts[1];
      const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
      const padding = '='.repeat((4 - base64.length % 4) % 4);
      const decoded = atob(base64 + padding);
      
      return JSON.parse(decoded);
    } catch (error) {
      throw new Error(`Failed to decode JWT payload: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Refresh an access token
   */
  async refreshToken(refreshToken: string, resource?: string): Promise<TokenResult> {
    const discovery = await this.getDiscovery();
    
    // Validate HTTPS endpoint (OAuth 2.1 requirement)
    if (!this.validateHttpsEndpoint(discovery.token_endpoint)) {
      throw new Error('Token endpoint must use HTTPS in production');
    }

    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this.config.clientId,
    });

    if (this.config.clientSecret) {
      params.set('client_secret', this.config.clientSecret);
    }
    
    // Add resource parameter (RFC 8707)
    if (resource) {
      params.set('resource', resource);
    }

    try {
      const response = await axios.post(discovery.token_endpoint, params.toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });

      return {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token,
        tokenType: response.data.token_type,
        expiresIn: response.data.expires_in,
        scope: response.data.scope,
      };
    } catch (error) {
      console.error('Failed to refresh token:', error);
      const oauthError = AuthentikErrorHandler.createTokenError(error);
      const errorObj = new Error(`Token refresh failed: ${oauthError.error} - ${oauthError.error_description}`);
      (errorObj as any).oauthError = oauthError;
      throw errorObj;
    }
  }

  /**
   * Authenticate a request (Bearer token or session)
   */
  async authenticate(req: Request): Promise<User | null> {
    // First try bearer token
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      // Extract expected audience from request (base URL)
      const expectedAudience = `${req.protocol}://${req.get('host')}`;
      return this.verifyToken(token, expectedAudience);
    }

    // Then try session
    if ((req as any).user) {
      return (req as any).user;
    }

    return null;
  }

  /**
   * Get user from request (sync - for session)
   */
  getUser(req: Request): User | null {
    return (req as any).user || null;
  }

  /**
   * Get OAuth discovery metadata
   */
  getDiscoveryMetadata(baseUrl: string): OAuthDiscovery {
    return {
      issuer: `${this.config.url}/application/o/${this.config.applicationSlug}/`,
      authorization_endpoint: `${this.config.url}/application/o/authorize/`,
      token_endpoint: `${this.config.url}/application/o/token/`,
      userinfo_endpoint: `${this.config.url}/application/o/userinfo/`,
      jwks_uri: `${this.config.url}/application/o/${this.config.applicationSlug}/jwks/`,
      registration_endpoint: this.supportsDynamicRegistration() ? `${baseUrl}/application/o/register/` : undefined,
      scopes_supported: ["openid", "profile", "email"],
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
      code_challenge_methods_supported: ["S256", "plain"]
    };
  }

  /**
   * Get protected resource metadata
   */
  getProtectedResourceMetadata(baseUrl: string): ProtectedResourceMetadata {
    return {
      resource: baseUrl,
      authorization_servers: [`${this.config.url}/application/o/${this.config.applicationSlug}/`]
    };
  }

  /**
   * Check if dynamic registration is supported
   */
  supportsDynamicRegistration(): boolean {
    // Dynamic registration is supported if we have an API token
    // or if we're handling Claude.ai (which uses pre-configured client)
    return !!this.config.registrationApiToken || true; // Always return true for Claude.ai fallback
  }

  /**
   * Test if the API token has the required permissions for dynamic registration
   */
  async validateRegistrationToken(): Promise<boolean> {
    if (!this.config.registrationApiToken) {
      return false;
    }

    try {
      // Test by making a simple API call that requires the necessary permissions
      const response = await axios.get(
        `${this.config.url}/api/v3/providers/oauth2/?page_size=1`,
        {
          headers: {
            'Authorization': `Bearer ${this.config.registrationApiToken}`
          }
        }
      );

      return response.status === 200;
    } catch (error) {
      console.error('API token validation failed:', error);
      return false;
    }
  }

  /**
   * Handle dynamic client registration
   */
  async registerClient(request: ClientRegistrationRequest): Promise<ClientRegistrationResponse> {
    // Dynamic registration using Authentik API
    if (!this.config.registrationApiToken) {
      throw new Error('Dynamic registration requires API token configuration');
    }

    try {
      // Generate a unique name for the provider and application
      const timestamp = Date.now();
      const providerName = `mcp-${request.client_name}-${timestamp}`;
      const appName = `MCP ${request.client_name}`;

      // Step 1: Create OAuth2 Provider
      const providerResponse = await axios.post(
        `${this.config.url}/api/v3/providers/oauth2/`,
        {
          name: providerName,
          authentication_flow: this.config.authenticationFlowId,
          invalidation_flow: this.config.invalidationFlowId,
          authorization_flow: this.config.authorizationFlowId,
          client_type: 'confidential',
          client_id: `mcp-${timestamp}`,
          redirect_uris: request.redirect_uris.join('\n'),
          signing_key: this.config.signingKeyId,
          access_code_validity: 'minutes=10',
          access_token_validity: 'minutes=5',
          refresh_token_validity: 'days=30',
          include_claims_in_id_token: true,
          issuer_mode: 'per_provider',
          scopes: request.scope || 'openid profile email',
          sub_mode: 'user_id'
        },
        {
          headers: {
            'Authorization': `Bearer ${this.config.registrationApiToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      const provider = providerResponse.data;

      // Step 2: Create Application
      const applicationResponse = await axios.post(
        `${this.config.url}/api/v3/core/applications/`,
        {
          name: appName,
          slug: `mcp-${request.client_name.replaceAll(' ', '_')}-${timestamp}`,
          provider: provider.pk,
          meta_launch_url: request.redirect_uris[0] || '',
          meta_description: `MCP application for ${request.client_name}`,
          meta_publisher: 'MCP Framework',
          policy_engine_mode: 'any',
          open_in_new_tab: false
        },
        {
          headers: {
            'Authorization': `Bearer ${this.config.registrationApiToken}`,
            'Content-Type': 'application/json'
          }
        }
      );

      const application = applicationResponse.data;

      // Step 3: Get the client secret from the provider
      const providerDetailsResponse = await axios.get(
        `${this.config.url}/api/v3/providers/oauth2/${provider.pk}/`,
        {
          headers: {
            'Authorization': `Bearer ${this.config.registrationApiToken}`
          }
        }
      );

      const clientSecret = providerDetailsResponse.data.client_secret;

      // Return the registration response
      return {
        client_id: provider.client_id,
        client_secret: clientSecret,
        registration_access_token: this.config.registrationApiToken,
        registration_client_uri: `${this.config.url}/api/v3/core/applications/${application.pk}/`,
        client_id_issued_at: Math.floor(Date.now() / 1000),
        client_secret_expires_at: 0, // Authentik doesn't expire client secrets by default
        redirect_uris: request.redirect_uris,
        token_endpoint_auth_method: 'client_secret_post',
        grant_types: request.grant_types || ['authorization_code', 'refresh_token'],
        response_types: request.response_types || ['code'],
        scope: request.scope || 'openid profile email',
        // Additional Authentik-specific fields
        provider_pk: provider.pk,
        application_pk: application.pk,
        application_slug: application.slug
      };

    } catch (error: any) {
      console.error('Authentik dynamic registration failed:', error);
      
      const errorInfo = AuthentikErrorHandler.mapApiError(error);
      const oauthError = createOAuthError(errorInfo.code, errorInfo.description);
      
      const errorObj = new Error(`Client registration failed: ${errorInfo.description}`);
      (errorObj as any).oauthError = oauthError;
      (errorObj as any).statusCode = errorInfo.status;
      throw errorObj;
    }
  }

  /**
   * Revoke/delete a dynamically registered client
   */
  async revokeRegistration(clientId: string, registrationAccessToken?: string): Promise<void> {
    if (!this.config.registrationApiToken && !registrationAccessToken) {
      throw new Error('API token required for client revocation');
    }

    const token = registrationAccessToken || this.config.registrationApiToken;

    try {
      // First, find the provider with this client_id
      const providersResponse = await axios.get(
        `${this.config.url}/api/v3/providers/oauth2/?client_id=${encodeURIComponent(clientId)}`,
        {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        }
      );

      const providers = providersResponse.data.results;
      if (!providers || providers.length === 0) {
        console.warn(`No provider found with client_id: ${clientId}`);
        return;
      }

      const provider = providers[0];

      // Find applications using this provider
      const applicationsResponse = await axios.get(
        `${this.config.url}/api/v3/core/applications/?provider=${provider.pk}`,
        {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        }
      );

      const applications = applicationsResponse.data.results;

      // Delete applications first
      for (const app of applications) {
        await axios.delete(
          `${this.config.url}/api/v3/core/applications/${app.pk}/`,
          {
            headers: {
              'Authorization': `Bearer ${token}`
            }
          }
        );
        console.log(`Deleted application: ${app.name}`);
      }

      // Then delete the provider
      await axios.delete(
        `${this.config.url}/api/v3/providers/oauth2/${provider.pk}/`,
        {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        }
      );
      
      console.log(`Deleted OAuth2 provider: ${provider.name}`);

    } catch (error: any) {
      console.error('Failed to revoke client registration:', error);
      
      if (axios.isAxiosError(error)) {
        const status = error.response?.status;
        if (status === 404) {
          console.warn(`Client ${clientId} not found or already deleted`);
          return;
        }
      }
      
      const errorInfo = AuthentikErrorHandler.mapApiError(error);
      const oauthError = createOAuthError(errorInfo.code, errorInfo.description);
      
      const errorObj = new Error(`Client revocation failed: ${errorInfo.description}`);
      (errorObj as any).oauthError = oauthError;
      (errorObj as any).statusCode = errorInfo.status;
      throw errorObj;
    }
  }

  /**
   * Setup OAuth routes
   */
  setupRoutes(router: Router): void {
    // Initialize passport first
    this.initialize().catch(console.error);

    // Login route
    router.get('/auth/login', (req, res, next) => {
      // Ensure passport is initialized
      if (!this.passportInitialized) {
        const errorResponse = createOAuthError(
          'temporarily_unavailable',
          'Authentication system initializing'
        );
        res.status(503).json(errorResponse);
        return;
      }
      passport.authenticate('authentik')(req, res, next);
    });

    // Callback route
    router.get('/auth/callback',
      (req, res, next) => {
        if (!this.passportInitialized) {
          const errorResponse = createOAuthError(
            'temporarily_unavailable',
            'Authentication system initializing'
          );
          res.status(503).json(errorResponse);
          return;
        }
        next();
      },
      passport.authenticate('authentik', {
        failureRedirect: '/auth/error'
      }),
      (_req, res) => {
        res.redirect('/');
      }
    );

    // Logout route
    router.post('/auth/logout', (req, res) => {
      (req as any).logout((err: any) => {
        if (err) {
          const errorResponse = createOAuthError(
            'server_error',
            'Logout failed'
          );
          res.status(500).json(errorResponse);
          return;
        }
        res.json({ success: true });
      });
    });

    // User info
    router.get('/auth/user', (req, res) => {
      const user = this.getUser(req);
      if (!user) {
        res.set('WWW-Authenticate', 'Bearer');
        const errorResponse = createOAuthError(
          'unauthorized',
          'Authentication required'
        );
        res.status(401).json(errorResponse);
        return;
      }
      res.json({ user });
    });

    // Error page
    router.get('/auth/error', (_req, res) => {
      const errorResponse = createOAuthError(
        'access_denied',
        'Authentication failed. Please check your credentials and try again.'
      );
      res.status(401).json(errorResponse);
    });

    // Setup session middleware
    router.use(session({
      secret: this.config.sessionSecret!,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      }
    }));

    // Initialize passport middleware
    router.use(passport.initialize());
    router.use(passport.session());
  }

  /**
   * Revoke a token (if supported by Authentik)
   */
  async revokeToken(token: string, tokenType: 'access_token' | 'refresh_token' = 'access_token'): Promise<void> {
    const discovery = await this.getDiscovery();

    if (!discovery.revocation_endpoint) {
      console.warn('Authentik does not support token revocation');
      return;
    }

    const params = new URLSearchParams({
      token,
      token_type_hint: tokenType,
      client_id: this.config.clientId,
    });

    if (this.config.clientSecret) {
      params.set('client_secret', this.config.clientSecret);
    }

    try {
      await axios.post(discovery.revocation_endpoint, params.toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });
    } catch (error) {
      console.error('Failed to revoke token:', error);
      // Token revocation failures are often not critical
    }
  }
}

/**
 * Utility function to create Authentik auth quickly
 */
export function createAuthentikAuth(config: AuthentikConfig): AuthentikAuth {
  return new AuthentikAuth(config);
}
