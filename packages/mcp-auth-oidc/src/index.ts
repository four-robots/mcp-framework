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
import jwt from 'jsonwebtoken';
import { createPublicKey } from 'crypto';
import fetch from 'node-fetch';
import { z } from 'zod';

/**
 * Extended token result with OIDC ID token
 */
export interface OIDCTokenResult extends TokenResult {
  idToken?: string;
}

/**
 * Session configuration for Passport.js OIDC login flow
 */
export interface OIDCSessionConfig {
  /** Secret for signing the session cookie (required) */
  secret: string;
  /** Full callback URL for the OIDC redirect (required) */
  callbackUrl: string;
  /** Session cookie options */
  cookie?: {
    /** Set secure cookie flag (default: true in production) */
    secure?: boolean;
    /** Cookie httpOnly flag (default: true) */
    httpOnly?: boolean;
    /** Cookie max age in milliseconds (default: 86400000 / 24 hours) */
    maxAge?: number;
    /** SameSite attribute for CSRF protection (default: 'lax') */
    sameSite?: 'strict' | 'lax' | 'none';
  };
  /** Route prefix for auth routes (default: '/auth') */
  routePrefix?: string;
  /** Redirect URL after successful login (default: '/') */
  successRedirect?: string;
  /** Redirect URL on auth failure (default: '{routePrefix}/error') */
  failureRedirect?: string;
}

/**
 * Generic OIDC provider configuration
 */
export interface OIDCConfig {
  // Discovery endpoint or manual configuration
  discoveryUrl?: string;
  issuer?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userinfoEndpoint?: string;
  jwksUri?: string;
  revocationEndpoint?: string;
  introspectionEndpoint?: string;
  registrationEndpoint?: string;

  // Client configuration
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  scopes?: string[];

  // Token validation
  validateAudience?: boolean;
  expectedAudience?: string | string[];
  validateIssuer?: boolean;
  clockTolerance?: number;

  // Claims mapping
  idClaim?: string; // Default: 'sub'
  usernameClaim?: string; // Default: 'preferred_username' or 'email'
  emailClaim?: string; // Default: 'email'
  nameClaim?: string; // Default: 'name'
  groupsClaim?: string; // Default: 'groups' or 'roles'

  // Access control
  allowedGroups?: string[];

  // Advanced options
  tokenEndpointAuthMethod?: 'client_secret_basic' | 'client_secret_post' | 'none';
  useIdToken?: boolean; // Use ID token for user info instead of userinfo endpoint
  additionalAuthParams?: Record<string, string>;

  // Session-based authentication (opt-in)
  session?: OIDCSessionConfig;
}

/**
 * OIDC discovery response schema
 */
const OIDCDiscoverySchema = z.object({
  issuer: z.string(),
  authorization_endpoint: z.string(),
  token_endpoint: z.string(),
  userinfo_endpoint: z.string().optional(),
  jwks_uri: z.string(),
  revocation_endpoint: z.string().optional(),
  introspection_endpoint: z.string().optional(),
  registration_endpoint: z.string().optional(),
  scopes_supported: z.array(z.string()).optional(),
  response_types_supported: z.array(z.string()).optional(),
  grant_types_supported: z.array(z.string()).optional(),
  subject_types_supported: z.array(z.string()).optional(),
  id_token_signing_alg_values_supported: z.array(z.string()).optional(),
  token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
  code_challenge_methods_supported: z.array(z.string()).optional(),
});

type OIDCDiscoveryType = z.infer<typeof OIDCDiscoverySchema>;

/**
 * Token response schema
 */
const TokenResponseSchema = z.object({
  access_token: z.string(),
  token_type: z.string(),
  expires_in: z.number().optional(),
  refresh_token: z.string().optional(),
  scope: z.string().optional(),
  id_token: z.string().optional(),
});

/**
 * Generic OpenID Connect provider implementation
 */
export class OIDCProvider extends OAuthProvider {
  private config: Required<OIDCConfig>;
  private discoveryCache: OIDCDiscoveryType | null = null;
  private discoveryCachedAt = 0;
  private static DISCOVERY_CACHE_TTL = 3600000; // 1 hour
  private jwksCache: { keys: any[]; fetchedAt: number } | null = null;
  private jwksFetchPromise: Promise<any[]> | null = null;
  private discoveryFetchPromise: Promise<void> | null = null;
  private passportInitialized = false;
  private initializationError: Error | null = null;
  private sessionEnabled: boolean;

  constructor(config: OIDCConfig) {
    super();

    this.sessionEnabled = !!config.session;

    // Validate session config
    if (config.session && !config.session.secret) {
      throw new Error('Session secret is required when session support is enabled');
    }

    // Apply defaults
    this.config = {
      scopes: ['openid', 'profile', 'email'],
      idClaim: 'sub',
      usernameClaim: 'preferred_username',
      emailClaim: 'email',
      nameClaim: 'name',
      groupsClaim: 'groups',
      validateAudience: true,
      validateIssuer: true,
      clockTolerance: 60,
      tokenEndpointAuthMethod: 'client_secret_post',
      useIdToken: false,
      allowedGroups: [],
      additionalAuthParams: {},
      ...config
    } as Required<OIDCConfig>;

    // Validate configuration
    if (!config.discoveryUrl && (!config.issuer || !config.authorizationEndpoint || !config.tokenEndpoint)) {
      throw new Error('Either discoveryUrl or manual endpoint configuration (issuer, authorizationEndpoint, tokenEndpoint) must be provided');
    }

    // When using ID token verification without discovery, jwksUri is required for signature validation
    if (!config.discoveryUrl && config.useIdToken && !config.jwksUri) {
      throw new Error('jwksUri is required when useIdToken is true and discoveryUrl is not provided');
    }
  }

  /**
   * Initialize the provider
   */
  async initialize(): Promise<void> {
    // Fetch discovery document if using discovery URL
    if (this.config.discoveryUrl) {
      await this.fetchDiscovery();
    }

    // Initialize Passport if session support is enabled
    if (this.sessionEnabled && !this.passportInitialized) {
      await this.initializePassport();
    }
  }

  /**
   * Initialize Passport.js with the OpenID Connect strategy
   */
  private async initializePassport(): Promise<void> {
    if (this.passportInitialized) {
      return;
    }

    const discovery = await this.getDiscovery();
    const sessionConfig = this.config.session!;

    passport.use('oidc', new OpenIDConnectStrategy({
      issuer: discovery.issuer,
      authorizationURL: discovery.authorization_endpoint,
      tokenURL: discovery.token_endpoint,
      userInfoURL: discovery.userinfo_endpoint || '',
      clientID: this.config.clientId,
      clientSecret: this.config.clientSecret || '',
      callbackURL: sessionConfig.callbackUrl,
      scope: this.config.scopes,
      skipUserProfile: false,
    }, this.passportVerifyCallback.bind(this)) as any);

    passport.serializeUser((user: any, done) => {
      done(null, user);
    });

    passport.deserializeUser((user: any, done) => {
      done(null, user);
    });

    this.passportInitialized = true;
  }

  /**
   * Passport verify callback — converts OIDC profile to User
   */
  private async passportVerifyCallback(
    _issuer: string,
    profile: any,
    done: (error: any, user?: any) => void
  ): Promise<void> {
    try {
      const claims = profile._json || profile;
      const user = this.mapClaimsToUser(claims);
      if (!user) {
        done(new Error('User not authorized'));
        return;
      }
      done(null, user);
    } catch (error) {
      done(error);
    }
  }

  /**
   * Fetch and cache OIDC discovery document
   */
  private async fetchDiscovery(): Promise<void> {
    if (!this.config.discoveryUrl) {
      throw new Error('Discovery URL not configured');
    }

    // Coalesce concurrent fetches into a single request
    if (this.discoveryFetchPromise) {
      return this.discoveryFetchPromise;
    }

    this.discoveryFetchPromise = this.doFetchDiscovery();
    try {
      await this.discoveryFetchPromise;
    } finally {
      this.discoveryFetchPromise = null;
    }
  }

  private async doFetchDiscovery(): Promise<void> {
    try {
      const response = await fetch(this.config.discoveryUrl!);
      if (!response.ok) {
        throw new Error(`Failed to fetch discovery document: ${response.statusText}`);
      }

      const data = await response.json();
      this.discoveryCache = OIDCDiscoverySchema.parse(data);
      this.discoveryCachedAt = Date.now();
    } catch (error) {
      console.error('Failed to fetch OIDC discovery:', error);
      throw new Error(`Failed to fetch OIDC configuration: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Get discovery configuration
   */
  private async getDiscovery(): Promise<OIDCDiscoveryType> {
    const cacheValid = this.discoveryCache && (Date.now() - this.discoveryCachedAt) < OIDCProvider.DISCOVERY_CACHE_TTL;
    if (cacheValid) {
      return this.discoveryCache!;
    }

    if (this.config.discoveryUrl) {
      await this.fetchDiscovery();
      return this.discoveryCache!;
    }
    
    // Build discovery from manual configuration
    return {
      issuer: this.config.issuer!,
      authorization_endpoint: this.config.authorizationEndpoint!,
      token_endpoint: this.config.tokenEndpoint!,
      userinfo_endpoint: this.config.userinfoEndpoint,
      jwks_uri: this.config.jwksUri!,
      revocation_endpoint: this.config.revocationEndpoint,
      introspection_endpoint: this.config.introspectionEndpoint,
      registration_endpoint: this.config.registrationEndpoint,
      scopes_supported: this.config.scopes,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      code_challenge_methods_supported: ['S256', 'plain'],
    };
  }

  /**
   * Get authorization URL
   */
  async getAuthUrl(
    state?: string,
    redirectUri?: string,
    resource?: string,
    pkceParams?: PKCEParams
  ): Promise<string> {
    const discovery = await this.getDiscovery();
    
    // Validate HTTPS endpoint
    if (!this.validateHttpsEndpoint(discovery.authorization_endpoint)) {
      throw new Error('Authorization endpoint must use HTTPS in production');
    }
    
    // Validate resource URI if provided
    if (resource && !this.validateResourceUri(resource)) {
      throw new Error('Invalid resource URI format');
    }
    
    const params = new URLSearchParams({
      ...this.config.additionalAuthParams,
      client_id: this.config.clientId,
      response_type: 'code',
      scope: this.config.scopes.join(' '),
      redirect_uri: redirectUri || this.config.redirectUri || '',
    });
    
    if (state) {
      params.set('state', state);
    }
    
    if (resource) {
      params.set('resource', resource);
    }
    
    if (pkceParams) {
      params.set('code_challenge', pkceParams.codeChallenge);
      params.set('code_challenge_method', pkceParams.codeChallengeMethod);
    }
    
    return `${discovery.authorization_endpoint}?${params.toString()}`;
  }

  /**
   * Handle OAuth callback
   */
  async handleCallback(
    code: string,
    state?: string,
    redirectUri?: string,
    resource?: string,
    codeVerifier?: string
  ): Promise<OIDCTokenResult> {
    const discovery = await this.getDiscovery();
    
    // Validate HTTPS endpoint
    if (!this.validateHttpsEndpoint(discovery.token_endpoint)) {
      throw new Error('Token endpoint must use HTTPS in production');
    }
    
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri || this.config.redirectUri || '',
      client_id: this.config.clientId,
    });
    
    if (this.config.clientSecret && this.config.tokenEndpointAuthMethod === 'client_secret_post') {
      params.set('client_secret', this.config.clientSecret);
    }
    
    if (resource) {
      params.set('resource', resource);
    }
    
    if (codeVerifier) {
      params.set('code_verifier', codeVerifier);
    }
    
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/x-www-form-urlencoded',
      };
      
      // Add basic auth if using client_secret_basic
      if (this.config.clientSecret && this.config.tokenEndpointAuthMethod === 'client_secret_basic') {
        const credentials = Buffer.from(`${encodeURIComponent(this.config.clientId)}:${encodeURIComponent(this.config.clientSecret)}`).toString('base64');
        headers['Authorization'] = `Basic ${credentials}`;
      }
      
      const response = await fetch(discovery.token_endpoint, {
        method: 'POST',
        headers,
        body: params.toString(),
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        if (errorData && typeof errorData === 'object' && 'error' in errorData) {
          const errorCode = String(errorData.error || 'server_error');
          const errorDesc = (errorData as any).error_description ? String((errorData as any).error_description) : undefined;
          const errorMessage = errorDesc ? `${errorCode}: ${errorDesc}` : errorCode;
          throw new Error(errorMessage);
        }
        throw new Error(`Token exchange failed: ${response.statusText}`);
      }
      
      const data = await response.json();
      const tokenResponse = TokenResponseSchema.parse(data);
      
      return {
        accessToken: tokenResponse.access_token,
        refreshToken: tokenResponse.refresh_token,
        tokenType: tokenResponse.token_type,
        expiresIn: tokenResponse.expires_in,
        scope: tokenResponse.scope,
        idToken: tokenResponse.id_token,
      };
    } catch (error) {
      console.error('Failed to exchange code for tokens:', error);
      if ((error as any).error) {
        // Convert OAuth error to regular Error
        const errorMessage = String((error as any).error || 'OAuth error');
        throw new Error(errorMessage);
      }
      throw new Error(error instanceof Error ? error.message : 'Token exchange failed');
    }
  }

  /**
   * Verify an access token
   */
  async verifyToken(token: string, expectedAudience?: string | string[]): Promise<User | null> {
    try {
      // If using ID tokens, decode and verify the ID token
      if (this.config.useIdToken) {
        return this.verifyIdToken(token, expectedAudience);
      }
      
      // Otherwise, use the userinfo endpoint
      const discovery = await this.getDiscovery();
      
      if (!discovery.userinfo_endpoint) {
        throw new Error('UserInfo endpoint not available');
      }
      
      // Validate HTTPS endpoint
      if (!this.validateHttpsEndpoint(discovery.userinfo_endpoint)) {
        throw new Error('UserInfo endpoint must use HTTPS in production');
      }
      
      const response = await fetch(discovery.userinfo_endpoint, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (!response.ok) {
        if (response.status === 401) {
          return null; // Invalid token
        }
        throw new Error(`UserInfo request failed: ${response.statusText}`);
      }
      
      const userInfo = await response.json();
      return this.mapClaimsToUser(userInfo);
    } catch (error) {
      console.error('Failed to verify token:', error);
      // Check if it's a 401 error (unauthorized token)
      if (error instanceof Error && (
        error.message.includes('401') || 
        error.message.includes('Unauthorized')
      )) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Fetch JWKS from the provider's jwks_uri endpoint
   */
  private async fetchJwks(): Promise<any[]> {
    const JWKS_CACHE_TTL = 3600000; // 1 hour
    if (this.jwksCache && (Date.now() - this.jwksCache.fetchedAt) < JWKS_CACHE_TTL) {
      return this.jwksCache.keys;
    }

    // Coalesce concurrent fetches into a single request
    if (this.jwksFetchPromise) {
      return this.jwksFetchPromise;
    }

    this.jwksFetchPromise = this.doFetchJwks();
    try {
      return await this.jwksFetchPromise;
    } finally {
      this.jwksFetchPromise = null;
    }
  }

  private async doFetchJwks(): Promise<any[]> {
    const discovery = await this.getDiscovery();
    if (!discovery.jwks_uri) {
      throw new Error('JWKS URI not available in discovery configuration');
    }

    const response = await fetch(discovery.jwks_uri);
    if (!response.ok) {
      throw new Error(`Failed to fetch JWKS: ${response.statusText}`);
    }

    const data = await response.json() as { keys: any[] };
    if (!data.keys || !Array.isArray(data.keys)) {
      throw new Error('Invalid JWKS response: missing keys array');
    }

    this.jwksCache = { keys: data.keys, fetchedAt: Date.now() };
    return data.keys;
  }

  /**
   * Get the signing key for a given key ID from JWKS
   */
  private async getSigningKey(kid: string): Promise<string> {
    let keys = await this.fetchJwks();
    let key = keys.find(k => k.kid === kid && k.use !== 'enc');

    // If key not found, refetch in case keys were rotated
    if (!key) {
      this.jwksCache = null;
      keys = await this.fetchJwks();
      key = keys.find(k => k.kid === kid && k.use !== 'enc');
    }

    if (!key) {
      throw new Error(`Signing key not found for kid: ${kid}`);
    }

    // Convert JWK to PEM using Node.js crypto
    const publicKey = createPublicKey({ key, format: 'jwk' });
    return publicKey.export({ type: 'spki', format: 'pem' }) as string;
  }

  /**
   * Verify ID token with signature verification and claim validation
   */
  private async verifyIdToken(idToken: string, expectedAudience?: string | string[]): Promise<User | null> {
    try {
      // Decode header to get kid
      const header = jwt.decode(idToken, { complete: true });
      if (!header || typeof header === 'string') {
        throw new Error('Invalid ID token format');
      }

      const kid = header.header.kid;
      if (!kid) {
        throw new Error('ID token missing kid in header');
      }

      // Get the signing key and verify
      const signingKey = await this.getSigningKey(kid);
      // Whitelist allowed signing algorithms to prevent algorithm confusion attacks
      const allowedAlgorithms: jwt.Algorithm[] = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'];
      const tokenAlg = header.header.alg;
      const algorithms: jwt.Algorithm[] = (tokenAlg && allowedAlgorithms.includes(tokenAlg as jwt.Algorithm))
        ? [tokenAlg as jwt.Algorithm]
        : ['RS256'];

      const verifyOptions: jwt.VerifyOptions = {
        algorithms,
        clockTolerance: this.config.clockTolerance,
      };

      // Validate issuer
      if (this.config.validateIssuer) {
        const discovery = await this.getDiscovery();
        verifyOptions.issuer = discovery.issuer;
      }

      // Validate audience
      if (this.config.validateAudience) {
        const audience = expectedAudience || this.config.expectedAudience || this.config.clientId;
        if (audience) {
          verifyOptions.audience = typeof audience === 'string' ? audience : (audience as [string, ...string[]]);
        }
      }

      const decoded = jwt.verify(idToken, signingKey, verifyOptions) as jwt.JwtPayload;
      return this.mapClaimsToUser(decoded);
    } catch (error) {
      console.error('ID token verification failed:', error);
      return null;
    }
  }

  /**
   * Map OIDC claims to User object
   */
  private mapClaimsToUser(claims: any): User | null {
    const id = claims[this.config.idClaim];
    if (!id) {
      console.error(`Missing required claim: ${this.config.idClaim}`);
      return null;
    }
    
    const username = claims[this.config.usernameClaim] || claims[this.config.emailClaim] || id;
    const email = claims[this.config.emailClaim] || '';
    const name = claims[this.config.nameClaim] || '';
    const rawGroups = claims[this.config.groupsClaim] || [];
    // Normalize to array to prevent String.prototype.includes substring matching
    const groups: string[] = Array.isArray(rawGroups) ? rawGroups.map(g => String(g)) : [String(rawGroups)];

    // Check group restrictions
    if (this.config.allowedGroups && this.config.allowedGroups.length > 0) {
      const hasAllowedGroup = this.config.allowedGroups.some(
        group => groups.includes(group)
      );
      
      if (!hasAllowedGroup) {
        console.warn(`User ${id} not in allowed groups`);
        return null;
      }
    }
    
    return {
      // Include all other claims as extra metadata
      ...claims,
      // Explicit sanitized fields override raw claims
      id: String(id),
      username: String(username),
      email: String(email),
      name: String(name),
      groups,
    };
  }

  /**
   * Refresh an access token
   */
  async refreshToken(refreshToken: string, resource?: string): Promise<OIDCTokenResult> {
    const discovery = await this.getDiscovery();
    
    // Validate HTTPS endpoint
    if (!this.validateHttpsEndpoint(discovery.token_endpoint)) {
      throw new Error('Token endpoint must use HTTPS in production');
    }
    
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this.config.clientId,
    });
    
    if (this.config.clientSecret && this.config.tokenEndpointAuthMethod === 'client_secret_post') {
      params.set('client_secret', this.config.clientSecret);
    }
    
    if (resource) {
      params.set('resource', resource);
    }
    
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/x-www-form-urlencoded',
      };
      
      // Add basic auth if using client_secret_basic
      if (this.config.clientSecret && this.config.tokenEndpointAuthMethod === 'client_secret_basic') {
        const credentials = Buffer.from(`${encodeURIComponent(this.config.clientId)}:${encodeURIComponent(this.config.clientSecret)}`).toString('base64');
        headers['Authorization'] = `Basic ${credentials}`;
      }
      
      const response = await fetch(discovery.token_endpoint, {
        method: 'POST',
        headers,
        body: params.toString(),
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        if (errorData && typeof errorData === 'object' && 'error' in errorData) {
          const errorCode = String(errorData.error || 'server_error');
          const errorDesc = (errorData as any).error_description ? String((errorData as any).error_description) : undefined;
          const errorMessage = errorDesc ? `${errorCode}: ${errorDesc}` : errorCode;
          throw new Error(errorMessage);
        }
        throw new Error(`Token refresh failed: ${response.statusText}`);
      }
      
      const data = await response.json();
      const tokenResponse = TokenResponseSchema.parse(data);
      
      return {
        accessToken: tokenResponse.access_token,
        refreshToken: tokenResponse.refresh_token,
        tokenType: tokenResponse.token_type,
        expiresIn: tokenResponse.expires_in,
        scope: tokenResponse.scope,
        idToken: tokenResponse.id_token,
      };
    } catch (error) {
      console.error('Failed to refresh token:', error);
      if ((error as any).error) {
        // Convert OAuth error to regular Error
        const errorMessage = String((error as any).error || 'OAuth error');
        throw new Error(errorMessage);
      }
      throw new Error(error instanceof Error ? error.message : 'Token refresh failed');
    }
  }

  /**
   * Revoke a token
   */
  async revokeToken(token: string, tokenType: 'access_token' | 'refresh_token' = 'access_token'): Promise<void> {
    const discovery = await this.getDiscovery();
    
    if (!discovery.revocation_endpoint) {
      console.warn('OIDC provider does not support token revocation');
      return;
    }
    
    // Validate HTTPS endpoint
    if (!this.validateHttpsEndpoint(discovery.revocation_endpoint)) {
      throw new Error('Revocation endpoint must use HTTPS in production');
    }
    
    const params = new URLSearchParams({
      token,
      token_type_hint: tokenType,
      client_id: this.config.clientId,
    });
    
    if (this.config.clientSecret && this.config.tokenEndpointAuthMethod === 'client_secret_post') {
      params.set('client_secret', this.config.clientSecret);
    }
    
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/x-www-form-urlencoded',
      };
      
      // Add basic auth if using client_secret_basic
      if (this.config.clientSecret && this.config.tokenEndpointAuthMethod === 'client_secret_basic') {
        const credentials = Buffer.from(`${encodeURIComponent(this.config.clientId)}:${encodeURIComponent(this.config.clientSecret)}`).toString('base64');
        headers['Authorization'] = `Basic ${credentials}`;
      }
      
      const response = await fetch(discovery.revocation_endpoint, {
        method: 'POST',
        headers,
        body: params.toString(),
      });
      
      if (!response.ok) {
        console.warn(`Token revocation failed: ${response.statusText}`);
      }
    } catch (error) {
      console.error('Failed to revoke token:', error);
      // Token revocation failures are often not critical
    }
  }

  /**
   * Authenticate a request (bearer token or session)
   */
  async authenticate(req: Request): Promise<User | null> {
    // Try bearer token first
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7).trim();
      if (!token) {
        return null;
      }
      const expectedAudience = this.config.expectedAudience || `${req.protocol}://${req.get('host')}`;
      return this.verifyToken(token, expectedAudience);
    }

    // Fall back to session if enabled
    if (this.sessionEnabled && (req as any).user) {
      return (req as any).user;
    }

    return null;
  }

  /**
   * Get user from request (sync)
   */
  getUser(req: Request): User | null {
    if (this.sessionEnabled) {
      return (req as any).user || null;
    }
    return null;
  }

  /**
   * Get OAuth discovery metadata
   */
  getDiscoveryMetadata(baseUrl: string): OAuthDiscovery {
    if (this.discoveryCache) {
      return {
        ...this.discoveryCache,
        issuer: this.discoveryCache.issuer,
        userinfo_endpoint: this.discoveryCache.userinfo_endpoint || `${baseUrl}/userinfo`,
        jwks_uri: this.discoveryCache.jwks_uri,
        scopes_supported: this.discoveryCache.scopes_supported || this.config.scopes,
        response_types_supported: this.discoveryCache.response_types_supported || ['code'],
        grant_types_supported: this.discoveryCache.grant_types_supported || ['authorization_code', 'refresh_token'],
        subject_types_supported: this.discoveryCache.subject_types_supported || ['public'],
      };
    }
    
    // Build from config
    const discovery: OAuthDiscovery = {
      issuer: this.config.issuer || baseUrl,
      authorization_endpoint: this.config.authorizationEndpoint!,
      token_endpoint: this.config.tokenEndpoint!,
      userinfo_endpoint: this.config.userinfoEndpoint || `${baseUrl}/userinfo`,
      jwks_uri: this.config.jwksUri!,
      registration_endpoint: this.config.registrationEndpoint,
      scopes_supported: this.config.scopes,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      code_challenge_methods_supported: ['S256', 'plain'],
    };
    
    return discovery;
  }

  /**
   * Get protected resource metadata
   */
  getProtectedResourceMetadata(baseUrl: string): ProtectedResourceMetadata {
    return {
      resource: baseUrl,
      authorization_servers: [this.config.issuer || this.getDiscoveryMetadata(baseUrl).issuer],
    };
  }

  /**
   * Check if dynamic registration is supported
   */
  supportsDynamicRegistration(): boolean {
    return !!this.config.registrationEndpoint || !!this.discoveryCache?.registration_endpoint;
  }

  /**
   * Register a client dynamically
   */
  async registerClient(request: ClientRegistrationRequest): Promise<ClientRegistrationResponse> {
    const discovery = await this.getDiscovery();
    
    if (!discovery.registration_endpoint) {
      throw new Error('Dynamic client registration not supported by this OIDC provider');
    }
    
    // Validate HTTPS endpoint
    if (!this.validateHttpsEndpoint(discovery.registration_endpoint)) {
      throw new Error('Registration endpoint must use HTTPS in production');
    }
    
    try {
      const response = await fetch(discovery.registration_endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        if (errorData && typeof errorData === 'object' && 'error' in errorData) {
          const errorCode = String(errorData.error || 'server_error');
          const errorDesc = (errorData as any).error_description ? String((errorData as any).error_description) : undefined;
          const errorMessage = errorDesc ? `${errorCode}: ${errorDesc}` : errorCode;
          throw new Error(errorMessage);
        }
        throw new Error(`Client registration failed: ${response.statusText}`);
      }
      
      const data = await response.json();
      return data as ClientRegistrationResponse;
    } catch (error) {
      console.error('Failed to register client:', error);
      if ((error as any).error) {
        // Convert OAuth error to regular Error
        const errorMessage = String((error as any).error || 'OAuth error');
        throw new Error(errorMessage);
      }
      throw new Error(error instanceof Error ? error.message : 'Client registration failed');
    }
  }

  /**
   * Setup OAuth routes with optional session-based authentication
   */
  setupRoutes(router: Router): void {
    if (!this.sessionEnabled) {
      return;
    }

    const sessionConfig = this.config.session!;
    const prefix = sessionConfig.routePrefix || '/auth';
    const failureRedirect = sessionConfig.failureRedirect || `${prefix}/error`;
    const successRedirect = sessionConfig.successRedirect || '/';

    // Initialize passport (non-blocking)
    this.initialize().catch(err => {
      this.initializationError = err instanceof Error ? err : new Error(String(err));
      console.error('Failed to initialize OIDC passport:', err);
    });

    // Session middleware
    router.use(session({
      secret: sessionConfig.secret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: sessionConfig.cookie?.secure ?? (process.env.NODE_ENV === 'production'),
        httpOnly: sessionConfig.cookie?.httpOnly ?? true,
        maxAge: sessionConfig.cookie?.maxAge ?? (24 * 60 * 60 * 1000),
        sameSite: sessionConfig.cookie?.sameSite ?? 'lax',
      },
    }));

    // Passport middleware
    router.use(passport.initialize());
    router.use(passport.session());

    // Login route
    router.get(`${prefix}/login`, (req, res, next) => {
      if (this.initializationError) {
        res.status(503).json(createOAuthError(
          'temporarily_unavailable',
          'Authentication system failed to initialize'
        ));
        return;
      }
      if (!this.passportInitialized) {
        res.status(503).json(createOAuthError(
          'temporarily_unavailable',
          'Authentication system initializing'
        ));
        return;
      }
      passport.authenticate('oidc')(req, res, next);
    });

    // Callback route
    router.get(`${prefix}/callback`,
      (req, res, next) => {
        if (this.initializationError) {
          res.status(503).json(createOAuthError(
            'temporarily_unavailable',
            'Authentication system failed to initialize'
          ));
          return;
        }
        if (!this.passportInitialized) {
          res.status(503).json(createOAuthError(
            'temporarily_unavailable',
            'Authentication system initializing'
          ));
          return;
        }
        next();
      },
      passport.authenticate('oidc', {
        failureRedirect,
      }),
      (_req, res) => {
        res.redirect(successRedirect);
      }
    );

    // Logout route
    router.post(`${prefix}/logout`, (req, res) => {
      (req as any).logout((err: any) => {
        if (err) {
          res.status(500).json(createOAuthError('server_error', 'Logout failed'));
          return;
        }
        // Destroy the session to prevent session fixation
        if ((req as any).session) {
          (req as any).session.destroy((destroyErr: any) => {
            if (destroyErr) {
              console.error('Failed to destroy session:', destroyErr);
            }
            res.json({ success: true });
          });
        } else {
          res.json({ success: true });
        }
      });
    });

    // User info route
    router.get(`${prefix}/user`, (req, res) => {
      const user = this.getUser(req);
      if (!user) {
        res.set('WWW-Authenticate', 'Bearer');
        res.status(401).json(createOAuthError('unauthorized', 'Authentication required'));
        return;
      }
      res.json({ user });
    });

    // Error route
    router.get(`${prefix}/error`, (_req, res) => {
      res.status(401).json(createOAuthError(
        'access_denied',
        'Authentication failed. Please check your credentials and try again.'
      ));
    });
  }
}

/**
 * Utility function to create OIDC provider quickly
 */
export function createOIDCProvider(config: OIDCConfig): OIDCProvider {
  return new OIDCProvider(config);
}

/**
 * Pre-configured provider factories
 */
export const Providers = {
  /**
   * Create Auth0 provider
   */
  Auth0: (domain: string, clientId: string, clientSecret?: string, config?: Partial<OIDCConfig>) =>
    new OIDCProvider({
      ...config,
      discoveryUrl: `https://${domain}/.well-known/openid-configuration`,
      clientId,
      clientSecret,
    }),

  /**
   * Create Okta provider
   */
  Okta: (domain: string, clientId: string, clientSecret?: string, config?: Partial<OIDCConfig>) =>
    new OIDCProvider({
      ...config,
      discoveryUrl: `https://${domain}/.well-known/openid-configuration`,
      clientId,
      clientSecret,
    }),

  /**
   * Create Keycloak provider
   */
  Keycloak: (baseUrl: string, realm: string, clientId: string, clientSecret?: string, config?: Partial<OIDCConfig>) =>
    new OIDCProvider({
      ...config,
      discoveryUrl: `${baseUrl}/realms/${realm}/.well-known/openid-configuration`,
      clientId,
      clientSecret,
    }),

  /**
   * Create Google provider
   */
  Google: (clientId: string, clientSecret: string, config?: Partial<OIDCConfig>) =>
    new OIDCProvider({
      ...config,
      discoveryUrl: 'https://accounts.google.com/.well-known/openid-configuration',
      clientId,
      clientSecret,
    }),

  /**
   * Create Microsoft/Azure AD provider
   */
  Microsoft: (tenantId: string, clientId: string, clientSecret?: string, config?: Partial<OIDCConfig>) =>
    new OIDCProvider({
      ...config,
      discoveryUrl: `https://login.microsoftonline.com/${tenantId}/v2.0/.well-known/openid-configuration`,
      clientId,
      clientSecret,
    }),

  /**
   * Create Authentik provider
   */
  Authentik: (baseUrl: string, applicationSlug: string, clientId: string, clientSecret?: string, config?: Partial<OIDCConfig>) =>
    new OIDCProvider({
      ...config,
      discoveryUrl: `${baseUrl}/application/o/${applicationSlug}/.well-known/openid-configuration`,
      clientId,
      clientSecret,
    }),
};