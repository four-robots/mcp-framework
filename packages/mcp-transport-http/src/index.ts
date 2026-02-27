import express, { Request, Response, Application, Router, RequestHandler } from 'express';
import cors, { CorsOptions } from 'cors';
import helmet from 'helmet';
import { randomUUID } from 'crypto';
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Transport, MCPServer, MCPErrorFactory, MCPErrorCode, formatMCPError } from "@tylercoles/mcp-server";
import type { AuthProvider, User, OAuthProvider } from "@tylercoles/mcp-auth";
import { createOAuthDiscoveryRoutes } from "@tylercoles/mcp-auth";
import { HttpRateLimitMiddleware, type HttpRateLimitConfig } from "@tylercoles/mcp-rate-limit";

/**
 * Session configuration
 */
export interface SessionConfig {
  secret?: string;
  maxAge?: number;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
}

/**
 * CORS configuration
 */
export interface CorsConfig extends CorsOptions {
  // Extends the standard CORS options
}

/**
 * HTTP transport configuration
 */
export interface HttpConfig {
  host?: string;
  port: number;
  cors?: CorsConfig;
  auth?: AuthProvider;
  sessionConfig?: SessionConfig;
  enableDnsRebindingProtection?: boolean;
  allowedHosts?: string[];
  helmetOptions?: any;
  trustProxy?: boolean;
  basePath?: string; // Base path for MCP endpoints (default: '/mcp')
  externalDomain?: string; // External domain for OAuth callbacks
  rateLimit?: HttpRateLimitConfig; // Rate limiting configuration
  enableJsonResponse?: boolean; // Enable JSON responses instead of SSE streams
}

/**
 * HTTP transport implementation with session management and auth integration
 */
export class HttpTransport implements Transport {
  private config: HttpConfig;
  private app: Application | null = null;
  private server: any = null;
  private mcpServer: MCPServer | null = null;
  private transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};
  private authProvider: AuthProvider | null = null;
  private rateLimitMiddleware: HttpRateLimitMiddleware | null = null;

  constructor(config: HttpConfig) {
    this.config = {
      host: config.host || '0.0.0.0',
      basePath: config.basePath || '/mcp',
      enableDnsRebindingProtection: config.enableDnsRebindingProtection ?? true,
      allowedHosts: config.allowedHosts || ['127.0.0.1', 'localhost'],
      ...config
    };

    if (config.auth) {
      this.authProvider = config.auth;
    }

    // Initialize rate limiting if configured
    if (config.rateLimit) {
      this.rateLimitMiddleware = new HttpRateLimitMiddleware(config.rateLimit);
    }
  }

  /**
   * Set or update the auth provider
   */
  useAuth(auth: AuthProvider): void {
    this.authProvider = auth;
  }

  /**
   * Start the HTTP transport
   */
  async start(server: MCPServer): Promise<void> {
    if (this.app) {
      throw new Error('Transport already started');
    }

    this.mcpServer = server;
    this.app = express();

    // Setup middleware
    this.setupMiddleware();

    // Setup routes
    this.setupRoutes();

    // Start the server
    await this.listen();
  }

  /**
   * Stop the HTTP transport
   */
  async stop(): Promise<void> {
    // Close all transports
    for (const transport of Object.values(this.transports)) {
      if (transport.close) {
        transport.close();
      }
    }
    this.transports = {};

    // Close the HTTP server
    if (this.server) {
      await new Promise<void>((resolve) => {
        this.server.close(() => resolve());
      });
    }

    // Cleanup rate limiting resources
    if (this.rateLimitMiddleware) {
      await this.rateLimitMiddleware.cleanup();
      this.rateLimitMiddleware = null;
    }

    this.app = null;
    this.server = null;
    this.mcpServer = null;
  }

  /**
   * Setup Express middleware
   */
  private setupMiddleware(): void {
    if (!this.app) return;

    // Helmet for security headers
    if (this.config.helmetOptions !== false) {
      this.app.use(helmet(this.config.helmetOptions || {
        contentSecurityPolicy: false, // Often causes issues with MCP
      }));
    }

    // CORS
    if (this.config.cors !== undefined) {
      const corsOptions: CorsOptions = {
        credentials: true,
        methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'mcp-session-id'],
        exposedHeaders: ['mcp-session-id'],
        ...this.config.cors
      };

      this.app.use(cors(corsOptions));
    }

    // Body parsing
    this.app.use(express.json({ limit: '1mb' }));

    // Trust proxy if configured
    if (this.config.trustProxy) {
      this.app.set('trust proxy', 1);
    }

    // Global rate limiting (before authentication for DDoS protection)
    if (this.rateLimitMiddleware) {
      this.app.use(this.rateLimitMiddleware.createGlobalMiddleware());
    }
  }

  /**
   * Check if auth provider is OAuth provider
   */
  private isOAuthProvider(provider: AuthProvider): provider is OAuthProvider {
    return 'getDiscoveryMetadata' in provider &&
      'getProtectedResourceMetadata' in provider &&
      'getAuthUrl' in provider;
  }

  /**
   * Setup MCP routes
   */
  private setupRoutes(): void {
    if (!this.app || !this.mcpServer) return;

    const basePath = this.config.basePath!;

    // Setup OAuth discovery routes if using OAuth provider
    if (this.authProvider && this.isOAuthProvider(this.authProvider)) {
      const oauthRoutes = createOAuthDiscoveryRoutes(this.authProvider);
      this.app.use('/', oauthRoutes);
    }

    // Apply auth middleware if configured
    if (this.authProvider) {
      this.app.use(basePath, this.createAuthMiddleware());
    }

    // Per-client rate limiting (after authentication for client-specific limits)
    if (this.rateLimitMiddleware) {
      this.app.use(basePath, this.rateLimitMiddleware.createClientMiddleware());
    }

    // Handle POST requests for client-to-server communication
    this.app.post(basePath, async (req: Request, res: Response) => {
      try {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        let transport: StreamableHTTPServerTransport;

        if (sessionId && this.transports[sessionId]) {
          // Reuse existing transport
          transport = this.transports[sessionId];
        } else {
          // Create new transport for new session
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (newSessionId) => {
              // Store the transport by session ID
              this.transports[newSessionId] = transport;
            },
            enableDnsRebindingProtection: this.config.enableDnsRebindingProtection,
            allowedHosts: this.config.allowedHosts,
            enableJsonResponse: this.config.enableJsonResponse,
          });

          // Clean up transport when closed
          transport.onclose = () => {
            if (transport.sessionId) {
              delete this.transports[transport.sessionId];
            }
          };

          // Connect the MCP server to this transport
          const sdkServer = this.mcpServer!.getSDKServer();
          await sdkServer.connect(transport);
        }

        // Update server context with user info if available
        if (this.authProvider) {
          const user = (req as any).user as User | undefined;
          if (user) {
            this.mcpServer!.setContext({ user });
          }
        }

        // Handle the request through the transport
        await transport.handleRequest(req, res, req.body);

      } catch (error) {
        console.error('MCP request failed:', error);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: {
              code: -32603,
              message: 'Internal server error',
            },
            id: req.body?.id || null,
          });
        }
      }
    });

    // Handle GET requests for server-to-client notifications via SSE
    this.app.get(basePath, async (req: Request, res: Response) => {
      try {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        if (!sessionId || !this.transports[sessionId]) {
          res.status(400).send('Invalid or missing session ID');
          return;
        }

        const transport = this.transports[sessionId];
        await transport.handleRequest(req, res);
      } catch (error) {
        console.error('MCP SSE request failed:', error);
        if (!res.headersSent) {
          res.status(500).send('Internal server error');
        }
      }
    });

    // Handle DELETE requests for session termination
    this.app.delete(basePath, async (req: Request, res: Response) => {
      try {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        if (!sessionId || !this.transports[sessionId]) {
          res.status(400).send('Invalid or missing session ID');
          return;
        }

        const transport = this.transports[sessionId];
        await transport.handleRequest(req, res);

        // Clean up the transport
        delete this.transports[sessionId];

      } catch (error) {
        console.error('MCP DELETE request failed:', error);
        if (!res.headersSent) {
          res.status(500).send('Internal server error');
        }
      }
    });

    // Health check endpoint
    this.app.get('/health', (_req: Request, res: Response) => {
      res.json({
        status: 'ok',
        transport: 'streamableHttp',
        timestamp: new Date().toISOString(),
        sessions: Object.keys(this.transports).length
      });
    });
  }

  /**
   * Create auth middleware
   */
  private createAuthMiddleware() {
    return async (req: Request, res: Response, next: any) => {
      if (!this.authProvider) {
        next();
        return;
      }

      try {
        const user = await this.authProvider.authenticate(req);
        if (user) {
          (req as any).user = user;
          next();
        } else {
          // Return 401 with WWW-Authenticate header for MCP compliance
          const baseUrl = this.getBaseUrl(req);
          res.status(401)
            .header('WWW-Authenticate', `Bearer realm="${baseUrl}", resource="${baseUrl}/.well-known/oauth-protected-resource"`)
            .json({ error: 'Authentication required' });
        }
      } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).json({ error: 'Authentication failed' });
      }
    };
  }

  /**
   * Get base URL from request or config
   */
  private getBaseUrl(req: Request): string {
    if (this.config.externalDomain) {
      return `https://${this.config.externalDomain}`;
    }
    return `${req.protocol}://${req.get('host')}`;
  }

  /**
   * Start listening on the configured port
   */
  private async listen(): Promise<void> {
    if (!this.app) return;

    return new Promise((resolve, reject) => {
      try {
        this.server = this.app!.listen(
          this.config.port,
          this.config.host!,
          () => {
            console.log(`MCP HTTP transport listening on ${this.config.host}:${this.config.port}`);
            resolve();
          }
        );
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Get the Express app instance (for advanced customization)
   */
  getApp(): Application | null {
    return this.app;
  }

  /**
   * Get active session count
   */
  getSessionCount(): number {
    return Object.keys(this.transports).length;
  }

  /**
   * Get the port the server is listening on
   * @returns Port number or undefined if not started
   */
  getPort(): number | undefined {
    if (!this.server || !this.server.listening) {
      return undefined;
    }
    const address = this.server.address();
    if (address && typeof address === 'object') {
      return address.port;
    }
    return undefined;
  }

  /**
   * Register a router with optional authentication
   * @param path - The base path for the router
   * @param router - Express router instance
   * @param requireAuth - Whether to require authentication for this router
   */
  registerRouter(path: string, router: Router, requireAuth = false): void {
    if (!this.app) {
      throw new Error('Transport not started yet');
    }

    if (requireAuth && this.authProvider) {
      // Apply auth middleware to the router
      router.use(this.createAuthMiddleware());
    }

    this.app.use(path, router);
  }

  /**
   * Create a router with built-in auth
   * @param requireAuth - Whether to require authentication
   * @returns Express router with optional auth middleware
   */
  createRouter(requireAuth = false): Router {
    const router = Router();

    if (requireAuth && this.authProvider) {
      router.use(this.createAuthMiddleware());
    }

    return router;
  }

  /**
   * Get the auth middleware for manual use
   * @returns Express middleware that checks authentication
   */
  getAuthMiddleware(): RequestHandler | null {
    if (!this.authProvider) {
      return null;
    }

    return this.createAuthMiddleware();
  }

  /**
   * Check if a user is authenticated (helper method)
   * @param req - Express request
   * @returns The authenticated user or null
   */
  getAuthenticatedUser(req: Request): User | null {
    return (req as any).user || null;
  }
}

/**
 * Utility function to create an HTTP server quickly
 */
export async function createHttpServer(
  server: MCPServer,
  config: HttpConfig
): Promise<HttpTransport> {
  const transport = new HttpTransport(config);
  server.useTransport(transport);
  await server.start();
  return transport;
}


// Re-export Router type for convenience
export { Router } from 'express';
