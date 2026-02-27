import { MCPServer } from '@tylercoles/mcp-server';
import { HttpTransport } from '@tylercoles/mcp-transport-http';
import { Providers } from '@tylercoles/mcp-auth-oidc';
import { loadConfig } from './config/index.js';
import { createLogger } from './utils/logger.js';
import { NATSService } from './services/nats-service.js';
import { MemoryService } from './services/memory-service.js';
import { setupMemoryTools } from './tools/memory-tools.js';

const config = loadConfig();
const logger = createLogger(config.logging);

/**
 * Main application using the new framework with router registration
 */
class Application {
  private mcpServer: MCPServer;
  private transport: HttpTransport;
  private natsService: NATSService;
  private memoryService!: MemoryService;

  constructor() {
    this.natsService = new NATSService(config.nats);
    
    // Create MCP server
    this.mcpServer = new MCPServer({
      name: 'mcp-memories',
      version: '1.0.0'
    });

    // Create HTTP transport with OIDC auth
    this.transport = new HttpTransport({
      port: config.port,
      host: config.host,
      basePath: '/mcp',
      externalDomain: config.externalDomain,
      auth: Providers.Authentik(config.auth.oidcUrl, 'claude-ai-mcp', 'claude-ai-mcp', config.auth.clientSecret, {
        allowedGroups: config.auth.allowedGroups,
        session: {
          secret: config.sessionSecret,
          callbackUrl: config.auth.redirectUri,
        },
      }),
      cors: {
        origin: (origin, callback) => {
          if (!origin) return callback(null, true);
          
          const allowed = config.corsOrigins.some(pattern => {
            if (pattern.includes('*')) {
              const regex = new RegExp(pattern.replace(/\*/g, '.*'));
              return regex.test(origin);
            }
            return origin === pattern;
          });

          callback(null, allowed);
        },
        credentials: true
      },
      helmetOptions: {
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
          },
        },
      },
      trustProxy: process.env.NODE_ENV === 'production'
    });
  }

  /**
   * Initialize all services
   */
  async initialize(): Promise<void> {
    try {
      // Initialize NATS connection
      await this.natsService.initialize();
      logger.info('NATS service initialized');

      // Initialize memory service
      this.memoryService = new MemoryService(this.natsService);

      // Setup memory tools on the MCP server
      setupMemoryTools(this.mcpServer, this.memoryService);
      logger.info('Memory tools registered');

      // Configure the MCP server to use the HTTP transport
      this.mcpServer.useTransport(this.transport);

      // Start the server FIRST so we can register routers
      await this.mcpServer.start();

      // Now register custom routes using the new router API
      this.setupCustomRoutes();

      logger.info('Application initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize application', { error });
      throw error;
    }
  }

  /**
   * Setup custom routes using router registration
   */
  private setupCustomRoutes(): void {
    // Create a public router (no auth required)
    const publicRouter = this.transport.createRouter(false);
    
    // Health check
    publicRouter.get('/health', async (_req, res) => {
      try {
        const health = await this.memoryService.healthCheck();
        res.json({
          status: 'ok',
          timestamp: new Date().toISOString(),
          services: health,
          sessions: this.transport.getSessionCount()
        });
      } catch (error) {
        logger.error('Health check failed', { error });
        res.status(503).json({
          status: 'error',
          error: 'Service unavailable'
        });
      }
    });

    // Home page
    publicRouter.get('/', (req, res) => {
      const user = this.transport.getAuthenticatedUser(req);
      res.json({
        message: 'MCP Memories Server',
        version: '1.0.0',
        user: user?.username || 'Not authenticated',
        authenticated: !!user,
        endpoints: {
          mcp: '/mcp',
          auth: '/auth',
          health: '/health',
          api: config.enableApi ? '/api' : undefined,
          discovery: '/.well-known/oauth-protected-resource'
        }
      });
    });

    // Register the public router
    this.transport.registerRouter('/', publicRouter);

    // Setup API routes if enabled
    if (config.enableApi) {
      this.setupAPIRoutes();
    }
  }

  /**
   * Setup REST API routes with authentication
   */
  private setupAPIRoutes(): void {
    // Create an authenticated router
    const apiRouter = this.transport.createRouter(true); // requireAuth = true

    // List available tools (authenticated) - using introspection
    apiRouter.get('/tools', (_req, res) => {
      const tools = this.mcpServer.getTools();
      res.json({ 
        tools: tools.map(tool => ({
          name: tool.name,
          title: tool.title,
          description: tool.description,
          inputSchema: tool.inputSchema
        }))
      });
    });

    // Get specific tool details (authenticated)
    apiRouter.get('/tools/:name', (req, res) => {
      const tool = this.mcpServer.getTool(req.params.name);
      if (!tool) {
        res.status(404).json({ error: 'Tool not found' });
        return;
      }
      res.json({
        name: tool.name,
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema
      });
    });

    // List all server capabilities (authenticated)
    apiRouter.get('/capabilities', (_req, res) => {
      const capabilities = this.mcpServer.getCapabilities();
      res.json({
        server: {
          name: 'mcp-memories',
          version: '1.0.0'
        },
        tools: {
          count: capabilities.tools.length,
          names: capabilities.tools.map(t => t.name)
        },
        resources: {
          count: capabilities.resources.length,
          names: capabilities.resources.map(r => r.name)
        },
        prompts: {
          count: capabilities.prompts.length,
          names: capabilities.prompts.map(p => p.name)
        }
      });
    });

    // Store memory (authenticated)
    apiRouter.post('/memories', async (req, res) => {
      try {
        const user = this.transport.getAuthenticatedUser(req);
        if (!user) {
          // This shouldn't happen with router auth, but just in case
          res.status(401).json({ error: 'Authentication required' });
          return;
        }

        const memory = await this.memoryService.storeMemory({
          user,
          content: req.body.content,
          projectName: req.body.projectName || 'default',
          memoryTopic: req.body.memoryTopic || 'general',
          memoryType: req.body.memoryType || 'note',
          tags: req.body.tags || []
        });
        res.json({ success: true, memory });
      } catch (error) {
        logger.error('API: Failed to store memory', { error });
        res.status(400).json({ 
          error: error instanceof Error ? error.message : 'Unknown error' 
        });
      }
    });

    // Search memories (authenticated)
    apiRouter.get('/memories', async (req, res) => {
      try {
        const user = this.transport.getAuthenticatedUser(req);
        if (!user) {
          res.status(401).json({ error: 'Authentication required' });
          return;
        }

        const results = await this.memoryService.retrieveMemories({
          user,
          query: req.query.q as string || '',
          projectName: req.query.project as string,
          memoryTopic: req.query.topic as string,
          memoryType: req.query.type as string,
          limit: parseInt(req.query.limit as string || '10', 10),
          tags: req.query.tags ? (req.query.tags as string).split(',') : []
        });
        res.json({ success: true, results });
      } catch (error) {
        logger.error('API: Failed to retrieve memories', { error });
        res.status(400).json({ 
          error: error instanceof Error ? error.message : 'Unknown error' 
        });
      }
    });

    // Delete memory (authenticated)
    apiRouter.delete('/memories/:id', async (req, res) => {
      try {
        const user = this.transport.getAuthenticatedUser(req);
        if (!user) {
          res.status(401).json({ error: 'Authentication required' });
          return;
        }

        const deleted = await this.memoryService.deleteMemory({
          user,
          memoryId: req.params.id
        });
        res.json({ success: true, deleted });
      } catch (error) {
        logger.error('API: Failed to delete memory', { error });
        res.status(400).json({ 
          error: error instanceof Error ? error.message : 'Unknown error' 
        });
      }
    });

    // Get statistics (authenticated)
    apiRouter.get('/stats', async (req, res) => {
      try {
        const user = this.transport.getAuthenticatedUser(req);
        if (!user) {
          res.status(401).json({ error: 'Authentication required' });
          return;
        }

        const stats = await this.memoryService.getMemoryStats(user);
        res.json({ success: true, stats });
      } catch (error) {
        logger.error('API: Failed to get stats', { error });
        res.status(400).json({ 
          error: error instanceof Error ? error.message : 'Unknown error' 
        });
      }
    });

    // Register the API router with auth required
    this.transport.registerRouter('/api', apiRouter, true);
  }

  /**
   * Start the server
   */
  async start(): Promise<void> {
    await this.initialize();
    
    logger.info('Server started', {
      host: config.host,
      port: config.port,
      environment: process.env.NODE_ENV || 'development',
      mcpEndpoint: `http://${config.host}:${config.port}/mcp`
    });
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    logger.info('Shutting down server...');

    try {
      await this.mcpServer.stop();
      await this.natsService.close();
      logger.info('Server shutdown complete');
    } catch (error) {
      logger.error('Error during shutdown', { error });
    }
  }
}

// Main entry point
if (import.meta.url === `file://${process.argv[1]}`) {
  const app = new Application();
  
  // Start server
  app.start().catch((error) => {
    logger.error('Failed to start server', { error });
    process.exit(1);
  });

  // Handle shutdown
  process.on('SIGINT', async () => {
    await app.shutdown();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    await app.shutdown();
    process.exit(0);
  });
}

export { Application };
