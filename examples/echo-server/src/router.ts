import { MCPServer, z } from '@tylercoles/mcp-server';
import { HttpTransport } from '@tylercoles/mcp-transport-http';
import { DevAuth } from '@tylercoles/mcp-auth';

/**
 * Example showing how to use the router registration API
 * This makes it easy to add custom routes with or without authentication
 */
async function main() {
  const PORT = parseInt(process.env.PORT || '3000', 10);

  // Create the server
  const server = new MCPServer({
    name: 'router-example',
    version: '1.0.0'
  });

  // Register a simple tool
  server.registerTool(
    'greet',
    {
      title: 'Greet User',
      description: 'Greet the authenticated user',
      inputSchema: z.object({
        greeting: z.string().optional().describe('Custom greeting')
      })
    },
    async ({ greeting }, context) => {
      const user = context.user;
      const prefix = greeting || 'Hello';
      
      if (!user) {
        return {
          content: [{
            type: 'text',
            text: `${prefix}, anonymous user!`
          }]
        };
      }
      
      return {
        content: [{
          type: 'text',
          text: `${prefix}, ${user.username}!`
        }]
      };
    }
  );

  // Create HTTP transport with dev auth
  const transport = new HttpTransport({
    port: PORT,
    host: '127.0.0.1',
    auth: new DevAuth({
      username: 'developer',
      email: 'dev@example.com'
    })
  });

  // Configure and start server
  server.useTransport(transport);
  await server.start();

  // Now we can register custom routers!
  
  // 1. Public router (no auth required)
  const publicRouter = transport.createRouter(false);
  
  publicRouter.get('/status', (_req, res) => {
    res.json({
      status: 'online',
      serverName: 'router-example',
      timestamp: new Date().toISOString()
    });
  });
  
  publicRouter.get('/info', (_req, res) => {
    res.json({
      message: 'This is a public endpoint',
      mcp: '/mcp',
      auth: 'Not required for this endpoint'
    });
  });

  // Register the public router
  transport.registerRouter('/public', publicRouter);

  // 2. Protected router (auth required)
  const protectedRouter = transport.createRouter(true);
  
  protectedRouter.get('/profile', (req, res) => {
    const user = transport.getAuthenticatedUser(req);
    res.json({
      user: user,
      message: 'This endpoint requires authentication'
    });
  });
  
  protectedRouter.post('/data', (req, res) => {
    const user = transport.getAuthenticatedUser(req);
    res.json({
      received: req.body,
      processedBy: user?.username,
      timestamp: new Date().toISOString()
    });
  });

  // Register the protected router
  transport.registerRouter('/protected', protectedRouter);

  // 3. Mixed router with manual auth checks
  const mixedRouter = transport.createRouter(false); // No automatic auth
  const authMiddleware = transport.getAuthMiddleware();
  
  mixedRouter.get('/public-data', (_req, res) => {
    res.json({ data: 'This is public data' });
  });
  
  // Apply auth middleware only to specific routes
  if (authMiddleware) {
    mixedRouter.get('/private-data', authMiddleware, (req, res) => {
      const user = transport.getAuthenticatedUser(req);
      res.json({ 
        data: 'This is private data',
        user: user?.username 
      });
    });
  }

  // Register the mixed router
  transport.registerRouter('/mixed', mixedRouter);

  console.log(`[Router Example] Server started on http://127.0.0.1:${PORT}`);
  console.log(`[Router Example] MCP endpoint: http://127.0.0.1:${PORT}/mcp`);
  console.log(`\n[Router Example] Available routes:`);
  console.log(`  Public (no auth):`);
  console.log(`    GET /public/status`);
  console.log(`    GET /public/info`);
  console.log(`    GET /mixed/public-data`);
  console.log(`  Protected (auth required):`);
  console.log(`    GET /protected/profile`);
  console.log(`    POST /protected/data`);
  console.log(`    GET /mixed/private-data`);
  console.log(`\n[Router Example] Benefits:`);
  console.log(`  - Easy router creation with createRouter(requireAuth)`);
  console.log(`  - Automatic auth middleware application`);
  console.log(`  - Clean separation of public/protected routes`);
  console.log(`  - Manual auth control when needed`);
}

// Run the server
const serverPromise = main();

// Handle shutdown gracefully
process.on('SIGINT', () => {
  console.log('\n[Router Example] Shutting down...');
  process.exit(0);
});

serverPromise.catch((error) => {
  console.error('[Router Example] Fatal error:', error);
  process.exit(1);
});
