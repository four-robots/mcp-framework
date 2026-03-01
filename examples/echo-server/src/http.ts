import { MCPServer, z } from '@tylercoles/mcp-server';
import { HttpTransport } from '@tylercoles/mcp-transport-http';
import { DevAuth } from '@tylercoles/mcp-auth';

/**
 * Echo server example using HTTP transport with development auth
 */
async function main() {
  const PORT = parseInt(process.env.PORT || '3000', 10);

  // Create the server
  const server = new MCPServer({
    name: 'echo-server-http',
    version: '1.0.0'
  });

  // Register echo tool
  server.registerTool(
    'echo',
    {
      title: 'Echo Tool',
      description: 'Echoes back the provided message with user info',
      inputSchema: z.object({
        message: z.string().describe('Message to echo back')
      })
    },
    async ({ message }, context) => {
      // Access user info from context
      const user = context.user;
      const prefix = user ? `[${user.username}]` : '[Anonymous]';
      
      return {
        content: [{
          type: 'text',
          text: `${prefix} Echo: ${message}`
        }]
      };
    }
  );

  // Register a tool that demonstrates error handling
  server.registerTool(
    'echo_with_validation',
    {
      title: 'Echo with Validation',
      description: 'Echo message with length validation',
      inputSchema: z.object({
        message: z.string().describe('Message to echo (max 100 chars)'),
        uppercase: z.boolean().optional().describe('Convert to uppercase')
      })
    },
    async ({ message, uppercase }, context) => {
      if (message.length > 100) {
        return {
          content: [{
            type: 'text',
            text: 'Error: Message too long (max 100 characters)'
          }],
          isError: true
        };
      }

      const processedMessage = uppercase ? message.toUpperCase() : message;
      
      return {
        content: [{
          type: 'text',
          text: `Echo: ${processedMessage}`
        }]
      };
    }
  );

  // Register a resource
  server.registerResource(
    'server-info',
    'echo://server/info',
    {
      title: 'Server Information',
      description: 'Get information about the echo server',
      mimeType: 'text/plain'
    },
    async (uri) => ({
      contents: [{
        uri: uri.href,
        text: `Echo Server v1.0.0\nRunning on port ${PORT}\nTransport: HTTP with sessions\nAuth: Development mode`
      }]
    })
  );

  // Create HTTP transport with dev auth
  const transport = new HttpTransport({
    port: PORT,
    host: '127.0.0.1',
    auth: new DevAuth({
      username: 'test-user',
      email: 'test@example.com'
    }),
    cors: {
      origin: true // Allow all origins in development
    }
  });

  server.useTransport(transport);

  // Start the server
  await server.start();
  
  console.log(`[Echo Server] HTTP server started on http://127.0.0.1:${PORT}`);
  console.log(`[Echo Server] MCP endpoint: http://127.0.0.1:${PORT}/mcp`);
  console.log(`[Echo Server] Using development auth (all requests authenticated as test-user)`);

  return server;
}

// Run the server
let serverInstance: MCPServer | undefined;

main().then((server) => {
  serverInstance = server;
}).catch((error) => {
  console.error('[Echo Server] Fatal error:', error);
  process.exit(1);
});

// Handle shutdown gracefully
process.on('SIGINT', async () => {
  console.log('\n[Echo Server] Shutting down...');
  if (serverInstance) {
    await serverInstance.stop();
  }
  process.exit(0);
});
