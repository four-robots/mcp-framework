import { MCPServer, z } from '@tylercoles/mcp-server';
import { HttpTransport } from '@tylercoles/mcp-transport-http';
import { Providers } from '@tylercoles/mcp-auth-oidc';

/**
 * Echo server example with OAuth authentication
 * Shows how simple it is to add OAuth with the framework
 */
async function main() {
  const PORT = parseInt(process.env.PORT || '3000', 10);
  const OIDC_URL = process.env.OIDC_URL || 'https://auth.example.com';
  const CLIENT_ID = process.env.CLIENT_ID || 'echo-server';
  const CLIENT_SECRET = process.env.CLIENT_SECRET; // Optional for public clients
  const SESSION_SECRET = process.env.SESSION_SECRET;

  if (!process.env.OIDC_URL || !process.env.CLIENT_ID) {
    console.warn('Warning: OIDC_URL and CLIENT_ID should be set via environment variables');
  }

  if (!SESSION_SECRET) {
    throw new Error('SESSION_SECRET environment variable is required for OAuth');
  }

  // Create the server
  const server = new MCPServer({
    name: 'echo-server-oauth',
    version: '1.0.0'
  });

  // Register authenticated echo tool
  server.registerTool(
    'echo',
    {
      title: 'Authenticated Echo',
      description: 'Echoes back the message with user info',
      inputSchema: z.object({
        message: z.string().describe('Message to echo back')
      })
    },
    async ({ message }, context) => {
      const user = context.user;

      if (!user) {
        return {
          content: [{
            type: 'text',
            text: 'Error: Authentication required'
          }],
          isError: true
        };
      }

      return {
        content: [{
          type: 'text',
          text: `[${user.username}] Echo: ${message}`
        }]
      };
    }
  );

  // Register user info tool
  server.registerTool(
    'whoami',
    {
      title: 'Who Am I',
      description: 'Get information about the authenticated user',
      inputSchema: z.object({})
    },
    async (_args, context) => {
      const user = context.user;

      if (!user) {
        return {
          content: [{
            type: 'text',
            text: 'Not authenticated'
          }],
          isError: true
        };
      }

      return {
        content: [{
          type: 'text',
          text: `User: ${user.username}\nEmail: ${user.email}\nGroups: ${user.groups.join(', ')}`
        }]
      };
    }
  );

  // Create HTTP transport with OIDC authentication (Authentik provider)
  // ALL OAuth discovery endpoints are automatically created!
  const transport = new HttpTransport({
    port: PORT,
    host: '127.0.0.1',
    auth: Providers.Authentik(OIDC_URL, CLIENT_ID, CLIENT_ID, CLIENT_SECRET, {
      session: {
        secret: SESSION_SECRET,
        callbackUrl: `http://localhost:${PORT}/auth/callback`,
      },
    }),
    cors: {
      origin: true // Allow all origins in development
    }
  });

  server.useTransport(transport);

  // Start the server
  await server.start();
  
  console.log(`[Echo Server] OAuth-enabled server started on http://127.0.0.1:${PORT}`);
  console.log(`[Echo Server] MCP endpoint: http://127.0.0.1:${PORT}/mcp`);
  console.log(`[Echo Server] OAuth discovery: http://127.0.0.1:${PORT}/.well-known/oauth-protected-resource`);
  console.log(`[Echo Server] Login: http://127.0.0.1:${PORT}/auth/login`);
  console.log(`\n[Echo Server] The framework automatically handles:`);
  console.log(`  - OAuth discovery endpoints`);
  console.log(`  - Protected resource metadata`);
  console.log(`  - Client registration`);
  console.log(`  - Login/callback flows`);
  console.log(`  - Session management`);
  console.log(`  - Token validation`);
}

// Handle shutdown gracefully
process.on('SIGINT', () => {
  console.log('\n[Echo Server] Shutting down...');
  process.exit(0);
});

// Run the server
main().catch((error) => {
  console.error('[Echo Server] Fatal error:', error);
  process.exit(1);
});
