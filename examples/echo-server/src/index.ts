import { MCPServer, z } from '@tylercoles/mcp-server';
import { HttpTransport } from '@tylercoles/mcp-transport-http';
import { StdioTransport } from '@tylercoles/mcp-transport-stdio';
import { DevAuth, NoAuth } from '@tylercoles/mcp-auth';

/**
 * Echo server example with configurable transport
 * Can run in either stdio or HTTP mode based on environment
 */
async function createEchoServer() {
  // Create the server
  const server = new MCPServer({
    name: 'echo-server-configurable',
    version: '1.0.0'
  });

  // Register tools
  server.registerTool(
    'echo',
    {
      title: 'Echo Tool',
      description: 'Echoes back the provided message',
      inputSchema: z.object({
        message: z.string().describe('Message to echo back')
      })
    },
    async ({ message }, context) => {
      const user = context.user;
      const prefix = user ? `[${user.username}]` : '';

      return {
        content: [{
          type: 'text',
          text: `${prefix} Echo: ${message}`.trim()
        }]
      };
    }
  );

  server.registerTool(
    'echo_stats',
    {
      title: 'Echo Statistics',
      description: 'Get statistics about a message',
      inputSchema: z.object({
        message: z.string().describe('Message to analyze')
      })
    },
    async ({ message }: { message: string }) => {
      const stats = {
        length: message.length,
        words: message.split(/\s+/).filter(w => w.length > 0).length,
        uppercase: (message.match(/[A-Z]/g) || []).length,
        lowercase: (message.match(/[a-z]/g) || []).length,
        digits: (message.match(/[0-9]/g) || []).length,
        special: (message.match(/[^A-Za-z0-9\s]/g) || []).length
      };

      return {
        content: [{
          type: 'text',
          text: `Message Statistics:\n` +
            `- Length: ${stats.length} characters\n` +
            `- Words: ${stats.words}\n` +
            `- Uppercase letters: ${stats.uppercase}\n` +
            `- Lowercase letters: ${stats.lowercase}\n` +
            `- Digits: ${stats.digits}\n` +
            `- Special characters: ${stats.special}`
        }]
      };
    }
  );

  // Register a prompt
  server.registerPrompt(
    'analyze_text',
    {
      title: 'Analyze Text',
      description: 'Prompt to analyze text in detail',
      argsSchema: {
        text: z.string().describe('Text to analyze')
      }
    },
    ({ text }) => ({
      messages: [{
        role: 'user',
        content: {
          type: 'text',
          text: `Please analyze the following text and provide insights about its content, tone, and structure:\n\n${text}`
        }
      }]
    })
  );

  return server;
}

async function main(): Promise<MCPServer> {
  const server = await createEchoServer();

  // Determine transport based on environment
  const transportType = process.env.TRANSPORT || 'stdio';

  if (transportType === 'http') {
    const port = parseInt(process.env.PORT || '3000', 10);
    const useAuth = process.env.USE_AUTH !== 'false';

    const transport = new HttpTransport({
      port,
      host: '127.0.0.1',
      auth: useAuth ? new DevAuth() : new NoAuth(),
      cors: {
        origin: true
      }
    });

    server.useTransport(transport);
    await server.start();

    console.log(`[Echo Server] HTTP server started on http://127.0.0.1:${port}`);
    console.log(`[Echo Server] Auth: ${useAuth ? 'Development mode' : 'Disabled'}`);
  } else {
    // Default to stdio
    const transport = new StdioTransport({
      logStderr: process.env.DEBUG === 'true'
    });

    server.useTransport(transport);
    await server.start();

    if (process.env.DEBUG === 'true') {
      console.error('[Echo Server] Started on stdio transport (debug mode)');
    }
  }

  return server;
}

// Run the server
let server: MCPServer | null = null;

main().then(s => { server = s; }).catch((error) => {
  console.error('[Echo Server] Fatal error:', error);
  process.exit(1);
});

// Handle shutdown gracefully
const shutdown = async () => {
  console.error('\n[Echo Server] Shutting down...');
  if (server) {
    await server.stop();
  }
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
