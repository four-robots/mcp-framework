import { MCPServer, z } from '@tylercoles/mcp-server';
import { HttpTransport } from '@tylercoles/mcp-transport-http';
import { StdioTransport } from '@tylercoles/mcp-transport-stdio';
import { NoAuth } from '@tylercoles/mcp-auth';

/**
 * Multi-transport server example
 * Demonstrates running a single MCP server with both HTTP and stdio transports
 * This allows the same server to be accessed via:
 * - HTTP API (for web clients)
 * - stdio (for CLI tools)
 */
async function createMultiTransportServer() {
  // Create the server
  const server = new MCPServer({
    name: 'multi-transport-server',
    version: '1.0.0',
    capabilities: {
      tools: {},
      resources: {},
      prompts: {}
    }
  });

  // Register tools that will be available on both transports
  server.registerTool(
    'get_time',
    {
      title: 'Get Current Time',
      description: 'Get the current time in various formats',
      inputSchema: z.object({
        format: z.enum(['iso', 'unix', 'human']).optional()
          .describe('Time format (default: iso)')
      })
    },
    async ({ format = 'iso' }) => {
      const now = new Date();
      let timeStr: string;

      switch (format) {
        case 'unix':
          timeStr = Math.floor(now.getTime() / 1000).toString();
          break;
        case 'human':
          timeStr = now.toLocaleString();
          break;
        case 'iso':
        default:
          timeStr = now.toISOString();
      }

      return {
        content: [{
          type: 'text',
          text: `Current time: ${timeStr}`
        }]
      };
    }
  );

  server.registerTool(
    'list_capabilities',
    {
      title: 'List Server Capabilities',
      description: 'Get information about available tools, resources, and prompts',
      inputSchema: z.object({})
    },
    async () => {
      const capabilities = server.getCapabilities();

      const report = [
        `Tools (${capabilities.tools.length}):`,
        ...capabilities.tools.map(t => `  - ${t.name}: ${t.description}`),
        '',
        `Resources (${capabilities.resources.length}):`,
        ...capabilities.resources.map(r => `  - ${r.name}: ${r.uri}`),
        '',
        `Prompts (${capabilities.prompts.length}):`,
        ...capabilities.prompts.map(p => `  - ${p.name}: ${p.description || 'No description'}`)
      ].join('\n');
      
      return {
        content: [{
          type: 'text',
          text: report
        }]
      };
    }
  );

  // Register a resource
  server.registerResource(
    'server-info',
    'info://server',
    {
      title: 'Server Information',
      description: 'Information about the multi-transport server',
      mimeType: 'text/plain'
    },
    async (uri) => ({
      contents: [{
        uri: uri.href,
        text: 'This server supports multiple transports simultaneously.\n' +
              'You can connect via HTTP API or stdio interface.\n' +
              `Available tools: ${server.getTools().map(t => t.name).join(', ')}`
      }]
    })
  );

  // Register a prompt
  server.registerPrompt(
    'analyze_transport',
    {
      title: 'Analyze Transport Usage',
      description: 'Prompt to analyze multi-transport patterns',
      argsSchema: {}
    },
    () => ({
      messages: [{
        role: 'user',
        content: {
          type: 'text',
          text: 'Analyze the benefits and use cases of running an MCP server with multiple transports (HTTP and stdio) simultaneously.'
        }
      }]
    })
  );

  return server;
}

async function main(): Promise<MCPServer> {
  const server = await createMultiTransportServer();
  
  // Configure transports based on environment
  const enableHttp = process.env.ENABLE_HTTP !== 'false';
  const enableStdio = process.env.ENABLE_STDIO !== 'false';
  const httpPort = parseInt(process.env.HTTP_PORT || '3000', 10);
  
  if (!enableHttp && !enableStdio) {
    console.error('Error: At least one transport must be enabled');
    console.error('Set ENABLE_HTTP=true or ENABLE_STDIO=true');
    process.exit(1);
  }
  
  // Setup HTTP transport
  if (enableHttp) {
    const httpTransport = new HttpTransport({
      port: httpPort,
      host: '127.0.0.1',
      auth: new NoAuth(),
      cors: {
        origin: true
      }
    });
    
    server.useTransport(httpTransport);
    console.log(`[Multi-Transport] HTTP transport configured on port ${httpPort}`);
  }
  
  // Setup stdio transport
  if (enableStdio) {
    const stdioTransport = new StdioTransport({
      logStderr: true
    });
    
    server.useTransport(stdioTransport);
    console.error('[Multi-Transport] stdio transport configured');
  }
  
  // Start the server with all configured transports
  await server.start();
  
  if (enableHttp) {
    console.log(`[Multi-Transport] Server started with ${server.getTools().length} tools`);
    console.log(`[Multi-Transport] HTTP endpoint: http://127.0.0.1:${httpPort}/mcp`);
  }
  
  if (enableStdio) {
    console.error('[Multi-Transport] Ready for stdio communication');
  }

  return server;
}

// Run the server
let server: MCPServer | null = null;

main().then(s => { server = s; }).catch((error) => {
  console.error('[Multi-Transport] Fatal error:', error);
  process.exit(1);
});

// Handle shutdown gracefully
const shutdown = async () => {
  console.error('\n[Multi-Transport] Shutting down...');
  if (server) {
    await server.stop();
  }
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
