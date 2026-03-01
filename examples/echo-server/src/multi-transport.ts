import { MCPServer, z } from '@tylercoles/mcp-server';
import { StdioTransport } from '@tylercoles/mcp-transport-stdio';
import { HttpTransport } from '@tylercoles/mcp-transport-http';
import { DevAuth } from '@tylercoles/mcp-auth';

/**
 * Example demonstrating:
 * 1. Multiple transports (stdio + HTTP) on the same server
 * 2. Tool introspection capabilities
 * 3. API endpoints for tool discovery
 */
async function main() {
  const PORT = parseInt(process.env.PORT || '3000', 10);

  // Create the server
  const server = new MCPServer({
    name: 'multi-transport-server',
    version: '1.0.0'
  });

  // Register some example tools
  server.registerTool(
    'calculate',
    {
      title: 'Calculator',
      description: 'Perform basic calculations',
      inputSchema: z.object({
        operation: z.enum(['add', 'subtract', 'multiply', 'divide']).describe('Operation to perform'),
        a: z.number().describe('First number'),
        b: z.number().describe('Second number')
      })
    },
    async ({ operation, a, b }) => {
      let result: number | undefined;
      switch (operation) {
        case 'add': result = a + b; break;
        case 'subtract': result = a - b; break;
        case 'multiply': result = a * b; break;
        case 'divide': result = b !== 0 ? a / b : NaN; break;
      }
      
      return {
        content: [{
          type: 'text',
          text: `${a} ${operation} ${b} = ${result}`
        }]
      };
    }
  );

  server.registerTool(
    'get_time',
    {
      title: 'Get Current Time',
      description: 'Get the current date and time',
      inputSchema: z.object({
        timezone: z.string().optional().describe('Timezone (e.g., "UTC", "America/New_York")')
      })
    },
    async ({ timezone }) => {
      const date = new Date();
      const timeString = timezone ? 
        date.toLocaleString('en-US', { timeZone: timezone }) :
        date.toISOString();
      
      return {
        content: [{
          type: 'text',
          text: `Current time: ${timeString}`
        }]
      };
    }
  );

  server.registerTool(
    'list_tools',
    {
      title: 'List Available Tools',
      description: 'Get a list of all available tools and their descriptions',
      inputSchema: z.object({
        detailed: z.boolean().optional().describe('Include input schemas')
      })
    },
    async ({ detailed }) => {
      const tools = server.getTools();
      
      let output = `Available Tools (${tools.length}):\n\n`;
      
      for (const tool of tools) {
        output += `• ${tool.name}`;
        if (tool.title) output += ` - ${tool.title}`;
        output += `\n  ${tool.description}\n`;
        
        if (detailed && tool.inputSchema) {
          const schema = JSON.stringify(tool.inputSchema, null, 2)
            .split('\n')
            .map(line => '  ' + line)
            .join('\n');
          output += `${schema}\n`;
        }
        output += '\n';
      }
      
      return {
        content: [{
          type: 'text',
          text: output
        }]
      };
    }
  );

  // Register a resource
  server.registerResource(
    'server-capabilities',
    'mcp://server/capabilities',
    {
      title: 'Server Capabilities',
      description: 'Complete list of server capabilities',
      mimeType: 'application/json'
    },
    async () => {
      const capabilities = server.getCapabilities();
      return {
        contents: [{
          uri: 'mcp://server/capabilities',
          text: JSON.stringify(capabilities, null, 2)
        }]
      };
    }
  );

  // Register a prompt
  server.registerPrompt(
    'tool_helper',
    {
      title: 'Tool Usage Helper',
      description: 'Generate a prompt to help use a specific tool',
      argsSchema: {
        toolName: z.string().describe('Name of the tool to get help with')
      }
    },
    ({ toolName }) => {
      const tool = server.getTool(toolName);
      if (!tool) {
        return {
          messages: [{
            role: 'user',
            content: {
              type: 'text',
              text: `I need help with a tool called "${toolName}", but it doesn't seem to exist. Can you list the available tools?`
            }
          }]
        };
      }
      
      return {
        messages: [{
          role: 'user',
          content: {
            type: 'text',
            text: `Please help me use the "${tool.name}" tool. ${tool.description}. ` +
                  `The parameters are: ${JSON.stringify(tool.inputSchema)}. ` +
                  `Can you show me an example of how to use it?`
          }
        }]
      };
    }
  );

  // Create transports
  const stdioTransport = new StdioTransport({
    logStderr: process.env.DEBUG === 'true'
  });
  
  const httpTransport = new HttpTransport({
    port: PORT,
    host: '127.0.0.1',
    auth: new DevAuth({
      username: 'multi-transport-user'
    }),
    cors: { origin: true }
  });

  // Use BOTH transports!
  server.useTransports(stdioTransport, httpTransport);

  // Start the server (starts both transports)
  await server.start();
  
  // After server starts, add API routes for tool discovery
  const apiRouter = httpTransport.createRouter(false);
  
  // List all tools
  apiRouter.get('/tools', (_req, res) => {
    const tools = server.getTools();
    res.json({
      count: tools.length,
      tools: tools.map(t => ({
        name: t.name,
        title: t.title || t.name,
        description: t.description
      }))
    });
  });
  
  // Get specific tool details
  apiRouter.get('/tools/:name', (req, res) => {
    const tool = server.getTool(req.params.name);
    if (tool) {
      res.json(tool);
    } else {
      res.status(404).json({ 
        error: 'Tool not found',
        available: server.getTools().map(t => t.name)
      });
    }
  });
  
  // Get all capabilities
  apiRouter.get('/capabilities', (_req, res) => {
    const caps = server.getCapabilities();
    res.json({
      server: {
        name: 'multi-transport-server',
        version: '1.0.0'
      },
      tools: {
        count: caps.tools.length,
        names: caps.tools.map(t => t.name)
      },
      resources: {
        count: caps.resources.length,
        names: caps.resources.map(r => r.name)
      },
      prompts: {
        count: caps.prompts.length,
        names: caps.prompts.map(p => p.name)
      }
    });
  });
  
  // Interactive tool tester
  apiRouter.post('/tools/:name/test', async (req, res) => {
    const toolName = req.params.name;
    const tool = server.getTool(toolName);
    
    if (!tool) {
      res.status(404).json({ error: 'Tool not found' });
      return;
    }
    
    try {
      // This is a simplified test - in reality you'd need to properly invoke the tool
      res.json({
        tool: toolName,
        input: req.body,
        message: 'Tool exists and can be called via MCP protocol'
      });
    } catch (error) {
      res.status(400).json({ 
        error: 'Invalid input',
        schema: tool.inputSchema 
      });
    }
  });
  
  httpTransport.registerRouter('/api', apiRouter);
  
  // Success message
  console.log(`\n✨ Multi-Transport MCP Server Started! ✨\n`);
  console.log(`📡 Available Transports:`);
  console.log(`   1. stdio  - Use this process's stdin/stdout`);
  console.log(`   2. HTTP   - http://127.0.0.1:${PORT}/mcp\n`);
  
  console.log(`🔧 Registered Tools: ${server.getTools().length}`);
  server.getTools().forEach(tool => {
    console.log(`   • ${tool.name} - ${tool.description}`);
  });
  
  console.log(`\n🌐 HTTP API Endpoints:`);
  console.log(`   GET  http://127.0.0.1:${PORT}/api/tools         - List all tools`);
  console.log(`   GET  http://127.0.0.1:${PORT}/api/tools/:name   - Get tool details`);
  console.log(`   GET  http://127.0.0.1:${PORT}/api/capabilities  - Server capabilities`);
  console.log(`   POST http://127.0.0.1:${PORT}/api/tools/:name/test - Test tool input\n`);
  
  console.log(`💡 Try these commands:`);
  console.log(`   - Use 'list_tools' to see all available tools`);
  console.log(`   - Use 'calculate' to perform math operations`);
  console.log(`   - Access the same server via HTTP or stdio!\n`);

  return server;
}

// Run the server
let serverInstance: MCPServer | undefined;

main().then((server) => {
  serverInstance = server;
}).catch((error) => {
  console.error('❌ Fatal error:', error);
  process.exit(1);
});

// Handle shutdown gracefully
process.on('SIGINT', async () => {
  console.log('\n👋 Shutting down multi-transport server...');
  if (serverInstance) {
    await serverInstance.stop();
  }
  process.exit(0);
});
