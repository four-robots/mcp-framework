import { MCPServer, z } from '../src';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { Transport, ToolContext, ToolHandler, ResourceHandler, PromptHandler } from '../src';

// Mock the SDK server
const mockSDKServer = {
  registerTool: vi.fn(),
  registerResource: vi.fn(),
  registerPrompt: vi.fn(),
  connect: vi.fn(),
  notification: vi.fn()  // Add notification method for enhanced logging
};

vi.mock('@modelcontextprotocol/sdk/server/mcp.js', () => ({
  McpServer: vi.fn(() => mockSDKServer)
}));

describe('MCPServer - Comprehensive Tests', () => {
  let server: MCPServer;

  beforeEach(() => {
    vi.clearAllMocks();
    server = new MCPServer({
      name: 'test-server',
      version: '1.0.0',
      capabilities: { tools: {}, resources: {} }
    });
  });

  describe('Server Lifecycle', () => {
    it('should initialize with correct config', () => {
      expect(server).toBeDefined();
      expect(server.isStarted()).toBe(false);
      expect(server.getSDKServer()).toBe(mockSDKServer);
    });

    it('should start with configured transport', async () => {
      const mockTransport: Transport = {
        start: vi.fn().mockResolvedValue(undefined),
        stop: vi.fn().mockResolvedValue(undefined)
      };

      server.useTransport(mockTransport);
      await server.start();

      expect(mockTransport.start).toHaveBeenCalledWith(server);
      expect(server.isStarted()).toBe(true);
    });

    it('should start with multiple transports', async () => {
      const transport1: Transport = {
        start: vi.fn().mockResolvedValue(undefined),
        stop: vi.fn().mockResolvedValue(undefined)
      };

      const transport2: Transport = {
        start: vi.fn().mockResolvedValue(undefined),
        stop: vi.fn().mockResolvedValue(undefined)
      };

      server.useTransports(transport1, transport2);
      await server.start();

      expect(transport1.start).toHaveBeenCalledWith(server);
      expect(transport2.start).toHaveBeenCalledWith(server);
      expect(server.isStarted()).toBe(true);
    });

    it('should throw if no transport configured', async () => {
      await expect(server.start()).rejects.toThrow('No transports configured');
    });

    it('should throw if already started', async () => {
      const mockTransport: Transport = {
        start: vi.fn().mockResolvedValue(undefined),
        stop: vi.fn().mockResolvedValue(undefined)
      };

      server.useTransport(mockTransport);
      await server.start();

      await expect(server.start()).rejects.toThrow('Server has already been started');
    });

    it('should stop all transports', async () => {
      const transport1: Transport = {
        start: vi.fn().mockResolvedValue(undefined),
        stop: vi.fn().mockResolvedValue(undefined)
      };

      const transport2: Transport = {
        start: vi.fn().mockResolvedValue(undefined),
        stop: vi.fn().mockResolvedValue(undefined)
      };

      server.useTransports(transport1, transport2);
      await server.start();
      await server.stop();

      expect(transport1.stop).toHaveBeenCalled();
      expect(transport2.stop).toHaveBeenCalled();
      expect(server.isStarted()).toBe(false);
    });

    it('should handle stop when not started', async () => {
      await expect(server.stop()).resolves.toBeUndefined();
    });

    it('should throw when adding transport after start', async () => {
      const mockTransport: Transport = {
        start: vi.fn().mockResolvedValue(undefined),
        stop: vi.fn().mockResolvedValue(undefined)
      };

      server.useTransport(mockTransport);
      await server.start();

      expect(() => {
        server.useTransport(mockTransport);
      }).toThrow('Cannot add transport after server has started');
    });
  });

  describe('Tool Registration and Management', () => {
    it('should register tool with all metadata', () => {
      const handler = vi.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'result' }]
      });

      server.registerTool(
        'test_tool',
        {
          title: 'Test Tool',
          description: 'A test tool',
          inputSchema: z.object({ message: z.string() })
        },
        handler
      );

      // Verify the SDK server was called
      expect(mockSDKServer.registerTool).toHaveBeenCalled();
      const [name, config, registeredHandler] = mockSDKServer.registerTool.mock.calls[0];
      expect(name).toBe('test_tool');
      expect(config.title).toBe('Test Tool');
      expect(config.description).toBe('A test tool');
      expect(config.inputSchema).toBeDefined();
      expect(config.inputSchema.message).toBeDefined();
      expect(typeof registeredHandler).toBe('function');

      // Check introspection
      const tools = server.getTools();
      expect(tools).toHaveLength(1);
      expect(tools[0].name).toBe('test_tool');
      expect(tools[0].title).toBe('Test Tool');
      expect(tools[0].description).toBe('A test tool');
      expect(tools[0].inputSchema).toBeDefined();
      expect(tools[0].inputSchema.shape.message).toBeDefined();
    });

    it('should inject context into tool handler', async () => {
      let capturedContext: ToolContext | undefined;
      const handler = vi.fn((args, context) => {
        capturedContext = context;
        return { content: [{ type: 'text', text: 'result' }] };
      });

      server.registerTool('test_tool', { description: 'Test', inputSchema: z.object({}) }, handler);
      server.setContext({ user: { id: '123', username: 'test' }, custom: 'value' });

      // Get the wrapped handler that was passed to SDK
      const wrappedHandler = mockSDKServer.registerTool.mock.calls[0][2];
      await wrappedHandler({ message: 'test' }, {} as any);

      expect(capturedContext).toMatchObject({
        user: { id: '123', username: 'test' },
        custom: 'value'
      });
      
      // Verify enhanced context fields are present
      expect(capturedContext).toHaveProperty('correlationId');
      expect(capturedContext).toHaveProperty('requestId');
      expect(capturedContext).toHaveProperty('traceId');
      expect(capturedContext).toHaveProperty('spanId');
      expect(capturedContext).toHaveProperty('startTime');
    });

    it('should handle tool errors gracefully', async () => {
      const handler = vi.fn().mockRejectedValue(new Error('Tool error'));

      server.registerTool('test_tool', { description: 'Test', inputSchema: z.object({}) }, handler);

      const wrappedHandler = mockSDKServer.registerTool.mock.calls[0][2];
      await expect(wrappedHandler({})).rejects.toThrow('Tool error');
    });

    it('should get specific tool by name', () => {
      server.registerTool('tool1', { description: 'Tool 1', inputSchema: z.object({}) }, vi.fn());
      server.registerTool('tool2', { description: 'Tool 2', inputSchema: z.object({}) }, vi.fn());

      const tool = server.getTool('tool1');
      expect(tool).toBeDefined();
      expect(tool?.name).toBe('tool1');
      expect(tool?.description).toBe('Tool 1');

      expect(server.getTool('nonexistent')).toBeUndefined();
    });
  });

  describe('Resource Registration and Management', () => {
    it('should register resource with string URI', () => {
      const handler: ResourceHandler = vi.fn().mockResolvedValue({
        contents: [{ uri: 'test://resource', text: 'content' }]
      });

      server.registerResource(
        'test_resource',
        'test://resource',
        {
          title: 'Test Resource',
          description: 'A test resource',
          mimeType: 'text/plain'
        },
        handler
      );

      expect(mockSDKServer.registerResource).toHaveBeenCalledWith(
        'test_resource',
        'test://resource',
        expect.objectContaining({
          title: 'Test Resource',
          description: 'A test resource',
          mimeType: 'text/plain'
        }),
        expect.any(Function)  // Handler is now wrapped for enhanced tracing
      );

      // Check introspection
      const resources = server.getResources();
      expect(resources).toHaveLength(1);
      expect(resources[0]).toEqual({
        name: 'test_resource',
        uri: 'test://resource',
        title: 'Test Resource',
        description: 'A test resource',
        mimeType: 'text/plain'
      });
    });

    it('should register resource with template URI', () => {
      const template = { uriTemplate: 'test://{id}' };
      const handler: ResourceHandler = vi.fn();

      server.registerResource(
        'template_resource',
        template,
        { description: 'Template resource' },
        handler
      );

      const resources = server.getResources();
      expect(resources[0].uri).toBe('test://{id}');
    });

    it('should get specific resource by name', () => {
      server.registerResource('res1', 'uri1', { description: 'Resource 1' }, vi.fn());
      server.registerResource('res2', 'uri2', { description: 'Resource 2' }, vi.fn());

      const resource = server.getResource('res1');
      expect(resource).toBeDefined();
      expect(resource?.name).toBe('res1');
      expect(resource?.uri).toBe('uri1');

      expect(server.getResource('nonexistent')).toBeUndefined();
    });
  });

  describe('Prompt Registration and Management', () => {
    it('should register prompt with all metadata', () => {
      const handler: PromptHandler = vi.fn().mockReturnValue({
        messages: [{ role: 'user', content: { type: 'text', text: 'prompt' } }]
      });

      server.registerPrompt(
        'test_prompt',
        {
          title: 'Test Prompt',
          description: 'A test prompt',
          argsSchema: {
            type: 'object',
            properties: {
              topic: { type: 'string' }
            }
          }
        },
        handler
      );

      // Verify the SDK server was called
      expect(mockSDKServer.registerPrompt).toHaveBeenCalled();
      const [promptName, promptConfig, promptHandler] = mockSDKServer.registerPrompt.mock.calls[0];
      expect(promptName).toBe('test_prompt');
      expect(promptConfig.title).toBe('Test Prompt');
      expect(promptConfig.description).toBe('A test prompt');
      expect(promptConfig.argsSchema).toBeDefined();
      expect(promptConfig.argsSchema.topic).toBeDefined();
      expect(typeof promptHandler).toBe('function');

      // Check introspection
      const prompts = server.getPrompts();
      expect(prompts).toHaveLength(1);
      expect(prompts[0]).toEqual({
        name: 'test_prompt',
        title: 'Test Prompt',
        description: 'A test prompt',
        arguments: ['topic']
      });
    });

    it('should handle prompts without args schema', () => {
      server.registerPrompt(
        'no_args_prompt',
        { description: 'No args' },
        () => ({ messages: [] })
      );

      const prompts = server.getPrompts();
      expect(prompts[0].arguments).toEqual([]);
    });

    it('should get specific prompt by name', () => {
      server.registerPrompt('prompt1', { description: 'Prompt 1' }, vi.fn());
      server.registerPrompt('prompt2', { description: 'Prompt 2' }, vi.fn());

      const prompt = server.getPrompt('prompt1');
      expect(prompt).toBeDefined();
      expect(prompt?.name).toBe('prompt1');

      expect(server.getPrompt('nonexistent')).toBeUndefined();
    });
  });

  describe('Context Management', () => {
    it('should set and retrieve context', () => {
      const context = { user: { id: '123', username: 'test' } };
      server.setContext(context);
      
      expect(server.getContext()).toEqual(context);
    });

    it('should merge partial context updates', () => {
      server.setContext({ user: { id: '123' } });
      server.setContext({ requestId: 'req-456' });
      server.setContext({ user: { username: 'updated' } });
      
      expect(server.getContext()).toEqual({
        user: { username: 'updated' },
        requestId: 'req-456'
      });
    });

    it('should return a copy of context', () => {
      const context = { user: { id: '123' } };
      server.setContext(context);
      
      const retrieved = server.getContext();
      retrieved.user = { id: '456' };
      
      // Original context should be unchanged
      expect(server.getContext()).toEqual({ user: { id: '123' } });
    });
  });

  describe('Capabilities and Introspection', () => {
    beforeEach(() => {
      // Register various items
      server.registerTool('tool1', { description: 'Tool 1', inputSchema: z.object({}) }, vi.fn());
      server.registerTool('tool2', { title: 'Tool Two', description: 'Tool 2', inputSchema: z.object({}) }, vi.fn());
      
      server.registerResource('res1', 'uri1', { title: 'Resource One' }, vi.fn());
      
      server.registerPrompt('prompt1', { description: 'Prompt 1' }, vi.fn());
      server.registerPrompt('prompt2', { title: 'Prompt Two', description: 'Prompt 2' }, vi.fn());
    });

    it('should return all capabilities', () => {
      const capabilities = server.getCapabilities();
      
      expect(capabilities.tools).toHaveLength(2);
      expect(capabilities.resources).toHaveLength(1);
      expect(capabilities.prompts).toHaveLength(2);
      
      expect(capabilities.tools[0].name).toBe('tool1');
      expect(capabilities.tools[1].title).toBe('Tool Two');
    });

    it('should return empty arrays for no registered items', () => {
      const emptyServer = new MCPServer({
        name: 'empty',
        version: '1.0.0'
      });
      
      const capabilities = emptyServer.getCapabilities();
      expect(capabilities.tools).toEqual([]);
      expect(capabilities.resources).toEqual([]);
      expect(capabilities.prompts).toEqual([]);
    });
  });

  describe('Error Handling', () => {
    it('should handle transport start errors', async () => {
      const failingTransport: Transport = {
        start: vi.fn().mockRejectedValue(new Error('Transport start failed')),
        stop: vi.fn()
      };

      server.useTransport(failingTransport);
      await expect(server.start()).rejects.toThrow('Transport start failed');
      expect(server.isStarted()).toBe(false);
    });

    it('should handle transport stop errors gracefully', async () => {
      const transport: Transport = {
        start: vi.fn().mockResolvedValue(undefined),
        stop: vi.fn().mockRejectedValue(new Error('Stop failed'))
      };

      server.useTransport(transport);
      await server.start();

      // Should not throw - stop uses allSettled for graceful error handling
      await expect(server.stop()).resolves.toBeUndefined();
      expect(server.isStarted()).toBe(false);
    });
  });
});
