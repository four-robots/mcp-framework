import { describe, it, expect, beforeEach, vi } from 'vitest';
import { MCPServer, CorrelationManager, z } from '../src/index.js';

// Mock the SDK server
vi.mock('@modelcontextprotocol/sdk/server/mcp.js', () => ({
  McpServer: vi.fn().mockImplementation(() => ({
    registerTool: vi.fn(),
    registerResource: vi.fn(),
    registerPrompt: vi.fn(),
    notification: vi.fn(),
    setRequestHandler: vi.fn(),
  })),
  ResourceTemplate: vi.fn().mockImplementation((uriTemplate, config) => ({
    uriTemplate,
    config,
  })),
}));

describe('MCPServer Edge Cases', () => {
  let server: MCPServer;

  beforeEach(() => {
    server = new MCPServer({
      name: 'test-server',
      version: '1.0.0',
    });
  });

  describe('Tool Registration Validation', () => {
    it('should reject empty tool name', () => {
      const handler = vi.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'test' }],
      });

      expect(() => {
        server.registerTool(
          '',
          { description: 'Test', inputSchema: z.object({}) },
          handler
        );
      }).toThrow();
    });

    it('should reject duplicate tool registration', () => {
      const handler = vi.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'test' }],
      });

      server.registerTool(
        'my_tool',
        { description: 'First', inputSchema: z.object({}) },
        handler
      );

      expect(() => {
        server.registerTool(
          'my_tool',
          { description: 'Second', inputSchema: z.object({}) },
          handler
        );
      }).toThrow();
    });

    it('should accept tool without title (optional)', () => {
      const handler = vi.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'test' }],
      });

      expect(() => {
        server.registerTool(
          'no_title_tool',
          { description: 'No title', inputSchema: z.object({}) },
          handler
        );
      }).not.toThrow();

      const tools = server.getTools();
      const tool = tools.find((t) => t.name === 'no_title_tool');
      expect(tool).toBeDefined();
      expect(tool!.description).toBe('No title');
    });

    it('should register tool with all optional fields', () => {
      const handler = vi.fn().mockResolvedValue({
        content: [{ type: 'text', text: 'test' }],
      });

      expect(() => {
        server.registerTool(
          'full_tool',
          {
            title: 'Full Tool',
            description: 'Fully configured',
            inputSchema: z.object({
              name: z.string().describe('Name input'),
            }),
          },
          handler
        );
      }).not.toThrow();

      const tool = server.getTool('full_tool');
      expect(tool).toBeDefined();
      expect(tool!.title).toBe('Full Tool');
    });
  });

  describe('Tool Introspection', () => {
    it('should return empty tools list initially', () => {
      expect(server.getTools()).toEqual([]);
    });

    it('should return undefined for non-existent tool', () => {
      expect(server.getTool('nonexistent')).toBeUndefined();
    });

    it('should list all registered tools', () => {
      const handler = vi.fn();

      server.registerTool('tool_a', { description: 'A', inputSchema: z.object({}) }, handler);
      server.registerTool('tool_b', { description: 'B', inputSchema: z.object({}) }, handler);
      server.registerTool('tool_c', { description: 'C', inputSchema: z.object({}) }, handler);

      const tools = server.getTools();
      expect(tools).toHaveLength(3);
      expect(tools.map((t) => t.name)).toEqual(
        expect.arrayContaining(['tool_a', 'tool_b', 'tool_c'])
      );
    });

    it('should return capabilities summary', () => {
      const handler = vi.fn();
      server.registerTool('t1', { description: 'T1', inputSchema: z.object({}) }, handler);

      const capabilities = server.getCapabilities();
      expect(capabilities.tools).toHaveLength(1);
      expect(capabilities.tools[0].name).toBe('t1');
    });
  });

  describe('Pagination Cursor Security', () => {
    beforeEach(() => {
      server = new MCPServer({
        name: 'pagination-test',
        version: '1.0.0',
        pagination: {
          defaultPageSize: 2,
          maxPageSize: 10,
          cursorTTL: 60000,
        },
      });

      const handler = vi.fn();
      for (let i = 0; i < 5; i++) {
        server.registerTool(`tool_${i}`, { description: `Tool ${i}`, inputSchema: z.object({}) }, handler);
      }
    });

    it('should generate unique cursor tokens using crypto', () => {
      const page1 = server.getToolsPaginated({ limit: 2 });
      const page2 = server.getToolsPaginated({ limit: 2 });

      // Both should have cursors
      expect(page1.nextCursor).toBeDefined();
      expect(page2.nextCursor).toBeDefined();

      // Cursors should be different (crypto-random tokens)
      expect(page1.nextCursor).not.toBe(page2.nextCursor);
    });

    it('should reject base64-encoded but unsigned cursors', () => {
      const fakeCursor = Buffer.from(
        JSON.stringify({
          payload: JSON.stringify({ token: 'fake', timestamp: Date.now(), sortKey: 'tool_0' }),
          signature: 'invalidsignature',
        })
      ).toString('base64');

      expect(() => {
        server.getToolsPaginated({ cursor: fakeCursor });
      }).toThrow('Invalid or expired cursor');
    });

    it('should reject completely invalid base64 cursors', () => {
      expect(() => {
        server.getToolsPaginated({ cursor: '!!!invalid!!!' });
      }).toThrow('Invalid or expired cursor');
    });
  });

  describe('Context Management', () => {
    it('should handle setting context multiple times', () => {
      server.setContext({ user: { id: '1' } });
      server.setContext({ requestId: 'req-1' });
      server.setContext({ user: { id: '2', username: 'updated' } });

      const ctx = server.getContext();
      expect(ctx.user?.id).toBe('2');
      expect(ctx.requestId).toBe('req-1');
    });

    it('should return empty context when not set', () => {
      const ctx = server.getContext();
      expect(ctx).toEqual({});
    });
  });
});

describe('CorrelationManager', () => {
  it('should generate unique correlation IDs', () => {
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) {
      ids.add(CorrelationManager.generateCorrelationId());
    }
    // All should be unique
    expect(ids.size).toBe(100);
  });

  it('should generate correlation IDs with correct prefix', () => {
    const id = CorrelationManager.generateCorrelationId();
    expect(id).toMatch(/^corr_\d+_[0-9a-f]+$/);
  });

  it('should generate request IDs with correct prefix', () => {
    const id = CorrelationManager.generateRequestId();
    expect(id).toMatch(/^req_\d+_[0-9a-f]+$/);
  });

  it('should generate trace IDs with correct prefix', () => {
    const id = CorrelationManager.generateTraceId();
    expect(id).toMatch(/^trace_[0-9a-f]+$/);
  });

  it('should generate span IDs with correct prefix', () => {
    const id = CorrelationManager.generateSpanId();
    expect(id).toMatch(/^span_[0-9a-f]+$/);
  });

  it('should generate trace IDs with sufficient entropy', () => {
    const id = CorrelationManager.generateTraceId();
    // trace_ prefix + 32 hex chars (16 bytes)
    expect(id.length).toBe(6 + 32); // 'trace_' + 32 hex chars
  });

  it('should generate span IDs with sufficient entropy', () => {
    const id = CorrelationManager.generateSpanId();
    // span_ prefix + 16 hex chars (8 bytes)
    expect(id.length).toBe(5 + 16); // 'span_' + 16 hex chars
  });

  it('should enhance context with all correlation fields', () => {
    const context = CorrelationManager.enhanceContext({});
    expect(context.correlationId).toBeDefined();
    expect(context.requestId).toBeDefined();
    expect(context.traceId).toBeDefined();
    expect(context.spanId).toBeDefined();
    expect(context.startTime).toBeDefined();
  });

  it('should preserve existing context values when enhancing', () => {
    const existing = {
      correlationId: 'existing-corr',
      user: { id: '123' },
    };

    const enhanced = CorrelationManager.enhanceContext(existing);
    expect(enhanced.correlationId).toBe('existing-corr');
    expect(enhanced.user?.id).toBe('123');
    // Should fill in missing fields
    expect(enhanced.requestId).toBeDefined();
    expect(enhanced.traceId).toBeDefined();
  });
});
