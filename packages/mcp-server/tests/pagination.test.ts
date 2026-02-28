import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { 
  MCPServer, 
  MCPErrorFactory, 
  type PaginationOptions,
  type PaginatedToolsResult,
  type PaginatedResourcesResult,
  type PaginatedPromptsResult,
  type PaginatedResourceTemplatesResult,
  z
} from '../src/index.js';

// Mock the SDK server
vi.mock('@modelcontextprotocol/sdk/server/mcp.js', () => ({
  McpServer: vi.fn().mockImplementation(() => ({
    registerTool: vi.fn(),
    registerResource: vi.fn(),
    registerPrompt: vi.fn(),
    notification: vi.fn(),
    setRequestHandler: vi.fn()
  })),
  ResourceTemplate: vi.fn().mockImplementation((uriTemplate, config) => ({
    uriTemplate,
    config
  }))
}));

describe('MCP Pagination System', () => {
  let server: MCPServer;

  beforeEach(() => {
    server = new MCPServer({
      name: 'test-server',
      version: '1.0.0',
      pagination: {
        defaultPageSize: 10,
        maxPageSize: 100,
        cursorTTL: 60000 // 1 minute for testing
      }
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Pagination Configuration', () => {
    it('should use default pagination settings when not configured', () => {
      const defaultServer = new MCPServer({
        name: 'default-server',
        version: '1.0.0'
      });

      // Test with default settings (should not throw)
      const result = defaultServer.getToolsPaginated({ limit: 50 });
      expect(result).toBeDefined();
      expect(result.items).toEqual([]);
      expect(result.hasMore).toBe(false);
    });

    it('should use custom pagination settings', () => {
      const customServer = new MCPServer({
        name: 'custom-server',
        version: '1.0.0',
        pagination: {
          defaultPageSize: 5,
          maxPageSize: 25,
          cursorTTL: 30000
        }
      });

      // Should allow up to max page size
      expect(() => {
        customServer.getToolsPaginated({ limit: 25 });
      }).not.toThrow();

      // Should reject beyond max page size
      expect(() => {
        customServer.getToolsPaginated({ limit: 26 });
      }).toThrow('Limit cannot exceed 25');
    });
  });

  describe('Tools Pagination', () => {
    beforeEach(() => {
      // Register multiple tools
      for (let i = 1; i <= 25; i++) {
        server.registerTool(
          `tool-${i.toString().padStart(2, '0')}`,
          {
            description: `Test tool ${i}`,
            inputSchema: z.object({})
          },
          async () => ({ content: [{ type: 'text', text: `Result from tool ${i}` }] })
        );
      }
    });

    it('should return first page with default limit', () => {
      const result: PaginatedToolsResult = server.getToolsPaginated();
      
      expect(result.items).toHaveLength(10); // Default page size
      expect(result.hasMore).toBe(true);
      expect(result.total).toBe(25);
      expect(result.nextCursor).toBeDefined();
      
      // Items should be sorted by name
      expect(result.items[0].name).toBe('tool-01');
      expect(result.items[9].name).toBe('tool-10');
    });

    it('should handle custom page size', () => {
      const result: PaginatedToolsResult = server.getToolsPaginated({ limit: 5 });
      
      expect(result.items).toHaveLength(5);
      expect(result.hasMore).toBe(true);
      expect(result.total).toBe(25);
      expect(result.items[0].name).toBe('tool-01');
      expect(result.items[4].name).toBe('tool-05');
    });

    it('should handle pagination with cursor', () => {
      // Get first page
      const firstPage = server.getToolsPaginated({ limit: 8 });
      expect(firstPage.items).toHaveLength(8);
      expect(firstPage.hasMore).toBe(true);
      expect(firstPage.nextCursor).toBeDefined();
      
      // Get second page using cursor
      const secondPage = server.getToolsPaginated({ 
        limit: 8, 
        cursor: firstPage.nextCursor 
      });
      expect(secondPage.items).toHaveLength(8);
      expect(secondPage.hasMore).toBe(true);
      
      // Verify no overlap
      const firstPageNames = firstPage.items.map(t => t.name);
      const secondPageNames = secondPage.items.map(t => t.name);
      const overlap = firstPageNames.filter(name => secondPageNames.includes(name));
      expect(overlap).toHaveLength(0);
      
      // Verify order continuation
      expect(firstPage.items[7].name).toBe('tool-08');
      expect(secondPage.items[0].name).toBe('tool-09');
    });

    it('should handle last page correctly', () => {
      // Get a page that includes the last items
      const result = server.getToolsPaginated({ limit: 10, cursor: undefined });
      let currentPage = result;
      
      // Navigate to last page
      while (currentPage.hasMore && currentPage.nextCursor) {
        currentPage = server.getToolsPaginated({ 
          limit: 10, 
          cursor: currentPage.nextCursor 
        });
      }
      
      expect(currentPage.hasMore).toBe(false);
      expect(currentPage.nextCursor).toBeUndefined();
      expect(currentPage.items.length).toBeGreaterThan(0);
      expect(currentPage.items[currentPage.items.length - 1].name).toBe('tool-25');
    });

    it('should handle empty results', () => {
      const emptyServer = new MCPServer({
        name: 'empty-server',
        version: '1.0.0'
      });
      
      const result = emptyServer.getToolsPaginated();
      expect(result.items).toHaveLength(0);
      expect(result.hasMore).toBe(false);
      expect(result.total).toBe(0);
      expect(result.nextCursor).toBeUndefined();
    });
  });

  describe('Resources Pagination', () => {
    beforeEach(() => {
      // Register multiple resources
      for (let i = 1; i <= 15; i++) {
        server.registerResource(
          `resource-${i.toString().padStart(2, '0')}`,
          `file:///resource-${i}`,
          {
            description: `Test resource ${i}`,
            mimeType: 'text/plain'
          },
          async () => ({ contents: [{ uri: `file:///resource-${i}`, type: 'text', text: `Content ${i}` }] })
        );
      }
    });

    it('should paginate resources correctly', () => {
      const result: PaginatedResourcesResult = server.getResourcesPaginated({ limit: 7 });
      
      expect(result.items).toHaveLength(7);
      expect(result.hasMore).toBe(true);
      expect(result.total).toBe(15);
      expect(result.items[0].name).toBe('resource-01');
      expect(result.items[6].name).toBe('resource-07');
    });

    it('should continue pagination correctly', () => {
      const firstPage = server.getResourcesPaginated({ limit: 6 });
      const secondPage = server.getResourcesPaginated({ 
        limit: 6, 
        cursor: firstPage.nextCursor 
      });
      const thirdPage = server.getResourcesPaginated({ 
        limit: 6, 
        cursor: secondPage.nextCursor 
      });
      
      expect(firstPage.items).toHaveLength(6);
      expect(secondPage.items).toHaveLength(6);
      expect(thirdPage.items).toHaveLength(3); // Remaining items
      expect(thirdPage.hasMore).toBe(false);
    });
  });

  describe('Prompts Pagination', () => {
    beforeEach(() => {
      // Register multiple prompts
      for (let i = 1; i <= 12; i++) {
        server.registerPrompt(
          `prompt-${i.toString().padStart(2, '0')}`,
          {
            description: `Test prompt ${i}`,
            argsSchema: z.object({
              name: z.string().describe('Input text')
            })
          },
          async () => ({ messages: [{ role: 'user', content: { type: 'text', text: `Prompt ${i}` } }] })
        );
      }
    });

    it('should paginate prompts correctly', () => {
      const result: PaginatedPromptsResult = server.getPromptsPaginated({ limit: 5 });
      
      expect(result.items).toHaveLength(5);
      expect(result.hasMore).toBe(true);
      expect(result.total).toBe(12);
      expect(result.items[0].name).toBe('prompt-01');
    });
  });

  describe('Resource Templates Pagination', () => {
    beforeEach(() => {
      // Register multiple resource templates
      for (let i = 1; i <= 8; i++) {
        server.registerResourceTemplate(
          `template-${i.toString().padStart(2, '0')}`,
          `file:///template-${i}/{id}`,
          {
            description: `Template ${i}`,
            mimeType: 'application/json'
          },
          async () => ({ contents: [{ uri: `file:///template-${i}/{id}`, type: 'text', text: `Template content ${i}` }] })
        );
      }
    });

    it('should paginate resource templates correctly', () => {
      const result: PaginatedResourceTemplatesResult = server.getResourceTemplatesPaginated({ limit: 3 });
      
      expect(result.items).toHaveLength(3);
      expect(result.hasMore).toBe(true);
      expect(result.total).toBe(8);
      expect(result.items[0].name).toBe('template-01');
    });
  });

  describe('Pagination Validation', () => {
    it('should validate limit parameter', () => {
      expect(() => {
        server.getToolsPaginated({ limit: 0 });
      }).toThrow('Limit must be a positive number');

      expect(() => {
        server.getToolsPaginated({ limit: -5 });
      }).toThrow('Limit must be a positive number');

      expect(() => {
        server.getToolsPaginated({ limit: 101 }); // Exceeds max of 100
      }).toThrow('Limit cannot exceed 100');
    });

    it('should validate cursor parameter', () => {
      expect(() => {
        server.getToolsPaginated({ cursor: '' });
      }).toThrow('Cursor must be a non-empty string');

      expect(() => {
        server.getToolsPaginated({ cursor: 'invalid-cursor' });
      }).toThrow('Invalid or expired cursor');
    });

    it('should handle expired cursors', async () => {
      // Create server with very short cursor TTL
      const shortTTLServer = new MCPServer({
        name: 'short-ttl-server',
        version: '1.0.0',
        pagination: {
          defaultPageSize: 10,
          maxPageSize: 100,
          cursorTTL: 1 // 1ms - will expire immediately
        }
      });

      // Register multiple tools to ensure pagination occurs
      shortTTLServer.registerTool(
        'test-tool-1',
        {
          description: 'Test tool 1',
          inputSchema: z.object({})
        },
        async () => ({ content: [{ type: 'text', text: 'test1' }] })
      );
      
      shortTTLServer.registerTool(
        'test-tool-2',
        {
          description: 'Test tool 2',
          inputSchema: z.object({})
        },
        async () => ({ content: [{ type: 'text', text: 'test2' }] })
      );

      // Get a page to generate cursor (with more items than page size)
      const firstPage = shortTTLServer.getToolsPaginated({ limit: 1 });
      
      // Verify we actually got a cursor
      expect(firstPage.nextCursor).toBeDefined();
      
      // Wait for cursor to expire
      await new Promise(resolve => setTimeout(resolve, 10));
      
      // Try to use expired cursor
      expect(() => {
        shortTTLServer.getToolsPaginated({ cursor: firstPage.nextCursor });
      }).toThrow();
    });
  });

  describe('Cursor Security', () => {
    it('should generate unique cursors for different items', () => {
      // Register tools
      server.registerTool('tool-a', {
        description: 'Tool A',
        inputSchema: z.object({})
      }, async () => ({ content: [{ type: 'text', text: 'A' }] }));

      server.registerTool('tool-b', {
        description: 'Tool B', 
        inputSchema: z.object({})
      }, async () => ({ content: [{ type: 'text', text: 'B' }] }));

      const result1 = server.getToolsPaginated({ limit: 1 });
      const result2 = server.getToolsPaginated({ limit: 1 });

      // Even though same query, cursors should be unique due to timestamp
      if (result1.nextCursor && result2.nextCursor) {
        expect(result1.nextCursor).not.toBe(result2.nextCursor);
      }
    });

    it('should reject tampered cursors', () => {
      server.registerTool('tool-test', {
        description: 'Test tool',
        inputSchema: z.object({})
      }, async () => ({ content: [{ type: 'text', text: 'test' }] }));

      const result = server.getToolsPaginated({ limit: 1 });
      
      if (result.nextCursor) {
        // Try to tamper with cursor
        const tamperedCursor = result.nextCursor.slice(0, -5) + 'XXXXX';
        
        expect(() => {
          server.getToolsPaginated({ cursor: tamperedCursor });
        }).toThrow('Invalid or expired cursor');
      }
    });
  });

  describe('Edge Cases', () => {
    it('should handle single item pagination', () => {
      server.registerTool('single-tool', {
        description: 'Single tool',
        inputSchema: z.object({})
      }, async () => ({ content: [{ type: 'text', text: 'single' }] }));

      const result = server.getToolsPaginated({ limit: 10 });
      expect(result.items).toHaveLength(1);
      expect(result.hasMore).toBe(false);
      expect(result.nextCursor).toBeUndefined();
    });

    it('should handle exact page size matches', () => {
      // Register exactly 10 tools
      for (let i = 1; i <= 10; i++) {
        server.registerTool(`exact-tool-${i}`, {
          description: `Exact tool ${i}`,
          inputSchema: z.object({})
        }, async () => ({ content: [{ type: 'text', text: `exact ${i}` }] }));
      }

      const result = server.getToolsPaginated({ limit: 10 });
      expect(result.items).toHaveLength(10);
      expect(result.hasMore).toBe(false);
      expect(result.nextCursor).toBeUndefined();
    });

    it('should maintain stable sorting with name collisions', () => {
      // Register tools with similar names
      server.registerTool('tool-001', {
        description: 'Tool 001',
        inputSchema: z.object({})
      }, async () => ({ content: [{ type: 'text', text: '001' }] }));

      server.registerTool('tool-002', {
        description: 'Tool 002',
        inputSchema: z.object({})
      }, async () => ({ content: [{ type: 'text', text: '002' }] }));

      const result1 = server.getToolsPaginated({ limit: 2 });
      const result2 = server.getToolsPaginated({ limit: 2 });

      // Results should be consistent
      expect(result1.items.map(t => t.name)).toEqual(result2.items.map(t => t.name));
    });
  });
});