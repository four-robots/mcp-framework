import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { MCPServer, MCPErrorFactory, MCPErrorCode } from '../src/index.js';
import type { ResourceTemplateConfig, ResourceTemplateHandler } from '../src/index.js';

// SDK server is mocked globally in setup.ts

describe('Resource Template System', () => {
  let server: MCPServer;
  let mockSDKServer: any;

  beforeEach(() => {
    server = new MCPServer({
      name: 'test-server',
      version: '1.0.0'
    });
    mockSDKServer = server.getSDKServer();
    
    // Ensure all SDK server methods are spies
    if (!vi.isMockFunction(mockSDKServer.registerResource)) {
      mockSDKServer.registerResource = vi.fn();
    }
    if (!vi.isMockFunction(mockSDKServer.server.notification)) {
      mockSDKServer.server.notification = vi.fn();
    }
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Template Registration', () => {
    it('should register a basic resource template', () => {
      const handler: ResourceTemplateHandler = vi.fn().mockResolvedValue({
        contents: [{ uri: 'file:///users/123/document.txt', text: 'content' }]
      });

      const config: ResourceTemplateConfig = {
        title: 'User Documents',
        description: 'Documents for a specific user',
        mimeType: 'text/plain'
      };

      expect(() => {
        server.registerResourceTemplate(
          'user-documents',
          'file:///users/{userId}/documents/{docId}',
          config,
          handler
        );
      }).not.toThrow();

      const template = server.getResourceTemplate('user-documents');
      expect(template).toBeDefined();
      expect(template?.name).toBe('user-documents');
      expect(template?.uriTemplate).toBe('file:///users/{userId}/documents/{docId}');
      expect(template?.title).toBe('User Documents');
      expect(template?.description).toBe('Documents for a specific user');
      expect(template?.mimeType).toBe('text/plain');
    });

    it('should register template with parameter schema', () => {
      const handler: ResourceTemplateHandler = vi.fn().mockResolvedValue({
        contents: [{ uri: 'file:///test', text: 'content' }]
      });

      const config: ResourceTemplateConfig = {
        title: 'Test Template',
        parameterSchema: {
          type: 'object',
          required: ['userId', 'docId'],
          properties: {
            userId: { type: 'number' },
            docId: { type: 'string' }
          }
        }
      };

      server.registerResourceTemplate(
        'test-template',
        'file:///users/{userId}/docs/{docId}',
        config,
        handler
      );

      const template = server.getResourceTemplate('test-template');
      expect(template?.parameterSchema).toEqual(config.parameterSchema);
    });

    it('should register template with annotations', () => {
      const handler: ResourceTemplateHandler = vi.fn().mockResolvedValue({
        contents: [{ uri: 'file:///test', text: 'content' }]
      });

      const config: ResourceTemplateConfig = {
        annotations: {
          category: 'documents',
          access: 'restricted',
          version: '1.0'
        }
      };

      server.registerResourceTemplate(
        'annotated-template',
        'file:///docs/{docId}',
        config,
        handler
      );

      const template = server.getResourceTemplate('annotated-template');
      expect(template?.annotations).toEqual(config.annotations);
    });
  });

  describe('Template Validation', () => {
    it('should throw error for empty template name', () => {
      const handler: ResourceTemplateHandler = vi.fn();
      
      expect(() => {
        server.registerResourceTemplate('', 'file:///test/{id}', {}, handler);
      }).toThrow(MCPErrorFactory.invalidParams('Resource template name must be a non-empty string'));
    });

    it('should throw error for non-string template name', () => {
      const handler: ResourceTemplateHandler = vi.fn();
      
      expect(() => {
        server.registerResourceTemplate(null as any, 'file:///test/{id}', {}, handler);
      }).toThrow(MCPErrorFactory.invalidParams('Resource template name must be a non-empty string'));
    });

    it('should throw error for empty URI template', () => {
      const handler: ResourceTemplateHandler = vi.fn();
      
      expect(() => {
        server.registerResourceTemplate('test', '', {}, handler);
      }).toThrow(MCPErrorFactory.invalidParams('URI template must be a non-empty string'));
    });

    it('should throw error for non-string URI template', () => {
      const handler: ResourceTemplateHandler = vi.fn();
      
      expect(() => {
        server.registerResourceTemplate('test', 123 as any, {}, handler);
      }).toThrow(MCPErrorFactory.invalidParams('URI template must be a non-empty string'));
    });

    it('should throw error for duplicate template name', () => {
      const handler: ResourceTemplateHandler = vi.fn();
      
      server.registerResourceTemplate('duplicate', 'file:///test/{id}', {}, handler);
      
      expect(() => {
        server.registerResourceTemplate('duplicate', 'file:///other/{id}', {}, handler);
      }).toThrow(MCPErrorFactory.invalidParams('Resource template \'duplicate\' is already registered'));
    });

    it('should validate URI template format', () => {
      const handler: ResourceTemplateHandler = vi.fn();
      
      // Valid templates should not throw
      expect(() => {
        server.registerResourceTemplate('valid1', 'file:///test', {}, handler);
      }).not.toThrow();
      
      expect(() => {
        server.registerResourceTemplate('valid2', 'file:///test/{id}', {}, handler);
      }).not.toThrow();
      
      expect(() => {
        server.registerResourceTemplate('valid3', 'file:///users/{userId}/docs/{docId}', {}, handler);
      }).not.toThrow();
      
      // Invalid templates should throw
      expect(() => {
        server.registerResourceTemplate('invalid1', 'file:///test/{123invalid}', {}, handler);
      }).toThrow(MCPErrorFactory.invalidParams('Invalid URI template format: file:///test/{123invalid}'));
      
      expect(() => {
        server.registerResourceTemplate('invalid2', 'file:///test/{id', {}, handler);
      }).toThrow(MCPErrorFactory.invalidParams('Invalid URI template format: file:///test/{id'));
    });
  });

  describe('Template Listing and Retrieval', () => {
    beforeEach(() => {
      const handler: ResourceTemplateHandler = vi.fn().mockResolvedValue({
        contents: [{ uri: 'test', text: 'content' }]
      });

      server.registerResourceTemplate('template1', 'file:///docs/{id}', {
        title: 'Template 1'
      }, handler);

      server.registerResourceTemplate('template2', 'file:///users/{userId}', {
        title: 'Template 2',
        description: 'User template'
      }, handler);
    });

    it('should list all resource templates', () => {
      const templates = server.listResourceTemplates();
      
      expect(templates).toHaveLength(2);
      expect(templates.map(t => t.name)).toEqual(['template1', 'template2']);
      expect(templates[0].title).toBe('Template 1');
      expect(templates[1].description).toBe('User template');
    });

    it('should get specific resource template', () => {
      const template = server.getResourceTemplate('template1');
      
      expect(template).toBeDefined();
      expect(template?.name).toBe('template1');
      expect(template?.uriTemplate).toBe('file:///docs/{id}');
      expect(template?.title).toBe('Template 1');
    });

    it('should return undefined for non-existent template', () => {
      const template = server.getResourceTemplate('non-existent');
      expect(template).toBeUndefined();
    });

    it('should throw error for invalid template name in getter', () => {
      expect(() => {
        server.getResourceTemplate('');
      }).toThrow(MCPErrorFactory.invalidParams('Resource template name must be a non-empty string'));

      expect(() => {
        server.getResourceTemplate(null as any);
      }).toThrow(MCPErrorFactory.invalidParams('Resource template name must be a non-empty string'));
    });

    it('should include templates in capabilities', () => {
      const capabilities = server.getCapabilities();
      
      expect(capabilities.resourceTemplates).toHaveLength(2);
      expect(capabilities.resourceTemplates.map(t => t.name)).toEqual(['template1', 'template2']);
    });
  });

  describe('URI Generation', () => {
    beforeEach(() => {
      const handler: ResourceTemplateHandler = vi.fn().mockResolvedValue({
        contents: [{ uri: 'test', text: 'content' }]
      });

      server.registerResourceTemplate(
        'user-docs',
        'file:///users/{userId}/documents/{docId}',
        {},
        handler
      );
    });

    it('should generate URI from template with parameters', () => {
      const uri = server.generateResourceUri('user-docs', {
        userId: '123',
        docId: 'document.txt'
      });
      
      expect(uri).toBe('file:///users/123/documents/document.txt');
    });

    it('should URL-encode parameter values', () => {
      const uri = server.generateResourceUri('user-docs', {
        userId: '123',
        docId: 'my document.txt'
      });
      
      expect(uri).toBe('file:///users/123/documents/my%20document.txt');
    });

    it('should throw error for missing parameters', () => {
      expect(() => {
        server.generateResourceUri('user-docs', { userId: '123' });
      }).toThrow(MCPErrorFactory.invalidParams('Missing parameter \'docId\' for URI template'));
    });

    it('should throw error for non-existent template', () => {
      expect(() => {
        server.generateResourceUri('non-existent', { id: '123' });
      }).toThrow(MCPErrorFactory.resourceNotFound('Resource template \'non-existent\' not found'));
    });
  });

  describe('Parameter Extraction', () => {
    let server: MCPServer;
    let templateHandler: ResourceTemplateHandler;

    beforeEach(() => {
      server = new MCPServer({ name: 'test', version: '1.0.0' });
      mockSDKServer = server.getSDKServer();
      
      // Ensure all SDK server methods are spies
      if (!vi.isMockFunction(mockSDKServer.registerResource)) {
        mockSDKServer.registerResource = vi.fn();
      }
      if (!vi.isMockFunction(mockSDKServer.server.notification)) {
        mockSDKServer.server.notification = vi.fn();
      }
      
      // Clear any calls from server initialization
      vi.clearAllMocks();
      
      templateHandler = vi.fn().mockResolvedValue({
        contents: [{ uri: 'test', text: 'content' }]
      });

      server.registerResourceTemplate(
        'user-docs',
        'file:///users/{userId}/documents/{docId}',
        {},
        templateHandler
      );
    });

    it('should extract parameters from URI using template (via private method testing)', () => {
      // We need to test parameter extraction through the handler wrapper
      // by triggering it with the SDK server registration
      
      // Verify that registerResource was called
      expect(mockSDKServer.registerResource).toHaveBeenCalled();
      
      // Get the registered handler from the SDK server mock
      const calls = mockSDKServer.registerResource.mock.calls;
      expect(calls.length).toBeGreaterThan(0);
      expect(calls[0]).toBeDefined();
      expect(calls[0].length).toBeGreaterThan(3);
      
      const registeredHandler = calls[0][3];
      expect(typeof registeredHandler).toBe('function');
      
      // Call the wrapped handler with a matching URI
      const testUri = new URL('file:///users/123/documents/test.txt');
      
      expect(async () => {
        await registeredHandler(testUri);
      }).not.toThrow();
      
      // Verify the original handler was called with extracted parameters
      expect(templateHandler).toHaveBeenCalledWith(
        testUri,
        { userId: '123', docId: 'test.txt' }
      );
    });

    it('should reject URI with invalid percent-encoding in parameters', async () => {
      const calls = mockSDKServer.registerResource.mock.calls;
      const registeredHandler = calls[0][3];

      // URI with malformed percent-encoding (%GG is not valid hex)
      const badUri = new URL('file:///users/123/documents/bad%GGname');

      await expect(registeredHandler(badUri)).rejects.toThrow('invalid percent-encoding');
    });
  });

  describe('Parameter Validation', () => {
    it('should validate required parameters', async () => {
      const handler: ResourceTemplateHandler = vi.fn().mockResolvedValue({
        contents: [{ uri: 'test', text: 'content' }]
      });

      server.registerResourceTemplate(
        'validated-template',
        'file:///users/{userId}/docs/{docId}',
        {
          parameterSchema: {
            type: 'object',
            required: ['userId', 'docId'],
            properties: {
              userId: { type: 'number' },
              docId: { type: 'string' }
            }
          }
        },
        handler
      );

      // Get the registered handler
      const registeredHandler = mockSDKServer.registerResource.mock.calls[0][3];
      
      // Test with valid parameters (numeric userId)
      const validUri = new URL('file:///users/123/docs/test.txt');
      await expect(registeredHandler(validUri)).resolves.not.toThrow();
      
      // Test with invalid parameters (non-numeric userId)
      const invalidUri = new URL('file:///users/abc/docs/test.txt');
      await expect(registeredHandler(invalidUri)).rejects.toThrow();
    });

    it('should validate parameter types', async () => {
      const handler: ResourceTemplateHandler = vi.fn().mockResolvedValue({
        contents: [{ uri: 'test', text: 'content' }]
      });

      server.registerResourceTemplate(
        'typed-template',
        'file:///items/{itemId}',
        {
          parameterSchema: {
            properties: {
              itemId: { type: 'number' }
            }
          }
        },
        handler
      );

      const registeredHandler = mockSDKServer.registerResource.mock.calls[0][3];
      
      // Valid numeric parameter
      const validUri = new URL('file:///items/123');
      await expect(registeredHandler(validUri)).resolves.not.toThrow();
      
      // Invalid non-numeric parameter
      const invalidUri = new URL('file:///items/abc');
      await expect(registeredHandler(invalidUri)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('Parameter \'itemId\' must be a number')
        })
      );
    });
  });

  describe('Error Handling', () => {
    it('should wrap handler errors in MCP error format', async () => {
      const handler: ResourceTemplateHandler = vi.fn().mockRejectedValue(
        new Error('Handler error')
      );

      server.registerResourceTemplate(
        'error-template',
        'file:///test/{id}',
        {},
        handler
      );

      const registeredHandler = mockSDKServer.registerResource.mock.calls[0][3];
      const testUri = new URL('file:///test/123');
      
      await expect(registeredHandler(testUri)).rejects.toThrow();
      
      try {
        await registeredHandler(testUri);
      } catch (error: any) {
        expect(error.code).toBe(MCPErrorCode.InternalError);
        expect(error.message).toBe('Handler error');
        expect(error.data?.type).toBe('wrapped_error');
      }
    });

    it('should preserve MCP errors from handler', async () => {
      const mcpError = MCPErrorFactory.resourceNotFound('file:///test/123');
      const handler: ResourceTemplateHandler = vi.fn().mockRejectedValue(mcpError);

      server.registerResourceTemplate(
        'mcp-error-template',
        'file:///test/{id}',
        {},
        handler
      );

      const registeredHandler = mockSDKServer.registerResource.mock.calls[0][3];
      const testUri = new URL('file:///test/123');
      
      await expect(registeredHandler(testUri)).rejects.toThrow(mcpError);
    });

    it('should handle URI template mismatch errors', async () => {
      const handler: ResourceTemplateHandler = vi.fn().mockResolvedValue({
        contents: [{ uri: 'test', text: 'content' }]
      });

      server.registerResourceTemplate(
        'mismatch-template',
        'file:///users/{userId}/docs/{docId}',
        {},
        handler
      );

      const registeredHandler = mockSDKServer.registerResource.mock.calls[0][3];
      
      // URI that doesn't match the template
      const mismatchUri = new URL('file:///different/path');
      
      await expect(registeredHandler(mismatchUri)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('does not match template')
        })
      );
    });
  });

  describe('Notifications', () => {
    let mockTransport: any;

    beforeEach(async () => {
      mockTransport = {
        start: vi.fn(),
        stop: vi.fn()
      };
      
      server.useTransport(mockTransport);
      await server.start();
    });

    afterEach(async () => {
      await server.stop();
    });

    it('should send resource list changed notification when template is registered', async () => {
      const handler: ResourceTemplateHandler = vi.fn().mockResolvedValue({
        contents: [{ uri: 'test', text: 'content' }]
      });

      server.registerResourceTemplate(
        'notification-template',
        'file:///test/{id}',
        {},
        handler
      );

      // Give it a moment for the async notification to be sent
      await new Promise(resolve => setTimeout(resolve, 10));

      expect(mockSDKServer.server.notification).toHaveBeenCalledWith({
        method: 'notifications/resources/list_changed',
        params: {}
      });
    });
  });

  describe('Integration with Regular Resources', () => {
    it('should work alongside regular resource registration', () => {
      const resourceHandler = vi.fn().mockResolvedValue({
        contents: [{ uri: 'file:///static.txt', text: 'static content' }]
      });

      const templateHandler: ResourceTemplateHandler = vi.fn().mockResolvedValue({
        contents: [{ uri: 'dynamic', text: 'dynamic content' }]
      });

      // Register both types
      server.registerResource('static-resource', 'file:///static.txt', {
        title: 'Static Resource'
      }, resourceHandler);

      server.registerResourceTemplate(
        'dynamic-template',
        'file:///dynamic/{id}',
        { title: 'Dynamic Template' },
        templateHandler
      );

      // Both should be available
      const resources = server.getResources();
      const templates = server.listResourceTemplates();
      
      expect(resources).toHaveLength(1);
      expect(templates).toHaveLength(1);
      expect(resources[0].name).toBe('static-resource');
      expect(templates[0].name).toBe('dynamic-template');

      // Capabilities should include both
      const capabilities = server.getCapabilities();
      expect(capabilities.resources).toHaveLength(1);
      expect(capabilities.resourceTemplates).toHaveLength(1);
    });
  });
});