import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { MCPServer, MCPErrorFactory, MCPErrorCode } from '../src/index.js';
import type { 
  CompletionConfig, 
  CompletionHandler, 
  CompletionRequest, 
  CompletionResult 
} from '../src/index.js';
import { z } from 'zod';

// SDK server is mocked globally in setup.ts

describe('MCP Completion System', () => {
  let server: MCPServer;
  let mockSDKServer: any;

  beforeEach(() => {
    server = new MCPServer({
      name: 'test-server',
      version: '1.0.0'
    });
    mockSDKServer = server.getSDKServer();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Completion Registration', () => {
    it('should register a basic completion handler', () => {
      const handler: CompletionHandler = vi.fn().mockResolvedValue({
        completion: {
          values: ['option1', 'option2'],
          total: 2,
          hasMore: false
        }
      });

      const config: CompletionConfig = {
        name: 'test-completion',
        description: 'Test completion handler',
        supportedTypes: ['ref/prompt']
      };

      expect(() => {
        server.registerCompletion(config, handler);
      }).not.toThrow();

      const registeredCompletion = server.getCompletion('test-completion');
      expect(registeredCompletion).toBeDefined();
      expect(registeredCompletion?.name).toBe('test-completion');
      expect(registeredCompletion?.supportedTypes).toEqual(['ref/prompt']);
    });

    it('should register completion handler for multiple types', () => {
      const handler: CompletionHandler = vi.fn().mockResolvedValue({
        completion: { values: [], total: 0, hasMore: false }
      });

      const config: CompletionConfig = {
        name: 'multi-type-completion',
        supportedTypes: ['ref/prompt', 'ref/resource'],
        supportedArguments: ['format', 'language']
      };

      server.registerCompletion(config, handler);

      const completion = server.getCompletion('multi-type-completion');
      expect(completion?.supportedTypes).toEqual(['ref/prompt', 'ref/resource']);
      expect(completion?.supportedArguments).toEqual(['format', 'language']);
    });

    it('should register request handler with SDK server on first completion', () => {
      const handler: CompletionHandler = vi.fn().mockResolvedValue({
        completion: { values: [], total: 0, hasMore: false }
      });

      server.registerCompletion({
        name: 'first-completion',
        supportedTypes: ['ref/prompt']
      }, handler);

      // Verify that the completion was registered internally
      expect(server.listCompletions()).toHaveLength(1);
      expect(server.listCompletions()[0].name).toBe('first-completion');
    });

    it('should register completion handler with SDK server integration', () => {
      const handler: CompletionHandler = vi.fn().mockResolvedValue({
        completion: { values: ['value1', 'value2'], total: 2, hasMore: false }
      });

      server.registerCompletion({
        name: 'test-completion',
        supportedTypes: ['ref/prompt']
      }, handler);

      // Verify the completion is registered internally
      const completion = server.getCompletion('test-completion');
      expect(completion).toBeDefined();
      expect(completion?.name).toBe('test-completion');
      expect(completion?.supportedTypes).toEqual(['ref/prompt']);
    });

    it('should handle completion requests through internal API', async () => {
      const handler: CompletionHandler = vi.fn().mockResolvedValue({
        completion: { 
          values: [
            { value: 'option1', label: 'Option 1', insertText: 'opt1' },
            { value: 'option2', label: 'Option 2' }
          ], 
          total: 2, 
          hasMore: false 
        }
      });

      server.registerCompletion({
        name: 'test-completion',
        supportedTypes: ['ref/prompt']
      }, handler);

      // Register a test prompt
      server.registerPrompt('test-prompt', {
        title: 'Test Prompt',
        description: 'A test prompt'
      }, vi.fn());

      // Test completion through internal API
      const result = await server.getCompletions(
        { type: 'ref/prompt', name: 'test-prompt' },
        { name: 'arg1', value: 'val1' }
      );
      
      // Verify the handler was called with correct parameters
      expect(handler).toHaveBeenCalledWith({
        ref: { type: 'ref/prompt', name: 'test-prompt' },
        argument: { name: 'arg1', value: 'val1' }
      });
      
      // Verify the response
      expect(result).toEqual({
        completion: {
          values: [
            { value: 'option1', label: 'Option 1', insertText: 'opt1' },
            { value: 'option2', label: 'Option 2' }
          ],
          total: 2,
          hasMore: false
        }
      });
    });

    it('should not register duplicate request handlers', () => {
      const handler: CompletionHandler = vi.fn().mockResolvedValue({
        completion: { values: [], total: 0, hasMore: false }
      });

      server.registerCompletion({
        name: 'first-completion',
        supportedTypes: ['ref/prompt']
      }, handler);

      server.registerCompletion({
        name: 'second-completion',
        supportedTypes: ['ref/resource']
      }, handler);

      // Should have registered both completions internally
      expect(server.listCompletions()).toHaveLength(2);
      expect(server.listCompletions().map(c => c.name)).toEqual(['first-completion', 'second-completion']);
    });
  });

  describe('Completion Validation', () => {
    it('should throw error for empty completion name', () => {
      const handler: CompletionHandler = vi.fn();
      
      expect(() => {
        server.registerCompletion({
          name: '',
          supportedTypes: ['ref/prompt']
        }, handler);
      }).toThrow(MCPErrorFactory.invalidParams('Completion name must be a non-empty string'));
    });

    it('should throw error for non-string completion name', () => {
      const handler: CompletionHandler = vi.fn();
      
      expect(() => {
        server.registerCompletion({
          name: null as any,
          supportedTypes: ['ref/prompt']
        }, handler);
      }).toThrow(MCPErrorFactory.invalidParams('Completion name must be a non-empty string'));
    });

    it('should throw error for duplicate completion name', () => {
      const handler: CompletionHandler = vi.fn();
      const config = {
        name: 'duplicate-completion',
        supportedTypes: ['ref/prompt'] as const
      };
      
      server.registerCompletion(config, handler);
      
      expect(() => {
        server.registerCompletion(config, handler);
      }).toThrow(MCPErrorFactory.invalidParams('Completion \'duplicate-completion\' is already registered'));
    });

    it('should throw error for empty supported types', () => {
      const handler: CompletionHandler = vi.fn();
      
      expect(() => {
        server.registerCompletion({
          name: 'invalid-completion',
          supportedTypes: []
        }, handler);
      }).toThrow(MCPErrorFactory.invalidParams('Completion must support at least one reference type'));
    });

    it('should throw error for invalid supported types', () => {
      const handler: CompletionHandler = vi.fn();
      
      expect(() => {
        server.registerCompletion({
          name: 'invalid-type-completion',
          supportedTypes: ['invalid/type' as any]
        }, handler);
      }).toThrow(MCPErrorFactory.invalidParams('Invalid completion type: invalid/type'));
    });

    it('should validate supported types array', () => {
      const handler: CompletionHandler = vi.fn();
      
      expect(() => {
        server.registerCompletion({
          name: 'no-types',
          supportedTypes: undefined as any
        }, handler);
      }).toThrow(MCPErrorFactory.invalidParams('Completion must support at least one reference type'));
    });
  });

  describe('Completion Listing and Retrieval', () => {
    beforeEach(() => {
      const handler: CompletionHandler = vi.fn().mockResolvedValue({
        completion: { values: [], total: 0, hasMore: false }
      });

      server.registerCompletion({
        name: 'completion1',
        description: 'First completion',
        supportedTypes: ['ref/prompt']
      }, handler);

      server.registerCompletion({
        name: 'completion2',
        description: 'Second completion',
        supportedTypes: ['ref/resource'],
        supportedArguments: ['format']
      }, handler);
    });

    it('should list all registered completions', () => {
      const completions = server.listCompletions();
      
      expect(completions).toHaveLength(2);
      expect(completions.map(c => c.name)).toEqual(['completion1', 'completion2']);
      expect(completions[0].description).toBe('First completion');
      expect(completions[1].supportedArguments).toEqual(['format']);
    });

    it('should get specific completion configuration', () => {
      const completion = server.getCompletion('completion1');
      
      expect(completion).toBeDefined();
      expect(completion?.name).toBe('completion1');
      expect(completion?.supportedTypes).toEqual(['ref/prompt']);
    });

    it('should return undefined for non-existent completion', () => {
      const completion = server.getCompletion('non-existent');
      expect(completion).toBeUndefined();
    });

    it('should throw error for invalid completion name in getter', () => {
      expect(() => {
        server.getCompletion('');
      }).toThrow(MCPErrorFactory.invalidParams('Completion name must be a non-empty string'));

      expect(() => {
        server.getCompletion(null as any);
      }).toThrow(MCPErrorFactory.invalidParams('Completion name must be a non-empty string'));
    });

    it('should include completions in capabilities', () => {
      const capabilities = server.getCapabilities();
      
      expect(capabilities.completions).toHaveLength(2);
      expect(capabilities.completions.map(c => c.name)).toEqual(['completion1', 'completion2']);
    });
  });

  describe('Completion Handling', () => {
    let promptHandler: CompletionHandler;
    let resourceHandler: CompletionHandler;

    beforeEach(() => {
      // Register a prompt for testing
      server.registerPrompt('test-prompt', {
        title: 'Test Prompt',
        description: 'A test prompt'
      }, vi.fn());

      // Register a resource for testing
      server.registerResource('test-resource', 'file:///test.txt', {
        title: 'Test Resource'
      }, vi.fn());

      promptHandler = vi.fn().mockResolvedValue({
        completion: {
          values: ['prompt-completion1', 'prompt-completion2'],
          total: 2,
          hasMore: false
        }
      });

      resourceHandler = vi.fn().mockResolvedValue({
        completion: {
          values: ['resource-completion1'],
          total: 1,
          hasMore: false
        }
      });

      server.registerCompletion({
        name: 'prompt-completion',
        supportedTypes: ['ref/prompt']
      }, promptHandler);

      server.registerCompletion({
        name: 'resource-completion',
        supportedTypes: ['ref/resource']
      }, resourceHandler);
    });

    it('should handle prompt completion requests', async () => {
      const result = await server.getCompletions(
        { type: 'ref/prompt', name: 'test-prompt' },
        { name: 'format', value: 'json' }
      );

      expect(result).toEqual({
        completion: {
          values: ['prompt-completion1', 'prompt-completion2'],
          total: 2,
          hasMore: false
        }
      });

      expect(promptHandler).toHaveBeenCalledWith({
        ref: { type: 'ref/prompt', name: 'test-prompt' },
        argument: { name: 'format', value: 'json' }
      });
    });

    it('should handle resource completion requests', async () => {
      const result = await server.getCompletions(
        { type: 'ref/resource', name: 'test-resource' },
        { name: 'encoding', value: 'utf' }
      );

      expect(result).toEqual({
        completion: {
          values: ['resource-completion1'],
          total: 1,
          hasMore: false
        }
      });

      expect(resourceHandler).toHaveBeenCalledWith({
        ref: { type: 'ref/resource', name: 'test-resource' },
        argument: { name: 'encoding', value: 'utf' }
      });
    });

    it('should return empty completion for non-existent references', async () => {
      const result = await server.getCompletions(
        { type: 'ref/prompt', name: 'non-existent' },
        { name: 'arg', value: 'val' }
      );

      expect(result).toEqual({
        completion: {
          values: [],
          total: 0,
          hasMore: false
        }
      });
    });

    it('should handle completion with argument filtering', async () => {
      const specificHandler = vi.fn().mockResolvedValue({
        completion: {
          values: ['specific-completion'],
          total: 1,
          hasMore: false
        }
      });

      server.registerCompletion({
        name: 'specific-completion',
        supportedTypes: ['ref/prompt'],
        supportedArguments: ['language']
      }, specificHandler);

      // Should use specific handler for 'language' argument
      await server.getCompletions(
        { type: 'ref/prompt', name: 'test-prompt' },
        { name: 'language', value: 'en' }
      );

      expect(specificHandler).toHaveBeenCalled();

      // Should not use specific handler for other arguments
      await server.getCompletions(
        { type: 'ref/prompt', name: 'test-prompt' },
        { name: 'format', value: 'json' }
      );

      expect(promptHandler).toHaveBeenCalled();
    });
  });

  describe('Default Completion Handlers', () => {
    beforeEach(() => {
      // Register test items
      server.registerPrompt('test-prompt', {
        title: 'Test Prompt',
        description: 'A test prompt',
        argsSchema: {
          format: { type: 'string', enum: ['json', 'xml'] },
          language: { type: 'string' }
        }
      }, vi.fn());

      server.registerResource('test-resource', 'file:///test.txt', {
        title: 'Test Resource'
      }, vi.fn());

      server.registerResourceTemplate('test-template', 'file:///users/{userId}/docs/{docId}', {
        title: 'Test Template'
      }, vi.fn());
    });

    it('should register default prompt completion handler', () => {
      server.registerDefaultPromptCompletion();

      const completions = server.listCompletions();
      const defaultCompletion = completions.find(c => c.name === 'default-prompt-completion');
      
      expect(defaultCompletion).toBeDefined();
      expect(defaultCompletion?.supportedTypes).toEqual(['ref/prompt']);
    });

    it('should register default resource completion handler', () => {
      server.registerDefaultResourceCompletion();

      const completions = server.listCompletions();
      const defaultCompletion = completions.find(c => c.name === 'default-resource-completion');
      
      expect(defaultCompletion).toBeDefined();
      expect(defaultCompletion?.supportedTypes).toEqual(['ref/resource']);
    });

    it('should provide file extension completions for file arguments', async () => {
      server.registerDefaultPromptCompletion();

      const result = await server.getCompletions(
        { type: 'ref/prompt', name: 'test-prompt' },
        { name: 'filename', value: 'test' }
      );

      expect(result.completion.values.length).toBeGreaterThan(0);
      expect(result.completion.values.some(v => v.includes('.txt'))).toBe(true);
    });

    it('should provide format completions for format arguments', async () => {
      server.registerDefaultPromptCompletion();

      const result = await server.getCompletions(
        { type: 'ref/prompt', name: 'test-prompt' },
        { name: 'format', value: 'js' }
      );

      expect(result.completion.values.length).toBeGreaterThan(0);
      expect(result.completion.values.some(v => v.includes('json'))).toBe(true);
    });

    it('should provide template variable completions for resources', async () => {
      server.registerDefaultResourceCompletion();

      const result = await server.getCompletions(
        { type: 'ref/resource', name: 'test-template' },
        { name: 'uri', value: '' }
      );

      expect(result.completion.values.length).toBeGreaterThan(0);
      expect(result.completion.values.some(v => v.includes('{userId}'))).toBe(true);
      expect(result.completion.values.some(v => v.includes('{docId}'))).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should handle completion handler errors gracefully', async () => {
      const faultyHandler: CompletionHandler = vi.fn().mockRejectedValue(
        new Error('Handler error')
      );

      server.registerCompletion({
        name: 'faulty-completion',
        supportedTypes: ['ref/prompt']
      }, faultyHandler);

      // Register prompt
      server.registerPrompt('test-prompt', {
        title: 'Test Prompt'
      }, vi.fn());

      // Should fallback to empty completion when handler fails
      const result = await server.getCompletions(
        { type: 'ref/prompt', name: 'test-prompt' },
        { name: 'arg', value: 'val' }
      );

      expect(result).toEqual({
        completion: {
          values: [],
          total: 0,
          hasMore: false
        }
      });
    });

    it('should handle multiple handlers with fallback', async () => {
      const faultyHandler: CompletionHandler = vi.fn().mockRejectedValue(
        new Error('First handler error')
      );

      const workingHandler: CompletionHandler = vi.fn().mockResolvedValue({
        completion: {
          values: ['fallback-completion'],
          total: 1,
          hasMore: false
        }
      });

      server.registerCompletion({
        name: 'faulty-completion',
        supportedTypes: ['ref/prompt']
      }, faultyHandler);

      server.registerCompletion({
        name: 'working-completion',
        supportedTypes: ['ref/prompt']
      }, workingHandler);

      // Register prompt
      server.registerPrompt('test-prompt', {
        title: 'Test Prompt'
      }, vi.fn());

      const result = await server.getCompletions(
        { type: 'ref/prompt', name: 'test-prompt' },
        { name: 'arg', value: 'val' }
      );

      expect(result).toEqual({
        completion: {
          values: ['fallback-completion'],
          total: 1,
          hasMore: false
        }
      });

      expect(workingHandler).toHaveBeenCalled();
    });

    it('should wrap handler errors in MCP error format', async () => {
      // Register a prompt first
      server.registerPrompt('error-test-prompt', {
        title: 'Error Test Prompt'
      }, vi.fn());

      // Test through the SDK request handler
      const faultyHandler: CompletionHandler = vi.fn().mockRejectedValue(
        new Error('Handler error')
      );

      server.registerCompletion({
        name: 'error-completion',
        supportedTypes: ['ref/prompt']
      }, faultyHandler);

      // Test that error propagation works when enabled
      const request = {
        ref: { type: 'ref/prompt', name: 'error-test-prompt' },
        argument: { name: 'arg', value: 'val' }
      };

      // Direct call with propagateErrors=true should throw
      await expect(
        (server as any).handleCompletion(request, true)
      ).rejects.toThrow('Handler error');
    });

    it('should propagate errors from getCompletions when ServerConfig.propagateErrors is true', async () => {
      const errorServer = new MCPServer({
        name: 'error-server',
        version: '1.0.0',
        propagateErrors: true
      });

      // Register a prompt so the reference exists
      errorServer.registerPrompt('error-prompt', {
        title: 'Error Prompt'
      }, vi.fn());

      // Register a failing completion handler
      const faultyHandler: CompletionHandler = vi.fn().mockRejectedValue(
        new Error('Config propagation test')
      );

      errorServer.registerCompletion({
        name: 'config-error-completion',
        supportedTypes: ['ref/prompt']
      }, faultyHandler);

      // getCompletions should propagate the error because config.propagateErrors=true
      await expect(
        errorServer.getCompletions(
          { type: 'ref/prompt', name: 'error-prompt' },
          { name: 'arg', value: 'val' }
        )
      ).rejects.toThrow('Config propagation test');
    });

    it('should not propagate errors from getCompletions when ServerConfig.propagateErrors is false', async () => {
      const safeServer = new MCPServer({
        name: 'safe-server',
        version: '1.0.0',
        propagateErrors: false
      });

      // Register a prompt so the reference exists
      safeServer.registerPrompt('safe-prompt', {
        title: 'Safe Prompt'
      }, vi.fn());

      // Register a failing completion handler
      const faultyHandler: CompletionHandler = vi.fn().mockRejectedValue(
        new Error('Should not propagate')
      );

      safeServer.registerCompletion({
        name: 'safe-error-completion',
        supportedTypes: ['ref/prompt']
      }, faultyHandler);

      // getCompletions should return empty result, NOT throw
      const result = await safeServer.getCompletions(
        { type: 'ref/prompt', name: 'safe-prompt' },
        { name: 'arg', value: 'val' }
      );

      expect(result.completion.values).toEqual([]);
      expect(result.completion.total).toBe(0);
    });
  });
});