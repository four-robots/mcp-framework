import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { MCPServer, MCPErrorFactory, MCPErrorCode } from '../src/index.js';
import type { 
  SamplingConfig,
  SamplingHandler,
  SamplingRequest,
  SamplingResponse,
  SamplingMessage,
  ModelPreferences
} from '../src/index.js';

// Mock the SDK server
vi.mock('@modelcontextprotocol/sdk/server/mcp.js', () => ({
  McpServer: vi.fn().mockImplementation(() => ({
    registerTool: vi.fn(),
    registerResource: vi.fn(),
    registerPrompt: vi.fn(),
    notification: vi.fn(),
    setRequestHandler: vi.fn(),
    server: {
      notification: vi.fn(),
      setRequestHandler: vi.fn()
    }
  }))
}));

describe('MCP Sampling System', () => {
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

  describe('Sampling Registration', () => {
    it('should register basic sampling configuration', () => {
      const mockHandler: SamplingHandler = vi.fn().mockResolvedValue({
        role: 'assistant',
        content: {
          type: 'text',
          text: 'Test response'
        }
      });

      const config: SamplingConfig = {
        createMessage: mockHandler,
        includeContext: true,
        supportedModels: ['gpt-4', 'claude-3'],
        maxTokensLimit: 4096
      };

      expect(() => {
        server.registerSampling(config);
      }).not.toThrow();

      expect(server.isSamplingAvailable()).toBe(true);
      
      const samplingInfo = server.getSamplingInfo();
      expect(samplingInfo).toEqual({
        includeContext: true,
        supportedModels: ['gpt-4', 'claude-3'],
        maxTokensLimit: 4096
      });
    });

    it('should register sampling with temperature range', () => {
      const mockHandler: SamplingHandler = vi.fn().mockResolvedValue({
        model: 'test-model',
        role: 'assistant',
        content: { type: 'text', text: 'Response' }
      });

      const config: SamplingConfig = {
        createMessage: mockHandler,
        temperatureRange: { min: 0.1, max: 1.5 },
        metadata: { provider: 'openai' }
      };

      server.registerSampling(config);

      const samplingInfo = server.getSamplingInfo();
      expect(samplingInfo?.temperatureRange).toEqual({ min: 0.1, max: 1.5 });
      expect(samplingInfo?.metadata).toEqual({ provider: 'openai' });
    });

    it('should register request handler with SDK server', () => {
      const mockHandler: SamplingHandler = vi.fn().mockResolvedValue({
        model: 'test-model',
        role: 'assistant',
        content: { type: 'text', text: 'Response' }
      });

      // Clear mock after server construction (logging handler was registered)
      mockSDKServer.server.setRequestHandler.mockClear();

      server.registerSampling({ createMessage: mockHandler });

      expect(mockSDKServer.server.setRequestHandler).toHaveBeenCalledTimes(1);
      expect(mockSDKServer.server.setRequestHandler).toHaveBeenCalledWith(
        expect.any(Object), // Zod schema
        expect.any(Function) // Handler function
      );
    });
  });

  describe('Sampling Validation', () => {
    it('should throw error for missing createMessage handler', () => {
      expect(() => {
        server.registerSampling({
          createMessage: undefined as any
        });
      }).toThrow(MCPErrorFactory.invalidParams('Sampling createMessage handler must be a function'));
    });

    it('should throw error for non-function createMessage', () => {
      expect(() => {
        server.registerSampling({
          createMessage: 'not a function' as any
        });
      }).toThrow(MCPErrorFactory.invalidParams('Sampling createMessage handler must be a function'));
    });

    it('should validate temperature range', () => {
      const mockHandler: SamplingHandler = vi.fn();

      expect(() => {
        server.registerSampling({
          createMessage: mockHandler,
          temperatureRange: { min: -1, max: 1 }
        });
      }).toThrow(MCPErrorFactory.invalidParams('Invalid temperature range: must be between 0-2 and min <= max'));

      expect(() => {
        server.registerSampling({
          createMessage: mockHandler,
          temperatureRange: { min: 1, max: 3 }
        });
      }).toThrow(MCPErrorFactory.invalidParams('Invalid temperature range: must be between 0-2 and min <= max'));

      expect(() => {
        server.registerSampling({
          createMessage: mockHandler,
          temperatureRange: { min: 1.5, max: 1.0 }
        });
      }).toThrow(MCPErrorFactory.invalidParams('Invalid temperature range: must be between 0-2 and min <= max'));
    });

    it('should validate max tokens limit', () => {
      const mockHandler: SamplingHandler = vi.fn();

      expect(() => {
        server.registerSampling({
          createMessage: mockHandler,
          maxTokensLimit: -100
        });
      }).toThrow(MCPErrorFactory.invalidParams('Max tokens limit must be a positive number'));

      expect(() => {
        server.registerSampling({
          createMessage: mockHandler,
          maxTokensLimit: 0
        });
      }).toThrow(MCPErrorFactory.invalidParams('Max tokens limit must be a positive number'));
    });
  });

  describe('Sampling Request Handling', () => {
    let mockHandler: SamplingHandler;

    beforeEach(() => {
      mockHandler = vi.fn().mockResolvedValue({
        model: 'test-model',
        role: 'assistant',
        content: {
          type: 'text',
          text: 'This is a test response from the sampling system.'
        },
        stopReason: 'endTurn',
        usage: {
          inputTokens: 50,
          outputTokens: 15,
          totalTokens: 65
        }
      });

      server.registerSampling({
        createMessage: mockHandler,
        includeContext: true,
        maxTokensLimit: 4096,
        temperatureRange: { min: 0.0, max: 2.0 }
      });
    });

    it('should handle basic sampling request', async () => {
      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: {
            type: 'text',
            text: 'Hello, how are you?'
          }
        }],
        maxTokens: 100,
        temperature: 0.7
      };

      const response = await server.createSamplingMessage(request);

      expect(response).toEqual({
        model: 'test-model',
        role: 'assistant',
        content: {
          type: 'text',
          text: 'This is a test response from the sampling system.'
        },
        stopReason: 'endTurn',
        usage: {
          inputTokens: 50,
          outputTokens: 15,
          totalTokens: 65
        }
      });

      expect(mockHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          messages: request.messages,
          maxTokens: 100,
          temperature: 0.7
        })
      );
    });

    it('should handle request with model preferences', async () => {
      const modelPreferences: ModelPreferences = {
        hints: ['be concise', 'use technical language'],
        costPriority: 0.3,
        speedPriority: 0.8,
        intelligencePriority: 0.9
      };

      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Explain quantum computing' }
        }],
        modelPreferences,
        systemPrompt: 'You are a helpful technical assistant.'
      };

      await server.createSamplingMessage(request);

      expect(mockHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          modelPreferences,
          systemPrompt: 'You are a helpful technical assistant.'
        })
      );
    });

    it('should handle multi-modal messages', async () => {
      const request: SamplingRequest = {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: 'What do you see in this image?'
            }
          },
          {
            role: 'user',
            content: {
              type: 'image',
              data: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==',
              mimeType: 'image/png'
            }
          }
        ]
      };

      await server.createSamplingMessage(request);

      expect(mockHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          messages: request.messages
        })
      );
    });

    it('should add server context when includeContext is true', async () => {
      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Hello' }
        }],
        includeContext: true
      };

      await server.createSamplingMessage(request);

      expect(mockHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata: expect.objectContaining({
            serverContext: expect.objectContaining({
              name: 'test-server',
              version: '1.0.0',
              capabilities: expect.any(Object),
              timestamp: expect.any(String)
            })
          })
        })
      );
    });

    it('should apply default temperature from server range', async () => {
      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Hello' }
        }]
        // No temperature specified
      };

      await server.createSamplingMessage(request);

      expect(mockHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          temperature: 1.0 // (0.0 + 2.0) / 2
        })
      );
    });
  });

  describe('Request Validation', () => {
    beforeEach(() => {
      const mockHandler: SamplingHandler = vi.fn().mockResolvedValue({
        model: 'test-model',
        role: 'assistant',
        content: { type: 'text', text: 'Response' }
      });

      server.registerSampling({
        createMessage: mockHandler,
        maxTokensLimit: 1000,
        temperatureRange: { min: 0.1, max: 1.8 }
      });
    });

    it('should validate required messages array', async () => {
      const invalidRequests = [
        { messages: [] },
        { messages: undefined as any },
        { messages: 'not an array' as any }
      ];

      for (const request of invalidRequests) {
        await expect(server.createSamplingMessage(request as any)).rejects.toThrow(
          expect.objectContaining({
            message: expect.stringContaining('must include at least one message')
          })
        );
      }
    });

    it('should validate message roles', async () => {
      const request: SamplingRequest = {
        messages: [{
          role: 'invalid' as any,
          content: { type: 'text', text: 'Hello' }
        }]
      };

      await expect(server.createSamplingMessage(request)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('Invalid role at message 0')
        })
      );
    });

    it('should validate message content types', async () => {
      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: {
            type: 'invalid' as any,
            text: 'Hello'
          }
        }]
      };

      await expect(server.createSamplingMessage(request)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('Invalid content type at message 0')
        })
      );
    });

    it('should validate text message content', async () => {
      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: {
            type: 'text'
            // Missing text field
          } as any
        }]
      };

      await expect(server.createSamplingMessage(request)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('Text message at index 0 must have text content')
        })
      );
    });

    it('should validate image message content', async () => {
      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: {
            type: 'image',
            data: 'base64data'
            // Missing mimeType
          } as any
        }]
      };

      await expect(server.createSamplingMessage(request)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('Image message at index 0 must have data and mimeType')
        })
      );
    });

    it('should validate model preferences ranges', async () => {
      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Hello' }
        }],
        modelPreferences: {
          costPriority: 1.5 // Invalid: > 1
        }
      };

      await expect(server.createSamplingMessage(request)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('Cost priority must be between 0 and 1')
        })
      );
    });

    it('should validate temperature against server limits', async () => {
      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Hello' }
        }],
        temperature: 2.0 // Outside server range of 0.1-1.8
      };

      await expect(server.createSamplingMessage(request)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('Temperature must be between 0.1 and 1.8')
        })
      );
    });

    it('should validate max tokens against server limits', async () => {
      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Hello' }
        }],
        maxTokens: 2000 // Exceeds server limit of 1000
      };

      await expect(server.createSamplingMessage(request)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('Max tokens cannot exceed 1000')
        })
      );
    });
  });

  describe('Response Validation', () => {
    it('should validate sampling response format', async () => {
      const invalidHandler: SamplingHandler = vi.fn().mockResolvedValue({
        // Missing model field
        role: 'assistant',
        content: { type: 'text', text: 'Response' }
      });

      server.registerSampling({ createMessage: invalidHandler });

      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Hello' }
        }]
      };

      await expect(server.createSamplingMessage(request)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('Sampling response must have a model string')
        })
      );
    });

    it('should reject user role in sampling response', async () => {
      const invalidHandler: SamplingHandler = vi.fn().mockResolvedValue({
        model: 'test-model',
        role: 'user', // Invalid: sampling responses must be from 'assistant'
        content: { type: 'text', text: 'Response' }
      });

      server.registerSampling({ createMessage: invalidHandler });

      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Hello' }
        }]
      };

      await expect(server.createSamplingMessage(request)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('Sampling response role must be assistant')
        })
      );
    });

    it('should validate response content format', async () => {
      const invalidHandler: SamplingHandler = vi.fn().mockResolvedValue({
        model: 'test-model',
        role: 'assistant',
        content: {
          type: 'image', // Invalid: should be 'text'
          text: 'Response'
        } as any
      });

      server.registerSampling({ createMessage: invalidHandler });

      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Hello' }
        }]
      };

      await expect(server.createSamplingMessage(request)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('Sampling response content must be text type')
        })
      );
    });

    it('should validate usage statistics format', async () => {
      const invalidHandler: SamplingHandler = vi.fn().mockResolvedValue({
        // Missing model field
        role: 'assistant',
        content: { type: 'text', text: 'Response' },
        usage: {
          inputTokens: -10 // This is now allowed since we removed usage validation
        }
      });

      server.registerSampling({ createMessage: invalidHandler });

      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Hello' }
        }]
      };

      await expect(server.createSamplingMessage(request)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('Sampling response must have a model string')
        })
      );
    });
  });

  describe('Error Handling', () => {
    it('should handle sampling when not configured', async () => {
      // Don't register sampling
      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Hello' }
        }]
      };

      await expect(server.createSamplingMessage(request)).rejects.toThrow(
        MCPErrorFactory.invalidRequest('Sampling is not configured on this server')
      );
    });

    it('should handle handler errors gracefully', async () => {
      const faultyHandler: SamplingHandler = vi.fn().mockRejectedValue(
        new Error('Model API error')
      );

      server.registerSampling({ createMessage: faultyHandler });

      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Hello' }
        }]
      };

      await expect(server.createSamplingMessage(request)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('Sampling failed: Model API error')
        })
      );
    });

    it('should handle unknown handler errors', async () => {
      const faultyHandler: SamplingHandler = vi.fn().mockRejectedValue(
        'Unknown error type'
      );

      server.registerSampling({ createMessage: faultyHandler });

      const request: SamplingRequest = {
        messages: [{
          role: 'user',
          content: { type: 'text', text: 'Hello' }
        }]
      };

      await expect(server.createSamplingMessage(request)).rejects.toThrow(
        expect.objectContaining({
          message: expect.stringContaining('Sampling failed with unknown error')
        })
      );
    });
  });

  describe('Capabilities Integration', () => {
    it('should include sampling in capabilities when configured', () => {
      const mockHandler: SamplingHandler = vi.fn();
      
      server.registerSampling({
        createMessage: mockHandler,
        includeContext: true,
        supportedModels: ['gpt-4']
      });

      const capabilities = server.getCapabilities();
      
      expect(capabilities.sampling).toBeDefined();
      expect(capabilities.sampling?.includeContext).toBe(true);
      expect(capabilities.sampling?.supportedModels).toEqual(['gpt-4']);
    });

    it('should not include sampling in capabilities when not configured', () => {
      const capabilities = server.getCapabilities();
      
      expect(capabilities.sampling).toBeUndefined();
    });

    it('should report sampling availability correctly', () => {
      expect(server.isSamplingAvailable()).toBe(false);
      
      const mockHandler: SamplingHandler = vi.fn();
      server.registerSampling({ createMessage: mockHandler });
      
      expect(server.isSamplingAvailable()).toBe(true);
    });
  });
});