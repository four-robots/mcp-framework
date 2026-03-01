import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  BaseMCPClient,
  ConnectionState,
  ElicitationAction,
  type ElicitationRequest,
  type ElicitationResponse,
  type ElicitationField,
  type ElicitationHandler,
  type ElicitationValidationError,
  type ClientConfig
} from '../src/index.js';
import { CallToolResult, JSONRPCMessage, JSONRPCResponse } from '@modelcontextprotocol/sdk/types';

// Mock implementation of BaseMCPClient for testing elicitation
class MockElicitationClient extends BaseMCPClient {
  private mockSDKClient = {
    connect: vi.fn(),
    disconnect: vi.fn(),
    listTools: vi.fn(),
    callTool: vi.fn(),
    listResources: vi.fn(),
    readResource: vi.fn(),
    listPrompts: vi.fn(),
    getPrompt: vi.fn()
  };

  async connect(): Promise<void> {
    this.setConnectionState(ConnectionState.Connecting);
    await this.mockSDKClient.connect();
    this.setConnectionState(ConnectionState.Connected);
  }

  async disconnect(): Promise<void> {
    this.setConnectionState(ConnectionState.Disconnecting);
    await this.mockSDKClient.disconnect();
    this.setConnectionState(ConnectionState.Disconnected);
  }

  async listTools() {
    this.ensureConnected();
    return this.mockSDKClient.listTools();
  }

  async listResources() {
    this.ensureConnected();
    return this.mockSDKClient.listResources();
  }

  async readResource(uri: string) {
    this.ensureConnected();
    return this.mockSDKClient.readResource(uri);
  }

  async listPrompts() {
    this.ensureConnected();
    return this.mockSDKClient.listPrompts();
  }

  async getPrompt(name: string, args?: any) {
    this.ensureConnected();
    return this.mockSDKClient.getPrompt(name, args);
  }

  protected async doCallTool(name: string, args?: any): Promise<CallToolResult> {
    this.ensureConnected();
    return this.mockSDKClient.callTool(name, args);
  }

  async sendMessage(message: JSONRPCMessage): Promise<JSONRPCResponse | void> {
    this.ensureConnected();
    
    if ('id' in message && message.id !== undefined) {
      return {
        jsonrpc: '2.0',
        id: message.id,
        result: { mock: 'response' }
      };
    }
  }

  protected async sendHeartbeat(): Promise<void> {
    // Mock heartbeat implementation
  }

  getSDKClient() {
    return this.mockSDKClient;
  }

  // Expose protected methods for testing
  public setConnectionStatePublic(state: any) {
    this.setConnectionState(state);
  }

  public handleElicitationNotificationPublic(notification: any) {
    return this.handleElicitationNotification(notification);
  }

  // Expose cleanup for testing handler persistence
  public cleanupPublic() {
    this.cleanup();
  }

  // Expose notifyProgress for testing progress callback persistence
  public notifyProgressPublic(progress: any) {
    this.notifyProgress(progress);
  }
}

describe('MCP Elicitation System', () => {
  let client: MockElicitationClient;
  let config: ClientConfig;

  beforeEach(() => {
    config = {
      timeout: 5000,
      autoReconnect: false
    };
    client = new MockElicitationClient(config);
    // Mock console.error to suppress expected error logs during tests
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(async () => {
    await client.disconnect();
    vi.clearAllMocks();
  });

  describe('Elicitation Handler Registration', () => {
    it('should register and unregister elicitation handlers', () => {
      const handler: ElicitationHandler = vi.fn().mockResolvedValue({
        id: 'test-request',
        action: ElicitationAction.Accept,
        values: { name: 'Test User' }
      });

      const unregister = client.registerElicitationHandler(handler);
      
      expect(typeof unregister).toBe('function');
      
      // Unregister the handler
      unregister();
      
      expect(() => unregister()).not.toThrow(); // Should be safe to call multiple times
    });

    it('should support multiple elicitation handlers', () => {
      const handler1: ElicitationHandler = vi.fn();
      const handler2: ElicitationHandler = vi.fn();

      const unregister1 = client.registerElicitationHandler(handler1);
      const unregister2 = client.registerElicitationHandler(handler2);

      expect(typeof unregister1).toBe('function');
      expect(typeof unregister2).toBe('function');

      // Unregister handlers
      unregister1();
      unregister2();
    });

    it('should preserve handlers after cleanup (disconnect/reconnect)', async () => {
      const handler: ElicitationHandler = vi.fn().mockResolvedValue({
        id: 'persist-test',
        action: ElicitationAction.Accept,
        values: { name: 'Persistent' }
      });

      const stateHandler = vi.fn();
      const progressHandler = vi.fn();

      client.registerElicitationHandler(handler);
      client.subscribeToConnectionState(stateHandler);
      client.subscribeToProgress(progressHandler);

      // Simulate cleanup (called during disconnect in concrete clients)
      client.cleanupPublic();

      // Elicitation handlers should still work after cleanup
      const request: ElicitationRequest = {
        id: 'persist-test',
        title: 'Test',
        fields: [{ name: 'name', type: 'text', label: 'Name' }]
      };

      const response = await client.handleElicitationRequest(request);
      expect(response.action).toBe(ElicitationAction.Accept);
      expect(response.values?.name).toBe('Persistent');
      expect(handler).toHaveBeenCalled();

      // State change callbacks should still fire after cleanup
      client.setConnectionStatePublic(ConnectionState.Connected);
      expect(stateHandler).toHaveBeenCalledWith(ConnectionState.Connected, undefined);

      // Progress callbacks should still fire after cleanup
      const progress = { progressToken: 'tok', progress: 50, total: 100 };
      client.notifyProgressPublic(progress);
      expect(progressHandler).toHaveBeenCalledWith(progress);
    });
  });

  describe('Elicitation Request Handling', () => {
    let testRequest: ElicitationRequest;
    let mockHandler: ElicitationHandler;

    beforeEach(() => {
      testRequest = {
        id: 'test-elicitation-1',
        title: 'User Information',
        description: 'Please provide your information',
        fields: [
          {
            name: 'name',
            type: 'text',
            label: 'Full Name',
            required: true
          },
          {
            name: 'email',
            type: 'email',
            label: 'Email Address',
            required: true
          },
          {
            name: 'age',
            type: 'number',
            label: 'Age',
            validation: { min: 18, max: 120 }
          }
        ],
        allowCancel: true
      };

      mockHandler = vi.fn().mockResolvedValue({
        id: testRequest.id,
        action: ElicitationAction.Accept,
        values: {
          name: 'John Doe',
          email: 'john@example.com',
          age: 30
        }
      });

      client.registerElicitationHandler(mockHandler);
    });

    it('should handle basic elicitation request', async () => {
      const response = await client.handleElicitationRequest(testRequest);

      expect(response).toEqual({
        id: testRequest.id,
        action: ElicitationAction.Accept,
        values: {
          name: 'John Doe',
          email: 'john@example.com',
          age: 30
        }
      });

      expect(mockHandler).toHaveBeenCalledWith(testRequest);
    });

    it('should handle decline response', async () => {
      // Create a new client to avoid interference from beforeEach handler
      const declineClient = new MockElicitationClient(config);
      
      const declineHandler: ElicitationHandler = vi.fn().mockResolvedValue({
        id: testRequest.id,
        action: ElicitationAction.Decline,
        reason: 'Information too sensitive'
      });

      declineClient.registerElicitationHandler(declineHandler);

      const response = await declineClient.handleElicitationRequest(testRequest);

      expect(response.action).toBe(ElicitationAction.Decline);
      expect(response.reason).toBe('Information too sensitive');
    });

    it('should handle cancel response', async () => {
      // Create a new client to avoid interference from beforeEach handler
      const cancelClient = new MockElicitationClient(config);
      
      const cancelHandler: ElicitationHandler = vi.fn().mockResolvedValue({
        id: testRequest.id,
        action: ElicitationAction.Cancel,
        reason: 'User cancelled'
      });

      cancelClient.registerElicitationHandler(cancelHandler);

      const response = await cancelClient.handleElicitationRequest(testRequest);

      expect(response.action).toBe(ElicitationAction.Cancel);
      expect(response.reason).toBe('User cancelled');
    });

    it('should track active elicitation requests', async () => {
      expect(client.getActiveElicitationRequests()).toHaveLength(0);

      // Start handling request but don't await yet
      const responsePromise = client.handleElicitationRequest(testRequest);
      
      // Should be active during handling
      expect(client.getActiveElicitationRequests()).toHaveLength(1);
      expect(client.getActiveElicitationRequests()[0].id).toBe(testRequest.id);

      // Wait for completion
      await responsePromise;
      
      // Should be removed after completion
      expect(client.getActiveElicitationRequests()).toHaveLength(0);
    });

    it('should handle multiple handlers with fallback', async () => {
      // Create a new client to avoid interference from beforeEach handler
      const fallbackClient = new MockElicitationClient(config);
      
      const faultyHandler: ElicitationHandler = vi.fn().mockRejectedValue(
        new Error('Handler failed')
      );
      
      const workingHandler: ElicitationHandler = vi.fn().mockResolvedValue({
        id: testRequest.id,
        action: ElicitationAction.Accept,
        values: { 
          name: 'Fallback User',
          email: 'fallback@example.com',
          age: 25
        }
      });

      // Register faulty handler first
      fallbackClient.registerElicitationHandler(faultyHandler);
      fallbackClient.registerElicitationHandler(workingHandler);

      const response = await fallbackClient.handleElicitationRequest(testRequest);

      expect(response.action).toBe(ElicitationAction.Accept);
      expect(response.values?.name).toBe('Fallback User');
      expect(faultyHandler).toHaveBeenCalled();
      expect(workingHandler).toHaveBeenCalled();
    });

    it('should cancel Accept response that has no values', async () => {
      const noValuesClient = new MockElicitationClient(config);

      const handler: ElicitationHandler = vi.fn().mockResolvedValue({
        id: testRequest.id,
        action: ElicitationAction.Accept,
        // Missing values field
      });

      noValuesClient.registerElicitationHandler(handler);

      const response = await noValuesClient.handleElicitationRequest(testRequest);

      expect(response.action).toBe(ElicitationAction.Cancel);
      expect(response.reason).toBe('Accept action requires values');
    });

    it('should return cancel when no handlers succeed', async () => {
      // Create a new client to avoid interference from beforeEach handler
      const failClient = new MockElicitationClient(config);
      
      const faultyHandler: ElicitationHandler = vi.fn().mockRejectedValue(
        new Error('Handler failed')
      );

      failClient.registerElicitationHandler(faultyHandler);

      const response = await failClient.handleElicitationRequest(testRequest);

      expect(response.action).toBe(ElicitationAction.Cancel);
      expect(response.reason).toBe('No elicitation handler available');
    });
  });

  describe('Elicitation Validation', () => {
    let testFields: ElicitationField[];

    beforeEach(() => {
      testFields = [
        {
          name: 'name',
          type: 'text',
          label: 'Full Name',
          required: true,
          validation: { minLength: 2, maxLength: 100 }
        },
        {
          name: 'email',
          type: 'email',
          label: 'Email Address',
          required: true
        },
        {
          name: 'age',
          type: 'number',
          label: 'Age',
          validation: { min: 18, max: 120 }
        },
        {
          name: 'website',
          type: 'url',
          label: 'Website',
          required: false
        },
        {
          name: 'subscribe',
          type: 'boolean',
          label: 'Subscribe to newsletter',
          required: false
        },
        {
          name: 'country',
          type: 'select',
          label: 'Country',
          required: true,
          validation: {
            options: [
              { value: 'us', label: 'United States' },
              { value: 'ca', label: 'Canada' },
              { value: 'uk', label: 'United Kingdom' }
            ]
          }
        }
      ];
    });

    it('should validate required fields', () => {
      const values = {
        email: 'test@example.com',
        age: 25
        // Missing required 'name' and 'country'
      };

      const errors = client.validateElicitationValues(testFields, values);
      
      expect(errors).toHaveLength(2);
      expect(errors.find(e => e.field === 'name')).toEqual({
        field: 'name',
        message: 'Full Name is required',
        code: 'REQUIRED'
      });
      expect(errors.find(e => e.field === 'country')).toEqual({
        field: 'country',
        message: 'Country is required',
        code: 'REQUIRED'
      });
    });

    it('should validate number types and ranges', () => {
      const values = {
        name: 'John Doe',
        email: 'john@example.com',
        age: 150, // Exceeds max
        country: 'us'
      };

      const errors = client.validateElicitationValues(testFields, values);
      
      expect(errors).toHaveLength(1);
      expect(errors[0]).toEqual({
        field: 'age',
        message: 'Age must be at most 120',
        code: 'MAX_VALUE'
      });
    });

    it('should validate email format', () => {
      const values = {
        name: 'John Doe',
        email: 'invalid-email',
        country: 'us'
      };

      const errors = client.validateElicitationValues(testFields, values);
      
      expect(errors).toHaveLength(1);
      expect(errors[0]).toEqual({
        field: 'email',
        message: 'Email Address must be a valid email address',
        code: 'INVALID_EMAIL'
      });
    });

    it('should validate URL format', () => {
      const values = {
        name: 'John Doe',
        email: 'john@example.com',
        website: 'not-a-url',
        country: 'us'
      };

      const errors = client.validateElicitationValues(testFields, values);
      
      expect(errors).toHaveLength(1);
      expect(errors[0]).toEqual({
        field: 'website',
        message: 'Website must be a valid URL',
        code: 'INVALID_URL'
      });
    });

    it('should validate boolean types', () => {
      const booleanField: ElicitationField = {
        name: 'terms',
        type: 'boolean',
        label: 'Accept Terms',
        required: true
      };

      const values = {
        terms: 'yes' // Should be boolean
      };

      const errors = client.validateElicitationValues([booleanField], values);
      
      expect(errors).toHaveLength(1);
      expect(errors[0]).toEqual({
        field: 'terms',
        message: 'Accept Terms must be true or false',
        code: 'INVALID_TYPE'
      });
    });

    it('should validate select options', () => {
      const values = {
        name: 'John Doe',
        email: 'john@example.com',
        country: 'invalid-country'
      };

      const errors = client.validateElicitationValues(testFields, values);
      
      expect(errors).toHaveLength(1);
      expect(errors[0]).toEqual({
        field: 'country',
        message: 'Country must be one of the provided options',
        code: 'INVALID_OPTION'
      });
    });

    it('should validate multiselect options', () => {
      const multiselectField: ElicitationField = {
        name: 'interests',
        type: 'multiselect',
        label: 'Interests',
        validation: {
          options: [
            { value: 'tech', label: 'Technology' },
            { value: 'sports', label: 'Sports' },
            { value: 'music', label: 'Music' }
          ]
        }
      };

      const values = {
        interests: ['tech', 'invalid-interest']
      };

      const errors = client.validateElicitationValues([multiselectField], values);
      
      expect(errors).toHaveLength(1);
      expect(errors[0]).toEqual({
        field: 'interests',
        message: 'Interests must contain only valid options',
        code: 'INVALID_OPTIONS'
      });
    });

    it('should validate string length constraints', () => {
      const values = {
        name: 'J', // Too short
        email: 'john@example.com',
        country: 'us'
      };

      const errors = client.validateElicitationValues(testFields, values);
      
      expect(errors).toHaveLength(1);
      expect(errors[0]).toEqual({
        field: 'name',
        message: 'Full Name must be at least 2 characters',
        code: 'MIN_LENGTH'
      });
    });

    it('should validate field dependencies', () => {
      const dependentField: ElicitationField = {
        name: 'other_specify',
        type: 'text',
        label: 'Please specify',
        dependencies: [
          { field: 'country', value: 'other' }
        ]
      };

      const fieldsWithDependency = [...testFields, dependentField];
      
      const values = {
        name: 'John Doe',
        email: 'john@example.com',
        country: 'us',
        other_specify: 'Some value' // Should not be provided when country is not 'other'
      };

      const errors = client.validateElicitationValues(fieldsWithDependency, values);
      
      expect(errors).toHaveLength(1);
      expect(errors[0]).toEqual({
        field: 'other_specify',
        message: 'Please specify is only valid when country is other',
        code: 'DEPENDENCY_NOT_MET'
      });
    });

    it('should skip validation for empty optional fields', () => {
      const values = {
        name: 'John Doe',
        email: 'john@example.com',
        country: 'us'
        // age, website, subscribe are optional and not provided
      };

      const errors = client.validateElicitationValues(testFields, values);
      
      expect(errors).toHaveLength(0);
    });
  });

  describe('Request Format Validation', () => {
    it('should validate elicitation request format', async () => {
      const invalidRequest = {
        // Missing required fields
        title: 'Test'
      } as any;

      await expect(client.handleElicitationRequest(invalidRequest)).rejects.toThrow(
        'Invalid elicitation request format'
      );
    });

    it('should validate response with accept action has values', async () => {
      const testRequest: ElicitationRequest = {
        id: 'test',
        title: 'Test',
        fields: [
          {
            name: 'name',
            type: 'text',
            label: 'Name',
            required: true
          }
        ]
      };

      const invalidHandler: ElicitationHandler = vi.fn().mockResolvedValue({
        id: 'test',
        action: ElicitationAction.Accept,
        values: {
          name: '' // Empty required field
        }
      });

      client.registerElicitationHandler(invalidHandler);

      const response = await client.handleElicitationRequest(testRequest);

      // Should return cancel with validation error details
      expect(response.action).toBe(ElicitationAction.Cancel);
      expect(response.reason).toContain('Validation failed');
    });

    it('should distinguish validation errors from handler crashes', async () => {
      const testRequest: ElicitationRequest = {
        id: 'test',
        title: 'Test',
        fields: [
          {
            name: 'name',
            type: 'text',
            label: 'Name',
            required: true
          }
        ]
      };

      // First handler crashes, second returns invalid values
      const crashingHandler: ElicitationHandler = vi.fn().mockRejectedValue(new Error('Handler crash'));
      const invalidHandler: ElicitationHandler = vi.fn().mockResolvedValue({
        id: 'test',
        action: ElicitationAction.Accept,
        values: { name: '' }
      });

      client.registerElicitationHandler(crashingHandler);
      client.registerElicitationHandler(invalidHandler);

      const response = await client.handleElicitationRequest(testRequest);

      // Crashing handler should be skipped, invalid handler's response should
      // be caught by validation (not treated as a crash)
      expect(crashingHandler).toHaveBeenCalled();
      expect(invalidHandler).toHaveBeenCalled();
      expect(response.action).toBe(ElicitationAction.Cancel);
      expect(response.reason).toContain('Validation failed');
    });
  });

  describe('Notification Handling', () => {
    beforeEach(async () => {
      await client.connect();
    });

    it('should handle elicitation request notifications', async () => {
      const sendMessageSpy = vi.spyOn(client, 'sendMessage').mockResolvedValue();
      
      const testRequest: ElicitationRequest = {
        id: 'notification-test',
        title: 'Test Notification',
        fields: [
          {
            name: 'response',
            type: 'text',
            label: 'Response',
            required: true
          }
        ]
      };

      const mockHandler: ElicitationHandler = vi.fn().mockResolvedValue({
        id: 'notification-test',
        action: ElicitationAction.Accept,
        values: { response: 'Test response' }
      });

      client.registerElicitationHandler(mockHandler);

      const notification = {
        jsonrpc: '2.0',
        method: 'notifications/elicitation/request',
        params: testRequest
      };

      await client.handleElicitationNotificationPublic(notification);

      expect(mockHandler).toHaveBeenCalledWith(testRequest);
      expect(sendMessageSpy).toHaveBeenCalledWith({
        jsonrpc: '2.0',
        method: 'elicitation/response',
        params: {
          id: 'notification-test',
          action: ElicitationAction.Accept,
          values: { response: 'Test response' }
        }
      });
    });

    it('should handle elicitation errors in notifications', async () => {
      const sendMessageSpy = vi.spyOn(client, 'sendMessage').mockResolvedValue();
      
      const testRequest: ElicitationRequest = {
        id: 'error-test',
        title: 'Error Test',
        fields: []
      };

      // No handler registered - should result in error

      const notification = {
        jsonrpc: '2.0',
        method: 'notifications/elicitation/request',
        params: testRequest
      };

      await client.handleElicitationNotificationPublic(notification);

      expect(sendMessageSpy).toHaveBeenCalledWith({
        jsonrpc: '2.0',
        method: 'elicitation/response',
        params: {
          id: 'error-test',
          action: ElicitationAction.Cancel,
          reason: 'No elicitation handler available'
        }
      });
    });
  });
});