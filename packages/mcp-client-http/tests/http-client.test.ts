import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { HttpMCPClient } from '../src/index.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { ConnectionState } from '@tylercoles/mcp-client';
import { z } from 'zod';

// Mock the SDK modules
vi.mock('@modelcontextprotocol/sdk/client/index.js', () => ({
  Client: vi.fn().mockImplementation(() => ({
    connect: vi.fn().mockResolvedValue(undefined),
    disconnect: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
    listTools: vi.fn().mockResolvedValue([]),
    callTool: vi.fn().mockResolvedValue({ content: [] }),
    listResources: vi.fn().mockResolvedValue([]),
    readResource: vi.fn().mockResolvedValue({ contents: [] }),
    listPrompts: vi.fn().mockResolvedValue([]),
    getPrompt: vi.fn().mockResolvedValue({ messages: [] }),
    request: vi.fn(),
    notification: vi.fn().mockResolvedValue(undefined)
  }))
}));

vi.mock('@modelcontextprotocol/sdk/client/streamableHttp.js', () => ({
  StreamableHTTPClientTransport: vi.fn()
}));

describe('HttpMCPClient', () => {
  let client: HttpMCPClient;
  let mockSDKClient: any;

  beforeEach(() => {
    client = new HttpMCPClient({
      url: 'http://localhost:3000',
      headers: { 'Authorization': 'Bearer test' }
    });

    // Get the mock client instance
    mockSDKClient = (Client as any).mock.results[0].value;
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('constructor', () => {
    it('should pass headers to StreamableHTTPClientTransport', () => {
      const headers = { 'Authorization': 'Bearer my-token', 'X-Custom': 'value' };
      const _client = new HttpMCPClient({
        url: 'http://localhost:4000',
        headers
      });

      expect(StreamableHTTPClientTransport).toHaveBeenCalledWith(
        expect.any(URL),
        { requestInit: { headers } }
      );
    });

    it('should not pass requestInit when no headers configured', () => {
      const _client = new HttpMCPClient({
        url: 'http://localhost:4000'
      });

      expect(StreamableHTTPClientTransport).toHaveBeenCalledWith(
        expect.any(URL),
        undefined
      );
    });
  });

  describe('sendMessage', () => {
    beforeEach(async () => {
      // Connect the client first
      await client.connect();
    });

    it('should send notifications without id', async () => {
      const notification = {
        jsonrpc: '2.0' as const,
        method: 'test/notification',
        params: { data: 'test' }
      };

      const result = await client.sendMessage(notification);

      expect(result).toBeUndefined();
      expect(mockSDKClient.notification).toHaveBeenCalledWith(notification);
      expect(mockSDKClient.request).not.toHaveBeenCalled();
    });

    it('should send requests with id and return response', async () => {
      const request = {
        jsonrpc: '2.0' as const,
        id: 1,
        method: 'test/request',
        params: { data: 'test' }
      };

      const mockResponse = { result: 'success' };
      mockSDKClient.request.mockResolvedValue(mockResponse);

      const result = await client.sendMessage(request);

      expect(result).toEqual({
        jsonrpc: '2.0',
        id: 1,
        result: mockResponse
      });
      expect(mockSDKClient.request).toHaveBeenCalledWith(
        request,
        expect.any(Object) // The schema
      );
      expect(mockSDKClient.notification).not.toHaveBeenCalled();
    });

    it('should handle request errors and return JSON-RPC error response', async () => {
      const request = {
        jsonrpc: '2.0' as const,
        id: 2,
        method: 'test/error',
        params: { data: 'test' }
      };

      const error = new Error('Request failed');
      mockSDKClient.request.mockRejectedValue(error);

      const result = await client.sendMessage(request);

      expect(result).toEqual({
        jsonrpc: '2.0',
        id: 2,
        error: {
          code: -32603,
          message: 'Request failed'
        }
      });
    });

    it('should throw error if not connected', async () => {
      await client.disconnect();

      const message = {
        jsonrpc: '2.0' as const,
        method: 'test',
        params: {}
      };

      await expect(client.sendMessage(message)).rejects.toThrow('Client is not connected');
    });

    it('should handle string request ids', async () => {
      const request = {
        jsonrpc: '2.0' as const,
        id: 'string-id',
        method: 'test/request',
        params: { data: 'test' }
      };

      const mockResponse = { result: 'success' };
      mockSDKClient.request.mockResolvedValue(mockResponse);

      const result = await client.sendMessage(request);

      expect(result).toEqual({
        jsonrpc: '2.0',
        id: 'string-id',
        result: mockResponse
      });
    });

    it('should pass schema that accepts any response structure', async () => {
      const request = {
        jsonrpc: '2.0' as const,
        id: 1,
        method: 'test/request',
        params: { data: 'test' }
      };

      mockSDKClient.request.mockResolvedValue({ anything: 'goes' });

      await client.sendMessage(request);

      // Get the schema that was passed
      const [_, schema] = mockSDKClient.request.mock.calls[0];
      
      // Test that it accepts various response structures
      expect(() => schema.parse({})).not.toThrow();
      expect(() => schema.parse({ foo: 'bar' })).not.toThrow();
      expect(() => schema.parse({ nested: { data: true } })).not.toThrow();
      expect(() => schema.parse([1, 2, 3])).toThrow(); // Should still be an object
    });

    it('should clean up when disconnecting while not connected', async () => {
      await client.disconnect();

      // Disconnect again while already disconnected — should not throw
      // and should still transition to Disconnected state
      await client.disconnect();

      expect(client.getConnectionState()).toBe(ConnectionState.Disconnected);
    });

    it('should handle notification with undefined id field', async () => {
      const notification = {
        jsonrpc: '2.0' as const,
        id: undefined,
        method: 'test/notification',
        params: { data: 'test' }
      };

      const result = await client.sendMessage(notification);

      expect(result).toBeUndefined();
      expect(mockSDKClient.notification).toHaveBeenCalledWith(notification);
      expect(mockSDKClient.request).not.toHaveBeenCalled();
    });
  });

  describe('Connection State Machine', () => {
    it('should throw when connecting while already connected', async () => {
      await client.connect();
      await expect(client.connect()).rejects.toThrow('Client is already connected or connecting');
    });

    it('should throw when connecting during disconnect', async () => {
      await client.connect();

      // Make close() hang so disconnect stays in Disconnecting state
      mockSDKClient.close.mockImplementation(() => new Promise(() => {}));

      // Start disconnect (will not resolve because close hangs)
      const disconnectPromise = client.disconnect();

      // connect() should reject because state is Disconnecting
      await expect(client.connect()).rejects.toThrow('Client is already connected or connecting');

      // Clean up: resolve the hanging promise
      mockSDKClient.close.mockResolvedValue(undefined);
    });

    it('should transition through Disconnecting state on disconnect', async () => {
      await client.connect();

      const states: ConnectionState[] = [];
      client.subscribeToConnectionState((state) => states.push(state));

      await client.disconnect();

      expect(states).toContain(ConnectionState.Disconnecting);
      expect(states).toContain(ConnectionState.Disconnected);
      // Disconnecting must come before Disconnected
      const disconnectingIdx = states.indexOf(ConnectionState.Disconnecting);
      const disconnectedIdx = states.indexOf(ConnectionState.Disconnected);
      expect(disconnectingIdx).toBeLessThan(disconnectedIdx);
    });

    it('should not trigger auto-reconnect on Disconnecting state', async () => {
      const reconnectClient = new HttpMCPClient({
        url: 'http://localhost:3000',
        autoReconnect: true,
        maxRetries: 5,
        retryDelay: 100,
      });
      const reconnectMock = (Client as any).mock.results[(Client as any).mock.results.length - 1].value;

      await reconnectClient.connect();

      const states: ConnectionState[] = [];
      reconnectClient.subscribeToConnectionState((state) => states.push(state));

      await reconnectClient.disconnect();

      // Should have Disconnecting and Disconnected, but no reconnect attempt
      expect(states).toContain(ConnectionState.Disconnecting);
      expect(states).toContain(ConnectionState.Disconnected);
      // No Connecting state should appear (no reconnect)
      expect(states).not.toContain(ConnectionState.Connecting);
    });
  });
});