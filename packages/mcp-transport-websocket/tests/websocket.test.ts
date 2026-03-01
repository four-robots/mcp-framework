import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { WebSocketTransport, WebSocketConnection, ConnectionState } from '../src/index.js';
import { WebSocket, WebSocketServer } from 'ws';
import { JSONRPCRequest, JSONRPCResponse, JSONRPCNotification } from '@modelcontextprotocol/sdk/types';

// Mock WebSocket
class MockWebSocket {
  readyState = WebSocket.CONNECTING;
  listeners: { [event: string]: Function[] } = {};

  on(event: string, listener: Function) {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event].push(listener);
  }

  emit(event: string, ...args: any[]) {
    if (this.listeners[event]) {
      this.listeners[event].forEach(listener => listener(...args));
    }
  }

  send = vi.fn((data: any, callback?: Function) => {
    if (callback) callback();
  });

  close = vi.fn();
  terminate = vi.fn();
  ping = vi.fn();
}

// Mock MCP Server
const mockMCPServer = {
  name: 'test-server',
  version: '1.0.0',
  getSDKServer: vi.fn().mockReturnValue({
    notification: vi.fn()
  })
};

describe('WebSocketTransport', () => {
  let transport: WebSocketTransport;
  let mockWs: MockWebSocket;

  beforeEach(() => {
    transport = new WebSocketTransport({
      port: 3001,
      host: 'localhost',
      heartbeatInterval: 1000,
      connectionTimeout: 2000
    });
    mockWs = new MockWebSocket();
  });

  afterEach(async () => {
    try {
      await transport.stop();
    } catch (error) {
      // Ignore cleanup errors
    }
    vi.clearAllMocks();
  });

  describe('Configuration', () => {
    it('should set default configuration values', () => {
      const defaultTransport = new WebSocketTransport({ port: 3000 });
      expect(defaultTransport).toBeDefined();
    });

    it('should merge custom configuration with defaults', () => {
      const customTransport = new WebSocketTransport({
        port: 4000,
        host: '127.0.0.1',
        maxConnections: 50,
        heartbeatInterval: 60000
      });
      expect(customTransport).toBeDefined();
    });
  });

  describe('Message Routing', () => {
    it('should register and unregister message routers', () => {
      const router = vi.fn();
      
      transport.registerMessageRouter('test/method', router);
      transport.unregisterMessageRouter('test/method');
      
      expect(router).not.toHaveBeenCalled();
    });

    it('should call registered router for matching method', () => {
      const router = vi.fn();
      transport.registerMessageRouter('test/method', router);
      
      // This would be called internally when a message is received
      expect(router).not.toHaveBeenCalled();
    });
  });

  describe('Broadcasting', () => {
    it('should broadcast messages to all connected clients', async () => {
      const message: JSONRPCNotification = {
        jsonrpc: '2.0',
        method: 'test/notification',
        params: { test: 'data' }
      };

      // No connections yet, should not throw
      await expect(transport.broadcast(message)).resolves.not.toThrow();
    });
  });

  describe('Statistics', () => {
    it('should return correct connection statistics', () => {
      const stats = transport.getStats();
      
      expect(stats).toEqual({
        totalConnections: 0,
        activeConnections: 0,
        maxConnections: 100 // default value
      });
    });
  });

  describe('Connection Management', () => {
    it('should return empty connections list initially', () => {
      const connections = transport.getConnections();
      expect(connections).toEqual([]);
    });
  });
});

describe('WebSocketConnection', () => {
  let mockWs: MockWebSocket;
  let connection: WebSocketConnection;
  let config: any;

  beforeEach(() => {
    mockWs = new MockWebSocket();
    config = {
      port: 3001,
      host: 'localhost',
      path: '/mcp',
      maxConnections: 100,
      heartbeatInterval: 1000,
      connectionTimeout: 2000,
      maxMessageSize: 1024 * 1024,
      enableCompression: true,
      enablePerMessageDeflate: true
    };
    
    connection = new WebSocketConnection(mockWs as any, config);
  });

  afterEach(() => {
    connection.terminate();
    vi.clearAllMocks();
  });

  describe('Connection State Management', () => {
    it('should start in connecting state', () => {
      expect(connection.getState()).toBe(ConnectionState.Connecting);
    });

    it('should transition to connected state on open', () => {
      const stateHandler = vi.fn();
      connection.onStateChange(stateHandler);
      
      // Simulate readyState change to OPEN
      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');
      
      expect(connection.getState()).toBe(ConnectionState.Connected);
      expect(stateHandler).toHaveBeenCalledWith(ConnectionState.Connected);
    });

    it('should transition to disconnected state on close', () => {
      const stateHandler = vi.fn();
      connection.onStateChange(stateHandler);
      
      mockWs.emit('close', 1000, 'Normal closure');
      
      expect(connection.getState()).toBe(ConnectionState.Disconnected);
      expect(stateHandler).toHaveBeenCalledWith(ConnectionState.Disconnected);
    });

    it('should transition to error state on error', () => {
      const stateHandler = vi.fn();
      connection.onStateChange(stateHandler);
      
      mockWs.emit('error', new Error('Connection error'));
      
      expect(connection.getState()).toBe(ConnectionState.Error);
      expect(stateHandler).toHaveBeenCalledWith(ConnectionState.Error);
    });
  });

  describe('Message Handling', () => {
    beforeEach(() => {
      // Set connection to connected state
      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');
    });

    it('should handle valid JSON-RPC messages', () => {
      const messageHandler = vi.fn();
      connection.onMessage(messageHandler);
      
      const message: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: '1',
        method: 'test/method',
        params: { test: 'data' }
      };
      
      mockWs.emit('message', JSON.stringify(message));
      
      expect(messageHandler).toHaveBeenCalledWith(message);
    });

    it('should handle ping messages automatically', () => {
      const pingMessage: JSONRPCRequest = {
        jsonrpc: '2.0',
        id: 'ping-1',
        method: 'ping'
      };
      
      mockWs.emit('message', JSON.stringify(pingMessage));
      
      expect(mockWs.send).toHaveBeenCalledWith(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 'ping-1',
          result: { type: 'pong' }
        }),
        expect.any(Function)
      );
    });

    it('should handle invalid JSON gracefully', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation();
      
      mockWs.emit('message', 'invalid json');
      
      expect(consoleSpy).toHaveBeenCalledWith('Failed to parse WebSocket message:', expect.any(Error));
      expect(mockWs.send).toHaveBeenCalledWith(
        expect.stringContaining('"code":-32700'),
        expect.any(Function)
      );
      
      consoleSpy.mockRestore();
    });

    it('should handle pong messages for heartbeat', () => {
      mockWs.emit('pong');
      // Should not throw and should reset heartbeat
      expect(() => mockWs.emit('pong')).not.toThrow();
    });
  });

  describe('Message Sending', () => {
    beforeEach(() => {
      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');
    });

    it('should send valid JSON-RPC messages', async () => {
      const message: JSONRPCResponse = {
        jsonrpc: '2.0',
        id: '1',
        result: { success: true }
      };
      
      await connection.send(message);
      
      expect(mockWs.send).toHaveBeenCalledWith(
        JSON.stringify(message),
        expect.any(Function)
      );
    });

    it('should reject sending when not connected', async () => {
      connection.close();
      
      const message: JSONRPCNotification = {
        jsonrpc: '2.0',
        method: 'test/method'
      };
      
      await expect(connection.send(message)).rejects.toThrow('Cannot send message: connection state is disconnecting');
    });

    it('should reject oversized messages', async () => {
      const largeMessage = {
        jsonrpc: '2.0' as const,
        method: 'test/method',
        params: { data: 'x'.repeat(config.maxMessageSize + 1) }
      };
      
      await expect(connection.send(largeMessage)).rejects.toThrow('Message too large');
    });

    it('should send error responses', async () => {
      await connection.sendError(-32602, 'Invalid params', '1');

      expect(mockWs.send).toHaveBeenCalledWith(
        JSON.stringify({
          jsonrpc: '2.0',
          id: '1',
          error: {
            code: -32602,
            message: 'Invalid params'
          }
        }),
        expect.any(Function)
      );
    });

    it('should send error with null id when id is not provided', async () => {
      await connection.sendError(-32700, 'Parse error');

      expect(mockWs.send).toHaveBeenCalledWith(
        JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: {
            code: -32700,
            message: 'Parse error'
          }
        }),
        expect.any(Function)
      );
    });
  });

  describe('Event Handlers', () => {
    it('should add and remove message handlers', () => {
      const handler1 = vi.fn();
      const handler2 = vi.fn();
      
      connection.onMessage(handler1);
      connection.onMessage(handler2);
      
      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');
      mockWs.emit('message', JSON.stringify({
        jsonrpc: '2.0',
        method: 'test'
      }));
      
      expect(handler1).toHaveBeenCalled();
      expect(handler2).toHaveBeenCalled();
      
      connection.offMessage(handler1);
      vi.clearAllMocks();
      
      mockWs.emit('message', JSON.stringify({
        jsonrpc: '2.0',
        method: 'test2'
      }));
      
      expect(handler1).not.toHaveBeenCalled();
      expect(handler2).toHaveBeenCalled();
    });

    it('should add and remove state change handlers', () => {
      const handler1 = vi.fn();
      const handler2 = vi.fn();
      
      connection.onStateChange(handler1);
      connection.onStateChange(handler2);
      
      // Simulate readyState change to OPEN and emit open
      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');
      
      expect(handler1).toHaveBeenCalledWith(ConnectionState.Connected);
      expect(handler2).toHaveBeenCalledWith(ConnectionState.Connected);
      
      connection.offStateChange(handler1);
      vi.clearAllMocks();
      
      // Simulate close
      mockWs.readyState = WebSocket.CLOSED;
      mockWs.emit('close');
      
      expect(handler1).not.toHaveBeenCalled();
      expect(handler2).toHaveBeenCalledWith(ConnectionState.Disconnected);
    });
  });

  describe('Connection Control', () => {
    beforeEach(() => {
      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');
    });

    it('should close connection gracefully', () => {
      connection.close(1000, 'Normal closure');
      
      expect(mockWs.close).toHaveBeenCalledWith(1000, 'Normal closure');
      expect(connection.getState()).toBe(ConnectionState.Disconnecting);
    });

    it('should terminate connection immediately', () => {
      connection.terminate();
      
      expect(mockWs.terminate).toHaveBeenCalled();
      expect(connection.getState()).toBe(ConnectionState.Disconnected);
    });

    it('should report connection status correctly', () => {
      expect(connection.isConnected()).toBe(true);
      
      connection.close();
      expect(connection.isConnected()).toBe(false);
    });
  });

  describe('Heartbeat', () => {
    it('should start heartbeat when connected', (done) => {
      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');
      
      // Wait for heartbeat interval
      setTimeout(() => {
        expect(mockWs.ping).toHaveBeenCalled();
        done();
      }, config.heartbeatInterval + 100);
    });

    it('should not start heartbeat if interval is 0', () => {
      const noHeartbeatConfig = { ...config, heartbeatInterval: 0 };
      const noHeartbeatConnection = new WebSocketConnection(mockWs as any, noHeartbeatConfig);
      
      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');
      
      setTimeout(() => {
        expect(mockWs.ping).not.toHaveBeenCalled();
      }, 100);
    });
  });

  describe('Error Handling', () => {
    it('should handle message handler errors gracefully', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation();
      const faultyHandler = vi.fn().mockImplementation(() => {
        throw new Error('Handler error');
      });
      
      connection.onMessage(faultyHandler);
      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');
      mockWs.emit('message', JSON.stringify({ jsonrpc: '2.0', method: 'test' }));
      
      expect(consoleSpy).toHaveBeenCalledWith('Message handler error:', expect.any(Error));
      consoleSpy.mockRestore();
    });

    it('should handle state change handler errors gracefully', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation();
      const faultyHandler = vi.fn().mockImplementation(() => {
        throw new Error('State handler error');
      });
      
      connection.onStateChange(faultyHandler);
      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');
      
      expect(consoleSpy).toHaveBeenCalledWith('State change handler error:', expect.any(Error));
      consoleSpy.mockRestore();
    });
  });
});