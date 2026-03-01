import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { WebSocketTransport, WebSocketConnection, ConnectionState } from '../src/index.js';
import { WebSocket } from 'ws';

// Mock WebSocket for unit testing
class MockWebSocket {
  readyState = WebSocket.CONNECTING;
  listeners: { [event: string]: Function[] } = {};

  on(event: string, listener: Function) {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event].push(listener);
  }

  removeAllListeners = vi.fn(() => {
    this.listeners = {};
  });

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

describe('WebSocketConnection Edge Cases', () => {
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
      heartbeatInterval: 0, // Disable for tests
      connectionTimeout: 2000,
      messageTimeout: 5000,
      maxMessageSize: 1024 * 1024,
    };
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Connection State Machine', () => {
    it('should start in Connecting state', () => {
      connection = new WebSocketConnection(mockWs as any, config);
      expect(connection.getState()).toBe(ConnectionState.Connecting);
    });

    it('should transition to Connected on open', () => {
      connection = new WebSocketConnection(mockWs as any, config);
      const states: ConnectionState[] = [];
      connection.onStateChange((state) => states.push(state));

      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');

      expect(states).toContain(ConnectionState.Connected);
    });

    it('should transition to Disconnected on close', () => {
      connection = new WebSocketConnection(mockWs as any, config);
      const states: ConnectionState[] = [];
      connection.onStateChange((state) => states.push(state));

      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');
      mockWs.emit('close', 1000, 'Normal closure');

      expect(states).toContain(ConnectionState.Disconnected);
    });

    it('should transition to Error on error event', () => {
      connection = new WebSocketConnection(mockWs as any, config);
      const states: ConnectionState[] = [];
      connection.onStateChange((state) => states.push(state));

      mockWs.emit('error', new Error('Connection failed'));

      expect(states).toContain(ConnectionState.Error);
    });

    it('should handle connection timeout', () => {
      vi.useFakeTimers();
      connection = new WebSocketConnection(mockWs as any, config);
      const states: ConnectionState[] = [];
      connection.onStateChange((state) => states.push(state));

      // Advance past connection timeout
      vi.advanceTimersByTime(config.connectionTimeout + 100);

      expect(states).toContain(ConnectionState.Error);
      expect(mockWs.terminate).toHaveBeenCalled();

      vi.useRealTimers();
    });

    it('should cancel timeout on successful connection', () => {
      vi.useFakeTimers();
      connection = new WebSocketConnection(mockWs as any, config);

      // Connect before timeout
      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');

      // Advance past original timeout
      vi.advanceTimersByTime(config.connectionTimeout + 100);

      // Should not have terminated
      expect(mockWs.terminate).not.toHaveBeenCalled();

      vi.useRealTimers();
    });
  });

  describe('Message Handling', () => {
    it('should parse valid JSON-RPC messages', () => {
      connection = new WebSocketConnection(mockWs as any, config);
      const messages: any[] = [];
      connection.onMessage((msg) => messages.push(msg));

      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');

      const validMessage = JSON.stringify({ jsonrpc: '2.0', method: 'test', id: 1 });
      mockWs.emit('message', Buffer.from(validMessage));

      expect(messages).toHaveLength(1);
      expect(messages[0].method).toBe('test');
    });

    it('should handle invalid JSON gracefully', () => {
      connection = new WebSocketConnection(mockWs as any, config);
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');

      mockWs.emit('message', Buffer.from('not json'));

      // Should not crash, should send error response
      expect(mockWs.send).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });
  });

  describe('Cleanup', () => {
    it('should remove all listeners on cleanup', () => {
      connection = new WebSocketConnection(mockWs as any, config);

      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');
      mockWs.emit('close', 1000, 'Normal');

      expect(mockWs.removeAllListeners).toHaveBeenCalled();
    });

    it('should be safe to call close multiple times', () => {
      connection = new WebSocketConnection(mockWs as any, config);

      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');

      connection.close();
      connection.close(); // Should not throw

      expect(mockWs.close).toHaveBeenCalled();
    });
  });

  describe('Send', () => {
    it('should reject send when not connected', async () => {
      connection = new WebSocketConnection(mockWs as any, config);

      await expect(
        connection.send({ jsonrpc: '2.0', method: 'test', id: 1 })
      ).rejects.toThrow();
    });

    it('should send when connected', async () => {
      connection = new WebSocketConnection(mockWs as any, config);
      mockWs.readyState = WebSocket.OPEN;
      mockWs.emit('open');

      await connection.send({ jsonrpc: '2.0', method: 'test', id: 1 });

      expect(mockWs.send).toHaveBeenCalled();
      const sentData = JSON.parse(mockWs.send.mock.calls[0][0]);
      expect(sentData.method).toBe('test');
    });
  });
});

describe('WebSocketTransport Edge Cases', () => {
  let transport: WebSocketTransport;

  afterEach(async () => {
    try {
      await transport.stop();
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('Connection Limits', () => {
    it('should track connection count in stats', () => {
      transport = new WebSocketTransport({
        port: 0,
        maxConnections: 5,
      });

      const stats = transport.getStats();
      expect(stats.maxConnections).toBe(5);
      expect(stats.activeConnections).toBe(0);
    });

    it('should default maxConnections to 100', () => {
      transport = new WebSocketTransport({ port: 0 });
      const stats = transport.getStats();
      expect(stats.maxConnections).toBe(100);
    });
  });

  describe('Configuration', () => {
    it('should accept custom path', () => {
      transport = new WebSocketTransport({
        port: 0,
        path: '/custom-ws',
      });
      expect(transport).toBeDefined();
    });

    it('should accept custom heartbeat interval', () => {
      transport = new WebSocketTransport({
        port: 0,
        heartbeatInterval: 60000,
      });
      expect(transport).toBeDefined();
    });

    it('should accept zero heartbeat interval to disable', () => {
      transport = new WebSocketTransport({
        port: 0,
        heartbeatInterval: 0,
      });
      expect(transport).toBeDefined();
    });
  });

  describe('Message Routing', () => {
    it('should register and retrieve message routers', () => {
      transport = new WebSocketTransport({ port: 0 });
      const router = vi.fn();

      transport.registerMessageRouter('custom/method', router);
      // Should not throw, router is registered
      expect(() => transport.unregisterMessageRouter('custom/method')).not.toThrow();
    });

    it('should handle unregistering non-existent router', () => {
      transport = new WebSocketTransport({ port: 0 });
      // Should not throw
      expect(() => transport.unregisterMessageRouter('nonexistent')).not.toThrow();
    });
  });

  describe('Broadcasting', () => {
    it('should not throw when broadcasting with no connections', async () => {
      transport = new WebSocketTransport({ port: 0 });

      await expect(
        transport.broadcast({ jsonrpc: '2.0', method: 'test/event' })
      ).resolves.not.toThrow();
    });
  });
});
