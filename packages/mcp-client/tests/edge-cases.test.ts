import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  BaseMCPClient,
  ConnectionState,
  type ClientConfig,
  type CallOptions,
} from '../src/index.js';
import { CallToolResult, JSONRPCMessage, JSONRPCResponse } from '@modelcontextprotocol/sdk/types';

// Expose protected methods for testing
class TestableClient extends BaseMCPClient {
  private mockConnected = false;

  async connect(): Promise<void> {
    this.setConnectionState(ConnectionState.Connecting);
    this.mockConnected = true;
    this.setConnectionState(ConnectionState.Connected);
  }

  async disconnect(): Promise<void> {
    this.setConnectionState(ConnectionState.Disconnecting);
    this.mockConnected = false;
    this.setConnectionState(ConnectionState.Disconnected);
  }

  async listTools() {
    this.ensureConnected();
    return [{ name: 'test-tool', description: 'Test', inputSchema: {} }];
  }

  async listResources() {
    this.ensureConnected();
    return [{ uri: 'test://r', name: 'r' }];
  }

  async readResource(uri: string) {
    this.ensureConnected();
    return { contents: [{ type: 'text' as const, text: 'content' }] };
  }

  async listPrompts() {
    this.ensureConnected();
    return [{ name: 'p', description: 'P' }];
  }

  async getPrompt(name: string, args?: any) {
    this.ensureConnected();
    return { messages: [{ role: 'user' as const, content: { type: 'text' as const, text: 'test' } }] };
  }

  protected async doCallTool(name: string, args?: any, options?: CallOptions, requestId?: string): Promise<CallToolResult> {
    this.ensureConnected();
    return { content: [{ type: 'text' as const, text: 'result' }] };
  }

  async sendMessage(message: JSONRPCMessage): Promise<JSONRPCResponse | void> {
    this.ensureConnected();
    return { jsonrpc: '2.0', id: (message as any).id, result: 'ok' };
  }

  getSDKClient() {
    return {};
  }

  isConnected(): boolean {
    return this.mockConnected;
  }

  // Expose protected methods for testing
  public testGenerateRequestId(): string {
    return this.generateRequestId();
  }

  public testGenerateSessionId(): string {
    return this.generateSessionId();
  }
}

describe('Client Edge Cases', () => {
  let client: TestableClient;

  beforeEach(() => {
    client = new TestableClient();
  });

  describe('Crypto-safe ID Generation', () => {
    it('should generate request IDs with hex characters', () => {
      const id = client.testGenerateRequestId();
      expect(id).toMatch(/^req_\d+_[0-9a-f]+$/);
    });

    it('should generate session IDs with hex characters', () => {
      const id = client.testGenerateSessionId();
      expect(id).toMatch(/^session_\d+_[0-9a-f]+$/);
    });

    it('should generate unique request IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(client.testGenerateRequestId());
      }
      expect(ids.size).toBe(100);
    });

    it('should generate unique session IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(client.testGenerateSessionId());
      }
      expect(ids.size).toBe(100);
    });

    it('should generate request IDs with sufficient entropy', () => {
      const id = client.testGenerateRequestId();
      // req_ + timestamp + _ + 12 hex chars (6 bytes)
      const hexPart = id.split('_').pop()!;
      expect(hexPart.length).toBe(12);
    });

    it('should generate session IDs with sufficient entropy', () => {
      const id = client.testGenerateSessionId();
      // session_ + timestamp + _ + 12 hex chars (6 bytes)
      const hexPart = id.split('_').pop()!;
      expect(hexPart.length).toBe(12);
    });
  });

  describe('Connection State Machine', () => {
    it('should start in disconnected state', () => {
      expect(client.isConnected()).toBe(false);
    });

    it('should track state transitions via subscribeToConnectionState', async () => {
      const states: ConnectionState[] = [];
      client.subscribeToConnectionState((state) => states.push(state));

      await client.connect();
      expect(states).toContain(ConnectionState.Connecting);
      expect(states).toContain(ConnectionState.Connected);
    });

    it('should track disconnect state transitions', async () => {
      await client.connect();

      const states: ConnectionState[] = [];
      client.subscribeToConnectionState((state) => states.push(state));

      await client.disconnect();
      expect(states).toContain(ConnectionState.Disconnecting);
      expect(states).toContain(ConnectionState.Disconnected);
    });

    it('should support unsubscribing from state changes', async () => {
      const states: ConnectionState[] = [];
      const unsubscribe = client.subscribeToConnectionState((state) => states.push(state));
      unsubscribe();

      await client.connect();
      expect(states).toHaveLength(0);
    });

    it('should throw when calling tools while disconnected', async () => {
      await expect(client.callTool('test', {})).rejects.toThrow();
    });

    it('should throw when listing tools while disconnected', async () => {
      await expect(client.listTools()).rejects.toThrow();
    });

    it('should throw when listing resources while disconnected', async () => {
      await expect(client.listResources()).rejects.toThrow();
    });

    it('should throw when reading resource while disconnected', async () => {
      await expect(client.readResource('test://r')).rejects.toThrow();
    });
  });

  describe('Session Context with Crypto IDs', () => {
    it('should use crypto-safe session IDs in session context', () => {
      client.setSessionContext({ metadata: { test: true } });
      const ctx = client.getSessionContext();
      expect(ctx?.sessionId).toMatch(/^session_\d+_[0-9a-f]+$/);
    });

    it('should preserve crypto-safe session ID across context updates', () => {
      client.setSessionContext({ metadata: { first: true } });
      const originalId = client.getSessionContext()?.sessionId;
      expect(originalId).toMatch(/^session_\d+_[0-9a-f]+$/);

      client.setSessionContext({ metadata: { second: true } });
      expect(client.getSessionContext()?.sessionId).toBe(originalId);
    });
  });

  describe('Stats Tracking', () => {
    it('should start with zero request count', () => {
      const stats = client.getStats();
      expect(stats.requestCount).toBe(0);
      expect(stats.errorCount).toBe(0);
    });

    it('should track request count on tool calls', async () => {
      await client.connect();
      await client.callTool('test', {});

      const stats = client.getStats();
      expect(stats.requestCount).toBeGreaterThan(0);
    });

    it('should track connect time after connection', async () => {
      await client.connect();
      const stats = client.getStats();
      expect(stats.connectTime).toBeInstanceOf(Date);
    });
  });
});
