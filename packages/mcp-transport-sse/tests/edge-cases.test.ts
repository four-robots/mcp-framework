import { describe, it, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { SSETransport } from '../src/index.js';

describe('SSETransport Edge Cases', () => {
  let server: any;
  let transport: SSETransport;

  beforeEach(() => {
    server = {
      name: 'test-server',
      version: '1.0.0',
      getSDKServer: vi.fn().mockReturnValue({
        connect: vi.fn().mockResolvedValue(undefined),
      }),
      useTransport: vi.fn(),
      start: vi.fn().mockResolvedValue(undefined),
      stop: vi.fn().mockResolvedValue(undefined),
      isStarted: vi.fn().mockReturnValue(false),
      registerTool: vi.fn(),
      getTool: vi.fn(),
    };
  });

  afterEach(async () => {
    if (transport && (transport as any).server) {
      await transport.stop();
    }
  });

  describe('stop() state reset', () => {
    it('should allow restart after stop by resetting internal state', async () => {
      transport = new SSETransport({ port: 0, host: '127.0.0.1' });

      // Start, then stop
      await transport.start(server);
      const firstUrl = transport.getBaseUrl();
      expect(firstUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/$/);

      await transport.stop();

      // After stop, routesSetup should be reset allowing a clean restart
      // Verify internal state was cleaned up
      expect((transport as any).server).toBeUndefined();
      expect((transport as any).mcpServer).toBeUndefined();
      expect((transport as any).routesSetup).toBe(false);
    });

    it('should clear transports map on stop', async () => {
      transport = new SSETransport({ port: 0, host: '127.0.0.1' });
      await transport.start(server);

      // Manually add a transport to the map
      (transport as any).transports.set('test-session', { close: vi.fn() });
      expect(transport.getSessionCount()).toBe(1);

      await transport.stop();
      expect(transport.getSessionCount()).toBe(0);
    });
  });

  describe('start() validation', () => {
    it('should throw if already started', async () => {
      transport = new SSETransport({ port: 0, host: '127.0.0.1' });
      await transport.start(server);

      await expect(transport.start(server)).rejects.toThrow(
        'SSE transport already started'
      );
    });
  });

  describe('configuration', () => {
    it('should use default configuration values', () => {
      transport = new SSETransport();
      expect((transport as any).config.port).toBe(3000);
      expect((transport as any).config.host).toBe('127.0.0.1');
      expect((transport as any).config.enableDnsRebindingProtection).toBe(true);
    });

    it('should normalize basePath to end with /', () => {
      transport = new SSETransport({ basePath: '/api' });
      expect((transport as any).config.basePath).toBe('/api/');

      const transport2 = new SSETransport({ basePath: '/api/' });
      expect((transport2 as any).config.basePath).toBe('/api/');
    });

    it('should report correct base URL with custom host', () => {
      transport = new SSETransport({ host: '0.0.0.0', port: 4000 });
      const baseUrl = transport.getBaseUrl();
      // 0.0.0.0 should be mapped to localhost in getBaseUrl
      expect(baseUrl).toBe('http://localhost:4000/');
    });
  });

  describe('health endpoint', () => {
    it('should respond to health check', async () => {
      transport = new SSETransport({ port: 0, host: '127.0.0.1' });
      await transport.start(server);

      const baseUrl = transport.getBaseUrl();
      const response = await fetch(`${baseUrl}health`);
      expect(response.status).toBe(200);

      const body = await response.json();
      expect(body.status).toBe('healthy');
      expect(body.transport).toBe('sse');
      expect(body.sessions).toBe(0);
    });
  });

  describe('messages endpoint validation', () => {
    it('should reject missing session ID', async () => {
      transport = new SSETransport({ port: 0, host: '127.0.0.1' });
      await transport.start(server);

      const baseUrl = transport.getBaseUrl();
      const response = await fetch(`${baseUrl}messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'test', id: 1 }),
      });
      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain('Invalid or missing session ID');
    });

    it('should reject malformed session ID', async () => {
      transport = new SSETransport({ port: 0, host: '127.0.0.1' });
      await transport.start(server);

      const baseUrl = transport.getBaseUrl();
      const response = await fetch(
        `${baseUrl}messages?sessionId=not-a-uuid`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', method: 'test', id: 1 }),
        }
      );
      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain('Invalid or missing session ID');
    });

    it('should reject valid UUID format but unknown session', async () => {
      transport = new SSETransport({ port: 0, host: '127.0.0.1' });
      await transport.start(server);

      const baseUrl = transport.getBaseUrl();
      const response = await fetch(
        `${baseUrl}messages?sessionId=12345678-1234-1234-1234-123456789abc`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', method: 'test', id: 1 }),
        }
      );
      expect(response.status).toBe(400);
      const body = await response.json();
      expect(body.error).toContain('Unknown session ID');
    });
  });

  describe('DNS rebinding protection', () => {
    it('should have protection enabled by default', () => {
      transport = new SSETransport({
        port: 0,
        host: '127.0.0.1',
      });
      expect((transport as any).config.enableDnsRebindingProtection).toBe(true);
      expect((transport as any).config.allowedHosts).toEqual(['127.0.0.1', 'localhost']);
    });

    it('should allow requests from allowed hosts', async () => {
      transport = new SSETransport({
        port: 0,
        host: '127.0.0.1',
        enableDnsRebindingProtection: true,
        allowedHosts: ['127.0.0.1', 'localhost'],
      });
      await transport.start(server);

      const baseUrl = transport.getBaseUrl();
      // Default fetch uses the actual host (127.0.0.1) which is in allowedHosts
      const response = await fetch(`${baseUrl}health`);
      expect(response.status).toBe(200);
    });

    it('should allow custom allowed hosts configuration', () => {
      transport = new SSETransport({
        port: 0,
        host: '127.0.0.1',
        enableDnsRebindingProtection: true,
        allowedHosts: ['myapp.local', '127.0.0.1'],
      });
      expect((transport as any).config.allowedHosts).toEqual(['myapp.local', '127.0.0.1']);
    });

    it('should work normally when DNS rebinding protection is disabled', async () => {
      transport = new SSETransport({
        port: 0,
        host: '127.0.0.1',
        enableDnsRebindingProtection: false,
      });
      await transport.start(server);

      const baseUrl = transport.getBaseUrl();
      const response = await fetch(`${baseUrl}health`);
      expect(response.status).toBe(200);
    });
  });
});
