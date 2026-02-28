import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { Transport, MCPServer } from "@tylercoles/mcp-server";

/**
 * Configuration for stdio transport
 */
export interface StdioConfig {
  // Minimal config for stdio - can be extended in future
  logStderr?: boolean;
}

/**
 * stdio transport implementation for MCP servers
 * Used for local/development MCP servers that communicate via stdin/stdout
 */
export class StdioTransport implements Transport {
  private config: StdioConfig;
  private transport: StdioServerTransport | null = null;
  private server: MCPServer | null = null;

  constructor(config?: StdioConfig) {
    this.config = config || {};
  }

  /**
   * Start the stdio transport
   */
  async start(server: MCPServer): Promise<void> {
    if (this.transport) {
      throw new Error('Transport already started');
    }

    this.server = server;

    // Create the SDK stdio transport
    this.transport = new StdioServerTransport();

    // Log stderr if configured
    if (this.config.logStderr) {
      console.error('[StdioTransport] Started with stderr logging enabled');
    }

    // Connect the server to the transport
    const sdkServer = server.getSDKServer();
    try {
      await sdkServer.connect(this.transport);
    } catch (error) {
      // Roll back state on connect failure
      this.transport = null;
      this.server = null;
      throw error;
    }

    if (this.config.logStderr) {
      console.error('[StdioTransport] Server connected successfully');
    }
  }

  /**
   * Stop the stdio transport
   */
  async stop(): Promise<void> {
    if (!this.transport) {
      return;
    }

    // Close the underlying transport before cleaning up references
    try {
      await this.transport.close();
    } catch {
      // Ignore close errors to ensure cleanup completes
    }
    this.transport = null;
    this.server = null;

    if (this.config.logStderr) {
      console.error('[StdioTransport] Stopped');
    }
  }

  /**
   * Check if transport is running
   */
  isRunning(): boolean {
    return this.transport !== null;
  }
}

/**
 * Utility function to create a stdio server quickly
 */
export function createStdioServer(
  server: MCPServer,
  config?: StdioConfig
): StdioTransport {
  const transport = new StdioTransport(config);
  server.useTransport(transport);
  return transport;
}
