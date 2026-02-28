import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { 
  CallToolResult, 
  GetPromptResult,
  ReadResourceResult,
  JSONRPCMessage,
  JSONRPCResponse
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { 
  BaseMCPClient, 
  ClientConfig, 
  ToolInfo, 
  ResourceInfo, 
  PromptInfo,
  MCPClientFactory,
  ConnectionState
} from "@tylercoles/mcp-client";

/**
 * Configuration for HTTP MCP client
 */
export interface HttpClientConfig extends ClientConfig {
  url: string;
  headers?: Record<string, string>;
}

/**
 * MCP Client for StreamableHTTP transport
 * Provides a clean TypeScript interface for communicating with HTTP MCP servers
 */
export class HttpMCPClient extends BaseMCPClient {
  private client: Client;
  private transport: StreamableHTTPClientTransport;
  private httpConfig: HttpClientConfig;
  private needsFreshTransport = false;

  constructor(config: HttpClientConfig) {
    super(config);
    this.httpConfig = config;
    this.transport = new StreamableHTTPClientTransport(
      new URL(config.url)
    );
    this.client = new Client({
      name: "http-mcp-client",
      version: "1.0.0"
    });
  }

  /**
   * Connect to the MCP server
   */
  async connect(): Promise<void> {
    if (this.isConnected() || this.getConnectionState() === ConnectionState.Connecting) {
      throw new Error("Client is already connected or connecting");
    }

    this.intentionalDisconnect = false;
    this.setConnectionState(ConnectionState.Connecting);

    if (this.needsFreshTransport) {
      this.transport = new StreamableHTTPClientTransport(
        new URL(this.httpConfig.url)
      );
      this.client = new Client({
        name: "http-mcp-client",
        version: "1.0.0"
      });
    }

    try {
      await this.client.connect(this.transport);
      this.setConnectionState(ConnectionState.Connected);
    } catch (error) {
      this.needsFreshTransport = true;
      this.setConnectionState(ConnectionState.Error, error as Error);
      throw error;
    }
  }

  /**
   * Disconnect from the MCP server
   */
  async disconnect(): Promise<void> {
    // Always cancel reconnect and signal intent before checking state,
    // so a pending reconnect timer doesn't re-establish the connection.
    this.intentionalDisconnect = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }

    if (!this.isConnected()) {
      return;
    }

    try {
      await this.client.close();
    } finally {
      try {
        if (typeof this.transport.close === 'function') {
          await this.transport.close();
        }
      } catch (error) {
        console.error('Error closing transport:', error);
      }
      this.needsFreshTransport = true;
      this.setConnectionState(ConnectionState.Disconnected);
      this.cleanup();
    }
  }

  /**
   * List all available tools
   */
  async listTools(): Promise<ToolInfo[]> {
    if (!this.isConnected()) {
      throw new Error("Client is not connected");
    }
    const result = await this.client.listTools();
    return result.tools.map(tool => ({
      name: tool.name,
      title: tool.title,
      description: tool.description || '',
      inputSchema: tool.inputSchema
    }));
  }

  /**
   * Call a tool with arguments (implementation for doCallTool)
   */
  protected async doCallTool(name: string, args?: any): Promise<CallToolResult> {
    if (!this.isConnected()) {
      throw new Error("Client is not connected");
    }
    const result = await this.client.callTool({
      name,
      arguments: args || {}
    });
    return result as CallToolResult;
  }

  /**
   * List all available resources
   */
  async listResources(): Promise<ResourceInfo[]> {
    if (!this.isConnected()) {
      throw new Error("Client is not connected");
    }
    const result = await this.client.listResources();
    return result.resources.map(resource => ({
      uri: resource.uri,
      name: resource.name,
      description: resource.description,
      mimeType: resource.mimeType
    }));
  }

  /**
   * Read a resource by URI
   */
  async readResource(uri: string): Promise<ReadResourceResult> {
    if (!this.isConnected()) {
      throw new Error("Client is not connected");
    }
    return await this.client.readResource({ uri });
  }

  /**
   * List all available prompts
   */
  async listPrompts(): Promise<PromptInfo[]> {
    if (!this.isConnected()) {
      throw new Error("Client is not connected");
    }
    const result = await this.client.listPrompts();
    return result.prompts.map(prompt => ({
      name: prompt.name,
      title: prompt.title,
      description: prompt.description,
      arguments: prompt.arguments
    }));
  }

  /**
   * Get a prompt with arguments
   */
  async getPrompt(name: string, args?: any): Promise<GetPromptResult> {
    if (!this.isConnected()) {
      throw new Error("Client is not connected");
    }
    return await this.client.getPrompt({
      name,
      arguments: args || {}
    });
  }

  /**
   * Get the underlying SDK client (for advanced usage)
   */
  getSDKClient(): Client {
    return this.client;
  }

  /**
   * Send a JSON-RPC message directly
   */
  async sendMessage(message: JSONRPCMessage): Promise<JSONRPCResponse | void> {
    if (!this.isConnected()) {
      throw new Error("Client is not connected");
    }
    
    // Handle notifications (no id field)
    if (!('id' in message) || message.id === undefined) {
      await this.client.notification(message as any);
      return;
    }
    
    // For requests, we need to create a schema for the expected response
    // Since we don't know the exact response structure, we'll use a generic schema
    const responseSchema = z.object({}).passthrough(); // Allow any additional properties
    
    try {
      const response = await this.client.request(message as any, responseSchema);
      return {
        jsonrpc: '2.0',
        id: message.id,
        result: response
      };
    } catch (error) {
      // Return error response
      return {
        jsonrpc: '2.0',
        id: message.id,
        error: {
          code: -32603,
          message: error instanceof Error ? error.message : 'Unknown error'
        }
      } as any; // JSONRPCResponse can be either success or error
    }
  }

  /**
   * Send heartbeat ping
   */
  protected async sendHeartbeat(): Promise<void> {
    // HTTP transport doesn't typically need heartbeat
    // This is a no-op for HTTP clients
  }

  /**
   * Get the server URL
   */
  getServerUrl(): string {
    return this.httpConfig.url;
  }
}

/**
 * Factory for creating HTTP MCP clients
 */
export class HttpMCPClientFactory implements MCPClientFactory<HttpClientConfig> {
  create(config: HttpClientConfig): HttpMCPClient {
    return new HttpMCPClient(config);
  }

  async createAndConnect(config: HttpClientConfig): Promise<HttpMCPClient> {
    const client = new HttpMCPClient(config);
    await client.connect();
    return client;
  }
}

/**
 * Utility function to create and connect an HTTP MCP client
 */
export async function createHttpMCPClient(config: HttpClientConfig): Promise<HttpMCPClient> {
  const factory = new HttpMCPClientFactory();
  return await factory.createAndConnect(config);
}
