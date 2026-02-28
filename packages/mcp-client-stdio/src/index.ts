import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
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
 * Configuration for stdio MCP client
 */
export interface StdioClientConfig extends ClientConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
}

/**
 * MCP Client for stdio transport
 * Provides a clean TypeScript interface for communicating with stdio MCP servers
 */
export class StdioMCPClient extends BaseMCPClient {
  private client: Client;
  private transport: StdioClientTransport;
  private stdioConfig: StdioClientConfig;
  private needsFreshTransport = false;

  constructor(config: StdioClientConfig) {
    super(config);
    this.stdioConfig = config;
    this.transport = new StdioClientTransport({
      command: config.command,
      args: config.args || [],
      env: config.env,
      cwd: config.cwd
    });
    this.client = new Client({
      name: "stdio-mcp-client",
      version: "1.0.0"
    });
  }

  /**
   * Connect to the MCP server
   */
  async connect(): Promise<void> {
    if (this.isConnected()) {
      throw new Error("Client is already connected");
    }

    this.intentionalDisconnect = false;
    if (this.needsFreshTransport) {
      this.transport = new StdioClientTransport({
        command: this.stdioConfig.command,
        args: this.stdioConfig.args || [],
        env: this.stdioConfig.env,
        cwd: this.stdioConfig.cwd
      });
      this.client = new Client({
        name: "stdio-mcp-client",
        version: "1.0.0"
      });
    }

    try {
      await this.client.connect(this.transport);
      this.setConnectionState(ConnectionState.Connected);
    } catch (error) {
      this.needsFreshTransport = true;
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
    // Stdio transport doesn't typically need heartbeat
    // This is a no-op for stdio clients
  }
}

/**
 * Factory for creating stdio MCP clients
 */
export class StdioMCPClientFactory implements MCPClientFactory<StdioClientConfig> {
  create(config: StdioClientConfig): StdioMCPClient {
    return new StdioMCPClient(config);
  }

  async createAndConnect(config: StdioClientConfig): Promise<StdioMCPClient> {
    const client = new StdioMCPClient(config);
    await client.connect();
    return client;
  }
}

/**
 * Utility function to create and connect a stdio MCP client
 */
export async function createStdioMCPClient(config: StdioClientConfig): Promise<StdioMCPClient> {
  const factory = new StdioMCPClientFactory();
  return await factory.createAndConnect(config);
}
