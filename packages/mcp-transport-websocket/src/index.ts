import { WebSocketServer, WebSocket } from 'ws';
import { Server as HttpServer, createServer } from 'http';
import type { Transport, MCPServer } from '@tylercoles/mcp-server';
import { JSONRPCMessage, JSONRPCRequest, JSONRPCResponse, JSONRPCNotification } from '@modelcontextprotocol/sdk/types';

/**
 * Connection state for WebSocket connections
 */
export enum ConnectionState {
  Connecting = 'connecting',
  Connected = 'connected',
  Disconnecting = 'disconnecting',
  Disconnected = 'disconnected',
  Error = 'error'
}

/**
 * WebSocket transport configuration
 */
export interface WebSocketConfig {
  port: number;
  host?: string;
  path?: string;
  maxConnections?: number;
  heartbeatInterval?: number;
  connectionTimeout?: number;
  messageTimeout?: number;
  maxMessageSize?: number;
  enableCompression?: boolean;
  enablePerMessageDeflate?: boolean;
}

/**
 * WebSocket connection wrapper with state management
 */
export class WebSocketConnection {
  private ws: WebSocket;
  private state: ConnectionState = ConnectionState.Connecting;
  private heartbeatTimer?: NodeJS.Timeout;
  private connectionTimeout?: NodeJS.Timeout;
  private messageHandlers: Set<(message: JSONRPCMessage) => void> = new Set();
  private stateChangeHandlers: Set<(state: ConnectionState) => void> = new Set();
  private readonly config: Required<WebSocketConfig>;
  public readonly createdAt: number = Date.now();

  constructor(ws: WebSocket, config: Required<WebSocketConfig>) {
    this.ws = ws;
    this.config = config;
    this.setupConnection();
  }

  private setupConnection(): void {
    // Set connection timeout
    this.connectionTimeout = setTimeout(() => {
      if (this.state === ConnectionState.Connecting) {
        this.setState(ConnectionState.Error);
        this.cleanup();
        this.ws.terminate();
      }
    }, this.config.connectionTimeout);
    this.connectionTimeout.unref();

    this.ws.on('open', () => {
      if (this.connectionTimeout) {
        clearTimeout(this.connectionTimeout);
        this.connectionTimeout = undefined;
      }
      this.setState(ConnectionState.Connected);
      this.startHeartbeat();
    });

    this.ws.on('message', (data: Buffer | string) => {
      try {
        const message = JSON.parse(data.toString()) as JSONRPCMessage;
        this.handleMessage(message);
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error);
        // Send parse error response if it was a request
        this.sendError(-32700, 'Parse error', undefined).catch(err => {
          console.error('Failed to send parse error response:', err);
        });
      }
    });

    this.ws.on('pong', () => {
      // WebSocket is alive, reset heartbeat
      this.resetHeartbeat();
    });

    this.ws.on('error', (error) => {
      console.error('WebSocket error:', error);
      this.setState(ConnectionState.Error);
      // Don't cleanup here -- close event always follows error and will handle cleanup
    });

    this.ws.on('close', (code, reason) => {
      this.setState(ConnectionState.Disconnected);
      this.cleanup();
    });

    // Set initial state to connected if WebSocket is already open
    if (this.ws.readyState === WebSocket.OPEN) {
      if (this.connectionTimeout) {
        clearTimeout(this.connectionTimeout);
        this.connectionTimeout = undefined;
      }
      this.setState(ConnectionState.Connected);
      this.startHeartbeat();
    }
  }

  private handleMessage(message: JSONRPCMessage): void {
    // Handle ping messages
    if (this.isPingMessage(message)) {
      this.sendPong(message as JSONRPCRequest);
      return;
    }

    // Notify all message handlers
    for (const handler of this.messageHandlers) {
      try {
        handler(message);
      } catch (error) {
        console.error('Message handler error:', error);
      }
    }
  }

  private isPingMessage(message: JSONRPCMessage): boolean {
    return 'method' in message && message.method === 'ping';
  }

  private sendPong(pingMessage: JSONRPCRequest): void {
    const pongResponse: JSONRPCResponse = {
      jsonrpc: '2.0',
      id: pingMessage.id,
      result: { type: 'pong' }
    };
    this.send(pongResponse);
  }

  private setState(newState: ConnectionState): void {
    if (this.state !== newState) {
      this.state = newState;
      for (const handler of this.stateChangeHandlers) {
        try {
          handler(newState);
        } catch (error) {
          console.error('State change handler error:', error);
        }
      }
    }
  }

  private startHeartbeat(): void {
    if (this.config.heartbeatInterval > 0) {
      this.heartbeatTimer = setInterval(() => {
        if (this.ws.readyState === WebSocket.OPEN) {
          this.ws.ping();
        }
      }, this.config.heartbeatInterval);
      this.heartbeatTimer.unref();
    }
  }

  private resetHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.startHeartbeat();
    }
  }

  private cleanup(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }
    if (this.connectionTimeout) {
      clearTimeout(this.connectionTimeout);
      this.connectionTimeout = undefined;
    }
    this.messageHandlers.clear();
    this.stateChangeHandlers.clear();
  }

  /**
   * Send a JSON-RPC message over the WebSocket
   */
  send(message: JSONRPCMessage): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.state !== ConnectionState.Connected) {
        reject(new Error(`Cannot send message: connection state is ${this.state}`));
        return;
      }

      try {
        const data = JSON.stringify(message);
        
        // Check message size
        const byteLength = Buffer.byteLength(data, 'utf8');
        if (byteLength > this.config.maxMessageSize) {
          reject(new Error(`Message too large: ${byteLength} bytes > ${this.config.maxMessageSize} bytes`));
          return;
        }

        this.ws.send(data, (error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Send an error response
   */
  sendError(code: number, message: string, id?: string | number | null): Promise<void> {
    // Per JSON-RPC 2.0 spec, id MUST be null when the id could not be detected
    const errorResponse = {
      jsonrpc: '2.0' as const,
      id: (id ?? null) as string | number,
      error: {
        code,
        message
      }
    };
    return this.send(errorResponse);
  }

  /**
   * Add a message handler
   */
  onMessage(handler: (message: JSONRPCMessage) => void): void {
    this.messageHandlers.add(handler);
  }

  /**
   * Remove a message handler
   */
  offMessage(handler: (message: JSONRPCMessage) => void): void {
    this.messageHandlers.delete(handler);
  }

  /**
   * Add a state change handler
   */
  onStateChange(handler: (state: ConnectionState) => void): void {
    this.stateChangeHandlers.add(handler);
  }

  /**
   * Remove a state change handler
   */
  offStateChange(handler: (state: ConnectionState) => void): void {
    this.stateChangeHandlers.delete(handler);
  }

  /**
   * Get the current connection state
   */
  getState(): ConnectionState {
    return this.state;
  }

  /**
   * Check if the connection is active
   */
  isConnected(): boolean {
    return this.state === ConnectionState.Connected && this.ws.readyState === WebSocket.OPEN;
  }

  /**
   * Close the connection
   */
  close(code?: number, reason?: string): void {
    this.setState(ConnectionState.Disconnecting);
    this.ws.close(code, reason);
  }

  /**
   * Terminate the connection immediately
   */
  terminate(): void {
    this.setState(ConnectionState.Disconnected);
    this.ws.terminate();
  }
}

/**
 * WebSocket transport implementation for real-time bidirectional communication
 */
export class WebSocketTransport implements Transport {
  private config: Required<WebSocketConfig>;
  private wss: WebSocketServer | null = null;
  private httpServer: HttpServer | null = null;
  private mcpServer: MCPServer | null = null;
  private connections: Set<WebSocketConnection> = new Set();
  private messageRouters: Map<string, (message: JSONRPCMessage, connection: WebSocketConnection) => Promise<void>> = new Map();

  constructor(config: WebSocketConfig) {
    this.config = {
      host: '0.0.0.0',
      path: '/mcp',
      maxConnections: 100,
      heartbeatInterval: 30000, // 30 seconds
      connectionTimeout: 10000, // 10 seconds
      messageTimeout: 30000, // 30 seconds
      maxMessageSize: 1024 * 1024, // 1MB
      enableCompression: true,
      enablePerMessageDeflate: true,
      ...config
    };
  }

  /**
   * Start the WebSocket transport
   */
  async start(server: MCPServer): Promise<void> {
    this.mcpServer = server;

    // Create HTTP server if not provided
    this.httpServer = createServer();

    // Create WebSocket server
    this.wss = new WebSocketServer({
      server: this.httpServer,
      path: this.config.path,
      maxPayload: this.config.maxMessageSize,
      perMessageDeflate: this.config.enablePerMessageDeflate
    });

    // Handle server-level errors to prevent uncaught exception crashes
    this.wss.on('error', (error: Error) => {
      console.error('WebSocket server error:', error);
    });

    // Handle new connections
    this.wss.on('connection', (ws, request) => {
      this.handleConnection(ws, request);
    });

    // Start HTTP server
    return new Promise((resolve, reject) => {
      const startupErrorHandler = (error: Error) => reject(error);
      this.httpServer!.listen(this.config.port, this.config.host, () => {
        this.httpServer!.removeListener('error', startupErrorHandler);
        this.httpServer!.on('error', (error: Error) => {
          console.error('WebSocket HTTP server error:', error);
        });
        console.log(`WebSocket transport listening on ${this.config.host}:${this.config.port}${this.config.path}`);
        resolve();
      });

      this.httpServer!.on('error', startupErrorHandler);
    });
  }

  /**
   * Stop the WebSocket transport
   */
  async stop(): Promise<void> {
    // Close all connections
    for (const connection of this.connections) {
      connection.close(1001, 'Server shutting down');
    }
    this.connections.clear();

    // Close WebSocket server (with timeout to prevent hanging)
    if (this.wss) {
      await new Promise<void>((resolve) => {
        const timeout = setTimeout(() => {
          console.warn('WebSocket server close timed out after 5s, forcing shutdown');
          this.wss = null;
          this.httpServer = null;
          resolve();
        }, 5000);
        timeout.unref();

        this.wss!.close(() => {
          this.wss = null;

          // Close HTTP server
          if (this.httpServer) {
            this.httpServer.close(() => {
              clearTimeout(timeout);
              this.httpServer = null;
              resolve();
            });
          } else {
            clearTimeout(timeout);
            resolve();
          }
        });
      });
    }
  }

  private handleConnection(ws: WebSocket, request: any): void {
    // Check connection limit
    if (this.connections.size >= this.config.maxConnections) {
      ws.close(1013, 'Too many connections');
      return;
    }

    const connection = new WebSocketConnection(ws, this.config);
    this.connections.add(connection);

    // Set up message handling
    connection.onMessage((message) => {
      this.handleMessage(message, connection);
    });

    // Handle connection state changes
    connection.onStateChange((state) => {
      if (state === ConnectionState.Disconnected || state === ConnectionState.Error) {
        this.connections.delete(connection);
      }
    });

    console.log(`New WebSocket connection established. Total connections: ${this.connections.size}`);
  }

  private async handleMessage(message: JSONRPCMessage, connection: WebSocketConnection): Promise<void> {
    try {
      // Route message based on method (for requests) or handle responses/notifications
      if ('method' in message) {
        const method = message.method;
        const router = this.messageRouters.get(method);
        
        if (router) {
          await router(message, connection);
        } else {
          // Forward to MCP server's SDK server
          if (this.mcpServer) {
            // This is a simplified approach - in a real implementation,
            // you'd want to integrate more closely with the MCP SDK
            console.log(`Received message for method: ${method}`);
          }
        }
      }
    } catch (error) {
      console.error('Error handling WebSocket message:', error);
      
      // Send error response if it was a request
      if ('id' in message && message.id !== undefined) {
        await connection.sendError(-32603, 'Internal error', message.id);
      }
    }
  }

  /**
   * Register a message router for a specific method
   */
  registerMessageRouter(method: string, router: (message: JSONRPCMessage, connection: WebSocketConnection) => Promise<void>): void {
    this.messageRouters.set(method, router);
  }

  /**
   * Remove a message router
   */
  unregisterMessageRouter(method: string): void {
    this.messageRouters.delete(method);
  }

  /**
   * Broadcast a message to all connected clients
   */
  async broadcast(message: JSONRPCMessage): Promise<void> {
    const promises: Promise<void>[] = [];
    
    for (const connection of this.connections) {
      if (connection.isConnected()) {
        promises.push(connection.send(message).catch(error => {
          console.error('Failed to send broadcast message:', error);
        }));
      }
    }

    await Promise.allSettled(promises);
  }

  /**
   * Send a message to a specific connection
   */
  async sendToConnection(connection: WebSocketConnection, message: JSONRPCMessage): Promise<void> {
    if (this.connections.has(connection) && connection.isConnected()) {
      await connection.send(message);
    } else {
      throw new Error('Connection not found or not connected');
    }
  }

  /**
   * Get all active connections
   */
  getConnections(): WebSocketConnection[] {
    return Array.from(this.connections).filter(conn => conn.isConnected());
  }

  /**
   * Get connection statistics
   */
  getStats(): {
    totalConnections: number;
    activeConnections: number;
    maxConnections: number;
  } {
    const activeConnections = this.getConnections();
    
    return {
      totalConnections: this.connections.size,
      activeConnections: activeConnections.length,
      maxConnections: this.config.maxConnections
    };
  }
}

// All types and classes are already exported where they are defined