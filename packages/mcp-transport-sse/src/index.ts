import { Transport, MCPServer } from "@tylercoles/mcp-server";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import express, { Express, Request, Response } from "express";
import cors from "cors";
import { randomUUID } from "crypto";
import http from "http";

/**
 * Configuration for SSE transport
 */
export interface SSEConfig {
  port: number;
  host: string;
  basePath: string;
  cors: cors.CorsOptions;
  enableDnsRebindingProtection: boolean;
  allowedHosts: string[];
}

/**
 * SSE Transport implementation
 * Uses the legacy SSE transport from the SDK for backwards compatibility
 */
export class SSETransport implements Transport {
  private config: SSEConfig;
  private app: Express;
  private server?: http.Server;
  private transports: Map<string, SSEServerTransport> = new Map();
  private mcpServer?: MCPServer;

  constructor(config: Partial<SSEConfig> = {}) {
    this.config = {
      port: config.port ?? 3000,
      host: config.host ?? "127.0.0.1",
      basePath: config.basePath ?? "/",
      enableDnsRebindingProtection: config.enableDnsRebindingProtection ?? true,
      allowedHosts: config.allowedHosts ?? ["127.0.0.1", "localhost"],
      cors: config.cors ?? {},
    };
    
    this.app = express();
    this.setupMiddleware();
  }

  private setupMiddleware(): void {
    // Enable CORS
    if (this.config.cors !== undefined) {
      this.app.use(cors(this.config.cors || {
        origin: true,
        credentials: true,
        exposedHeaders: ["Mcp-Session-Id"],
        allowedHeaders: ["Content-Type", "Mcp-Session-Id"]
      }));
    }

    // Body parsing
    this.app.use(express.json({ limit: "1mb" }));

    // DNS rebinding protection
    if (this.config.enableDnsRebindingProtection) {
      this.app.use((req, res, next) => {
        const host = req.headers.host?.split(":")[0];
        if (host && !this.config.allowedHosts?.includes(host)) {
          return res.status(403).json({
            error: "Forbidden: Invalid host"
          });
        }
        next();
      });
    }
  }

  private setupRoutes(): void {
    const basePath = this.config.basePath!;

    // SSE endpoint for server-to-client messages
    this.app.get(basePath + "sse", async (req: Request, res: Response) => {
      const sessionId = randomUUID();
      let connected = false;

      try {
        // Create SSE transport
        const transport = new SSEServerTransport("/messages", res);

        this.transports.set(sessionId, transport);

        // Send session ID as first event
        res.write(`data: ${JSON.stringify({ sessionId })}\n\n`);

        // Clean up on disconnect
        res.on("close", () => {
          connected = false;
          this.transports.delete(sessionId);
        });

        // Connect MCP server
        const sdkServer = this.mcpServer!.getSDKServer();
        await sdkServer.connect(transport);
        connected = true;

      } catch (error) {
        // Clean up transport on connect failure
        this.transports.delete(sessionId);
        console.error("SSE connection failed:", error);
        if (!res.headersSent) {
          res.status(500).send("SSE connection failed");
        } else {
          // Headers already sent (SSE stream started), end the response
          res.end();
        }
      }
    });

    // Messages endpoint for client-to-server messages
    this.app.post(basePath + "messages", async (req: Request, res: Response) => {
      try {
        const sessionId = req.query.sessionId as string;

        // Validate sessionId format (must be a valid UUID)
        if (!sessionId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sessionId)) {
          return res.status(400).json({
            error: "Invalid or missing session ID"
          });
        }

        const transport = this.transports.get(sessionId);

        if (!transport) {
          return res.status(400).json({
            error: "Unknown session ID"
          });
        }

        await transport.handlePostMessage(req, res, req.body);
        
      } catch (error) {
        console.error("Message handling failed:", error);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: "2.0",
            error: {
              code: -32603,
              message: "Internal server error"
            },
            id: req.body?.id || null
          });
        }
      }
    });

    // Health check endpoint
    this.app.get(basePath + "health", (req: Request, res: Response) => {
      res.json({
        status: "healthy",
        transport: "sse",
        sessions: this.transports.size
      });
    });
  }

  async start(server: MCPServer): Promise<void> {
    this.mcpServer = server;
    this.setupRoutes();

    return new Promise<void>((resolve, reject) => {
      try {
        this.server = this.app.listen(this.config.port, this.config.host!, () => {
          const address = this.server!.address();
          const actualPort = typeof address === 'string' ? this.config.port : address?.port || this.config.port;
          this.config.port = actualPort!;
          console.log(`SSE transport listening on http://${this.config.host}:${actualPort}`);
          resolve();
        });
        
        this.server.on("error", reject);
      } catch (error) {
        reject(error);
      }
    });
  }

  async stop(): Promise<void> {
    // Close all transports
    for (const transport of this.transports.values()) {
      await transport.close();
    }
    this.transports.clear();

    // Stop HTTP server
    return new Promise((resolve, reject) => {
      if (!this.server) {
        resolve();
        return;
      }

      this.server.close((err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }

  /**
   * Get the base URL for this transport
   */
  getBaseUrl(): string {
    const protocol = "http";
    const host = this.config.host === "0.0.0.0" ? "localhost" : this.config.host;
    return `${protocol}://${host}:${this.config.port}${this.config.basePath}`;
  }

  /**
   * Get the number of active sessions
   */
  getSessionCount(): number {
    return this.transports.size;
  }
}

/**
 * Helper function to create an SSE server with default configuration
 */
export function createSSEServer(
  server: MCPServer,
  config?: Partial<SSEConfig>
): SSETransport {
  const transport = new SSETransport(config);
  server.useTransport(transport);
  return transport;
}
