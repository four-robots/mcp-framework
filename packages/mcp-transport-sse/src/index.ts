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
    let basePath = config.basePath ?? "/";
    if (!basePath.endsWith('/')) {
      basePath += '/';
    }
    this.config = {
      port: config.port ?? 3000,
      host: config.host ?? "127.0.0.1",
      basePath,
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
        if (!host || !this.config.allowedHosts?.includes(host)) {
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

      try {
        // Create SSE transport and connect to SDK server before exposing to clients
        const transport = new SSEServerTransport(basePath + "messages", res);

        // Register close handler BEFORE connect so early disconnects are caught
        res.on("close", () => {
          this.transports.delete(sessionId);
        });

        const sdkServer = this.mcpServer!.getSDKServer();
        await sdkServer.connect(transport);

        // Now that the transport is connected, register it and notify the client
        this.transports.set(sessionId, transport);

        // Send session ID as first event
        const writeOk = res.write(`data: ${JSON.stringify({ sessionId })}\n\n`);
        if (!writeOk) {
          this.transports.delete(sessionId);
          return;
        }

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
        const startupErrorHandler = (error: Error) => reject(error);
        this.server = this.app.listen(this.config.port, this.config.host!, () => {
          const address = this.server!.address();
          const actualPort = typeof address === 'string' ? this.config.port : address?.port || this.config.port;
          this.config.port = actualPort!;
          this.server!.removeListener("error", startupErrorHandler);
          this.server!.on("error", (error: Error) => {
            console.error("SSE server error:", error);
          });
          console.log(`SSE transport listening on http://${this.config.host}:${actualPort}`);
          resolve();
        });

        this.server.on("error", startupErrorHandler);
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

    // Stop HTTP server (with timeout to prevent hanging)
    if (this.server) {
      await new Promise<void>((resolve) => {
        const timeout = setTimeout(() => {
          console.warn('SSE server close timed out after 5s, forcing shutdown');
          resolve();
        }, 5000);
        timeout.unref();

        this.server!.close(() => {
          clearTimeout(timeout);
          resolve();
        });
      });
      this.server = undefined;
    }
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
