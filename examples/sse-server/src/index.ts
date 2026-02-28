import { MCPServer, Transport } from "@tylercoles/mcp-server";
import { createSSEServer } from "@tylercoles/mcp-transport-sse";
import { createStdioServer } from "@tylercoles/mcp-transport-stdio";
import { z } from "zod";

// Configuration from environment variables or command line args
const USE_STDIO = process.env.MCP_TRANSPORT === "stdio" || process.argv.includes("--stdio");
const PORT = parseInt(process.env.PORT || "3000");
const HOST = process.env.HOST || "127.0.0.1";

// Create MCP server
const server = new MCPServer({
  name: "example-sse-server",
  version: "1.0.0",
  capabilities: {
    tools: { listChanged: true },
    resources: { listChanged: true },
    prompts: { listChanged: true }
  }
});

// Register example tools
server.registerTool("echo", {
  title: "Echo Tool",
  description: "Echoes back the input message",
  inputSchema: z.object({ message: z.string() })
}, async ({ message }) => ({
  content: [{ type: "text", text: `Echo: ${message}` }]
}));

server.registerTool("calculate", {
  title: "Calculator",
  description: "Performs basic arithmetic operations",
  inputSchema: z.object({
    operation: z.enum(["add", "subtract", "multiply", "divide"]),
    a: z.number(),
    b: z.number()
  })
}, async ({ operation, a, b }) => {
  let result: number | undefined;
  switch (operation) {
    case "add": result = a + b; break;
    case "subtract": result = a - b; break;
    case "multiply": result = a * b; break;
    case "divide":
      if (b === 0) {
        return {
          content: [{ type: "text", text: "Error: Division by zero" }],
          isError: true
        };
      }
      result = a / b;
      break;
  }
  return {
    content: [{ type: "text", text: `Result: ${result}` }]
  };
});

// Register example resource
server.registerResource(
  "time",
  "time://current",
  {
    title: "Current Time",
    description: "Get the current date and time",
    mimeType: "text/plain"
  },
  async (uri) => ({
    contents: [{
      uri: uri.href,
      text: new Date().toISOString()
    }]
  })
);

// Register example prompt
server.registerPrompt("greet", {
  title: "Greeting Prompt",
  description: "Generate a friendly greeting",
  argsSchema: z.object({
    name: z.string().describe("Name to greet"),
    language: z.enum(["english", "spanish", "french"]).default("english").describe("Language for the greeting")
  })
}, ({ name, language }) => {
  const greetings: Record<string, string> = {
    english: `Hello, ${name}! How can I help you today?`,
    spanish: `¡Hola, ${name}! ¿En qué puedo ayudarte hoy?`,
    french: `Bonjour, ${name}! Comment puis-je vous aider aujourd'hui?`
  };

  return {
    messages: [{
      role: "assistant",
      content: {
        type: "text",
        text: greetings[language]
      }
    }]
  };
});

// Configure transport based on environment
async function main() {
  let transport: Transport;
  try {
    if (USE_STDIO) {
      console.error("Starting with stdio transport...");
      transport = createStdioServer(server);
    } else {
      console.log(`Starting with SSE transport on http://${HOST}:${PORT}`);
      transport = createSSEServer(server, {
        port: PORT,
        host: HOST,
        basePath: "/",
        enableDnsRebindingProtection: true,
        allowedHosts: ["127.0.0.1", "localhost"],
        cors: {
          origin: true,
          credentials: true,
          exposedHeaders: ["Mcp-Session-Id"],
          allowedHeaders: ["Content-Type", "Mcp-Session-Id"]
        }
      });
    }

    // Start the server
    await server.start().then(() => {
      console.log("MCP Server started successfully!");
    });

    // Handle shutdown gracefully
    process.on("SIGINT", async () => {
      console.log("\nShutting down server...");
      await server.stop();
      process.exit(0);
    });

    process.on("SIGTERM", async () => {
      console.log("\nShutting down server...");
      await server.stop();
      process.exit(0);
    });

  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

// Run the server
main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
