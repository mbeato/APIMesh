#!/usr/bin/env bun
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { createServer } from "./server.js";

function resolvePort(envVar: string, defaultPort: number): number {
  const raw = process.env[envVar];
  if (!raw) return defaultPort;
  const port = parseInt(raw, 10);
  if (isNaN(port) || port < 1024 || port > 65535) {
    console.error(`FATAL: ${envVar}=${raw} is not a valid port (1024-65535)`);
    process.exit(1);
  }
  return port;
}

const PORT = resolvePort("MCP_PORT", 3002);

// Track transports by session ID for stateful mode
const transports = new Map<string, WebStandardStreamableHTTPServerTransport>();

Bun.serve({
  port: PORT,
  hostname: "127.0.0.1",
  async fetch(req) {
    const url = new URL(req.url);

    // Health check
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "ok" }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // Only handle /mcp
    if (url.pathname !== "/mcp") {
      return new Response(JSON.stringify({ error: "Not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Check for existing session
    const sessionId = req.headers.get("mcp-session-id");
    if (sessionId && transports.has(sessionId)) {
      const transport = transports.get(sessionId)!;
      return transport.handleRequest(req);
    }

    // DELETE with unknown session → 404
    if (req.method === "DELETE") {
      return new Response(JSON.stringify({ error: "Session not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    // New session — create transport + server
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: () => crypto.randomUUID(),
      onsessioninitialized: (id) => {
        transports.set(id, transport);
      },
    });

    // Clean up on close
    transport.onclose = () => {
      if (transport.sessionId) {
        transports.delete(transport.sessionId);
      }
    };

    const server = createServer();
    await server.connect(transport);

    return transport.handleRequest(req);
  },
});

console.log(`mcp-server (HTTP) listening on port ${PORT}`);
