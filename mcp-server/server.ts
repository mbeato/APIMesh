import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Helper: make an HTTP request and return a structured MCP tool result.
// Handles 402 (payment required) by returning the payment details.
// ---------------------------------------------------------------------------
async function callApi(
  url: string,
  options?: RequestInit,
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  try {
    const res = await fetch(url, options);
    const body = await res.text();

    if (res.status === 402) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                status: 402,
                message: "Payment Required (x402)",
                headers: Object.fromEntries(res.headers.entries()),
                body: tryParseJSON(body),
              },
              null,
              2,
            ),
          },
        ],
      };
    }

    if (!res.ok) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              { status: res.status, error: tryParseJSON(body) },
              null,
              2,
            ),
          },
        ],
        isError: true,
      };
    }

    return {
      content: [
        {
          type: "text",
          text: typeof tryParseJSON(body) === "object"
            ? JSON.stringify(tryParseJSON(body), null, 2)
            : body,
        },
      ],
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      content: [{ type: "text", text: `Fetch error: ${message}` }],
      isError: true,
    };
  }
}

function tryParseJSON(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function qs(params: Record<string, string | number | undefined>): string {
  const entries = Object.entries(params).filter(
    ([, v]) => v !== undefined && v !== null,
  );
  if (entries.length === 0) return "";
  return "?" + entries.map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`).join("&");
}

export function createServer(): McpServer {
  const server = new McpServer({
    name: "apimesh",
    version: "1.1.0",
  });

  server.tool(
    "web_checker",
    "Check if a brand name is available across 5 domain TLDs (.com, .io, .xyz, .dev, .ai), GitHub, npm, PyPI, and Reddit in one call. Free preview: GET https://check.apimesh.xyz/preview?name=... returns .com availability only",
    { name: z.string().describe("The brand or product name to check") },
    async ({ name }) => callApi(`https://check.apimesh.xyz/check${qs({ name })}`),
  );

  server.tool(
    "http_status_checker",
    "Check the live HTTP status of any URL, optionally verify against an expected code. Useful for uptime monitoring, redirect validation, and link checking",
    {
      url: z.string().describe("The URL to check"),
      expected: z.number().optional().describe("Expected HTTP status code"),
    },
    async ({ url, expected }) =>
      callApi(`https://http-status-checker.apimesh.xyz/check${qs({ url, expected })}`),
  );

  server.tool(
    "favicon_checker",
    "Check whether a website has a favicon and get its URL, format, and status. Useful for link previews and site branding validation",
    { url: z.string().describe("The URL to check for a favicon") },
    async ({ url }) =>
      callApi(`https://favicon-checker.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "microservice_health_check",
    "Check health and response times of up to 10 service URLs in parallel. Free preview: GET https://microservice-health-check.apimesh.xyz/preview?url=... checks 1 service for free",
    {
      services: z.array(z.string()).describe("Array of service URLs to health-check"),
    },
    async ({ services }) =>
      callApi("https://microservice-health-check.apimesh.xyz/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ services }),
      }),
  );

  server.tool(
    "robots_txt_parser",
    "Fetch and parse a website's robots.txt into structured rules, sitemaps, and crawl directives",
    { url: z.string().describe("The website URL whose robots.txt to parse") },
    async ({ url }) =>
      callApi(`https://robots-txt-parser.apimesh.xyz/analyze${qs({ url })}`),
  );

  return server;
}
