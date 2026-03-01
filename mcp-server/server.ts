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
    version: "1.0.0",
  });

  server.tool(
    "web_checker",
    "Check brand/product name availability across domains, social media, and package registries",
    { name: z.string().describe("The brand or product name to check") },
    async ({ name }) => callApi(`https://check.apimesh.xyz/check${qs({ name })}`),
  );

  server.tool(
    "http_status_checker",
    "Check the HTTP status code of a URL, optionally verifying against an expected status",
    {
      url: z.string().describe("The URL to check"),
      expected: z.number().optional().describe("Expected HTTP status code"),
    },
    async ({ url, expected }) =>
      callApi(`https://http-status-checker.apimesh.xyz/check${qs({ url, expected })}`),
  );

  server.tool(
    "favicon_checker",
    "Check whether a URL has a favicon and retrieve its details",
    { url: z.string().describe("The URL to check for a favicon") },
    async ({ url }) =>
      callApi(`https://favicon-checker.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "microservice_health_check",
    "Check the health status of multiple service URLs simultaneously",
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
    "status_code_checker",
    "Check the HTTP status code returned by a URL",
    { url: z.string().describe("The URL to check") },
    async ({ url }) =>
      callApi(`https://status-code-checker.apimesh.xyz/check${qs({ url })}`),
  );

  server.tool(
    "regex_builder",
    "Build and validate a regular expression pattern with optional flags",
    {
      pattern: z.string().describe("The regex pattern to build"),
      flags: z.string().optional().describe("Regex flags (e.g. 'gi')"),
    },
    async ({ pattern, flags }) =>
      callApi("https://regex-builder.apimesh.xyz/build", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pattern, flags }),
      }),
  );

  server.tool(
    "regex_tester",
    "Test a regular expression against a string and return matches",
    {
      pattern: z.string().describe("The regex pattern to test"),
      testString: z.string().describe("The string to test against"),
      flags: z.string().optional().describe("Regex flags (e.g. 'gi')"),
    },
    async ({ pattern, testString, flags }) =>
      callApi("https://regex-builder.apimesh.xyz/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pattern, testString, flags }),
      }),
  );

  server.tool(
    "user_agent_analyzer",
    "Parse and analyze a user-agent string to extract browser, OS, and device info",
    { ua: z.string().describe("The user-agent string to analyze") },
    async ({ ua }) =>
      callApi(`https://user-agent-analyzer.apimesh.xyz/analyze${qs({ ua })}`),
  );

  server.tool(
    "robots_txt_parser",
    "Fetch and analyze the robots.txt file of a website",
    { url: z.string().describe("The website URL whose robots.txt to analyze") },
    async ({ url }) =>
      callApi(`https://robots-txt-parser.apimesh.xyz/analyze${qs({ url })}`),
  );

  server.tool(
    "mock_jwt_generator",
    "Generate a mock JSON Web Token (JWT) for testing purposes",
    {
      payload: z.record(z.unknown()).describe("The JWT payload as a JSON object"),
      secret: z.string().describe("The secret key to sign the JWT"),
      expiresInSeconds: z.number().optional().describe("Token expiration time in seconds"),
    },
    async ({ payload, secret, expiresInSeconds }) =>
      callApi("https://mock-jwt-generator.apimesh.xyz/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ payload, secret, expiresInSeconds }),
      }),
  );

  server.tool(
    "yaml_validator",
    "Validate YAML syntax and report any errors",
    { yaml: z.string().describe("The YAML string to validate") },
    async ({ yaml }) =>
      callApi("https://yaml-validator.apimesh.xyz/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ yaml }),
      }),
  );

  server.tool(
    "swagger_docs_creator",
    "Generate Swagger/OpenAPI documentation for an API endpoint",
    {
      path: z.string().describe("The API path (e.g. '/users/{id}')"),
      method: z.string().describe("HTTP method (GET, POST, PUT, DELETE, etc.)"),
      summary: z.string().optional().describe("Short summary of the endpoint"),
      description: z.string().optional().describe("Detailed description of the endpoint"),
    },
    async ({ path, method, summary, description }) =>
      callApi("https://swagger-docs-creator.apimesh.xyz/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path, method, summary, description }),
      }),
  );

  return server;
}
