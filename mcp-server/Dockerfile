FROM oven/bun:1.3-alpine

WORKDIR /app

COPY mcp-server/package.json mcp-server/server.ts mcp-server/index.ts mcp-server/server.json ./
RUN bun install --production

ENTRYPOINT ["bun", "run", "index.ts"]
