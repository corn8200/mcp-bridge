import express, { type Request, type Response, type NextFunction } from "express";
import { randomUUID } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  renameSync,
  statSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  isInitializeRequest,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { runOAuthBootstrap, UpstreamBridge, type LogFn } from "./upstream.js";

const HOME = homedir();
const PORT = Number(process.env.MCP_BRIDGE_PORT ?? "8769");
const HOST = process.env.MCP_BRIDGE_HOST ?? "127.0.0.1";
const MCP_PATH = process.env.MCP_BRIDGE_MCP_PATH ?? "/mcp";
const OVERSEER_URL = process.env.MCP_BRIDGE_OVERSEER_URL ?? "";
const CONFIG_DIR = process.env.MCP_BRIDGE_CONFIG_DIR ?? join(HOME, ".config", "mcp-bridge");
const OAUTH_STATE_PATH = process.env.MCP_BRIDGE_OAUTH_STATE_PATH ?? join(CONFIG_DIR, "oauth-state.json");
const TOOL_CACHE_PATH = process.env.MCP_BRIDGE_TOOL_CACHE_PATH ?? join(CONFIG_DIR, "tools-cache.json");
const LOG_PATH = process.env.MCP_BRIDGE_LOG_PATH ?? join(HOME, "Library", "Logs", "mcp-bridge.log");
const LOG_MAX_BYTES = Number(process.env.MCP_BRIDGE_LOG_MAX_BYTES ?? String(5 * 1024 * 1024));
const LOG_BACKUPS = Number(process.env.MCP_BRIDGE_LOG_BACKUPS ?? "5");
const SENTINEL_COMMAND = process.env.MCP_BRIDGE_SENTINEL_COMMAND ?? "";
const SENTINEL_ARGS = (process.env.MCP_BRIDGE_SENTINEL_ARGS ?? "")
  .split(/\s+/)
  .map((part) => part.trim())
  .filter(Boolean);

class RotatingLogger {
  constructor(
    private readonly path: string,
    private readonly maxBytes: number,
    private readonly backups: number,
  ) {
    mkdirSync(dirname(path), { recursive: true });
  }

  log: LogFn = (level, message, meta) => {
    const record = {
      ts: new Date().toISOString(),
      level,
      message,
      ...(meta === undefined ? {} : { meta }),
    };
    try {
      this.rotateIfNeeded();
      appendFileSync(this.path, `${JSON.stringify(record)}\n`, "utf8");
    } catch (error) {
      process.stderr.write(`mcp-bridge log failure: ${error instanceof Error ? error.message : String(error)}\n`);
    }
  };

  private rotateIfNeeded(): void {
    if (!existsSync(this.path)) {
      return;
    }
    const size = statSync(this.path).size;
    if (size < this.maxBytes) {
      return;
    }
    for (let i = this.backups - 1; i >= 1; i -= 1) {
      const from = `${this.path}.${i}`;
      const to = `${this.path}.${i + 1}`;
      if (existsSync(from)) {
        renameSync(from, to);
      }
    }
    renameSync(this.path, `${this.path}.1`);
  }
}

function createMcpServer(bridge: UpstreamBridge, log: LogFn): Server {
  const server = new Server(
    { name: "mcp-bridge", version: "0.1.0" },
    {
      capabilities: {
        tools: {},
        resources: {},
        prompts: {},
      },
      instructions:
        "Persistent local MCP bridge for Overseer and Sentinel. Tools are cached locally and proxied to warm upstream clients.",
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: bridge.listTools(),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    const args = request.params.arguments ?? {};
    try {
      return await bridge.callTool(name, args);
    } catch (error) {
      const text = error instanceof Error ? error.message : String(error);
      log("error", `tool call failed: ${name}`, { error: text });
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `mcp-bridge failed to call ${name}: ${text}`,
          },
        ],
      };
    }
  });

  server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: [] }));
  server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({ resourceTemplates: [] }));
  server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: [] }));

  return server;
}

function originAllowed(origin: string | undefined): boolean {
  if (!origin) {
    return false;
  }
  try {
    const url = new URL(origin);
    const host = url.hostname.toLowerCase();
    return (
      origin === "https://claude.ai" ||
      origin === "https://chatgpt.com" ||
      origin === "https://chat.openai.com" ||
      host.endsWith(".claudeusercontent.com") ||
      host.endsWith(".openai.com") ||
      origin.startsWith("http://127.0.0.1:") ||
      origin.startsWith("http://localhost:")
    );
  } catch {
    return false;
  }
}

function corsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const origin = req.headers.origin;
  if (originAllowed(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin as string);
    res.setHeader("Access-Control-Allow-Credentials", "false");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Authorization,Content-Type,Accept,MCP-Protocol-Version,MCP-Session-Id,Last-Event-ID,Mcp-Method,Mcp-Name",
    );
    res.setHeader("Access-Control-Expose-Headers", "MCP-Session-Id");
    res.setHeader("Vary", "Origin");
  }
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  next();
}

function getSessionId(req: Request): string | undefined {
  const raw = req.headers["mcp-session-id"];
  if (Array.isArray(raw)) {
    return raw[0];
  }
  return raw;
}

function sendUnauthorizedMcpResponse(res: Response): void {
  res.setHeader("WWW-Authenticate", 'Bearer realm="mcp-bridge"');
  res.status(401).json({
    jsonrpc: "2.0",
    error: {
      code: -32001,
      message: "Unauthorized",
    },
    id: null,
  });
}

async function startDaemon(log: LogFn): Promise<void> {
  const bridge = new UpstreamBridge({
    overseerUrl: OVERSEER_URL,
    oauthStatePath: OAUTH_STATE_PATH,
    toolCachePath: TOOL_CACHE_PATH,
    sentinelCommand: SENTINEL_COMMAND,
    sentinelArgs: SENTINEL_ARGS,
    log,
  });
  await bridge.start();

  const app = express();
  app.use(corsMiddleware);
  app.use(express.json({ limit: "1mb", type: ["application/json", "application/*+json"] }));

  app.get("/", (_req, res) => {
    res.json({
      ok: true,
      service: "mcp-bridge",
      mcp: `http://${HOST}:${PORT}${MCP_PATH}`,
      health: `http://${HOST}:${PORT}/health`,
    });
  });

  app.get("/health", (_req, res) => {
    res.json({
      service: "mcp-bridge",
      ...bridge.health(),
    });
  });

  const transports: Record<
    string,
    { transport: StreamableHTTPServerTransport; server: Server; closing: boolean }
  > = {};

  app.all(MCP_PATH, async (req, res) => {
    try {
      const sessionId = getSessionId(req);
      const existing = sessionId ? transports[sessionId] : undefined;

      if (req.method === "GET" && !sessionId) {
        sendUnauthorizedMcpResponse(res);
        return;
      }

      if (existing) {
        await existing.transport.handleRequest(req, res, req.body);
        return;
      }

      if (req.method === "POST" && isInitializeRequest(req.body)) {
        let transport!: StreamableHTTPServerTransport;
        const server = createMcpServer(bridge, log);
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (newSessionId) => {
            transports[newSessionId] = { transport, server, closing: false };
            log("info", "MCP session initialized", { sessionId: newSessionId });
          },
        });
        transport.onclose = () => {
          const closedSessionId = transport.sessionId;
          const record = closedSessionId ? transports[closedSessionId] : undefined;
          if (record?.closing) {
            return;
          }
          if (record) {
            record.closing = true;
          }
          if (closedSessionId) {
            delete transports[closedSessionId];
            log("info", "MCP session closed", { sessionId: closedSessionId });
          }
          server.close().catch((error) => {
            log("warn", "MCP server close failed", { error: error instanceof Error ? error.message : String(error) });
          });
        };
        await server.connect(transport);
        await transport.handleRequest(req, res, req.body);
        return;
      }

      res.status(sessionId ? 404 : 400).json({
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: sessionId
            ? "Unknown MCP session ID"
            : "Bad Request: initialize request or MCP-Session-Id is required",
        },
        id: null,
      });
    } catch (error) {
      log("error", "MCP request handling failed", { error: error instanceof Error ? error.message : String(error) });
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    }
  });

  const httpServer = app.listen(PORT, HOST, () => {
    log("info", "mcp-bridge listening", {
      host: HOST,
      port: PORT,
      mcpPath: MCP_PATH,
      overseerUrl: OVERSEER_URL,
      sentinelCommand: SENTINEL_COMMAND,
      toolCount: bridge.listTools().length,
    });
  });

  const shutdown = async (signal: string) => {
    log("info", "shutting down", { signal });
    httpServer.close();
    await Promise.allSettled(
      Object.values(transports).map(async (record) => {
        record.closing = true;
        const { transport, server } = record;
        await server.close();
        await transport.close();
      }),
    );
    await bridge.close();
    process.exit(0);
  };

  process.on("SIGINT", () => {
    shutdown("SIGINT");
  });
  process.on("SIGTERM", () => {
    shutdown("SIGTERM");
  });
}

async function main(): Promise<void> {
  const logger = new RotatingLogger(LOG_PATH, LOG_MAX_BYTES, LOG_BACKUPS);
  const log = logger.log;

  process.on("unhandledRejection", (reason) => {
    log("error", "unhandled rejection", { error: reason instanceof Error ? reason.stack ?? reason.message : String(reason) });
  });
  process.on("uncaughtException", (error) => {
    log("error", "uncaught exception", { error: error.stack ?? error.message });
    process.exit(1);
  });

  if (process.argv[2] === "auth") {
    await runOAuthBootstrap({
      serverUrl: OVERSEER_URL,
      statePath: OAUTH_STATE_PATH,
      ownerPassword: process.env.MCP_BRIDGE_OWNER_PASSWORD,
      ownerPasswordOpRef: process.env.MCP_BRIDGE_OWNER_PASSWORD_OP_REF,
      log,
    });
    return;
  }

  await startDaemon(log);
}

main().catch((error) => {
  const logger = new RotatingLogger(LOG_PATH, LOG_MAX_BYTES, LOG_BACKUPS);
  logger.log("error", "startup failed", { error: error instanceof Error ? error.stack ?? error.message : String(error) });
  process.exit(1);
});
