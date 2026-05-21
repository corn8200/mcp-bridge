import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";

const HOME = homedir();
const BRIDGE_URL = process.env.MCP_BRIDGE_PROXY_URL ?? "http://127.0.0.1:8769/mcp";
const TOOL_CACHE_PATH =
  process.env.MCP_BRIDGE_TOOL_CACHE_PATH ?? join(HOME, ".config", "mcp-bridge", "tools-cache.json");
const REQUEST_TIMEOUT_MS = Number(process.env.MCP_BRIDGE_PROXY_TIMEOUT_MS ?? "60000");

function log(message: string, meta?: unknown): void {
  const suffix = meta === undefined ? "" : ` ${JSON.stringify(meta)}`;
  process.stderr.write(`[mcp-bridge-stdio] ${message}${suffix}\n`);
}

function asErrorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

class LocalBridgeClient {
  private client?: Client;
  private transport?: StreamableHTTPClientTransport;
  private connecting?: Promise<Client>;

  async listTools(): Promise<Tool[]> {
    try {
      const client = await this.ensureConnected();
      const result = await client.listTools(undefined, { timeout: REQUEST_TIMEOUT_MS });
      return result.tools;
    } catch (error) {
      log("listTools failed; using cache if available", { error: asErrorText(error) });
      this.reset();
      return readCachedTools();
    }
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
    try {
      const client = await this.ensureConnected();
      return (await client.callTool(
        { name, arguments: args },
        undefined,
        { timeout: REQUEST_TIMEOUT_MS },
      )) as CallToolResult;
    } catch (firstError) {
      log("callTool failed; reconnecting once", { tool: name, error: asErrorText(firstError) });
      this.reset();
      try {
        const client = await this.ensureConnected();
        return (await client.callTool(
          { name, arguments: args },
          undefined,
          { timeout: REQUEST_TIMEOUT_MS },
        )) as CallToolResult;
      } catch (secondError) {
        this.reset();
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `mcp-bridge stdio proxy failed to call ${name}: ${asErrorText(secondError)}`,
            },
          ],
        };
      }
    }
  }

  async close(): Promise<void> {
    try {
      await this.client?.close();
    } catch {
      // Best effort shutdown.
    }
    try {
      await this.transport?.close();
    } catch {
      // Best effort shutdown.
    }
    this.client = undefined;
    this.transport = undefined;
  }

  private async ensureConnected(): Promise<Client> {
    if (this.client) {
      return this.client;
    }
    if (this.connecting) {
      return this.connecting;
    }
    this.connecting = this.connect().finally(() => {
      this.connecting = undefined;
    });
    return this.connecting;
  }

  private async connect(): Promise<Client> {
    const client = new Client({ name: "mcp-bridge-stdio-proxy-client", version: "0.1.0" }, { capabilities: {} });
    const transport = new StreamableHTTPClientTransport(new URL(BRIDGE_URL), {
      reconnectionOptions: {
        initialReconnectionDelay: 1_000,
        maxReconnectionDelay: 30_000,
        reconnectionDelayGrowFactor: 1.6,
        maxRetries: 10,
      },
    });
    transport.onerror = (error) => {
      log("local bridge transport error", { error: asErrorText(error) });
    };
    transport.onclose = () => {
      log("local bridge transport closed");
      this.reset();
    };
    await client.connect(transport, { timeout: REQUEST_TIMEOUT_MS });
    this.client = client;
    this.transport = transport;
    return client;
  }

  private reset(): void {
    this.client = undefined;
    this.transport = undefined;
  }
}

async function readCachedTools(): Promise<Tool[]> {
  try {
    const cache = JSON.parse(await readFile(TOOL_CACHE_PATH, "utf8")) as {
      toolsByUpstream?: Record<string, Tool[]>;
    };
    return Object.values(cache.toolsByUpstream ?? {}).flat();
  } catch {
    return [];
  }
}

async function main(): Promise<void> {
  const bridgeClient = new LocalBridgeClient();
  const server = new Server(
    { name: "mcp-bridge-stdio-proxy", version: "0.1.0" },
    {
      capabilities: {
        tools: {},
        resources: {},
        prompts: {},
      },
      instructions: `Stdio adapter for the persistent local MCP bridge at ${BRIDGE_URL}.`,
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: await bridgeClient.listTools(),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) =>
    bridgeClient.callTool(request.params.name, request.params.arguments ?? {}),
  );

  server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: [] }));
  server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({ resourceTemplates: [] }));
  server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: [] }));

  const transport = new StdioServerTransport();
  await server.connect(transport);

  const shutdown = async () => {
    await bridgeClient.close();
    await server.close();
    await transport.close();
  };

  process.on("SIGINT", () => {
    shutdown().finally(() => process.exit(0));
  });
  process.on("SIGTERM", () => {
    shutdown().finally(() => process.exit(0));
  });
}

main().catch((error) => {
  log("fatal startup error", { error: error instanceof Error ? error.stack ?? error.message : String(error) });
  process.exit(1);
});
