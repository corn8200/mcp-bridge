import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir, readFile, rename, writeFile, chmod } from "node:fs/promises";
import { dirname } from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  OAuthClientProvider,
  UnauthorizedError,
  auth,
  type OAuthDiscoveryState,
} from "@modelcontextprotocol/sdk/client/auth.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  StreamableHTTPClientTransport,
  StreamableHTTPError,
} from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type {
  OAuthClientInformationMixed,
  OAuthClientMetadata,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";

export type LogFn = (level: "debug" | "info" | "warn" | "error", message: string, meta?: unknown) => void;

export type UpstreamHealth = {
  name: string;
  kind: "http" | "stdio";
  connected: boolean;
  toolCount: number;
  lastConnectedAt?: string;
  lastToolRefreshAt?: string;
  lastError?: string;
  reconnectAttempts: number;
  nextReconnectAt?: string;
};

type ToolCacheFile = {
  updatedAt?: string;
  toolsByUpstream?: Record<string, Tool[]>;
};

type OAuthStateFile = {
  clientInformation?: OAuthClientInformationMixed;
  tokens?: OAuthTokens;
  codeVerifier?: string;
  discoveryState?: OAuthDiscoveryState;
  lastSavedAt?: string;
};

export type BridgeOptions = {
  overseerUrl: string;
  oauthStatePath: string;
  toolCachePath: string;
  sentinelCommand: string;
  sentinelArgs: string[];
  log: LogFn;
};

const DEFAULT_OWNER_PASSWORD_OP_REF = "op://MachineAutoBiz/ChatGPT Codex Bridge OAuth/password";
const TOOL_REFRESH_MS = 5 * 60_000;
const PING_INTERVAL_MS = 60_000;
const CONNECT_TIMEOUT_MS = 30_000;
const INITIAL_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 60_000;

function nowIso(): string {
  return new Date().toISOString();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function fetchTimeout(ms = 15_000): AbortSignal {
  return AbortSignal.timeout(ms);
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function isRetryableError(error: unknown): boolean {
  if (error instanceof UnauthorizedError || error instanceof StreamableHTTPError) {
    return true;
  }
  const message = errorMessage(error).toLowerCase();
  return [
    "401",
    "403",
    "404",
    "408",
    "429",
    "500",
    "502",
    "503",
    "504",
    "aborted",
    "closed",
    "disconnected",
    "econnreset",
    "econnrefused",
    "fetch failed",
    "socket",
    "terminated",
    "timeout",
    "transport",
  ].some((token) => message.includes(token));
}

async function writeJsonAtomic(path: string, value: unknown, mode = 0o600): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tempPath = `${path}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  await chmod(tempPath, mode);
  await rename(tempPath, path);
}

async function readJson<T>(path: string, fallback: T): Promise<T> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
    return fallback;
  }
}

export class PersistentOAuthProvider implements OAuthClientProvider {
  private stateData?: OAuthStateFile;
  private pendingAuthorizationUrl?: URL;

  constructor(
    private readonly statePath: string,
    private readonly redirectUri = "http://127.0.0.1:8770/callback",
  ) {}

  get redirectUrl(): string {
    return this.redirectUri;
  }

  get clientMetadata(): OAuthClientMetadata {
    return {
      client_name: "Mac Mini MCP Bridge",
      redirect_uris: [this.redirectUri],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
      scope: "overseer.all",
    };
  }

  async clientInformation(): Promise<OAuthClientInformationMixed | undefined> {
    return (await this.load()).clientInformation;
  }

  async saveClientInformation(clientInformation: OAuthClientInformationMixed): Promise<void> {
    const state = await this.load();
    state.clientInformation = clientInformation;
    await this.save(state);
  }

  async tokens(): Promise<OAuthTokens | undefined> {
    return (await this.load()).tokens;
  }

  async saveTokens(tokens: OAuthTokens): Promise<void> {
    const state = await this.load();
    state.tokens = tokens;
    await this.save(state);
  }

  redirectToAuthorization(authorizationUrl: URL): void {
    this.pendingAuthorizationUrl = authorizationUrl;
  }

  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    const state = await this.load();
    state.codeVerifier = codeVerifier;
    await this.save(state);
  }

  async codeVerifier(): Promise<string> {
    const codeVerifier = (await this.load()).codeVerifier;
    if (!codeVerifier) {
      throw new Error("OAuth code verifier is missing; rerun npm run auth");
    }
    return codeVerifier;
  }

  async saveDiscoveryState(discoveryState: OAuthDiscoveryState): Promise<void> {
    const state = await this.load();
    state.discoveryState = discoveryState;
    await this.save(state);
  }

  async discoveryState(): Promise<OAuthDiscoveryState | undefined> {
    return (await this.load()).discoveryState;
  }

  async invalidateCredentials(scope: "all" | "client" | "tokens" | "verifier" | "discovery"): Promise<void> {
    const state = await this.load();
    if (scope === "all" || scope === "client") {
      delete state.clientInformation;
    }
    if (scope === "all" || scope === "tokens") {
      delete state.tokens;
    }
    if (scope === "all" || scope === "verifier") {
      delete state.codeVerifier;
    }
    if (scope === "all" || scope === "discovery") {
      delete state.discoveryState;
    }
    await this.save(state);
  }

  consumeAuthorizationUrl(): URL | undefined {
    const url = this.pendingAuthorizationUrl;
    this.pendingAuthorizationUrl = undefined;
    return url;
  }

  private async load(): Promise<OAuthStateFile> {
    if (!this.stateData) {
      this.stateData = await readJson<OAuthStateFile>(this.statePath, {});
    }
    return this.stateData;
  }

  private async save(state: OAuthStateFile): Promise<void> {
    state.lastSavedAt = nowIso();
    this.stateData = state;
    await writeJsonAtomic(this.statePath, state);
  }
}

class UpstreamEndpoint {
  private client?: Client;
  private transport?: StreamableHTTPClientTransport | StdioClientTransport;
  private tools: Tool[] = [];
  private connected = false;
  private connecting?: Promise<void>;
  private lastConnectedAt?: string;
  private lastToolRefreshAt?: string;
  private lastError?: string;
  private reconnectTimer?: NodeJS.Timeout;
  private reconnectAttempts = 0;
  private nextReconnectAt?: string;
  private readonly log: LogFn;

  constructor(
    readonly name: string,
    readonly kind: "http" | "stdio",
    private readonly makeTransport: () => StreamableHTTPClientTransport | StdioClientTransport,
    log: LogFn,
    initialTools: Tool[] = [],
  ) {
    this.log = log;
    this.tools = initialTools;
  }

  getTools(): Tool[] {
    return this.tools;
  }

  health(): UpstreamHealth {
    return {
      name: this.name,
      kind: this.kind,
      connected: this.connected,
      toolCount: this.tools.length,
      lastConnectedAt: this.lastConnectedAt,
      lastToolRefreshAt: this.lastToolRefreshAt,
      lastError: this.lastError,
      reconnectAttempts: this.reconnectAttempts,
      nextReconnectAt: this.nextReconnectAt,
    };
  }

  async start(): Promise<void> {
    await this.connectWithTimeout();
  }

  async refreshTools(): Promise<boolean> {
    try {
      await this.ensureConnected();
      const result = await this.client!.listTools(undefined, { timeout: CONNECT_TIMEOUT_MS });
      this.tools = result.tools;
      this.lastToolRefreshAt = nowIso();
      this.lastError = undefined;
      return true;
    } catch (error) {
      this.recordFailure(error, "tool refresh failed");
      if (isRetryableError(error)) {
        this.scheduleReconnect();
      }
      return false;
    }
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
    await this.ensureConnected();
    try {
      return (await this.client!.callTool(
        { name, arguments: args },
        undefined,
        { timeout: CONNECT_TIMEOUT_MS },
      )) as CallToolResult;
    } catch (error) {
      if (!isRetryableError(error)) {
        throw error;
      }
      this.recordFailure(error, `retryable failure calling ${name}`);
      await this.reconnectNow();
      return (await this.client!.callTool(
        { name, arguments: args },
        undefined,
        { timeout: CONNECT_TIMEOUT_MS },
      )) as CallToolResult;
    }
  }

  async ping(): Promise<void> {
    try {
      await this.ensureConnected();
      await this.client!.ping({ timeout: CONNECT_TIMEOUT_MS });
    } catch (error) {
      this.recordFailure(error, "ping failed");
      if (isRetryableError(error)) {
        this.scheduleReconnect();
      }
    }
  }

  async close(): Promise<void> {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    await this.closeTransport();
  }

  private async ensureConnected(): Promise<void> {
    if (this.connected && this.client) {
      return;
    }
    await this.reconnectNow();
  }

  private async reconnectNow(): Promise<void> {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
      this.nextReconnectAt = undefined;
    }
    await this.connectWithTimeout();
  }

  private async connectWithTimeout(): Promise<void> {
    if (this.connecting) {
      return this.connecting;
    }
    this.connecting = this.connect().finally(() => {
      this.connecting = undefined;
    });
    return this.connecting;
  }

  private async connect(): Promise<void> {
    await this.closeTransport();
    const transport = this.makeTransport();
    const client = new Client(
      { name: `mcp-bridge-${this.name}-client`, version: "0.1.0" },
      { capabilities: {} },
    );

    transport.onerror = (error) => {
      this.recordFailure(error, "transport error");
    };
    transport.onclose = () => {
      if (this.connected) {
        this.log("warn", `${this.name} upstream closed; scheduling reconnect`);
      }
      this.connected = false;
      this.scheduleReconnect();
    };

    this.transport = transport;
    this.client = client;

    try {
      await client.connect(transport, { timeout: CONNECT_TIMEOUT_MS });
      this.connected = true;
      this.lastConnectedAt = nowIso();
      this.lastError = undefined;
      this.reconnectAttempts = 0;
      this.nextReconnectAt = undefined;
      await this.refreshTools();
      this.log("info", `${this.name} upstream connected`, { toolCount: this.tools.length });
    } catch (error) {
      this.connected = false;
      this.recordFailure(error, "connect failed");
      this.scheduleReconnect();
      throw error;
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) {
      return;
    }
    this.connected = false;
    const delay = Math.min(
      MAX_BACKOFF_MS,
      Math.round(INITIAL_BACKOFF_MS * 2 ** Math.min(this.reconnectAttempts, 6)),
    );
    this.reconnectAttempts += 1;
    this.nextReconnectAt = new Date(Date.now() + delay).toISOString();
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      this.nextReconnectAt = undefined;
      this.connectWithTimeout().catch(() => {
        this.scheduleReconnect();
      });
    }, delay);
  }

  private recordFailure(error: unknown, context: string): void {
    this.lastError = `${context}: ${errorMessage(error)}`;
    this.log("warn", `${this.name} ${context}`, { error: errorMessage(error) });
  }

  private async closeTransport(): Promise<void> {
    this.connected = false;
    try {
      await this.client?.close();
    } catch {
      // Best effort; the replacement connection is more important than a clean close.
    }
    try {
      await this.transport?.close();
    } catch {
      // Best effort.
    }
    this.client = undefined;
    this.transport = undefined;
  }
}

export class UpstreamBridge {
  private readonly oauthProvider: PersistentOAuthProvider;
  private readonly endpoints: UpstreamEndpoint[];
  private readonly toolOwners = new Map<string, UpstreamEndpoint>();
  private intervals: NodeJS.Timeout[] = [];

  constructor(private readonly options: BridgeOptions) {
    this.oauthProvider = new PersistentOAuthProvider(options.oauthStatePath);
    const cachedTools = this.loadInitialToolCache();
    this.endpoints = [
      new UpstreamEndpoint(
        "overseer",
        "http",
        () =>
          new StreamableHTTPClientTransport(new URL(options.overseerUrl), {
            authProvider: this.oauthProvider,
            reconnectionOptions: {
              initialReconnectionDelay: 1_000,
              maxReconnectionDelay: 30_000,
              reconnectionDelayGrowFactor: 1.7,
              maxRetries: 20,
            },
          }),
        options.log,
        cachedTools.overseer ?? [],
      ),
      new UpstreamEndpoint(
        "sentinel",
        "stdio",
        () => {
          const transport = new StdioClientTransport({
            command: options.sentinelCommand,
            args: options.sentinelArgs,
            stderr: "pipe",
            env: {
              HOME: process.env.HOME ?? "/Users/johncornelius",
              PATH: process.env.PATH ?? "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
              TERM: process.env.TERM ?? "xterm-256color",
            },
          });
          transport.stderr?.on("data", (chunk) => {
            const text = String(chunk).trim();
            if (text) {
              options.log("warn", "sentinel stderr", { text });
            }
          });
          return transport;
        },
        options.log,
        cachedTools.sentinel ?? [],
      ),
    ];
    this.reindexTools();
  }

  async start(): Promise<void> {
    await Promise.allSettled(this.endpoints.map((endpoint) => endpoint.start()));
    this.reindexTools();
    await this.persistToolCache();
    this.intervals = [
      setInterval(() => {
        for (const endpoint of this.endpoints) {
          endpoint.ping();
        }
      }, PING_INTERVAL_MS),
      setInterval(() => {
        this.refreshAllTools();
      }, TOOL_REFRESH_MS),
    ];
  }

  async close(): Promise<void> {
    for (const interval of this.intervals) {
      clearInterval(interval);
    }
    await Promise.allSettled(this.endpoints.map((endpoint) => endpoint.close()));
  }

  listTools(): Tool[] {
    this.reindexTools();
    return this.endpoints.flatMap((endpoint) => endpoint.getTools());
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
    this.reindexTools();
    const owner = this.toolOwners.get(name);
    if (!owner) {
      throw new Error(`Tool ${name} is not known to the bridge`);
    }
    return owner.callTool(name, args);
  }

  health(): { ok: boolean; upstreams: UpstreamHealth[]; toolCount: number } {
    const upstreams = this.endpoints.map((endpoint) => endpoint.health());
    return {
      ok: upstreams.every((upstream) => upstream.connected || upstream.toolCount > 0),
      upstreams,
      toolCount: this.listTools().length,
    };
  }

  async refreshAllTools(): Promise<void> {
    await Promise.allSettled(this.endpoints.map((endpoint) => endpoint.refreshTools()));
    this.reindexTools();
    await this.persistToolCache();
  }

  private reindexTools(): void {
    this.toolOwners.clear();
    for (const endpoint of this.endpoints) {
      for (const tool of endpoint.getTools()) {
        this.toolOwners.set(tool.name, endpoint);
      }
    }
  }

  private loadInitialToolCache(): Record<string, Tool[]> {
    try {
      const raw = JSON.parse(readFileSync(this.options.toolCachePath, "utf8")) as ToolCacheFile;
      return raw.toolsByUpstream ?? {};
    } catch {
      return {};
    }
  }

  private async persistToolCache(): Promise<void> {
    const toolsByUpstream: Record<string, Tool[]> = {};
    for (const endpoint of this.endpoints) {
      const tools = endpoint.getTools();
      if (tools.length > 0) {
        toolsByUpstream[endpoint.name] = tools;
      }
    }
    await writeJsonAtomic(this.options.toolCachePath, { updatedAt: nowIso(), toolsByUpstream });
  }
}

export async function runOAuthBootstrap(options: {
  serverUrl: string;
  statePath: string;
  log: LogFn;
  ownerPassword?: string;
  ownerPasswordOpRef?: string;
}): Promise<void> {
  const provider = new PersistentOAuthProvider(options.statePath);
  let result = await auth(provider, { serverUrl: options.serverUrl, scope: "overseer.all" });
  if (result === "AUTHORIZED") {
    options.log("info", "OAuth state is already authorized");
    return;
  }

  const authorizationUrl = provider.consumeAuthorizationUrl();
  if (!authorizationUrl) {
    throw new Error("OAuth flow requested redirect but did not provide an authorization URL");
  }

  const ownerPassword =
    options.ownerPassword ??
    (await readOwnerPassword(options.ownerPasswordOpRef ?? DEFAULT_OWNER_PASSWORD_OP_REF).catch(() => undefined));

  if (!ownerPassword) {
    throw new Error(`Owner password unavailable; open and approve manually: ${authorizationUrl.toString()}`);
  }

  const authorizationCode = await completeOwnerConsent(authorizationUrl, ownerPassword);
  result = await auth(provider, {
    serverUrl: options.serverUrl,
    authorizationCode,
    scope: "overseer.all",
  });
  if (result !== "AUTHORIZED") {
    throw new Error(`OAuth did not complete; result=${result}`);
  }
  options.log("info", "OAuth bootstrap completed");
}

async function readOwnerPassword(opRef: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("op", ["read", opRef], { stdio: ["ignore", "pipe", "pipe"] });
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error("op read timed out"));
    }, 10_000);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("error", reject);
    child.on("exit", (code) => {
      clearTimeout(timer);
      if (code === 0 && stdout.trim()) {
        resolve(stdout.trim());
      } else {
        reject(new Error(stderr.trim() || `op read exited ${code}`));
      }
    });
  });
}

async function completeOwnerConsent(authorizationUrl: URL, password: string): Promise<string> {
  const consentUrl = await followToConsent(authorizationUrl);
  const txn = consentUrl.searchParams.get("txn");
  if (!txn) {
    throw new Error(`Consent URL missing txn: ${consentUrl.toString()}`);
  }
  const response = await fetch(consentUrl, {
    method: "POST",
    redirect: "manual",
    signal: fetchTimeout(),
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ txn, password }),
  });
  const location = response.headers.get("location");
  if (!location) {
    const text = await response.text().catch(() => "");
    throw new Error(`Consent POST did not return a redirect (${response.status}): ${text.slice(0, 200)}`);
  }
  const redirectUrl = new URL(location, consentUrl);
  const code = redirectUrl.searchParams.get("code");
  const error = redirectUrl.searchParams.get("error");
  if (error) {
    throw new Error(`Consent denied: ${error}`);
  }
  if (!code) {
    throw new Error(`Consent redirect missing code: ${redirectUrl.toString()}`);
  }
  return code;
}

async function followToConsent(startUrl: URL): Promise<URL> {
  let current = startUrl;
  for (let i = 0; i < 5; i += 1) {
    if (current.pathname === "/consent" && current.searchParams.get("txn")) {
      return current;
    }
    const response = await fetch(current, { redirect: "manual", signal: fetchTimeout() });
    const location = response.headers.get("location");
    if (!location) {
      throw new Error(`OAuth authorize did not redirect to consent (${response.status})`);
    }
    current = new URL(location, current);
    await sleep(100);
  }
  throw new Error("OAuth authorize redirect chain did not reach /consent");
}
