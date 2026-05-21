# mcp-bridge

OAuth-aware local bridge for [Model Context Protocol](https://modelcontextprotocol.io/) servers.

A persistent daemon that runs on `127.0.0.1:8769` and exposes a single stable HTTP MCP endpoint backed by multiple upstreams — both remote OAuth-protected MCP servers and local stdio MCP processes. The bridge handles the rough edges that custom Claude / ChatGPT connectors trip on: refresh-token rotation, transport-protocol differences, reconnect with backoff, and a warm tool-cache that survives restarts.

## Why this exists

Custom MCP connectors in Claude Desktop and ChatGPT need a stable HTTP endpoint. But the actual MCP servers you want to expose are usually one of:

- A **remote MCP server behind OAuth** — refresh tokens, PKCE, owner-consent prompts. Not something a Desktop app wants to manage on every launch.
- A **stdio MCP server** running as a local process — not reachable from a web client at all.

This bridge solves both with one local daemon: warm OAuth tokens cached to disk, transport-agnostic upstream registry, automatic reconnect/backoff, and a CORS allowlist for `claude.ai` / `chatgpt.com` / `*.claudeusercontent.com` origins.

## Architecture

```
Claude Desktop (stdio)
    │
    ▼
stdio-proxy ──► http://127.0.0.1:8769/mcp ──► UpstreamRegistry
                                                ├── HTTP (OAuth refresh, retry)
                                                └── stdio (spawned child, stderr logged)
```

- `src/index.ts` — Express HTTP server, log rotation, OAuth callback receiver, top-level wiring.
- `src/upstream.ts` — `UpstreamEndpoint` state machine: connect → handshake → list tools → keep warm. Backoff schedule, ping keepalive, tool-cache persistence.
- `src/stdio-proxy.ts` — Small stdio↔HTTP proxy for clients (like Claude Desktop) that only speak stdio.

## Reliability features

- **Warm tool cache** — last-known tool list is persisted to disk; if an upstream is down at startup, the bridge still answers `tools/list` from cache so the client doesn't see an empty surface.
- **OAuth state persistence** — tokens are written atomically with `0o600` perms; refresh flows kick off in the background well before expiry.
- **Reconnect with backoff** — exponential up to 60s, jittered, with a `pingInterval` keepalive that proactively reconnects on idle drops.
- **CORS allowlist** — explicitly enumerates `claude.ai`, `chatgpt.com`, `chat.openai.com`, `*.claudeusercontent.com`, `*.openai.com`. Everything else is rejected.

## Quickstart

```bash
npm install
npm run build

# Configure the upstreams you want to proxy via env vars (see below).
# Then either authenticate the OAuth upstream once...
npm run auth

# ...or just start the bridge if your upstreams don't need OAuth.
npm start
```

## Configuration

Everything is env-driven; nothing is hardcoded to a specific identity or host.

| Env var | Default | Purpose |
| --- | --- | --- |
| `MCP_BRIDGE_PORT` | `8769` | HTTP listen port |
| `MCP_BRIDGE_HOST` | `127.0.0.1` | HTTP bind address (loopback only by default) |
| `MCP_BRIDGE_MCP_PATH` | `/mcp` | HTTP path for the MCP endpoint |
| `MCP_BRIDGE_OVERSEER_URL` | (none) | URL of the remote OAuth-protected MCP server to proxy. Empty disables this upstream. |
| `MCP_BRIDGE_SENTINEL_COMMAND` | (none) | Command to spawn a local stdio MCP server. Empty disables this upstream. |
| `MCP_BRIDGE_SENTINEL_ARGS` | (empty) | Space-separated args for the stdio upstream |
| `MCP_BRIDGE_CONFIG_DIR` | `~/.config/mcp-bridge` | Where `oauth-state.json` and `tools-cache.json` live |
| `MCP_BRIDGE_LOG_PATH` | `~/Library/Logs/mcp-bridge.log` | Rotating log file |
| `MCP_BRIDGE_OWNER_PASSWORD_OP_REF` | (none) | Optional `op://vault/item/field` reference to pull the OAuth owner-consent password from 1Password via the `op` CLI |
| `MCP_BRIDGE_OWNER_PASSWORD` | (none) | Alternate: pass the OAuth owner-consent password directly |

## Status

Stable. Runs in production on the author's workstation since May 2026.

## License

MIT. See [LICENSE](LICENSE).
